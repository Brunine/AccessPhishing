package integration

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"phishforge/internal/apikey"
	"phishforge/internal/tenant"
)

// seedEngagementStatus inserts an engagement in an arbitrary status (and
// optional expiry) directly, for the negative launch/send gate cases.
func seedEngagementStatus(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID, createdBy uuid.UUID, status string, expiresAt *time.Time) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := pool.QueryRow(ctx,
		`INSERT INTO engagements (tenant_id, name, client_name, status, expires_at, authorized_at, authorized_by, created_by)
		 VALUES ($1, $2, $3, $4::engagement_status, $5, now(), $6, $6) RETURNING id`,
		tenantID, "Seed "+short(), "Client", status, expiresAt, createdBy).Scan(&id)
	if err != nil {
		t.Fatalf("seed engagement status %q: %v", status, err)
	}
	return id
}

// TestEngagementLifecycleAndGates covers the engagement authorization workflow
// and the campaign launch/send gate it introduces.
func TestEngagementLifecycleAndGates(t *testing.T) {
	pool := setupDB(t)
	ctx := context.Background()

	tenants := tenant.NewRepository()
	tn, err := tenants.Create(ctx, pool, "Eng Co", "eng-"+short())
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	adminID := createUser(t, ctx, pool, tn.ID, "admin@eng.test", "admin")
	opID := createUser(t, ctx, pool, tn.ID, "op@eng.test", "operator")
	keys := apikey.NewService(pool)
	adminTok, _, _ := keys.Create(ctx, tn.ID, adminID, "admin")
	opTok, _, _ := keys.Create(ctx, tn.ID, opID, "op")

	srv, enq := newAPI(t, pool)
	defer srv.Close()

	// --- create (operator) ---
	code, body := do(t, srv.URL, http.MethodPost, "/api/v1/engagements", opTok, map[string]any{
		"client_name": "Acme Inc", "name": "Q1 Acme Test",
		"authorized_scope": []string{"*.acme.com", "https://acme.com"},
	})
	if code != http.StatusCreated {
		t.Fatalf("create engagement: want 201, got %d (%s)", code, body)
	}
	var eng struct {
		ID     uuid.UUID `json:"id"`
		Status string    `json:"status"`
	}
	mustJSON(t, body, &eng)
	if eng.Status != "draft" {
		t.Fatalf("new engagement status: want draft, got %q", eng.Status)
	}

	// invalid scope -> 400
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/engagements", opTok, map[string]any{
		"client_name": "Acme", "name": "Bad Scope", "authorized_scope": []string{"not a domain"},
	}); code != http.StatusBadRequest {
		t.Fatalf("invalid scope: want 400, got %d", code)
	}

	// --- authorization workflow ---
	// operator cannot reach the admin-only authorize route (self-authorization
	// is impossible, enforced server-side).
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/engagements/"+eng.ID.String()+"/authorize", opTok, nil); code != http.StatusForbidden {
		t.Fatalf("operator authorize: want 403, got %d", code)
	}
	// admin authorize from draft is an invalid transition -> 409.
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/engagements/"+eng.ID.String()+"/authorize", adminTok, nil); code != http.StatusConflict {
		t.Fatalf("authorize from draft: want 409, got %d", code)
	}
	// operator requests authorization -> pending_authorization.
	if code, b := do(t, srv.URL, http.MethodPost, "/api/v1/engagements/"+eng.ID.String()+"/request-authorization", opTok, nil); code != http.StatusOK {
		t.Fatalf("request-authorization: want 200, got %d (%s)", code, b)
	}
	// admin authorizes -> authorized, authorized_at/by set.
	code, body = do(t, srv.URL, http.MethodPost, "/api/v1/engagements/"+eng.ID.String()+"/authorize", adminTok, nil)
	if code != http.StatusOK {
		t.Fatalf("authorize: want 200, got %d (%s)", code, body)
	}
	var authd struct {
		Status          string     `json:"status"`
		AuthorizedAt    *time.Time `json:"authorized_at"`
		AuthorizedBy    *uuid.UUID `json:"authorized_by"`
		EffectiveStatus string     `json:"effective_status"`
	}
	mustJSON(t, body, &authd)
	if authd.Status != "authorized" || authd.AuthorizedAt == nil || authd.AuthorizedBy == nil {
		t.Fatalf("authorized engagement: %+v", authd)
	}
	if *authd.AuthorizedBy != adminID {
		t.Fatalf("authorized_by: want %s, got %s", adminID, *authd.AuthorizedBy)
	}
	if authd.EffectiveStatus != "active" {
		t.Fatalf("effective status: want active, got %q", authd.EffectiveStatus)
	}

	// --- happy path: bind campaign -> launch -> approve -> send ---
	_, gb := do(t, srv.URL, http.MethodPost, "/api/v1/contact-groups", opTok, map[string]any{"name": "wave"})
	var grp struct {
		ID uuid.UUID `json:"id"`
	}
	mustJSON(t, gb, &grp)
	do(t, srv.URL, http.MethodPost, "/api/v1/contacts", opTok, map[string]any{"email": "victim@acme.com", "group_id": grp.ID})

	_, tb := do(t, srv.URL, http.MethodPost, "/api/v1/templates", opTok, map[string]any{
		"kind": "email", "name": "drill", "subject": "Hi", "body": `<a href="{{.link}}">x</a>`,
	})
	var tmpl struct {
		ID uuid.UUID `json:"id"`
	}
	mustJSON(t, tb, &tmpl)
	_, pb := do(t, srv.URL, http.MethodPost, "/api/v1/sending-profiles", opTok, map[string]any{
		"name": "mock", "smtp_host": "127.0.0.1", "smtp_port": 2525, "from_address": "x@phish.test", "tls_mode": "none",
	})
	var prof struct {
		ID uuid.UUID `json:"id"`
	}
	mustJSON(t, pb, &prof)

	code, body = do(t, srv.URL, http.MethodPost, "/api/v1/campaigns", opTok, map[string]any{"name": "Bound", "engagement_id": eng.ID})
	if code != http.StatusCreated {
		t.Fatalf("create bound campaign: %d (%s)", code, body)
	}
	var camp struct {
		ID           uuid.UUID `json:"id"`
		EngagementID uuid.UUID `json:"engagement_id"`
	}
	mustJSON(t, body, &camp)
	if camp.EngagementID != eng.ID {
		t.Fatalf("campaign engagement_id: want %s, got %s", eng.ID, camp.EngagementID)
	}
	// Detail/list responses carry the derived engagement status label.
	_, db := do(t, srv.URL, http.MethodGet, "/api/v1/campaigns/"+camp.ID.String(), opTok, nil)
	var detail struct {
		EngagementStatus string `json:"engagement_status"`
	}
	mustJSON(t, db, &detail)
	if detail.EngagementStatus != "active" {
		t.Fatalf("campaign detail engagement_status: want active, got %q", detail.EngagementStatus)
	}

	if code, b := do(t, srv.URL, http.MethodPost, "/api/v1/campaigns/"+camp.ID.String()+"/launch", opTok, map[string]any{
		"group_id": grp.ID, "template_id": tmpl.ID, "sending_profile_id": prof.ID, "landing_url": "http://base.local/px/x",
	}); code != http.StatusOK {
		t.Fatalf("launch bound campaign: want 200, got %d (%s)", code, b)
	}
	// approve the template, then send enqueues.
	_, ab := do(t, srv.URL, http.MethodPost, "/api/v1/approvals", opTok, map[string]any{"subject_type": "template", "subject_id": tmpl.ID})
	var appr struct {
		ID uuid.UUID `json:"id"`
	}
	mustJSON(t, ab, &appr)
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/approvals/"+appr.ID.String()+"/approve", adminTok, nil); code != http.StatusOK {
		t.Fatalf("approve template failed")
	}
	if code, b := do(t, srv.URL, http.MethodPost, "/api/v1/campaigns/"+camp.ID.String()+"/send", opTok, nil); code != http.StatusAccepted {
		t.Fatalf("send bound campaign: want 202, got %d (%s)", code, b)
	}
	if enq.count() != 1 {
		t.Fatalf("enqueue count: want 1, got %d", enq.count())
	}

	// --- changing a campaign's engagement after launch is rejected (409) ---
	eng2 := seedAuthorizedEngagement(t, ctx, pool, tn.ID, opID)
	if code, b := do(t, srv.URL, http.MethodPatch, "/api/v1/campaigns/"+camp.ID.String(), opTok, map[string]any{"engagement_id": eng2}); code != http.StatusConflict {
		t.Fatalf("rebind engagement after launch: want 409, got %d (%s)", code, b)
	}

	// --- launch/send gates ---
	launchFresh := func(engID *uuid.UUID) (int, string) {
		b := map[string]any{"name": "Gate " + short()}
		if engID != nil {
			b["engagement_id"] = *engID
		}
		_, cb := do(t, srv.URL, http.MethodPost, "/api/v1/campaigns", opTok, b)
		var c struct {
			ID uuid.UUID `json:"id"`
		}
		mustJSON(t, cb, &c)
		return do(t, srv.URL, http.MethodPost, "/api/v1/campaigns/"+c.ID.String()+"/launch", opTok, map[string]any{"group_id": grp.ID})
	}

	// no engagement -> 403 with a problem detail that names the fix.
	if code, b := launchFresh(nil); code != http.StatusForbidden || !strings.Contains(b, "bind an authorized engagement") {
		t.Fatalf("launch w/o engagement: want 403 + detail, got %d (%s)", code, b)
	}
	// pending_authorization -> 403.
	pendID := seedEngagementStatus(t, ctx, pool, tn.ID, opID, "pending_authorization", nil)
	if code, _ := launchFresh(&pendID); code != http.StatusForbidden {
		t.Fatalf("launch w/ pending engagement: want 403, got %d", code)
	}
	// expired (authorized + past expiry) -> 409.
	past := time.Now().Add(-time.Hour)
	expID := seedEngagementStatus(t, ctx, pool, tn.ID, opID, "authorized", &past)
	if code, _ := launchFresh(&expID); code != http.StatusConflict {
		t.Fatalf("launch w/ expired engagement: want 409, got %d", code)
	}
	// terminated -> 409.
	termID := seedEngagementStatus(t, ctx, pool, tn.ID, opID, "terminated", nil)
	if code, _ := launchFresh(&termID); code != http.StatusConflict {
		t.Fatalf("launch w/ terminated engagement: want 409, got %d", code)
	}

	// --- terminal engagement: no re-auth, no edit ---
	// create -> request -> authorize -> terminate, then re-auth/edit are 409.
	code, body = do(t, srv.URL, http.MethodPost, "/api/v1/engagements", opTok, map[string]any{"client_name": "C", "name": "ToTerminate"})
	var te struct {
		ID uuid.UUID `json:"id"`
	}
	mustJSON(t, body, &te)
	do(t, srv.URL, http.MethodPost, "/api/v1/engagements/"+te.ID.String()+"/request-authorization", opTok, nil)
	do(t, srv.URL, http.MethodPost, "/api/v1/engagements/"+te.ID.String()+"/authorize", adminTok, nil)
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/engagements/"+te.ID.String()+"/terminate", adminTok, nil); code != http.StatusOK {
		t.Fatalf("terminate: want 200, got %d", code)
	}
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/engagements/"+te.ID.String()+"/request-authorization", opTok, nil); code != http.StatusConflict {
		t.Fatalf("re-request after terminate: want 409, got %d", code)
	}
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/engagements/"+te.ID.String()+"/authorize", adminTok, nil); code != http.StatusConflict {
		t.Fatalf("re-authorize after terminate: want 409, got %d", code)
	}
	if code, _ := do(t, srv.URL, http.MethodPatch, "/api/v1/engagements/"+te.ID.String(), opTok, map[string]any{"name": "X", "client_name": "C"}); code != http.StatusConflict {
		t.Fatalf("patch terminated: want 409, got %d", code)
	}

	// --- audit counts ---
	// create: Q1 Acme + Bad Scope(400, not created) + ToTerminate = 2 created.
	if n := count(t, ctx, pool, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='engagement.create'`, tn.ID); n != 2 {
		t.Fatalf("engagement.create audit: want 2, got %d", n)
	}
	if n := count(t, ctx, pool, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='engagement.request_authorization'`, tn.ID); n != 2 {
		t.Fatalf("engagement.request_authorization audit: want 2, got %d", n)
	}
	if n := count(t, ctx, pool, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='engagement.authorize'`, tn.ID); n != 2 {
		t.Fatalf("engagement.authorize audit: want 2, got %d", n)
	}
	if n := count(t, ctx, pool, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='engagement.terminate'`, tn.ID); n != 1 {
		t.Fatalf("engagement.terminate audit: want 1, got %d", n)
	}
}

// TestEngagementTenantIsolation covers cross-tenant scoping: a foreign
// engagement id is a 400 on campaign create and a 404 on GET, and never
// appears in another tenant's list.
func TestEngagementTenantIsolation(t *testing.T) {
	pool := setupDB(t)
	ctx := context.Background()

	tenants := tenant.NewRepository()
	keys := apikey.NewService(pool)

	tnA, _ := tenants.Create(ctx, pool, "A Co", "a-"+short())
	aOp := createUser(t, ctx, pool, tnA.ID, "op@a.test", "operator")
	aTok, _, _ := keys.Create(ctx, tnA.ID, aOp, "a-op")

	tnB, _ := tenants.Create(ctx, pool, "B Co", "b-"+short())
	bOp := createUser(t, ctx, pool, tnB.ID, "op@b.test", "operator")
	bTok, _, _ := keys.Create(ctx, tnB.ID, bOp, "b-op")

	srv, _ := newAPI(t, pool)
	defer srv.Close()

	// B creates an engagement.
	_, bb := do(t, srv.URL, http.MethodPost, "/api/v1/engagements", bTok, map[string]any{"name": "B Eng", "client_name": "B"})
	var bEng struct {
		ID uuid.UUID `json:"id"`
	}
	mustJSON(t, bb, &bEng)

	// A cannot bind B's engagement (same-tenant check) -> 400.
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/campaigns", aTok, map[string]any{"name": "X", "engagement_id": bEng.ID}); code != http.StatusBadRequest {
		t.Fatalf("A bind B engagement: want 400, got %d", code)
	}
	// A cannot GET B's engagement -> 404 (tenant-scoped, not 403).
	if code, _ := do(t, srv.URL, http.MethodGet, "/api/v1/engagements/"+bEng.ID.String(), aTok, nil); code != http.StatusNotFound {
		t.Fatalf("A get B engagement: want 404, got %d", code)
	}
	// A's list is empty (does not include B's).
	code, lb := do(t, srv.URL, http.MethodGet, "/api/v1/engagements", aTok, nil)
	if code != http.StatusOK {
		t.Fatalf("A list: %d", code)
	}
	var list struct {
		Items []struct {
			ID uuid.UUID `json:"id"`
		} `json:"items"`
	}
	mustJSON(t, lb, &list)
	if len(list.Items) != 0 {
		t.Fatalf("A list should be empty, got %d", len(list.Items))
	}
}
