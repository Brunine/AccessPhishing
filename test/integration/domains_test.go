package integration

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"phishforge/internal/apikey"
	"phishforge/internal/tenant"
)

// TestDomainInventoryLifecycle drives the full M8b+M8c flow: manual import ->
// verification (fail then succeed) -> assign -> admin authorize -> activate ->
// suspend/retire, plus the delete rules and diagnostics.
func TestDomainInventoryLifecycle(t *testing.T) {
	pool := setupDB(t)
	ctx := context.Background()

	tenants := tenant.NewRepository()
	tn, err := tenants.Create(ctx, pool, "Dom Co", "dom-"+short())
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	adminID := createUser(t, ctx, pool, tn.ID, "admin@dom.test", "admin")
	opID := createUser(t, ctx, pool, tn.ID, "op@dom.test", "operator")
	keys := apikey.NewService(pool)
	adminTok, _, _ := keys.Create(ctx, tn.ID, adminID, "admin")
	opTok, _, _ := keys.Create(ctx, tn.ID, opID, "op")

	srv, _ := newAPI(t, pool)
	defer srv.Close()

	// --- manual import ---
	// invalid name -> 400.
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/domains", opTok, map[string]any{"name": "not a domain"}); code != http.StatusBadRequest {
		t.Fatalf("import bad name: want 400, got %d", code)
	}
	code, body := do(t, srv.URL, http.MethodPost, "/api/v1/domains", opTok, map[string]any{
		"name": "Phish-Target.Example", "registrar": "namecheap",
	})
	if code != http.StatusCreated {
		t.Fatalf("import: want 201, got %d (%s)", code, body)
	}
	var dom struct {
		ID     uuid.UUID `json:"id"`
		Name   string    `json:"name"`
		Status string    `json:"status"`
	}
	mustJSON(t, body, &dom)
	if dom.Name != "phish-target.example" {
		t.Fatalf("name not normalized: %q", dom.Name)
	}
	if dom.Status != "pending_verification" {
		t.Fatalf("import status: want pending_verification, got %q", dom.Status)
	}
	// duplicate -> 409.
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/domains", opTok, map[string]any{"name": "phish-target.example"}); code != http.StatusConflict {
		t.Fatalf("dup import: want 409, got %d", code)
	}

	// --- cannot verify-promote via PATCH ---
	if code, _ := do(t, srv.URL, http.MethodPatch, "/api/v1/domains/"+dom.ID.String(), opTok, map[string]any{"status": "verified"}); code != http.StatusConflict {
		t.Fatalf("PATCH to verified: want 409, got %d", code)
	}

	// --- cannot assign before verification ---
	engID := seedAuthorizedEngagement(t, ctx, pool, tn.ID, opID)
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/domains/"+dom.ID.String()+"/assign", opTok, map[string]any{"engagement_id": engID}); code != http.StatusConflict {
		t.Fatalf("assign before verify: want 409, got %d", code)
	}

	// --- create verification ---
	code, body = do(t, srv.URL, http.MethodPost, "/api/v1/domains/"+dom.ID.String()+"/verification", opTok, nil)
	if code != http.StatusCreated {
		t.Fatalf("create verification: want 201, got %d (%s)", code, body)
	}
	var ver struct {
		ID        uuid.UUID `json:"id"`
		Hostname  string    `json:"hostname"`
		TXTRecord string    `json:"txt_record"`
	}
	mustJSON(t, body, &ver)
	if ver.Hostname != "_phishforge.phish-target.example" {
		t.Fatalf("verification hostname: %q", ver.Hostname)
	}

	// --- check against a DNS that lacks the record -> failed (200, verified:false) ---
	code, body = do(t, srv.URL, http.MethodPost, "/api/v1/domains/"+dom.ID.String()+"/verification/"+ver.ID.String()+"/check", opTok, nil)
	if code != http.StatusOK {
		t.Fatalf("check (no record): want 200, got %d (%s)", code, body)
	}
	var chk struct {
		Verified bool `json:"verified"`
	}
	mustJSON(t, body, &chk)
	if chk.Verified {
		t.Fatal("check against DNS with no record should be verified:false")
	}
	// Re-checking a non-pending verification -> 409.
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/domains/"+dom.ID.String()+"/verification/"+ver.ID.String()+"/check", opTok, nil); code != http.StatusConflict {
		t.Fatalf("recheck failed verification: want 409, got %d", code)
	}

	// --- simulate the operator publishing the TXT record: seed it so that a
	// fresh verification's expected_value is present in a stubbed resolver.
	// Since the integration harness uses the system resolver (no record will
	// ever resolve for example-domains), we promote the domain directly via a
	// second verification whose expected_value we inject into the DB and then
	// mark verified through the repository-equivalent SQL path the handler uses.
	// To keep this black-box, we instead seed the domain to 'verified' via SQL
	// (the production promotion path is covered by the verified->active flow
	// below and by the handler's unit-level guard). ---
	seedDomainStatus(t, ctx, pool, dom.ID, "verified")

	// --- assign (verified domain + authorized engagement) ---
	code, body = do(t, srv.URL, http.MethodPost, "/api/v1/domains/"+dom.ID.String()+"/assign", opTok, map[string]any{"engagement_id": engID})
	if code != http.StatusCreated {
		t.Fatalf("assign: want 201, got %d (%s)", code, body)
	}
	var asg struct {
		ID     uuid.UUID `json:"id"`
		Status string    `json:"status"`
	}
	mustJSON(t, body, &asg)
	if asg.Status != "pending" {
		t.Fatalf("assignment status: want pending, got %q", asg.Status)
	}
	// duplicate assignment -> 409.
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/domains/"+dom.ID.String()+"/assign", opTok, map[string]any{"engagement_id": engID}); code != http.StatusConflict {
		t.Fatalf("dup assign: want 409, got %d", code)
	}

	// --- activate before any authorized assignment -> 409 ---
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/domains/"+dom.ID.String()+"/activate", adminTok, nil); code != http.StatusConflict {
		t.Fatalf("activate w/o authorized assignment: want 409, got %d", code)
	}

	// --- operator cannot authorize an assignment (admin only) -> 403 ---
	authzPath := "/api/v1/domains/" + dom.ID.String() + "/assignments/" + asg.ID.String() + "/authorize"
	if code, _ := do(t, srv.URL, http.MethodPost, authzPath, opTok, nil); code != http.StatusForbidden {
		t.Fatalf("operator authorize assignment: want 403, got %d", code)
	}
	// admin authorizes.
	code, body = do(t, srv.URL, http.MethodPost, authzPath, adminTok, nil)
	if code != http.StatusOK {
		t.Fatalf("admin authorize assignment: want 200, got %d (%s)", code, body)
	}
	// re-authorize -> 409 (already authorized).
	if code, _ := do(t, srv.URL, http.MethodPost, authzPath, adminTok, nil); code != http.StatusConflict {
		t.Fatalf("re-authorize assignment: want 409, got %d", code)
	}

	// --- activate (verified + authorized assignment) ---
	code, body = do(t, srv.URL, http.MethodPost, "/api/v1/domains/"+dom.ID.String()+"/activate", adminTok, nil)
	if code != http.StatusOK {
		t.Fatalf("activate: want 200, got %d (%s)", code, body)
	}
	var active struct {
		Status string `json:"status"`
	}
	mustJSON(t, body, &active)
	if active.Status != "active" {
		t.Fatalf("activated status: want active, got %q", active.Status)
	}

	// --- active domain cannot be deleted -> 409 ---
	if code, _ := do(t, srv.URL, http.MethodDelete, "/api/v1/domains/"+dom.ID.String(), opTok, nil); code != http.StatusConflict {
		t.Fatalf("delete active: want 409, got %d", code)
	}

	// --- suspend (admin), then reactivate via activate, then retire ---
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/domains/"+dom.ID.String()+"/suspend", adminTok, nil); code != http.StatusOK {
		t.Fatalf("suspend: want 200, got %d", code)
	}
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/domains/"+dom.ID.String()+"/retire", adminTok, nil); code != http.StatusOK {
		t.Fatalf("retire: want 200, got %d", code)
	}
	// retire is terminal: suspend now 409.
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/domains/"+dom.ID.String()+"/suspend", adminTok, nil); code != http.StatusConflict {
		t.Fatalf("suspend after retire: want 409, got %d", code)
	}

	// --- diagnostics against a non-resolving domain: structured errors, not 500 ---
	code, body = do(t, srv.URL, http.MethodGet, "/api/v1/domains/"+dom.ID.String()+"/diagnostics", opTok, nil)
	if code != http.StatusOK {
		t.Fatalf("diagnostics: want 200, got %d (%s)", code, body)
	}
	var diag struct {
		DNS struct {
			DKIM *string `json:"dkim"`
		} `json:"dns"`
		Errors   []string `json:"errors"`
		Warnings []string `json:"warnings"`
	}
	mustJSON(t, body, &diag)
	if diag.DNS.DKIM != nil {
		t.Fatalf("diagnostics dkim: want null, got %v", *diag.DNS.DKIM)
	}
	if len(diag.Errors) == 0 {
		t.Fatalf("diagnostics against non-resolving domain should populate errors[], got none (%s)", body)
	}

	// --- audit counts for the main actions ---
	checks := map[string]int{
		"domain.create":               1,
		"domain.verification.create":  1,
		"domain.verification.check":   1,
		"domain.assign":               1,
		"domain.assignment.authorize": 1,
		"domain.activate":             1,
		"domain.suspend":              1,
		"domain.retire":               1,
	}
	for action, want := range checks {
		if n := count(t, ctx, pool, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action=$2`, tn.ID, action); n != want {
			t.Errorf("audit %s: want %d, got %d", action, want, n)
		}
	}
}

// TestDomainVerificationPromotion exercises the real check -> verified promotion
// through the handler, using an injected resolver that returns the published
// TXT record.
func TestDomainVerificationPromotion(t *testing.T) {
	pool := setupDB(t)
	ctx := context.Background()

	tenants := tenant.NewRepository()
	tn, _ := tenants.Create(ctx, pool, "Promote Co", "prom-"+short())
	opID := createUser(t, ctx, pool, tn.ID, "op@prom.test", "operator")
	keys := apikey.NewService(pool)
	opTok, _, _ := keys.Create(ctx, tn.ID, opID, "op")

	// An API server whose resolver returns whatever TXT we stage.
	res := newStubResolver()
	srv := newAPIWithResolver(t, pool, res)
	defer srv.Close()

	_, body := do(t, srv.URL, http.MethodPost, "/api/v1/domains", opTok, map[string]any{"name": "promote.example"})
	var dom struct {
		ID uuid.UUID `json:"id"`
	}
	mustJSON(t, body, &dom)

	_, body = do(t, srv.URL, http.MethodPost, "/api/v1/domains/"+dom.ID.String()+"/verification", opTok, nil)
	var ver struct {
		ID        uuid.UUID `json:"id"`
		Hostname  string    `json:"hostname"`
		TXTRecord string    `json:"txt_record"`
	}
	mustJSON(t, body, &ver)

	// Publish the exact TXT value the operator was told to set.
	res.set(ver.Hostname, []string{"some-other=1", ver.TXTRecord})

	code, body := do(t, srv.URL, http.MethodPost, "/api/v1/domains/"+dom.ID.String()+"/verification/"+ver.ID.String()+"/check", opTok, nil)
	if code != http.StatusOK {
		t.Fatalf("check (with record): want 200, got %d (%s)", code, body)
	}
	var chk struct {
		Verified bool `json:"verified"`
	}
	mustJSON(t, body, &chk)
	if !chk.Verified {
		t.Fatalf("check with published record should verify: %s", body)
	}
	// Domain promoted to verified.
	code, body = do(t, srv.URL, http.MethodGet, "/api/v1/domains/"+dom.ID.String(), opTok, nil)
	var got struct {
		Status string `json:"status"`
	}
	mustJSON(t, body, &got)
	if got.Status != "verified" {
		t.Fatalf("domain not promoted: status %q", got.Status)
	}
}

// TestDomainTenantIsolation covers cross-tenant scoping.
func TestDomainTenantIsolation(t *testing.T) {
	pool := setupDB(t)
	ctx := context.Background()

	tenants := tenant.NewRepository()
	keys := apikey.NewService(pool)

	tnA, _ := tenants.Create(ctx, pool, "DA Co", "da-"+short())
	aOp := createUser(t, ctx, pool, tnA.ID, "op@da.test", "operator")
	aTok, _, _ := keys.Create(ctx, tnA.ID, aOp, "a-op")

	tnB, _ := tenants.Create(ctx, pool, "DB Co", "db-"+short())
	bOp := createUser(t, ctx, pool, tnB.ID, "op@db.test", "operator")
	bTok, _, _ := keys.Create(ctx, tnB.ID, bOp, "b-op")

	srv, _ := newAPI(t, pool)
	defer srv.Close()

	// B imports + seeds a verified domain.
	_, bb := do(t, srv.URL, http.MethodPost, "/api/v1/domains", bTok, map[string]any{"name": "b-owned.example"})
	var bDom struct {
		ID uuid.UUID `json:"id"`
	}
	mustJSON(t, bb, &bDom)
	seedDomainStatus(t, ctx, pool, bDom.ID, "verified")

	// A's engagement.
	aEng := seedAuthorizedEngagement(t, ctx, pool, tnA.ID, aOp)

	// A cannot GET B's domain -> 404 (tenant-scoped).
	if code, _ := do(t, srv.URL, http.MethodGet, "/api/v1/domains/"+bDom.ID.String(), aTok, nil); code != http.StatusNotFound {
		t.Fatalf("A get B domain: want 404, got %d", code)
	}
	// A cannot assign to B's domain (domain not in A's tenant -> 404).
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/domains/"+bDom.ID.String()+"/assign", aTok, map[string]any{"engagement_id": aEng}); code != http.StatusNotFound {
		t.Fatalf("A assign B domain: want 404, got %d", code)
	}

	// A's own verified domain cannot bind B's engagement -> 400 (foreign ref).
	_, ab := do(t, srv.URL, http.MethodPost, "/api/v1/domains", aTok, map[string]any{"name": "a-owned.example"})
	var aDom struct {
		ID uuid.UUID `json:"id"`
	}
	mustJSON(t, ab, &aDom)
	seedDomainStatus(t, ctx, pool, aDom.ID, "verified")
	bEng := seedAuthorizedEngagement(t, ctx, pool, tnB.ID, bOp)
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/domains/"+aDom.ID.String()+"/assign", aTok, map[string]any{"engagement_id": bEng}); code != http.StatusBadRequest {
		t.Fatalf("A assign to B engagement: want 400, got %d", code)
	}

	// A's list excludes B's domain.
	code, lb := do(t, srv.URL, http.MethodGet, "/api/v1/domains", aTok, nil)
	if code != http.StatusOK {
		t.Fatalf("A list: %d", code)
	}
	var list struct {
		Items []struct {
			ID uuid.UUID `json:"id"`
		} `json:"items"`
	}
	mustJSON(t, lb, &list)
	for _, it := range list.Items {
		if it.ID == bDom.ID {
			t.Fatal("A's list leaked B's domain")
		}
	}
}
