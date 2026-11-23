package integration

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"phishforge/internal/apikey"
	"phishforge/internal/bounce"
	"phishforge/internal/crypto"
	"phishforge/internal/delivery"
	"phishforge/internal/events"
	"phishforge/internal/tenant"
)

func TestDeliveryChannelsAndBounce(t *testing.T) {
	pool := setupDB(t)
	ctx := context.Background()

	tenants := tenant.NewRepository()
	tn, err := tenants.Create(ctx, pool, "Chan Co", "chan-"+short())
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	opID := createUser(t, ctx, pool, tn.ID, "op@chan.test", "operator")
	keys := apikey.NewService(pool)
	opTok, _, _ := keys.Create(ctx, tn.ID, opID, "op")

	srv, _ := newAPI(t, pool)
	defer srv.Close()

	// --- graph-channel profile: secret encrypted at rest ---
	code, body := do(t, srv.URL, http.MethodPost, "/api/v1/sending-profiles", opTok, map[string]any{
		"name": "graph-prof", "channel": "graph",
		"from_address": "it@customer.test", "from_name": "IT",
		"api_tenant_id": "tenant-guid", "api_client_id": "client-guid",
		"secret": "super-secret-value",
	})
	if code != http.StatusCreated {
		t.Fatalf("create graph profile: %d (%s)", code, body)
	}
	var prof struct {
		ID      uuid.UUID `json:"id"`
		Channel string    `json:"channel"`
	}
	mustJSON(t, body, &prof)
	if prof.Channel != "graph" {
		t.Fatalf("channel: %q", prof.Channel)
	}
	// Response must not leak the secret.
	if strings.Contains(body, "super-secret-value") {
		t.Fatalf("secret leaked in response: %s", body)
	}
	// Stored ciphertext differs from plaintext.
	var stored string
	if err := pool.QueryRow(ctx, `SELECT smtp_pass_encrypted FROM sending_profiles WHERE id=$1`, prof.ID).Scan(&stored); err != nil {
		t.Fatalf("read stored secret: %v", err)
	}
	if stored == "" || strings.Contains(stored, "super-secret-value") {
		t.Fatalf("secret not encrypted at rest: %q", stored)
	}

	// SMTP-only profiles still work unchanged.
	if code, b := do(t, srv.URL, http.MethodPost, "/api/v1/sending-profiles", opTok, map[string]any{
		"name": "smtp-prof", "smtp_host": "127.0.0.1", "smtp_port": 2525,
		"from_address": "it@customer.test", "tls_mode": "none",
	}); code != http.StatusCreated {
		t.Fatalf("create smtp profile: %d (%s)", code, b)
	}

	// template + two contacts in a group
	_, tb := do(t, srv.URL, http.MethodPost, "/api/v1/templates", opTok, map[string]any{
		"kind": "email", "name": "drill", "subject": "Hi {{.first_name}}", "body": "<a href=\"{{.link}}\">x</a>",
	})
	var tmpl struct {
		ID uuid.UUID `json:"id"`
	}
	mustJSON(t, tb, &tmpl)
	_, grpB := do(t, srv.URL, http.MethodPost, "/api/v1/contact-groups", opTok, map[string]any{"name": "wave"})
	var grp struct {
		ID uuid.UUID `json:"id"`
	}
	mustJSON(t, grpB, &grp)
	for _, e := range []string{"alice@target.test", "bob@target.test"} {
		do(t, srv.URL, http.MethodPost, "/api/v1/contacts", opTok, map[string]any{"email": e, "first_name": "X", "group_id": grp.ID})
	}

	// --- campaign 1: graph send without network config -> graceful failure ---
	engID := seedAuthorizedEngagement(t, ctx, pool, tn.ID, opID)
	_, cb := do(t, srv.URL, http.MethodPost, "/api/v1/campaigns", opTok, map[string]any{"name": "Graph Drill", "engagement_id": engID})
	var camp1 struct {
		ID uuid.UUID `json:"id"`
	}
	mustJSON(t, cb, &camp1)
	if code, b := do(t, srv.URL, http.MethodPost, "/api/v1/campaigns/"+camp1.ID.String()+"/launch", opTok, map[string]any{
		"group_id": grp.ID, "template_id": tmpl.ID, "sending_profile_id": prof.ID,
	}); code != http.StatusOK {
		t.Fatalf("launch camp1: %d (%s)", code, b)
	}

	cip, _ := crypto.New(strings.Repeat("ab", 32))
	// No UseGraph() -> no tenant/client/secret config; token fetch fails before
	// any network call, so every send fails gracefully.
	res, err := delivery.NewSender(pool, cip, "http://base.local", 4).SendCampaign(ctx, tn.ID, camp1.ID)
	if err != nil {
		t.Fatalf("graph send returned hard error (want graceful per-recipient failure): %v", err)
	}
	if res.Sent != 0 || res.Failed != 2 {
		t.Fatalf("graph send result: want sent=0 failed=2, got %+v", res)
	}
	if n := count(t, ctx, pool, `SELECT count(*) FROM events WHERE campaign_id=$1 AND type='failed'`, camp1.ID); n != 2 {
		t.Fatalf("failed events: want 2, got %d", n)
	}

	// --- campaign 2: bounce ingest (fresh recipients, pending) ---
	_, cb2 := do(t, srv.URL, http.MethodPost, "/api/v1/campaigns", opTok, map[string]any{"name": "Bounce Drill", "engagement_id": engID})
	var camp2 struct {
		ID uuid.UUID `json:"id"`
	}
	mustJSON(t, cb2, &camp2)
	if code, b := do(t, srv.URL, http.MethodPost, "/api/v1/campaigns/"+camp2.ID.String()+"/launch", opTok, map[string]any{
		"group_id": grp.ID, "template_id": tmpl.ID, "sending_profile_id": prof.ID,
	}); code != http.StatusOK {
		t.Fatalf("launch camp2: %d (%s)", code, b)
	}

	bounces := bounce.NewRepository(events.NewRepository(pool))

	// ParseNDR extracts recipient + message id.
	raw := "Message-ID: <ndr-123@mail.customer.test>\r\n" +
		"Subject: Undelivered Mail Returned to Sender\r\n\r\n" +
		"Final-Recipient: rfc822; alice@target.test\r\n" +
		"Action: failed\r\nStatus: 5.1.1\r\n"
	email, msgID, ok := bounce.ParseNDR(raw)
	if !ok || email != "alice@target.test" || msgID != "ndr-123@mail.customer.test" {
		t.Fatalf("ParseNDR: email=%q msgID=%q ok=%v", email, msgID, ok)
	}

	msg := bounce.NDRMessage{MessageID: msgID, RecipientEmail: email, CampaignID: &camp2.ID, Raw: raw}
	if inserted, err := bounces.Enqueue(ctx, pool, tn.ID, msg); err != nil || !inserted {
		t.Fatalf("enqueue1: inserted=%v err=%v", inserted, err)
	}
	// Duplicate NDR (same message id) is not inserted again.
	if inserted, err := bounces.Enqueue(ctx, pool, tn.ID, msg); err != nil || inserted {
		t.Fatalf("enqueue dup: inserted=%v err=%v (want false)", inserted, err)
	}

	// Unmatched recipient -> skipped, no event.
	if _, err := bounces.Enqueue(ctx, pool, tn.ID, bounce.NDRMessage{
		MessageID: "ndr-unknown", RecipientEmail: "nobody@target.test", CampaignID: &camp2.ID,
	}); err != nil {
		t.Fatalf("enqueue unknown: %v", err)
	}

	processed, skipped, err := bounces.Process(ctx, pool, tn.ID, 50)
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if processed != 1 || skipped != 1 {
		t.Fatalf("process counts: want processed=1 skipped=1, got %d/%d", processed, skipped)
	}
	// bounced event recorded + target advanced.
	if n := count(t, ctx, pool, `SELECT count(*) FROM events WHERE campaign_id=$1 AND type='bounced'`, camp2.ID); n != 1 {
		t.Fatalf("bounced events: want 1, got %d", n)
	}
	if got := targetState(t, ctx, pool, camp2.ID, contactByEmail(t, ctx, pool, tn.ID, "alice@target.test")); got != "bounced" {
		t.Fatalf("target state: want bounced, got %q", got)
	}

	// Re-processing does not double-count (rows are no longer 'pending').
	processed, _, _ = bounces.Process(ctx, pool, tn.ID, 50)
	if processed != 0 {
		t.Fatalf("reprocess: want 0, got %d", processed)
	}
	if n := count(t, ctx, pool, `SELECT count(*) FROM events WHERE campaign_id=$1 AND type='bounced'`, camp2.ID); n != 1 {
		t.Fatalf("bounced events after reprocess: want 1, got %d", n)
	}
}

func contactByEmail(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID uuid.UUID, email string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM contacts WHERE tenant_id=$1 AND lower(email)=lower($2)`, tenantID, email).Scan(&id); err != nil {
		t.Fatalf("contact by email: %v", err)
	}
	return id
}
