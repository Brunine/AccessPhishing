package integration

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"phishforge/internal/apikey"
	"phishforge/internal/bounce"
	"phishforge/internal/events"
	"phishforge/internal/tenant"
)

// TestBouncePollerIngest exercises the IMAP poller's transport-independent core
// (IngestRaw): a raw NDR is parsed, attributed to the recipient's tenant/
// campaign, enqueued, and processed into a 'bounced' event + state — idempotent
// per message-id. The live IMAP fetch is config-gated (PollOnce no-ops when
// disabled) and build-verified.
func TestBouncePollerIngest(t *testing.T) {
	pool := setupDB(t)
	ctx := context.Background()

	tenants := tenant.NewRepository()
	tn, err := tenants.Create(ctx, pool, "Bounce Co", "bnc-"+short())
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	opID := createUser(t, ctx, pool, tn.ID, "op@bnc.test", "operator")
	opTok, _, _ := apikey.NewService(pool).Create(ctx, tn.ID, opID, "op")

	srv, _ := newAPI(t, pool)
	defer srv.Close()

	// group + 2 contacts + campaign + launch (recipients pending)
	_, gb := do(t, srv.URL, http.MethodPost, "/api/v1/contact-groups", opTok, map[string]any{"name": "wave"})
	var grp struct {
		ID uuid.UUID `json:"id"`
	}
	mustJSON(t, gb, &grp)
	for _, e := range []string{"alice@target.test", "bob@target.test"} {
		do(t, srv.URL, http.MethodPost, "/api/v1/contacts", opTok, map[string]any{"email": e, "first_name": "X", "group_id": grp.ID})
	}
	engID := seedAuthorizedEngagement(t, ctx, pool, tn.ID, opID)
	_, cb := do(t, srv.URL, http.MethodPost, "/api/v1/campaigns", opTok, map[string]any{"name": "Bounce Drill", "engagement_id": engID})
	var camp struct {
		ID uuid.UUID `json:"id"`
	}
	mustJSON(t, cb, &camp)
	if code, b := do(t, srv.URL, http.MethodPost, "/api/v1/campaigns/"+camp.ID.String()+"/launch", opTok, map[string]any{"group_id": grp.ID}); code != http.StatusOK {
		t.Fatalf("launch: %d (%s)", code, b)
	}

	repo := bounce.NewRepository(events.NewRepository(pool))
	// Disabled IMAP config: PollOnce is a no-op; we drive IngestRaw directly.
	poller := bounce.NewPoller(bounce.IMAPConfig{}, pool, repo)

	if f, e, err := poller.PollOnce(ctx); err != nil || f != 0 || e != 0 {
		t.Fatalf("disabled PollOnce: want 0,0,nil, got %d,%d,%v", f, e, err)
	}

	raw := "Message-ID: <ndr-abc@mail.bounce.test>\r\n" +
		"Subject: Undelivered Mail Returned to Sender\r\n\r\n" +
		"Final-Recipient: rfc822; alice@target.test\r\nAction: failed\r\nStatus: 5.1.1\r\n"

	n, err := poller.IngestRaw(ctx, []string{raw})
	if err != nil || n != 1 {
		t.Fatalf("ingest: n=%d err=%v (want 1,nil)", n, err)
	}
	if got := targetState(t, ctx, pool, camp.ID, contactByEmail(t, ctx, pool, tn.ID, "alice@target.test")); got != "bounced" {
		t.Fatalf("state: want bounced, got %q", got)
	}
	if nb := count(t, ctx, pool, `SELECT count(*) FROM events WHERE campaign_id=$1 AND type='bounced'`, camp.ID); nb != 1 {
		t.Fatalf("bounced events: want 1, got %d", nb)
	}

	// Same NDR again: idempotent — no new ndr row, no new bounced event.
	if _, err := poller.IngestRaw(ctx, []string{raw}); err != nil {
		t.Fatalf("ingest dup: %v", err)
	}
	if nb := count(t, ctx, pool, `SELECT count(*) FROM events WHERE campaign_id=$1 AND type='bounced'`, camp.ID); nb != 1 {
		t.Fatalf("bounced events after dup: want 1, got %d", nb)
	}

	// NDR for an address we never sent to: skipped, not enqueued.
	unknown := "Message-ID: <ndr-x@mail.test>\r\n\r\nFinal-Recipient: rfc822; stranger@elsewhere.test\r\n"
	if n, err := poller.IngestRaw(ctx, []string{unknown}); err != nil || n != 0 {
		t.Fatalf("ingest unknown: n=%d err=%v (want 0,nil)", n, err)
	}
	if nr := count(t, ctx, pool, `SELECT count(*) FROM ndr_messages WHERE tenant_id=$1`, tn.ID); nr != 1 {
		t.Fatalf("ndr rows: want 1 (unknown not enqueued), got %d", nr)
	}
}
