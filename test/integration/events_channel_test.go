package integration

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"phishforge/internal/apikey"
	"phishforge/internal/events"
	"phishforge/internal/tenant"
)

// TestEventChannelMechanism verifies event taxonomy v2: the email tracking path
// is unchanged and records channel='email'; a zero-channel repository append
// defaults to email; and a non-email (QR) append fails closed with
// ErrUnknownChannelEvent and writes no row.
func TestEventChannelMechanism(t *testing.T) {
	pool := setupDB(t)
	ctx := context.Background()

	tenants := tenant.NewRepository()
	tn, err := tenants.Create(ctx, pool, "Chan Co", "chan-"+short())
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	opID := createUser(t, ctx, pool, tn.ID, "op@chan.test", "operator")
	opTok, _, err := apikey.NewService(pool).Create(ctx, tn.ID, opID, "op")
	if err != nil {
		t.Fatalf("op key: %v", err)
	}

	srv, _ := newAPI(t, pool)
	defer srv.Close()

	// group + one contact
	_, gb := do(t, srv.URL, http.MethodPost, "/api/v1/contact-groups", opTok, map[string]any{"name": "wave"})
	var grp struct {
		ID uuid.UUID `json:"id"`
	}
	mustJSON(t, gb, &grp)
	if code, b := do(t, srv.URL, http.MethodPost, "/api/v1/contacts", opTok, map[string]any{"email": "a@chan.test", "group_id": grp.ID}); code != http.StatusCreated {
		t.Fatalf("create contact: %d (%s)", code, b)
	}

	// campaign bound to an authorized engagement, then launch
	engID := seedAuthorizedEngagement(t, ctx, pool, tn.ID, opID)
	_, cb := do(t, srv.URL, http.MethodPost, "/api/v1/campaigns", opTok, map[string]any{"name": "Chan Drill", "engagement_id": engID})
	var camp struct {
		ID uuid.UUID `json:"id"`
	}
	mustJSON(t, cb, &camp)
	if code, b := do(t, srv.URL, http.MethodPost, "/api/v1/campaigns/"+camp.ID.String()+"/launch", opTok, map[string]any{
		"group_id": grp.ID, "landing_url": srv.URL + "/api/v1/health",
	}); code != http.StatusOK {
		t.Fatalf("launch: %d (%s)", code, b)
	}

	// links -> token + contact id
	_, lb := do(t, srv.URL, http.MethodGet, "/api/v1/campaigns/"+camp.ID.String()+"/links", opTok, nil)
	var links struct {
		Items []struct {
			ContactID uuid.UUID `json:"contact_id"`
			Token     string    `json:"token"`
		} `json:"items"`
	}
	mustJSON(t, lb, &links)
	if len(links.Items) != 1 {
		t.Fatalf("links: want 1, got %d", len(links.Items))
	}
	tok, contactID := links.Items[0].Token, links.Items[0].ContactID

	// email tracking path unchanged: /t click -> 'clicked' state, email channel.
	if code, _ := do(t, srv.URL, http.MethodGet, "/t/"+tok, "", nil); code != http.StatusOK {
		t.Fatalf("click: want 200, got %d", code)
	}
	if got := targetState(t, ctx, pool, camp.ID, contactID); got != "clicked" {
		t.Fatalf("state after click: want clicked, got %q", got)
	}
	if n := count(t, ctx, pool, `SELECT count(*) FROM events WHERE campaign_id=$1 AND channel='email'`, camp.ID); n != 1 {
		t.Fatalf("email events: want 1, got %d", n)
	}

	er := events.NewRepository(pool)

	// zero-channel repository append defaults to email.
	if _, err := er.Append(ctx, events.NewEvent{
		TenantID: tn.ID, CampaignID: camp.ID, ContactID: contactID, Type: events.TypeSessionHijacked,
	}); err != nil {
		t.Fatalf("zero-channel append: %v", err)
	}
	if n := count(t, ctx, pool, `SELECT count(*) FROM events WHERE campaign_id=$1 AND channel='email'`, camp.ID); n != 2 {
		t.Fatalf("email events after default append: want 2, got %d", n)
	}

	// non-email (QR) append fails closed and writes nothing.
	_, err = er.Append(ctx, events.NewEvent{
		TenantID: tn.ID, CampaignID: camp.ID, ContactID: contactID,
		Type: events.TypeClicked, Channel: events.ChannelQR,
	})
	if !errors.Is(err, events.ErrUnknownChannelEvent) {
		t.Fatalf("QR append: want ErrUnknownChannelEvent, got %v", err)
	}

	// all seeded rows are email only; the QR attempt left no row.
	if n := count(t, ctx, pool, `SELECT count(*) FROM events WHERE campaign_id=$1 AND channel <> 'email'`, camp.ID); n != 0 {
		t.Fatalf("non-email rows: want 0, got %d", n)
	}
	var distinct int
	if err := pool.QueryRow(ctx, `SELECT count(DISTINCT channel) FROM events WHERE campaign_id=$1`, camp.ID).Scan(&distinct); err != nil {
		t.Fatalf("distinct channel query: %v", err)
	}
	if distinct != 1 {
		t.Fatalf("distinct channels: want 1 (email), got %d", distinct)
	}
}
