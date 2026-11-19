package integration

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"phishforge/internal/apikey"
	"phishforge/internal/tenant"
)

// TestCampaignLaunchAndTracking covers M4-style tracking: launch snapshots
// recipients with tokens, the links endpoint exposes them, and the public
// /t and /px routes record clicked/opened events and advance target state.
func TestCampaignLaunchAndTracking(t *testing.T) {
	pool := setupDB(t)
	ctx := context.Background()

	tenants := tenant.NewRepository()
	tn, err := tenants.Create(ctx, pool, "Track Co", "track-"+short())
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	opID := createUser(t, ctx, pool, tn.ID, "op@track.test", "operator")
	opTok, _, err := apikey.NewService(pool).Create(ctx, tn.ID, opID, "op")
	if err != nil {
		t.Fatalf("op key: %v", err)
	}

	srv, _ := newAPI(t, pool)
	defer srv.Close()
	get := func(path string) (int, string) { return do(t, srv.URL, http.MethodGet, path, "", nil) }

	// group + two contacts
	_, body := do(t, srv.URL, http.MethodPost, "/api/v1/contact-groups", opTok, map[string]any{"name": "wave1"})
	var grp struct {
		ID uuid.UUID `json:"id"`
	}
	mustJSON(t, body, &grp)
	for _, email := range []string{"alice@track.test", "bob@track.test"} {
		if code, b := do(t, srv.URL, http.MethodPost, "/api/v1/contacts", opTok, map[string]any{"email": email, "group_id": grp.ID}); code != http.StatusCreated {
			t.Fatalf("create contact %s: %d (%s)", email, code, b)
		}
	}

	// draft campaign
	_, body = do(t, srv.URL, http.MethodPost, "/api/v1/campaigns", opTok, map[string]any{"name": "Phish Drill"})
	var camp struct {
		ID uuid.UUID `json:"id"`
	}
	mustJSON(t, body, &camp)

	// launch: snapshot the group, redirect target is our own health endpoint
	code, body := do(t, srv.URL, http.MethodPost, "/api/v1/campaigns/"+camp.ID.String()+"/launch", opTok, map[string]any{
		"group_id":    grp.ID,
		"landing_url": srv.URL + "/api/v1/health",
	})
	if code != http.StatusOK {
		t.Fatalf("launch: want 200, got %d (%s)", code, body)
	}
	var launch struct {
		Status     string `json:"status"`
		Recipients int    `json:"recipients"`
	}
	mustJSON(t, body, &launch)
	if launch.Status != "scheduled" || launch.Recipients != 2 {
		t.Fatalf("launch result: want scheduled/2, got %+v", launch)
	}

	// re-launch rejected (not draft)
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/campaigns/"+camp.ID.String()+"/launch", opTok, map[string]any{"group_id": grp.ID}); code != http.StatusConflict {
		t.Fatalf("relaunch: want 409, got %d", code)
	}

	// links (authenticated operator endpoint)
	code, body = do(t, srv.URL, http.MethodGet, "/api/v1/campaigns/"+camp.ID.String()+"/links", opTok, nil)
	if code != http.StatusOK {
		t.Fatalf("links: got %d (%s)", code, body)
	}
	var links struct {
		Items []struct {
			ContactID uuid.UUID `json:"contact_id"`
			Token     string    `json:"token"`
			ClickURL  string    `json:"click_url"`
			PixelURL  string    `json:"pixel_url"`
		} `json:"items"`
	}
	mustJSON(t, body, &links)
	if len(links.Items) != 2 {
		t.Fatalf("links: want 2, got %d", len(links.Items))
	}
	if links.Items[0].ClickURL != "http://base.local/t/"+links.Items[0].Token {
		t.Fatalf("click_url malformed: %s", links.Items[0].ClickURL)
	}

	clickTok, clickContact := links.Items[0].Token, links.Items[0].ContactID
	openTok, openContact := links.Items[1].Token, links.Items[1].ContactID

	// click: follows 302 to landing (health) and returns 200
	if code, _ := get("/t/" + clickTok); code != http.StatusOK {
		t.Fatalf("click redirect: want 200, got %d", code)
	}
	if got := targetState(t, ctx, pool, camp.ID, clickContact); got != "clicked" {
		t.Fatalf("click state: want clicked, got %q", got)
	}

	// open: returns a 1x1 gif
	if code, _ := get("/px/" + openTok); code != http.StatusOK {
		t.Fatalf("pixel: want 200, got %d", code)
	}
	if got := targetState(t, ctx, pool, camp.ID, openContact); got != "opened" {
		t.Fatalf("open state: want opened, got %q", got)
	}

	// exactly two tracking events recorded so far
	if n := count(t, ctx, pool, `SELECT count(*) FROM events WHERE campaign_id=$1`, camp.ID); n != 2 {
		t.Fatalf("events after tracking: want 2, got %d", n)
	}

	// bogus tokens: /t returns the 200 neutral page (anti-enumeration — the
	// status code must not reveal whether a token exists), /px still 200 gif,
	// and neither records an event (no state for a nonexistent recipient).
	if code, respBody := get("/t/not-a-real-token"); code != http.StatusOK || !strings.Contains(respBody, "Thank you.") {
		t.Fatalf("bogus click: want 200 neutral page, got %d (%s)", code, respBody)
	}
	if code, _ := get("/px/not-a-real-token"); code != http.StatusOK {
		t.Fatalf("bogus pixel: want 200 (no leak), got %d", code)
	}
	if n := count(t, ctx, pool, `SELECT count(*) FROM events WHERE campaign_id=$1`, camp.ID); n != 2 {
		t.Fatalf("events after bogus: want 2 (no new rows for a nonexistent recipient), got %d", n)
	}

	// launch audit recorded
	if n := count(t, ctx, pool, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='campaign.launch'`, tn.ID); n != 1 {
		t.Fatalf("campaign.launch audit: want 1, got %d", n)
	}
}
