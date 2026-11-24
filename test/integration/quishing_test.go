package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"image/png"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"phishforge/internal/apikey"
	"phishforge/internal/tenant"
)

// TestQuishingCampaign covers M9b: a qr-channel campaign renders per-recipient
// QR codes of the tracking URLs, and the first /t hit records scanned then
// clicked (state=clicked). A second hit does not duplicate scanned. An
// email-channel campaign is unchanged: /t records only clicked.
func TestQuishingCampaign(t *testing.T) {
	pool := setupDB(t)
	ctx := context.Background()

	tenants := tenant.NewRepository()
	tn, err := tenants.Create(ctx, pool, "Quish Co", "quish-"+short())
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	opID := createUser(t, ctx, pool, tn.ID, "op@quish.test", "operator")
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
	for _, email := range []string{"alice@quish.test", "bob@quish.test"} {
		if code, b := do(t, srv.URL, http.MethodPost, "/api/v1/contacts", opTok, map[string]any{"email": email, "group_id": grp.ID}); code != http.StatusCreated {
			t.Fatalf("create contact %s: %d (%s)", email, code, b)
		}
	}

	engID := seedAuthorizedEngagement(t, ctx, pool, tn.ID, opID)

	// --- qr-channel campaign ---
	code, body := do(t, srv.URL, http.MethodPost, "/api/v1/campaigns", opTok, map[string]any{
		"name": "QR Drill", "channel": "qr", "engagement_id": engID,
	})
	if code != http.StatusCreated {
		t.Fatalf("create qr campaign: want 201, got %d (%s)", code, body)
	}
	var camp struct {
		ID      uuid.UUID `json:"id"`
		Channel string    `json:"channel"`
	}
	mustJSON(t, body, &camp)
	if camp.Channel != "qr" {
		t.Fatalf("campaign channel: want qr, got %q", camp.Channel)
	}

	// invalid channel is rejected at create
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/campaigns", opTok, map[string]any{
		"name": "bad", "channel": "pigeon", "engagement_id": engID,
	}); code != http.StatusBadRequest {
		t.Fatalf("invalid channel: want 400, got %d", code)
	}

	// launch (no sending profile / template needed for QR)
	code, body = do(t, srv.URL, http.MethodPost, "/api/v1/campaigns/"+camp.ID.String()+"/launch", opTok, map[string]any{
		"group_id":    grp.ID,
		"landing_url": srv.URL + "/api/v1/health",
	})
	if code != http.StatusOK {
		t.Fatalf("launch: want 200, got %d (%s)", code, body)
	}

	// --- qrcodes endpoint ---
	code, body = do(t, srv.URL, http.MethodGet, "/api/v1/campaigns/"+camp.ID.String()+"/qrcodes", opTok, nil)
	if code != http.StatusOK {
		t.Fatalf("qrcodes: want 200, got %d (%s)", code, body)
	}
	var qrResp struct {
		Channel string `json:"channel"`
		Items   []struct {
			RecipientID uuid.UUID `json:"recipient_id"`
			Token       string    `json:"token"`
			ClickURL    string    `json:"click_url"`
			QRPNGBase64 string    `json:"qr_png_base64"`
			DataURI     string    `json:"data_uri"`
		} `json:"items"`
	}
	mustJSON(t, body, &qrResp)
	if qrResp.Channel != "qr" {
		t.Fatalf("qrcodes channel: want qr, got %q", qrResp.Channel)
	}
	if len(qrResp.Items) != 2 {
		t.Fatalf("qrcodes items: want 2, got %d", len(qrResp.Items))
	}
	for _, it := range qrResp.Items {
		if it.ClickURL != "http://base.local/t/"+it.Token {
			t.Fatalf("click_url malformed: %s", it.ClickURL)
		}
		if it.DataURI != "data:image/png;base64,"+it.QRPNGBase64 {
			t.Fatalf("data_uri mismatch for token %s", it.Token)
		}
		raw, err := base64.StdEncoding.DecodeString(it.QRPNGBase64)
		if err != nil {
			t.Fatalf("decode qr base64: %v", err)
		}
		if _, err := png.Decode(bytes.NewReader(raw)); err != nil {
			t.Fatalf("qr png not decodable: %v", err)
		}
	}
	if n := count(t, ctx, pool, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='qrcode.view'`, tn.ID); n != 1 {
		t.Fatalf("qrcode.view audit: want 1, got %d", n)
	}

	// --- first /t hit: scanned (qr) then clicked (email), state=clicked ---
	tok := qrResp.Items[0].Token
	var contactID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT contact_id FROM recipients WHERE token=$1`, tok).Scan(&contactID); err != nil {
		t.Fatalf("resolve contact: %v", err)
	}

	if code, _ := get("/t/" + tok); code != http.StatusOK {
		t.Fatalf("qr click: want 200, got %d", code)
	}
	if got := targetState(t, ctx, pool, camp.ID, contactID); got != "clicked" {
		t.Fatalf("state after scan+click: want clicked, got %q", got)
	}
	if n := count(t, ctx, pool, `SELECT count(*) FROM events WHERE campaign_id=$1 AND contact_id=$2 AND type='scanned' AND channel='qr'`, camp.ID, contactID); n != 1 {
		t.Fatalf("scanned events: want 1 (qr channel), got %d", n)
	}
	if n := count(t, ctx, pool, `SELECT count(*) FROM events WHERE campaign_id=$1 AND contact_id=$2 AND type='clicked' AND channel='email'`, camp.ID, contactID); n != 1 {
		t.Fatalf("clicked events: want 1 (email channel), got %d", n)
	}

	// --- second hit: no duplicate scanned (best-effort no-op) ---
	if code, _ := get("/t/" + tok); code != http.StatusOK {
		t.Fatalf("second qr click: want 200, got %d", code)
	}
	if n := count(t, ctx, pool, `SELECT count(*) FROM events WHERE campaign_id=$1 AND contact_id=$2 AND type='scanned'`, camp.ID, contactID); n != 1 {
		t.Fatalf("scanned events after second hit: want 1 (no duplicate), got %d", n)
	}
	if got := targetState(t, ctx, pool, camp.ID, contactID); got != "clicked" {
		t.Fatalf("state after second hit: want clicked, got %q", got)
	}

	// --- report: scanned shows up in timeline + per-recipient drilldown ---
	code, rep := do(t, srv.URL, http.MethodGet, "/api/v1/campaigns/"+camp.ID.String()+"/report", opTok, nil)
	if code != http.StatusOK {
		t.Fatalf("report: want 200, got %d (%s)", code, rep)
	}
	var report struct {
		Timeline []struct {
			Counts map[string]int `json:"counts"`
		} `json:"timeline"`
	}
	mustJSON(t, rep, &report)
	scannedInTimeline := 0
	for _, b := range report.Timeline {
		scannedInTimeline += b.Counts["scanned"]
	}
	if scannedInTimeline != 1 {
		t.Fatalf("report timeline scanned: want 1, got %d", scannedInTimeline)
	}

	// --- email-channel campaign: /t records only clicked, no scanned ---
	_, body = do(t, srv.URL, http.MethodPost, "/api/v1/campaigns", opTok, map[string]any{
		"name": "Email Drill", "engagement_id": engID, // channel omitted -> email
	})
	var ecamp struct {
		ID      uuid.UUID `json:"id"`
		Channel string    `json:"channel"`
	}
	mustJSON(t, body, &ecamp)
	if ecamp.Channel != "email" {
		t.Fatalf("default channel: want email, got %q", ecamp.Channel)
	}
	if code, b := do(t, srv.URL, http.MethodPost, "/api/v1/campaigns/"+ecamp.ID.String()+"/launch", opTok, map[string]any{
		"group_id": grp.ID, "landing_url": srv.URL + "/api/v1/health",
	}); code != http.StatusOK {
		t.Fatalf("email launch: %d (%s)", code, b)
	}
	var etok string
	if err := pool.QueryRow(ctx, `SELECT token FROM recipients WHERE campaign_id=$1 LIMIT 1`, ecamp.ID).Scan(&etok); err != nil {
		t.Fatalf("email token: %v", err)
	}
	if code, _ := get("/t/" + etok); code != http.StatusOK {
		t.Fatalf("email click: want 200, got %d", code)
	}
	if n := count(t, ctx, pool, `SELECT count(*) FROM events WHERE campaign_id=$1 AND type='scanned'`, ecamp.ID); n != 0 {
		t.Fatalf("email campaign scanned events: want 0, got %d", n)
	}
	if n := count(t, ctx, pool, `SELECT count(*) FROM events WHERE campaign_id=$1 AND type='clicked'`, ecamp.ID); n != 1 {
		t.Fatalf("email campaign clicked events: want 1, got %d", n)
	}
}
