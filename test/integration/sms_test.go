package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"phishforge/internal/apikey"
	"phishforge/internal/crypto"
	"phishforge/internal/delivery"
	"phishforge/internal/tenant"
)

// fakeTwilio records Messages.json calls and returns 201.
type fakeTwilio struct {
	mu    sync.Mutex
	calls []map[string]string
}

func (f *fakeTwilio) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/2010-04-01/Accounts/AC123/Messages.json", func(w http.ResponseWriter, r *http.Request) {
		user, _, _ := r.BasicAuth()
		_ = r.ParseForm()
		f.mu.Lock()
		f.calls = append(f.calls, map[string]string{
			"sid": user, "to": r.PostForm.Get("To"), "from": r.PostForm.Get("From"), "body": r.PostForm.Get("Body"),
		})
		f.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"sid":"SM1","status":"queued"}`))
	})
	return httptest.NewServer(mux)
}

func TestSMSCampaign(t *testing.T) {
	pool := setupDB(t)
	ctx := context.Background()

	tenants := tenant.NewRepository()
	tn, _ := tenants.Create(ctx, pool, "Smish Co", "sms-"+short())
	adminID := createUser(t, ctx, pool, tn.ID, "admin@s.test", "admin")
	opID := createUser(t, ctx, pool, tn.ID, "op@s.test", "operator")
	keys := apikey.NewService(pool)
	adminTok, _, _ := keys.Create(ctx, tn.ID, adminID, "admin")
	opTok, _, _ := keys.Create(ctx, tn.ID, opID, "op")

	srv, _ := newAPI(t, pool)
	defer srv.Close()

	// --- SMS sending profile: credentials encrypted at rest, not leaked ---
	code, body := do(t, srv.URL, http.MethodPost, "/api/v1/sending-profiles", opTok, map[string]any{
		"name": "twilio", "channel": "sms", "sms_provider": "twilio",
		"api_client_id": "AC123", "secret": "super-auth-token", "sms_sender_id": "+15550000000",
	})
	if code != http.StatusCreated {
		t.Fatalf("create sms profile: %d (%s)", code, body)
	}
	var prof struct {
		ID      uuid.UUID `json:"id"`
		Channel string    `json:"channel"`
	}
	mustJSON(t, body, &prof)
	if prof.Channel != "sms" || strings.Contains(body, "super-auth-token") {
		t.Fatalf("profile wrong/leaked: %s", body)
	}
	var stored string
	_ = pool.QueryRow(ctx, `SELECT smtp_pass_encrypted FROM sending_profiles WHERE id=$1`, prof.ID).Scan(&stored)
	if stored == "" || strings.Contains(stored, "super-auth-token") {
		t.Fatalf("auth token not encrypted at rest: %q", stored)
	}

	// --- SMS template + length guard ---
	_, tb := do(t, srv.URL, http.MethodPost, "/api/v1/templates", opTok, map[string]any{
		"kind": "sms", "name": "smish", "body": "Hi {{.first_name}}, review: {{.link}}",
	})
	var tmpl struct {
		ID uuid.UUID `json:"id"`
	}
	mustJSON(t, tb, &tmpl)
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/templates", opTok, map[string]any{
		"kind": "sms", "name": "toolong", "body": strings.Repeat("x", 1601),
	}); code != http.StatusBadRequest {
		t.Fatalf("sms length guard: want 400, got %d", code)
	}

	// --- group + contact WITH phone ---
	_, gb := do(t, srv.URL, http.MethodPost, "/api/v1/contact-groups", opTok, map[string]any{"name": "wave"})
	var grp struct {
		ID uuid.UUID `json:"id"`
	}
	mustJSON(t, gb, &grp)
	if code, b := do(t, srv.URL, http.MethodPost, "/api/v1/contacts", opTok, map[string]any{
		"email": "alice@t.test", "first_name": "Alice", "phone_e164": "+15551234567", "group_id": grp.ID,
	}); code != http.StatusCreated {
		t.Fatalf("create contact: %d (%s)", code, b)
	}
	// invalid E.164 -> 400
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/contacts", opTok, map[string]any{
		"email": "bad@t.test", "phone_e164": "5551234567", "group_id": grp.ID,
	}); code != http.StatusBadRequest {
		t.Fatalf("invalid e164: want 400, got %d", code)
	}

	// --- launch refuses SMS campaign with a phone-less recipient ---
	_, ng := do(t, srv.URL, http.MethodPost, "/api/v1/contact-groups", opTok, map[string]any{"name": "nophone"})
	var ngrp struct {
		ID uuid.UUID `json:"id"`
	}
	mustJSON(t, ng, &ngrp)
	do(t, srv.URL, http.MethodPost, "/api/v1/contacts", opTok, map[string]any{"email": "nophone@t.test", "group_id": ngrp.ID})
	// Bind an authorized engagement so launch reaches the SMS phone gate (the
	// engagement gate runs first; without a binding this would 403, not 400).
	engID := seedAuthorizedEngagement(t, ctx, pool, tn.ID, opID)
	_, nc := do(t, srv.URL, http.MethodPost, "/api/v1/campaigns", opTok, map[string]any{"name": "No Phone", "engagement_id": engID})
	var ncamp struct {
		ID uuid.UUID `json:"id"`
	}
	mustJSON(t, nc, &ncamp)
	if code, b := do(t, srv.URL, http.MethodPost, "/api/v1/campaigns/"+ncamp.ID.String()+"/launch", opTok, map[string]any{
		"group_id": ngrp.ID, "template_id": tmpl.ID, "sending_profile_id": prof.ID,
	}); code != http.StatusBadRequest {
		t.Fatalf("launch sms w/o phone: want 400, got %d (%s)", code, b)
	}

	// --- happy campaign: launch (has phone) ---
	_, cb := do(t, srv.URL, http.MethodPost, "/api/v1/campaigns", opTok, map[string]any{"name": "Smish Drill", "engagement_id": engID})
	var camp struct {
		ID uuid.UUID `json:"id"`
	}
	mustJSON(t, cb, &camp)
	if code, b := do(t, srv.URL, http.MethodPost, "/api/v1/campaigns/"+camp.ID.String()+"/launch", opTok, map[string]any{
		"group_id": grp.ID, "template_id": tmpl.ID, "sending_profile_id": prof.ID,
	}); code != http.StatusOK {
		t.Fatalf("launch: %d (%s)", code, b)
	}

	// --- approval gate: send 403 before approval, 202 after ---
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/campaigns/"+camp.ID.String()+"/send", opTok, nil); code != http.StatusForbidden {
		t.Fatalf("send before approval: want 403, got %d", code)
	}
	_, ab := do(t, srv.URL, http.MethodPost, "/api/v1/approvals", opTok, map[string]any{"subject_type": "template", "subject_id": tmpl.ID})
	var appr struct {
		ID uuid.UUID `json:"id"`
	}
	mustJSON(t, ab, &appr)
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/approvals/"+appr.ID.String()+"/approve", adminTok, nil); code != http.StatusOK {
		t.Fatalf("approve: %d", code)
	}
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/campaigns/"+camp.ID.String()+"/send", opTok, nil); code != http.StatusAccepted {
		t.Fatalf("send after approval: want 202, got %d", code)
	}

	// --- delivery core over a mocked Twilio (what the worker runs) ---
	fake := &fakeTwilio{}
	ts := fake.server(t)
	defer ts.Close()
	cip, _ := crypto.New(strings.Repeat("ab", 32))
	sender := delivery.NewSender(pool, cip, "http://base.local", 4)
	sender.UseSMS(delivery.SMSConfig{BaseURL: ts.URL, Timeout: 5 * time.Second})
	res, err := sender.SendCampaign(ctx, tn.ID, camp.ID)
	if err != nil {
		t.Fatalf("send campaign: %v", err)
	}
	if res.Sent != 1 || res.Failed != 0 {
		t.Fatalf("result: want sent=1 failed=0, got %+v", res)
	}
	if len(fake.calls) != 1 {
		t.Fatalf("twilio calls: want 1, got %d", len(fake.calls))
	}
	call := fake.calls[0]
	if call["to"] != "+15551234567" || call["from"] != "+15550000000" || call["sid"] != "AC123" {
		t.Fatalf("twilio call wrong: %+v", call)
	}
	if !strings.Contains(call["body"], "http://base.local/t/") || !strings.Contains(call["body"], "Hi Alice") {
		t.Fatalf("rendered body wrong: %q", call["body"])
	}

	// one 'sent' event, zero 'opened' (SMS has no open pixel)
	if n := count(t, ctx, pool, `SELECT count(*) FROM events WHERE campaign_id=$1 AND type='sent'`, camp.ID); n != 1 {
		t.Fatalf("sent events: want 1, got %d", n)
	}
	if n := count(t, ctx, pool, `SELECT count(*) FROM events WHERE campaign_id=$1 AND type='opened'`, camp.ID); n != 0 {
		t.Fatalf("opened events: want 0 for SMS, got %d", n)
	}

	// --- click path still works for SMS ---
	_, lb := do(t, srv.URL, http.MethodGet, "/api/v1/campaigns/"+camp.ID.String()+"/links", opTok, nil)
	var links struct {
		Items []struct {
			Token string `json:"token"`
		} `json:"items"`
	}
	mustJSON(t, lb, &links)
	if len(links.Items) != 1 {
		t.Fatalf("links: want 1, got %d", len(links.Items))
	}
	if code, _ := do(t, srv.URL, http.MethodGet, "/t/"+links.Items[0].Token, "", nil); code != http.StatusOK {
		t.Fatalf("click: want 200, got %d", code)
	}
	if n := count(t, ctx, pool, `SELECT count(*) FROM events WHERE campaign_id=$1 AND type='clicked'`, camp.ID); n != 1 {
		t.Fatalf("clicked events: want 1, got %d", n)
	}
	if n := count(t, ctx, pool, `SELECT count(*) FROM events WHERE campaign_id=$1 AND type='opened'`, camp.ID); n != 0 {
		t.Fatalf("opened events after click: want 0 for SMS, got %d", n)
	}
}
