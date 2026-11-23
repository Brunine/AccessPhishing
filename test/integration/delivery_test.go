package integration

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	smtpmock "github.com/mocktools/go-smtp-mock/v2"

	"phishforge/internal/apikey"
	"phishforge/internal/crypto"
	"phishforge/internal/delivery"
	"phishforge/internal/tenant"
)

// TestCampaignSend covers M3 delivery: the approval gate on /send, and the
// delivery core sending rendered emails to a local SMTP mock + 'sent' events.
func TestCampaignSend(t *testing.T) {
	pool := setupDB(t)
	ctx := context.Background()

	// local SMTP sink
	smtp := smtpmock.New(smtpmock.ConfigurationAttr{})
	if err := smtp.Start(); err != nil {
		t.Fatalf("start smtp mock: %v", err)
	}
	defer smtp.Stop()
	smtpPort := smtp.PortNumber()

	tenants := tenant.NewRepository()
	tn, err := tenants.Create(ctx, pool, "Send Co", "send-"+short())
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	adminID := createUser(t, ctx, pool, tn.ID, "admin@send.test", "admin")
	opID := createUser(t, ctx, pool, tn.ID, "op@send.test", "operator")
	keys := apikey.NewService(pool)
	adminTok, _, _ := keys.Create(ctx, tn.ID, adminID, "admin")
	opTok, _, _ := keys.Create(ctx, tn.ID, opID, "op")

	srv, enq := newAPI(t, pool)
	defer srv.Close()

	// template with text/template variables
	_, body := do(t, srv.URL, http.MethodPost, "/api/v1/templates", opTok, map[string]any{
		"kind": "email", "name": "drill", "subject": "Hi {{.first_name}}",
		"body": `<a href="{{.link}}">review</a>`,
	})
	var tmplResp struct {
		ID uuid.UUID `json:"id"`
	}
	mustJSON(t, body, &tmplResp)

	// sending profile pointing at the mock (no auth, no TLS)
	code, body := do(t, srv.URL, http.MethodPost, "/api/v1/sending-profiles", opTok, map[string]any{
		"name": "mock", "smtp_host": "127.0.0.1", "smtp_port": smtpPort,
		"from_address": "drill@phish.test", "from_name": "IT", "tls_mode": "none",
	})
	if code != http.StatusCreated {
		t.Fatalf("create profile: %d (%s)", code, body)
	}
	var profResp struct {
		ID uuid.UUID `json:"id"`
	}
	mustJSON(t, body, &profResp)

	// group + two contacts
	_, body = do(t, srv.URL, http.MethodPost, "/api/v1/contact-groups", opTok, map[string]any{"name": "wave"})
	var grp struct {
		ID uuid.UUID `json:"id"`
	}
	mustJSON(t, body, &grp)
	for _, e := range []string{"alice@target.test", "bob@target.test"} {
		do(t, srv.URL, http.MethodPost, "/api/v1/contacts", opTok, map[string]any{"email": e, "first_name": "X", "group_id": grp.ID})
	}

	// campaign (bound to an authorized engagement) + launch with template & profile
	engID := seedAuthorizedEngagement(t, ctx, pool, tn.ID, opID)
	_, body = do(t, srv.URL, http.MethodPost, "/api/v1/campaigns", opTok, map[string]any{"name": "Send Drill", "engagement_id": engID})
	var camp struct {
		ID uuid.UUID `json:"id"`
	}
	mustJSON(t, body, &camp)
	code, body = do(t, srv.URL, http.MethodPost, "/api/v1/campaigns/"+camp.ID.String()+"/launch", opTok, map[string]any{
		"group_id": grp.ID, "template_id": tmplResp.ID, "sending_profile_id": profResp.ID,
		"landing_url": "http://base.local/px/x",
	})
	if code != http.StatusOK {
		t.Fatalf("launch: %d (%s)", code, body)
	}

	// --- approval gate ---
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/campaigns/"+camp.ID.String()+"/send", opTok, nil); code != http.StatusForbidden {
		t.Fatalf("send before approval: want 403, got %d", code)
	}
	if enq.count() != 0 {
		t.Fatalf("enqueue happened before approval")
	}

	// request + admin approve
	_, body = do(t, srv.URL, http.MethodPost, "/api/v1/approvals", opTok, map[string]any{"subject_type": "template", "subject_id": tmplResp.ID})
	var appr struct {
		ID uuid.UUID `json:"id"`
	}
	mustJSON(t, body, &appr)
	// operator cannot approve
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/approvals/"+appr.ID.String()+"/approve", opTok, nil); code != http.StatusForbidden {
		t.Fatalf("operator approve: want 403, got %d", code)
	}
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/approvals/"+appr.ID.String()+"/approve", adminTok, nil); code != http.StatusOK {
		t.Fatalf("admin approve: got %d", code)
	}

	// now send enqueues
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/campaigns/"+camp.ID.String()+"/send", opTok, nil); code != http.StatusAccepted {
		t.Fatalf("send after approval: want 202, got %d", code)
	}
	if enq.count() != 1 {
		t.Fatalf("expected 1 enqueue, got %d", enq.count())
	}

	// --- delivery core (what the worker runs) ---
	cip, _ := crypto.New(strings.Repeat("ab", 32))
	res, err := delivery.NewSender(pool, cip, "http://base.local", 4).SendCampaign(ctx, tn.ID, camp.ID)
	if err != nil {
		t.Fatalf("send campaign: %v", err)
	}
	if res.Sent != 2 || res.Failed != 0 {
		t.Fatalf("delivery result: want sent=2 failed=0, got %+v", res)
	}
	if n := len(smtp.Messages()); n != 2 {
		t.Fatalf("smtp mock received: want 2, got %d", n)
	}
	if n := count(t, ctx, pool, `SELECT count(*) FROM events WHERE campaign_id=$1 AND type='sent'`, camp.ID); n != 2 {
		t.Fatalf("sent events: want 2, got %d", n)
	}
}
