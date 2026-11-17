package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"phishforge/internal/api"
	"phishforge/internal/apikey"
	"phishforge/internal/crypto"
	"phishforge/internal/llm"
	"phishforge/internal/tenant"
)

// fakeOllama serves the two endpoints our client uses: POST /api/generate
// returns a canned completion; GET /api/tags answers the health ping.
func fakeOllama(t *testing.T, completion string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/generate", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"response":` + jsonString(completion) + `}`))
	})
	mux.HandleFunc("/api/tags", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"models":[]}`))
	})
	return httptest.NewServer(mux)
}

// jsonString quotes s as a JSON string literal (handles the newline in the
// canned completion).
func jsonString(s string) string {
	r := strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "\n", "\\n", "\r", "\\r", "\t", "\\t")
	return "\"" + r.Replace(s) + "\""
}

// apiWithLLM builds an httptest API server wired to a specific LLM client.
func apiWithLLM(t *testing.T, pool *pgxpool.Pool, client api.LLMClient) *httptest.Server {
	t.Helper()
	cip, err := crypto.New(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	return httptest.NewServer(api.NewServer(api.Deps{
		Pool:     pool,
		BaseURL:  "http://base.local",
		Cipher:   cip,
		Enqueuer: &fakeEnqueuer{},
		LLM:      client,
	}).Router())
}

func TestLLMPipeline(t *testing.T) {
	pool := setupDB(t)
	ctx := context.Background()

	ollama := fakeOllama(t, "Subject: Reset your password\n<p>Hi {{.first_name}},</p>\n<p><a href=\"{{.link}}\">Reset now</a></p>")
	defer ollama.Close()

	tenants := tenant.NewRepository()
	tn, err := tenants.Create(ctx, pool, "LLM Co", "llm-"+short())
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	adminID := createUser(t, ctx, pool, tn.ID, "admin@llm.test", "admin")
	opID := createUser(t, ctx, pool, tn.ID, "op@llm.test", "operator")
	keys := apikey.NewService(pool)
	adminTok, _, _ := keys.Create(ctx, tn.ID, adminID, "admin")
	opTok, _, _ := keys.Create(ctx, tn.ID, opID, "op")

	client := llm.New(ollama.URL, "test-model", 10*time.Second)
	srv := apiWithLLM(t, pool, client)
	defer srv.Close()

	// health reports the LLM sub-check as ok (reachable fake host).
	_, hb := do(t, srv.URL, http.MethodGet, "/api/v1/health", "", nil)
	if !strings.Contains(hb, `"llm":"ok"`) {
		t.Fatalf("health llm sub-check: want ok, got %s", hb)
	}

	// generate -> stores a draft (status draft, model recorded, subject parsed).
	code, body := do(t, srv.URL, http.MethodPost, "/api/v1/llm/generate", opTok, map[string]any{
		"kind": "email", "topic": "quarterly password reset", "tone": "urgent", "audience": "all staff",
	})
	if code != http.StatusCreated {
		t.Fatalf("generate: want 201, got %d (%s)", code, body)
	}
	var draft struct {
		ID      uuid.UUID `json:"id"`
		Kind    string    `json:"kind"`
		Subject *string   `json:"subject"`
		Body    string    `json:"body"`
		Model   string    `json:"model"`
		Status  string    `json:"status"`
	}
	mustJSON(t, body, &draft)
	if draft.Status != "draft" {
		t.Fatalf("draft status: want draft, got %q", draft.Status)
	}
	if draft.Model != "test-model" {
		t.Fatalf("draft model: want test-model, got %q", draft.Model)
	}
	if draft.Subject == nil || *draft.Subject != "Reset your password" {
		t.Fatalf("draft subject: want 'Reset your password', got %v", draft.Subject)
	}
	if !strings.Contains(draft.Body, "{{.first_name}}") || !strings.Contains(draft.Body, "{{.link}}") {
		t.Fatalf("draft body missing placeholders: %q", draft.Body)
	}

	// list + get
	if code, lb := do(t, srv.URL, http.MethodGet, "/api/v1/llm/drafts", opTok, nil); code != http.StatusOK || !strings.Contains(lb, draft.ID.String()) {
		t.Fatalf("list drafts: code %d body %s", code, lb)
	}
	if code, _ := do(t, srv.URL, http.MethodGet, "/api/v1/llm/drafts/"+draft.ID.String(), opTok, nil); code != http.StatusOK {
		t.Fatalf("get draft: want 200, got %d", code)
	}

	// promote before approval -> 403
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/llm/drafts/"+draft.ID.String()+"/promote", opTok, nil); code != http.StatusForbidden {
		t.Fatalf("promote before approval: want 403, got %d", code)
	}

	// request approval (llm_draft) + admin approve via the existing flow
	_, ab := do(t, srv.URL, http.MethodPost, "/api/v1/approvals", opTok, map[string]any{
		"subject_type": "llm_draft", "subject_id": draft.ID,
	})
	var appr struct {
		ID uuid.UUID `json:"id"`
	}
	mustJSON(t, ab, &appr)
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/approvals/"+appr.ID.String()+"/approve", adminTok, nil); code != http.StatusOK {
		t.Fatalf("admin approve: want 200, got %d", code)
	}

	// promote -> 201 template
	code, pb := do(t, srv.URL, http.MethodPost, "/api/v1/llm/drafts/"+draft.ID.String()+"/promote", opTok, nil)
	if code != http.StatusCreated {
		t.Fatalf("promote after approval: want 201, got %d (%s)", code, pb)
	}
	var tpl struct {
		ID   uuid.UUID `json:"id"`
		Kind string    `json:"kind"`
		Body string    `json:"body"`
	}
	mustJSON(t, pb, &tpl)
	if tpl.Kind != "email" || tpl.ID == uuid.Nil {
		t.Fatalf("promoted template wrong: %+v", tpl)
	}
	if n := count(t, ctx, pool, `SELECT count(*) FROM templates WHERE tenant_id=$1 AND id=$2`, tn.ID, tpl.ID); n != 1 {
		t.Fatalf("template row: want 1, got %d", n)
	}
	// draft is now marked approved
	if code, gb := do(t, srv.URL, http.MethodGet, "/api/v1/llm/drafts/"+draft.ID.String(), opTok, nil); code != http.StatusOK || !strings.Contains(gb, `"status":"approved"`) {
		t.Fatalf("draft status after promote: %s", gb)
	}

	// discard a second draft
	_, db2 := do(t, srv.URL, http.MethodPost, "/api/v1/llm/generate", opTok, map[string]any{"kind": "sms", "topic": "mfa check"})
	var d2 struct {
		ID uuid.UUID `json:"id"`
	}
	mustJSON(t, db2, &d2)
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/llm/drafts/"+d2.ID.String()+"/discard", opTok, nil); code != http.StatusOK {
		t.Fatalf("discard: want 200, got %d", code)
	}

	// audit entries written for generate + promote
	if n := count(t, ctx, pool, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='llm.generate'`, tn.ID); n != 2 {
		t.Fatalf("llm.generate audit: want 2, got %d", n)
	}
	if n := count(t, ctx, pool, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='llm.promote'`, tn.ID); n != 1 {
		t.Fatalf("llm.promote audit: want 1, got %d", n)
	}
}

// TestLLMUnreachable asserts an unreachable LLM host yields 503 on generate
// while the rest of the API stays healthy (200).
func TestLLMUnreachable(t *testing.T) {
	pool := setupDB(t)
	ctx := context.Background()

	tenants := tenant.NewRepository()
	tn, err := tenants.Create(ctx, pool, "Down Co", "down-"+short())
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	opID := createUser(t, ctx, pool, tn.ID, "op@down.test", "operator")
	keys := apikey.NewService(pool)
	opTok, _, _ := keys.Create(ctx, tn.ID, opID, "op")

	// Point at a closed port on localhost: connections are refused quickly.
	client := llm.New("http://127.0.0.1:1", "test-model", 2*time.Second)
	srv := apiWithLLM(t, pool, client)
	defer srv.Close()

	// API health still serves (200); llm sub-check reports down.
	code, hb := do(t, srv.URL, http.MethodGet, "/api/v1/health", "", nil)
	if code != http.StatusOK {
		t.Fatalf("health with llm down: want 200, got %d (%s)", code, hb)
	}
	if !strings.Contains(hb, `"llm":"down"`) {
		t.Fatalf("health llm sub-check: want down, got %s", hb)
	}

	// generate -> 503
	if code, b := do(t, srv.URL, http.MethodPost, "/api/v1/llm/generate", opTok, map[string]any{"kind": "email", "topic": "x"}); code != http.StatusServiceUnavailable {
		t.Fatalf("generate with llm down: want 503, got %d (%s)", code, b)
	}

	// non-LLM endpoints still work.
	if code, _ := do(t, srv.URL, http.MethodGet, "/api/v1/campaigns", opTok, nil); code != http.StatusOK {
		t.Fatalf("campaigns with llm down: want 200, got %d", code)
	}
}
