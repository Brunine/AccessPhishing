package integration

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"phishforge/internal/apikey"
	"phishforge/internal/llm"
	"phishforge/internal/tenant"
)

// TestPromptTemplatePipeline covers M6 prompt-template CRUD, strict validation,
// the no-LLM dry-run render, and generate-with-template (LLM unreachable -> 503,
// so no live model is needed).
func TestPromptTemplatePipeline(t *testing.T) {
	pool := setupDB(t)
	ctx := context.Background()

	tenants := tenant.NewRepository()
	tn, err := tenants.Create(ctx, pool, "Prompt Co", "pt-"+short())
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	opID := createUser(t, ctx, pool, tn.ID, "op@pt.test", "operator")
	opTok, _, _ := apikey.NewService(pool).Create(ctx, tn.ID, opID, "op")

	// LLM points at a closed port (unreachable) so generate reaches the model
	// call and returns 503 without a live model.
	client := llm.New("http://127.0.0.1:1", "test-model", 2*time.Second)
	srv := apiWithLLM(t, pool, client)
	defer srv.Close()

	// --- validation: undeclared variable is rejected at save ---
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/prompt-templates", opTok, map[string]any{
		"name": "bad", "kind": "email",
		"user_template": "Hi {{.FirstName}} at {{.Company}}",
		"variables":     []map[string]any{{"name": "FirstName"}},
	}); code != http.StatusBadRequest {
		t.Fatalf("undeclared var: want 400, got %d", code)
	}

	// --- create (valid) ---
	code, body := do(t, srv.URL, http.MethodPost, "/api/v1/prompt-templates", opTok, map[string]any{
		"name": "awareness-email", "kind": "email",
		"system_prompt": "You write authorized security-awareness simulation emails.",
		"user_template": "Subject: Action for {{.Company}}\nHi {{.FirstName}}, please review.",
		"variables": []map[string]any{
			{"name": "FirstName", "example": "Dana"},
			{"name": "Company", "example": "Acme"},
		},
	})
	if code != http.StatusCreated {
		t.Fatalf("create: want 201, got %d (%s)", code, body)
	}
	var tpl struct {
		ID   uuid.UUID `json:"id"`
		Kind string    `json:"kind"`
	}
	mustJSON(t, body, &tpl)
	if tpl.Kind != "email" {
		t.Fatalf("kind: %q", tpl.Kind)
	}

	// duplicate name -> 409
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/prompt-templates", opTok, map[string]any{
		"name": "awareness-email", "kind": "email", "user_template": "x",
	}); code != http.StatusConflict {
		t.Fatalf("dup name: want 409, got %d", code)
	}

	// list + get
	if code, lb := do(t, srv.URL, http.MethodGet, "/api/v1/prompt-templates", opTok, nil); code != http.StatusOK || !strings.Contains(lb, tpl.ID.String()) {
		t.Fatalf("list: code %d body %s", code, lb)
	}
	if code, _ := do(t, srv.URL, http.MethodGet, "/api/v1/prompt-templates/"+tpl.ID.String(), opTok, nil); code != http.StatusOK {
		t.Fatalf("get: want 200, got %d", code)
	}

	// --- render dry-run (no LLM) ---
	code, rb := do(t, srv.URL, http.MethodPost, "/api/v1/prompt-templates/"+tpl.ID.String()+"/render", opTok, map[string]any{
		"variables": map[string]string{"FirstName": "Sam"},
	})
	if code != http.StatusOK {
		t.Fatalf("render: want 200, got %d (%s)", code, rb)
	}
	var rendered struct {
		RenderedUser string `json:"rendered_user"`
		Prompt       string `json:"prompt"`
	}
	mustJSON(t, rb, &rendered)
	// Supplied override + declared example fallback.
	if !strings.Contains(rendered.RenderedUser, "Hi Sam") || !strings.Contains(rendered.RenderedUser, "for Acme") {
		t.Fatalf("render output wrong: %q", rendered.RenderedUser)
	}
	if !strings.HasPrefix(rendered.Prompt, "You write authorized") {
		t.Fatalf("prompt should start with system prompt: %q", rendered.Prompt)
	}

	// --- generate with template_id (LLM unreachable -> 503) ---
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/llm/generate", opTok, map[string]any{
		"template_id": tpl.ID,
		"variables":   map[string]string{"FirstName": "Lee", "Company": "Globex"},
	}); code != http.StatusServiceUnavailable {
		t.Fatalf("generate with template (llm down): want 503, got %d", code)
	}

	// bad template_id -> 400 (before the LLM is consulted)
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/llm/generate", opTok, map[string]any{
		"template_id": uuid.New(),
	}); code != http.StatusBadRequest {
		t.Fatalf("generate with bogus template: want 400, got %d", code)
	}

	// update -> re-validate (undeclared var rejected)
	if code, _ := do(t, srv.URL, http.MethodPatch, "/api/v1/prompt-templates/"+tpl.ID.String(), opTok, map[string]any{
		"name": "awareness-email", "kind": "email", "user_template": "{{.Nope}}",
	}); code != http.StatusBadRequest {
		t.Fatalf("update undeclared: want 400, got %d", code)
	}

	// delete
	if code, _ := do(t, srv.URL, http.MethodDelete, "/api/v1/prompt-templates/"+tpl.ID.String(), opTok, nil); code != http.StatusNoContent {
		t.Fatalf("delete: want 204, got %d", code)
	}

	// audit entries
	if n := count(t, ctx, pool, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='prompttpl.create'`, tn.ID); n != 1 {
		t.Fatalf("prompttpl.create audit: want 1, got %d", n)
	}
	if n := count(t, ctx, pool, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='prompttpl.render'`, tn.ID); n != 1 {
		t.Fatalf("prompttpl.render audit: want 1, got %d", n)
	}
}
