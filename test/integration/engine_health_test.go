package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"phishforge/internal/api"
	"phishforge/internal/apikey"
	"phishforge/internal/crypto"
	"phishforge/internal/engine"
	"phishforge/internal/enginehealth"
	"phishforge/internal/tenant"
)

// engineHealthBody mirrors the GET /engines/{id}/health response fields the
// test asserts on.
type engineHealthBody struct {
	EngineID         uuid.UUID  `json:"engine_id"`
	Status           string     `json:"status"`
	Detail           string     `json:"detail"`
	Live             bool       `json:"live"`
	AdapterKind      string     `json:"adapter_kind"`
	EngineKind       string     `json:"engine_kind"`
	EngineStatus     string     `json:"engine_status"`
	LastTransitionAt *time.Time `json:"last_transition_at"`
	LastPollAt       *time.Time `json:"last_poll_at"`
}

// TestEngineHealthThroughAdapter drives start/stop through the adapter and
// asserts the health snapshot surface, the worker poller's last_poll_at
// heartbeat, and RBAC on the read endpoint.
func TestEngineHealthThroughAdapter(t *testing.T) {
	pool := setupDB(t)
	ctx := context.Background()

	// Tenant + operator/viewer users and keys.
	tenants := tenant.NewRepository()
	tn, err := tenants.Create(ctx, pool, "Acme Engine Health", "acme-eh-"+short())
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	opID := createUser(t, ctx, pool, tn.ID, "op-eh@acme.test", "operator")
	viewerID := createUser(t, ctx, pool, tn.ID, "viewer-eh@acme.test", "viewer")

	keys := apikey.NewService(pool)
	opTok, _, err := keys.Create(ctx, tn.ID, opID, "op-key")
	if err != nil {
		t.Fatalf("op key: %v", err)
	}
	viewerTok, _, err := keys.Create(ctx, tn.ID, viewerID, "viewer-key")
	if err != nil {
		t.Fatalf("viewer key: %v", err)
	}

	// Build an API server with a real supervisor pointing at this test binary
	// (TestMain re-executes it in PF_ENGINE_HELPER mode).
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	mgr := engine.New(exe, 0, 10*time.Millisecond)
	cip, err := crypto.New(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	srv := httptest.NewServer(api.NewServer(api.Deps{
		Pool: pool, BaseURL: "http://base.local", Cipher: cip,
		Enqueuer: &fakeEnqueuer{}, Engines: mgr,
	}).Router())
	defer srv.Close()

	// Create an engine whose helper child sleeps (stays running).
	cfg := "kind: helper\n" +
		"env:\n  PF_ENGINE_HELPER: \"1\"\n  PF_ENGINE_MODE: sleep\n" +
		"stop_timeout_ms: 3000\n"
	code, body := do(t, srv.URL, http.MethodPost, "/api/v1/engines", opTok,
		map[string]any{"name": "eh-engine-" + short(), "config": cfg})
	if code != http.StatusCreated {
		t.Fatalf("create engine: want 201, got %d (%s)", code, body)
	}
	var created struct {
		ID uuid.UUID `json:"id"`
	}
	mustJSON(t, body, &created)

	// Health before start: no live process, snapshot absent -> derived from row.
	code, body = do(t, srv.URL, http.MethodGet, "/api/v1/engines/"+created.ID.String()+"/health", opTok, nil)
	if code != http.StatusOK {
		t.Fatalf("health before start: want 200, got %d (%s)", code, body)
	}
	var h0 engineHealthBody
	mustJSON(t, body, &h0)
	if h0.EngineStatus != "stopped" {
		t.Fatalf("pre-start engine_status: want stopped, got %q", h0.EngineStatus)
	}
	if h0.Live {
		t.Fatalf("pre-start: want live=false")
	}

	// Start through the adapter.
	code, body = do(t, srv.URL, http.MethodPost, "/api/v1/engines/"+created.ID.String()+"/start", opTok, nil)
	if code != http.StatusOK {
		t.Fatalf("start: want 200, got %d (%s)", code, body)
	}

	// Health after start: live, running/starting, transition recorded.
	code, body = do(t, srv.URL, http.MethodGet, "/api/v1/engines/"+created.ID.String()+"/health", opTok, nil)
	if code != http.StatusOK {
		t.Fatalf("health after start: want 200, got %d (%s)", code, body)
	}
	var h1 engineHealthBody
	mustJSON(t, body, &h1)
	if !h1.Live {
		t.Fatalf("after start: want live=true (status=%q)", h1.Status)
	}
	if h1.Status != "running" && h1.Status != "starting" {
		t.Fatalf("after start status: want running/starting, got %q", h1.Status)
	}
	if h1.AdapterKind != "builtin" {
		t.Fatalf("adapter_kind: want builtin, got %q", h1.AdapterKind)
	}
	if h1.EngineKind != "helper" {
		t.Fatalf("engine_kind: want helper, got %q", h1.EngineKind)
	}
	if h1.LastTransitionAt == nil {
		t.Fatalf("after start: last_transition_at must be set")
	}
	if h1.LastPollAt != nil {
		t.Fatalf("after start: last_poll_at should be nil before any poll")
	}

	// Poller tick (the worker's job) records last_poll_at.
	n, err := enginehealth.NewPoller(pool).PollOnce(ctx)
	if err != nil {
		t.Fatalf("poll once: %v", err)
	}
	if n < 1 {
		t.Fatalf("poll once: want >=1 engine polled, got %d", n)
	}
	code, body = do(t, srv.URL, http.MethodGet, "/api/v1/engines/"+created.ID.String()+"/health", opTok, nil)
	if code != http.StatusOK {
		t.Fatalf("health after poll: want 200, got %d (%s)", code, body)
	}
	var h2 engineHealthBody
	mustJSON(t, body, &h2)
	if h2.LastPollAt == nil {
		t.Fatalf("after poll: last_poll_at must be set")
	}
	if h2.LastTransitionAt == nil {
		t.Fatalf("after poll: last_transition_at must be preserved")
	}

	// Stop through the adapter.
	code, body = do(t, srv.URL, http.MethodPost, "/api/v1/engines/"+created.ID.String()+"/stop", opTok, nil)
	if code != http.StatusOK {
		t.Fatalf("stop: want 200, got %d (%s)", code, body)
	}
	code, body = do(t, srv.URL, http.MethodGet, "/api/v1/engines/"+created.ID.String()+"/health", opTok, nil)
	if code != http.StatusOK {
		t.Fatalf("health after stop: want 200, got %d (%s)", code, body)
	}
	var h3 engineHealthBody
	mustJSON(t, body, &h3)
	// A SIGTERM/kill of the sleeper can surface as stopped or failed depending
	// on platform signal semantics; assert only that it is no longer up.
	if h3.Status == "running" || h3.Status == "starting" {
		t.Fatalf("after stop status: want a stopped state, got %q", h3.Status)
	}
	if h3.EngineStatus != "stopped" && h3.EngineStatus != "stopped_failed" {
		t.Fatalf("after stop engine_status: want stopped|stopped_failed, got %q", h3.EngineStatus)
	}
	if h3.LastTransitionAt == nil || h3.LastTransitionAt.Before(*h1.LastTransitionAt) {
		t.Fatalf("after stop: last_transition_at must advance (start=%v stop=%v)", h1.LastTransitionAt, h3.LastTransitionAt)
	}

	// RBAC: viewer is forbidden, missing key is unauthorized.
	if code, _ := do(t, srv.URL, http.MethodGet, "/api/v1/engines/"+created.ID.String()+"/health", viewerTok, nil); code != http.StatusForbidden {
		t.Fatalf("viewer health: want 403, got %d", code)
	}
	if code, _ := do(t, srv.URL, http.MethodGet, "/api/v1/engines/"+created.ID.String()+"/health", "", nil); code != http.StatusUnauthorized {
		t.Fatalf("no-key health: want 401, got %d", code)
	}

	// Unknown engine id is 404.
	if code, _ := do(t, srv.URL, http.MethodGet, "/api/v1/engines/"+uuid.NewString()+"/health", opTok, nil); code != http.StatusNotFound {
		t.Fatalf("unknown engine health: want 404, got %d", code)
	}
}
