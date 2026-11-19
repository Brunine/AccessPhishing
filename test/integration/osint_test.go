package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"phishforge/internal/api"
	"phishforge/internal/apikey"
	"phishforge/internal/crypto"
	"phishforge/internal/osintclient"
	"phishforge/internal/tenant"
)

// fakeOSINT serves the subset of the Python OSINT service the Go client calls.
func fakeOSINT(t *testing.T, healthy bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		if !healthy {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("/recon/subdomains", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-OSINT-TOKEN") != "tok" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"domain":"example.com","source":"crtsh","count":2,"subdomains":["a.example.com","b.example.com"]}`))
	})
	mux.HandleFunc("/domains/generate", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"domain":"example.com","count":2,"truncated":false,"candidates":[{"domain":"examplea.com","fuzzer":"addition"},{"domain":"exarnple.com","fuzzer":"replacement"}]}`))
	})
	mux.HandleFunc("/domains/availability", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[{"domain":"examplea.com","available":true,"status_code":404},{"domain":"exarnple.com","available":false,"status_code":200}]}`))
	})
	return httptest.NewServer(mux)
}

func apiWithOSINT(t *testing.T, pool *pgxpool.Pool, oc api.OSINTClient) *httptest.Server {
	t.Helper()
	cip, err := crypto.New(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	return httptest.NewServer(api.NewServer(api.Deps{
		Pool: pool, BaseURL: "http://base.local", Cipher: cip, Enqueuer: &fakeEnqueuer{}, OSINT: oc,
	}).Router())
}

func TestOSINTOrchestration(t *testing.T) {
	pool := setupDB(t)
	ctx := context.Background()

	tenants := tenant.NewRepository()
	tn, err := tenants.Create(ctx, pool, "OSINT Co", "osint-"+short())
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	opID := createUser(t, ctx, pool, tn.ID, "op@osint.test", "operator")
	opTok, _, _ := apikey.NewService(pool).Create(ctx, tn.ID, opID, "op")

	svc := fakeOSINT(t, true)
	defer svc.Close()
	client := osintclient.New(svc.URL, "tok", 10*time.Second)
	srv := apiWithOSINT(t, pool, client)
	defer srv.Close()

	// status -> ok
	if code, b := do(t, srv.URL, http.MethodGet, "/api/v1/osint/status", opTok, nil); code != http.StatusOK || !strings.Contains(b, `"service":"ok"`) {
		t.Fatalf("status: %d (%s)", code, b)
	}

	// collect -> 201, stored result aggregates subdomains + lookalikes + availability
	code, body := do(t, srv.URL, http.MethodPost, "/api/v1/osint/collect", opTok, map[string]any{"domain": "example.com"})
	if code != http.StatusCreated {
		t.Fatalf("collect: %d (%s)", code, body)
	}
	var stored struct {
		Domain string          `json:"domain"`
		Result json.RawMessage `json:"result"`
	}
	mustJSON(t, body, &stored)
	if stored.Domain != "example.com" {
		t.Fatalf("stored domain: %q", stored.Domain)
	}
	var res osintclient.Result
	mustJSON(t, string(stored.Result), &res)
	if len(res.Subdomains) != 2 || res.SubdomainSource != "crtsh" {
		t.Fatalf("subdomains: %+v", res)
	}
	if len(res.Lookalikes) != 2 || res.Lookalikes[0].Domain != "examplea.com" {
		t.Fatalf("lookalikes: %+v", res.Lookalikes)
	}
	if len(res.Availability) != 2 || res.Availability[0].Available == nil || *res.Availability[0].Available != true {
		t.Fatalf("availability: %+v", res.Availability)
	}

	// re-collect same domain upserts (still one row)
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/osint/collect", opTok, map[string]any{"domain": "example.com"}); code != http.StatusCreated {
		t.Fatalf("recollect: %d", code)
	}
	if n := count(t, ctx, pool, `SELECT count(*) FROM osint_results WHERE tenant_id=$1`, tn.ID); n != 1 {
		t.Fatalf("osint rows after upsert: want 1, got %d", n)
	}

	// results list
	if code, b := do(t, srv.URL, http.MethodGet, "/api/v1/osint/results", opTok, nil); code != http.StatusOK || !strings.Contains(b, "example.com") {
		t.Fatalf("results: %d (%s)", code, b)
	}

	// invalid domain -> 400
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/osint/collect", opTok, map[string]any{"domain": "not a domain"}); code != http.StatusBadRequest {
		t.Fatalf("invalid domain: want 400, got %d", code)
	}

	// audit entry
	if n := count(t, ctx, pool, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='osint.collect'`, tn.ID); n != 2 {
		t.Fatalf("osint.collect audit: want 2, got %d", n)
	}

	// --- unreachable service ---
	down := osintclient.New("http://127.0.0.1:1", "tok", 2*time.Second)
	dsrv := apiWithOSINT(t, pool, down)
	defer dsrv.Close()
	if code, b := do(t, dsrv.URL, http.MethodGet, "/api/v1/osint/status", opTok, nil); code != http.StatusOK || !strings.Contains(b, `"service":"down"`) {
		t.Fatalf("status (down): %d (%s)", code, b)
	}
	if code, _ := do(t, dsrv.URL, http.MethodPost, "/api/v1/osint/collect", opTok, map[string]any{"domain": "example.com"}); code != http.StatusServiceUnavailable {
		t.Fatalf("collect (down): want 503, got %d", code)
	}

	// --- not configured (nil client) ---
	nsrv := apiWithOSINT(t, pool, nil)
	defer nsrv.Close()
	if code, _ := do(t, nsrv.URL, http.MethodGet, "/api/v1/osint/status", opTok, nil); code != http.StatusServiceUnavailable {
		t.Fatalf("status (nil): want 503, got %d", code)
	}
	if code, _ := do(t, nsrv.URL, http.MethodPost, "/api/v1/osint/collect", opTok, map[string]any{"domain": "example.com"}); code != http.StatusServiceUnavailable {
		t.Fatalf("collect (nil): want 503, got %d", code)
	}
}
