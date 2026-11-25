package aitmproxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"phishforge/internal/engineconfig"
)

func compiledForUpstream(t *testing.T, baseURL, loginPath string) Compiled {
	t.Helper()
	u, err := url.Parse(baseURL)
	if err != nil {
		t.Fatalf("parse base url: %v", err)
	}
	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		port = 80
	}
	return Compiled{
		CloneStrategy: "mirror",
		AssetPolicy:   "proxy",
		LoginPath:     loginPath,
		LoginPageURL:  baseURL + loginPath,
		Upstream:      Upstream{Scheme: u.Scheme, Host: u.Hostname(), Port: port},
		Capture:       engineconfig.Capture{TokenQueryKey: "_pft", FormActionContains: "logon", MaxBodyBytes: DefaultMaxBodyBytes},
	}
}

func TestGenerateCloneUnsupportedStrategy(t *testing.T) {
	in := NewInstanceFromCompiled(Compiled{CloneStrategy: "llm_assisted"}, nil, nil)
	err := in.GenerateClone(context.Background(), &http.Client{}, t.TempDir(), "camp")
	if !errors.Is(err, ErrCloneStrategyUnsupported) {
		t.Fatalf("llm_assisted must be unsupported, got %v", err)
	}
}

func TestGenerateCloneFetchFailFailsClosed(t *testing.T) {
	// Point at a closed port so the fetch fails.
	comp := compiledForUpstream(t, "http://127.0.0.1:1", "/logon")
	in := NewInstanceFromCompiled(comp, nil, nil)
	err := in.GenerateClone(context.Background(), &http.Client{}, t.TempDir(), "camp")
	if !errors.Is(err, ErrUpstreamFetch) {
		t.Fatalf("closed upstream must fail closed, got %v", err)
	}
	if _, _, _, ready := in.CloneInfo(); ready {
		t.Fatal("clone must not be ready after a fetch failure")
	}
	// The root then fails closed (503), never a placeholder.
	rec := httptest.NewRecorder()
	in.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("root must be 503 with no clone, got %d", rec.Code)
	}
}

func TestGenerateCloneAndServe(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><body>
<form action="` + "/logon" + `"><input name="username"></form>
<a href="/next">Next</a></body></html>`))
	}))
	defer upstream.Close()

	comp := compiledForUpstream(t, upstream.URL, "/logon")
	in := NewInstanceFromCompiled(comp, nil, nil)

	dir := t.TempDir()
	if err := in.GenerateClone(context.Background(), &http.Client{}, dir, "camp"); err != nil {
		t.Fatalf("generate clone: %v", err)
	}
	hash, _, fetchOK, ready := in.CloneInfo()
	if !ready || !fetchOK || len(hash) != 64 {
		t.Fatalf("clone state: ready=%v fetchOK=%v hash=%q", ready, fetchOK, hash)
	}
	// index.html landed in the per-campaign directory.
	if _, err := os.Stat(filepath.Join(dir, "camp", "index.html")); err != nil {
		t.Fatalf("clone index not written: %v", err)
	}

	h := in.Handler()

	// GET / with a victim token injects it into the form action.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/?_pft=victim123", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("serve clone: want 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "action=\"/logon?_pft=victim123\"") {
		t.Fatalf("victim token not injected into form action:\n%s", body)
	}
	if strings.Contains(body, tokenSentinel) {
		t.Fatalf("sentinel leaked into served page:\n%s", body)
	}

	// GET / without a token leaves an empty token (no sentinel remains).
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if strings.Contains(rec.Body.String(), tokenSentinel) {
		t.Fatalf("sentinel must be replaced even with no token")
	}

	// A missing asset inside the namespace is a 404 (reaches serveCloneAsset).
	// Encoded/literal ".." traversal is handled before this point by the mux's
	// path cleaning and by resolveCloneAsset (see TestResolveCloneAssetBoundary).
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/__clone/missing.css", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing asset must 404, got %d", rec.Code)
	}

	// A real asset inside the clone dir is served.
	if err := os.WriteFile(filepath.Join(dir, "camp", "a.css"), []byte("body{}"), 0o600); err != nil {
		t.Fatalf("write asset: %v", err)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/__clone/a.css", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "body{}") {
		t.Fatalf("asset within clone dir not served: code=%d body=%q", rec.Code, rec.Body.String())
	}

	// Cleanup removes the clone directory.
	in.Cleanup()
	if _, err := os.Stat(filepath.Join(dir, "camp")); !os.IsNotExist(err) {
		t.Fatalf("clone dir not cleaned up: %v", err)
	}
}
