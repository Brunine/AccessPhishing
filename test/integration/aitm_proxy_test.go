package integration

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// fakeUpstream stands in for the real login origin the AiTM proxy forwards to.
// It records the last request body + query so the test can prove the full body
// reached the upstream and the victim token was stripped before forwarding.
type fakeUpstream struct {
	mu       sync.Mutex
	lastBody string
	lastPFT  string // the _pft value as seen by the upstream (must be empty)
	hits     int
}

func (u *fakeUpstream) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/owa/auth/logon.aspx", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.lastBody = string(body)
		u.lastPFT = r.URL.Query().Get("_pft")
		u.hits++
		u.mu.Unlock()
		// Successful upstream login: set the session cookie the profile watches.
		http.SetCookie(w, &http.Cookie{Name: "cadata", Value: "UPSTREAM-SECRET-COOKIE", Path: "/"})
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	return mux
}

// aitmProfileYAML builds a form profile whose phishing_facet.login_page_url
// points at the given upstream origin (so the proxy forwards there).
func aitmProfileYAML(name, upstreamURL string) string {
	return fmt.Sprintf(`
version: 1
metadata:
  name: %s
  vendor: Microsoft
auth:
  login_path: /owa/auth/logon.aspx
  method: form
  fields:
    - selector: input[name=username]
      upstream_field: username
      capture: true
    - selector: input[name=password]
      upstream_field: password
      capture: true
    - selector: input[name=flags]
      upstream_field: flags
      capture: false
session:
  success_indicators:
    - type: cookie_set
      name: cadata
  token_locations:
    - in: cookie
      name: cadata
      sensitive: true
mfa:
  mode: none
phishing_facet:
  login_page_url: %s/owa/auth/logon.aspx
  clone_strategy: mirror
  asset_policy: proxy
proxy:
  token_query_key: _pft
  form_action_contains: logon.aspx
  max_body_bytes: 65536
`, name, upstreamURL)
}

type proxyState struct {
	Running bool   `json:"running"`
	Addr    string `json:"addr"`
	Port    int    `json:"port"`
}

func TestAiTMProxyFormCaptureE2E(t *testing.T) {
	pool := setupDB(t)
	ctx := context.Background()

	up := &fakeUpstream{}
	upstream := httptest.NewServer(up.handler())
	defer upstream.Close()

	tn := mkTenant(t, ctx, pool, "AiTMCo")
	opID := createUser(t, ctx, pool, tn.ID, "op@aitm.test", "operator")
	opTok := mkKey(t, ctx, pool, tn.ID, opID, "op")

	srv, _ := newAPI(t, pool)
	defer srv.Close()

	// Import the profile pointing at our controllable upstream.
	profID := mustImport(t, srv.URL, opTok, aitmProfileYAML("owa-aitm", upstream.URL))
	var profChecksum string
	if err := pool.QueryRow(ctx, `SELECT checksum FROM app_profiles WHERE id=$1`, profID).Scan(&profChecksum); err != nil {
		t.Fatalf("read profile checksum: %v", err)
	}

	engID := seedAuthorizedEngagement(t, ctx, pool, tn.ID, opID)
	contactID := createContact(t, ctx, pool, tn.ID, "victim@target.test")

	// Launch the campaign bound to the profile, then start the proxy.
	camp := mustCampaign(t, srv.URL, opTok, "owa-aitm-camp", engID)
	if code, body := launch(t, srv.URL, opTok, camp, contactID, &profID); code != http.StatusOK {
		t.Fatalf("launch: want 200, got %d (%s)", code, body)
	}
	token := firstRecipientToken(t, srv.URL, opTok, camp)

	code, body := do(t, srv.URL, http.MethodPost, "/api/v1/campaigns/"+camp.String()+"/proxy/start", opTok, nil)
	if code != http.StatusOK {
		t.Fatalf("proxy start: want 200, got %d (%s)", code, body)
	}
	var st proxyState
	mustJSON(t, body, &st)
	if !st.Running || st.Addr == "" {
		t.Fatalf("proxy state not running: %+v", st)
	}

	// Status endpoint reflects running.
	if c, b := do(t, srv.URL, http.MethodGet, "/api/v1/campaigns/"+camp.String()+"/proxy/status", opTok, nil); c != http.StatusOK || !strings.Contains(b, `"running":true`) {
		t.Fatalf("proxy status: want running true, got %d (%s)", c, b)
	}

	// --- POST the captured login form THROUGH the proxy ---
	proxyURL := "http://" + st.Addr + "/owa/auth/logon.aspx?_pft=" + url.QueryEscape(token)
	form := url.Values{"username": {"victim@target.test"}, "password": {"hunter2"}, "flags": {"4"}}
	resp, err := http.Post(proxyURL, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("post through proxy: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("proxy forward: want 200 from upstream, got %d", resp.StatusCode)
	}

	// Upstream received the FULL body unmodified, with the victim token stripped.
	up.mu.Lock()
	gotBody, gotPFT, hits := up.lastBody, up.lastPFT, up.hits
	up.mu.Unlock()
	if hits != 1 {
		t.Fatalf("upstream hits: want 1, got %d", hits)
	}
	if !strings.Contains(gotBody, "username=victim") || !strings.Contains(gotBody, "password=hunter2") || !strings.Contains(gotBody, "flags=4") {
		t.Fatalf("upstream must receive full body unmodified, got %q", gotBody)
	}
	if gotPFT != "" {
		t.Fatalf("victim token must be stripped before upstream, got _pft=%q", gotPFT)
	}

	// --- creds event: names-only, source=proxy, checksum-stamped ---
	credFields, credSource, credChecksum := credsRow(t, ctx, pool, camp)
	if credSource != "proxy" {
		t.Fatalf("creds source: want proxy, got %q", credSource)
	}
	if credChecksum != profChecksum {
		t.Fatalf("creds checksum stamp: want %s, got %s", profChecksum, credChecksum)
	}
	if credFields != "password,username" { // sorted names only — never 'flags' (capture:false), never values
		t.Fatalf("creds fields: want \"password,username\", got %q", credFields)
	}

	// --- session_hijacked event: cookie NAMES only, source=proxy, stamped ---
	sessCookies, sessHost, sessSource, sessChecksum := sessionRow(t, ctx, pool, camp)
	if sessSource != "proxy" {
		t.Fatalf("session source: want proxy, got %q", sessSource)
	}
	if sessChecksum != profChecksum {
		t.Fatalf("session checksum stamp: want %s, got %s", profChecksum, sessChecksum)
	}
	if sessCookies != "cadata" {
		t.Fatalf("session cookies: want \"cadata\" (name only), got %q", sessCookies)
	}
	upHost, _, _ := netSplit(upstream.URL)
	if sessHost != upHost {
		t.Fatalf("session host: want upstream host %q, got %q", upHost, sessHost)
	}

	// --- stop: listener freed ---
	if c, b := do(t, srv.URL, http.MethodPost, "/api/v1/campaigns/"+camp.String()+"/proxy/stop", opTok, nil); c != http.StatusOK {
		t.Fatalf("proxy stop: want 200, got %d (%s)", c, b)
	}
	if c, b := do(t, srv.URL, http.MethodGet, "/api/v1/campaigns/"+camp.String()+"/proxy/status", opTok, nil); c != http.StatusOK || !strings.Contains(b, `"running":false`) {
		t.Fatalf("proxy status after stop: want running false, got %d (%s)", c, b)
	}
	// A second stop is a conflict (nothing running).
	if c, _ := do(t, srv.URL, http.MethodPost, "/api/v1/campaigns/"+camp.String()+"/proxy/stop", opTok, nil); c != http.StatusConflict {
		t.Fatalf("double stop: want 409, got %d", c)
	}
	// The freed port no longer accepts connections.
	if _, err := http.Get("http://" + st.Addr + "/"); err == nil {
		t.Fatalf("expected connection refused after stop on %s", st.Addr)
	}

	// --- audit counts ---
	if n := count(t, ctx, pool, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='campaign.proxy.start'`, tn.ID); n != 1 {
		t.Fatalf("proxy.start audit: want 1, got %d", n)
	}
	if n := count(t, ctx, pool, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='campaign.proxy.stop'`, tn.ID); n != 1 {
		t.Fatalf("proxy.stop audit: want 1, got %d", n)
	}
}

// TestAiTMProxyStartFailClosed covers the start-side gates: unbound engagement
// (403), no bound profile (409), and an unsupported bound profile (409/501).
func TestAiTMProxyStartFailClosed(t *testing.T) {
	pool := setupDB(t)
	ctx := context.Background()

	tn := mkTenant(t, ctx, pool, "FailCo")
	opID := createUser(t, ctx, pool, tn.ID, "op@fail.test", "operator")
	opTok := mkKey(t, ctx, pool, tn.ID, opID, "op")

	srv, _ := newAPI(t, pool)
	defer srv.Close()

	engID := seedAuthorizedEngagement(t, ctx, pool, tn.ID, opID)

	// 1) Campaign with NO engagement -> 403 (engagement gate).
	code, body := do(t, srv.URL, http.MethodPost, "/api/v1/campaigns", opTok, map[string]any{"name": "no-eng"})
	if code != http.StatusCreated {
		t.Fatalf("create campaign: %d (%s)", code, body)
	}
	var unbound struct {
		ID uuid.UUID `json:"id"`
	}
	mustJSON(t, body, &unbound)
	if c, _ := do(t, srv.URL, http.MethodPost, "/api/v1/campaigns/"+unbound.ID.String()+"/proxy/start", opTok, nil); c != http.StatusForbidden {
		t.Fatalf("start unbound-engagement campaign: want 403, got %d", c)
	}

	// 2) Campaign bound to an authorized engagement but NO app profile -> 409.
	noProf := mustCampaign(t, srv.URL, opTok, "no-profile", engID)
	if c, b := do(t, srv.URL, http.MethodPost, "/api/v1/campaigns/"+noProf.String()+"/proxy/start", opTok, nil); c != http.StatusConflict {
		t.Fatalf("start no-profile campaign: want 409, got %d (%s)", c, b)
	}

	// 3) Reserved-method profiles bound to a campaign (via SQL, since launch
	// itself refuses to bind them) -> 409 (oauth) / 501 (push) at proxy start.
	oauthID := mustImport(t, srv.URL, opTok, reservedOAuthProfile)
	pushID := mustImport(t, srv.URL, opTok, pushMFAProfile)

	oauthCamp := mustCampaign(t, srv.URL, opTok, "oauth-proxy", engID)
	bindProfileSQL(t, ctx, pool, oauthCamp, oauthID)
	if c, b := do(t, srv.URL, http.MethodPost, "/api/v1/campaigns/"+oauthCamp.String()+"/proxy/start", opTok, nil); c != http.StatusConflict {
		t.Fatalf("start oauth profile: want 409 AUTH-METHOD-UNSUPPORTED, got %d (%s)", c, b)
	}

	pushCamp := mustCampaign(t, srv.URL, opTok, "push-proxy", engID)
	bindProfileSQL(t, ctx, pool, pushCamp, pushID)
	if c, b := do(t, srv.URL, http.MethodPost, "/api/v1/campaigns/"+pushCamp.String()+"/proxy/start", opTok, nil); c != http.StatusNotImplemented {
		t.Fatalf("start push profile: want 501 MFA-METHOD-UNSUPPORTED, got %d (%s)", c, b)
	}

	// 4) Cross-tenant start is a 404 (campaign not visible to the other tenant).
	otherTn := mkTenant(t, ctx, pool, "OtherFailCo")
	otherOp := createUser(t, ctx, pool, otherTn.ID, "op@otherfail.test", "operator")
	otherTok := mkKey(t, ctx, pool, otherTn.ID, otherOp, "op")
	if c, _ := do(t, srv.URL, http.MethodPost, "/api/v1/campaigns/"+noProf.String()+"/proxy/start", otherTok, nil); c != http.StatusNotFound {
		t.Fatalf("cross-tenant start: want 404, got %d", c)
	}
}

// --- helpers --------------------------------------------------------------

func bindProfileSQL(t *testing.T, ctx context.Context, pool *pgxpool.Pool, campaignID, profileID uuid.UUID) {
	t.Helper()
	if _, err := pool.Exec(ctx, `UPDATE campaigns SET app_profile_id=$2 WHERE id=$1`, campaignID, profileID); err != nil {
		t.Fatalf("bind profile via sql: %v", err)
	}
}

func credsRow(t *testing.T, ctx context.Context, pool *pgxpool.Pool, campaignID uuid.UUID) (fields, source, checksum string) {
	t.Helper()
	var f []string
	err := pool.QueryRow(ctx,
		`SELECT array(SELECT jsonb_array_elements_text(metadata->'fields') ORDER BY 1),
		        metadata->>'source', metadata->>'profile_checksum'
		 FROM events WHERE campaign_id=$1 AND type='creds' ORDER BY occurred_at DESC LIMIT 1`,
		campaignID).Scan(&f, &source, &checksum)
	if err != nil {
		t.Fatalf("read creds row: %v", err)
	}
	return strings.Join(f, ","), source, checksum
}

func sessionRow(t *testing.T, ctx context.Context, pool *pgxpool.Pool, campaignID uuid.UUID) (cookies, host, source, checksum string) {
	t.Helper()
	var c []string
	err := pool.QueryRow(ctx,
		`SELECT array(SELECT jsonb_array_elements_text(metadata->'cookies') ORDER BY 1),
		        metadata->>'host', metadata->>'source', metadata->>'profile_checksum'
		 FROM events WHERE campaign_id=$1 AND type='session_hijacked' ORDER BY occurred_at DESC LIMIT 1`,
		campaignID).Scan(&c, &host, &source, &checksum)
	if err != nil {
		t.Fatalf("read session row: %v", err)
	}
	return strings.Join(c, ","), host, source, checksum
}

// netSplit extracts the host (without port) from an http URL.
func netSplit(raw string) (host, port, scheme string) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", ""
	}
	return u.Hostname(), u.Port(), u.Scheme
}
