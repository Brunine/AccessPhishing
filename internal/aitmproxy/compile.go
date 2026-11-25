// Package aitmproxy implements M5 Phase 1: the in-process AiTM reverse proxy
// runtime bound to a campaign's M10b application profile. It compiles a
// validated profile spec into the proxy's runtime shape (an engineconfig.Capture
// plus upstream + success-detection), serves one listener per campaign, and
// emits capture events through the orchestrator's existing names-only ingest
// boundary (source="proxy").
//
// Scope — Phase 1: form (and basic) auth capture, cookie-based session-hijack
// detection, lifecycle + a minimal placeholder landing. Clone generation,
// llm_assisted strategy, OAuth2/SAML interception, and push/custom MFA are later
// phases or declined (see docs/ADR.md).
package aitmproxy

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"phishforge/internal/engineconfig"
)

// DefaultTokenQueryKey is the victim-token query parameter stripped before
// forwarding upstream when a profile declares no proxy.token_query_key. It
// matches engineconfig's default so the whole platform speaks one token key.
const DefaultTokenQueryKey = "_pft"

// DefaultMaxBodyBytes bounds request/response body inspection when a profile
// declares no proxy.max_body_bytes (mirrors engineconfig's default).
const DefaultMaxBodyBytes int64 = 64 << 10 // 64 KiB

// Success-indicator types (docs/PROFILES/SCHEMA.md §3.3).
const (
	IndicatorCookieSet   = "cookie_set"
	IndicatorURLRedirect = "url_redirect"
	IndicatorStatusCode  = "status_code"
	IndicatorBodyRegex   = "body_regex"
)

// Indicator is one compiled session-success marker. Exactly one of the typed
// fields is meaningful per Type.
type Indicator struct {
	Type     string
	Name     string         // cookie_set: the Set-Cookie name
	Location string         // url_redirect: Location substring
	Code     int            // status_code: exact HTTP status
	Pattern  *regexp.Regexp // body_regex: compiled RE2 over a bounded body
}

// Upstream is the real login origin the proxy forwards to, derived from
// phishing_facet.login_page_url (the one URL in the schema, not a path).
type Upstream struct {
	Scheme string
	Host   string // host only, no port
	Port   int
}

// Compiled is the runtime shape of a profile: everything the proxy needs to
// serve a campaign, with no further profile lookups. It is produced once from a
// schema-valid spec (InstantiateFlow already cleared the auth/MFA method).
type Compiled struct {
	// Capture is the engineconfig capture block (credential field + session
	// cookie NAME allowlists, token key, body cap). The names-only boundary is
	// enforced downstream at ingest; this only ever names fields/cookies.
	Capture engineconfig.Capture
	// LoginPath is the absolute upstream path a captured POST targets.
	LoginPath string
	// AuthMethod is the (already runtime-supported) auth method: form | basic.
	AuthMethod string
	// Upstream is the real login origin to reverse-proxy to.
	Upstream Upstream
	// SuccessIndicators are evaluated in order against the upstream response.
	SuccessIndicators []Indicator
	// SessionCookieNames are the token_locations[in=cookie] names — the shape of
	// the session material a hijack reports (names only, never values).
	SessionCookieNames []string
	// NeedsBody is true when any indicator is body_regex (the only case the
	// response body must be read for success detection).
	NeedsBody bool
	// LoginPageURL is phishing_facet.login_page_url — the real page cloned at
	// proxy start (M5 Phase 2). It is the only URL the clone fetcher ever
	// requests, and its host always equals Upstream.Host (SSRF-safe by design).
	LoginPageURL string
	// CloneStrategy is phishing_facet.clone_strategy (mirror | template |
	// llm_assisted). Phase 2 serves mirror/template via a static transform;
	// llm_assisted is runtime-unsupported (proxy start fails closed, 501).
	CloneStrategy string
	// AssetPolicy is phishing_facet.asset_policy (proxy | inline | strip) —
	// how the clone's asset references are rewritten.
	AssetPolicy string
}

// errCompile wraps a compilation failure so the caller fails closed.
var errCompile = errors.New("aitmproxy: compile")

// Compile turns a schema-valid profile spec (the canonical map decoded from the
// stored JSON) into its runtime Compiled form. It implements the SCHEMA.md §4.1
// mapping exactly:
//
//   - auth.fields[*].upstream_field where capture:true -> Capture.CredentialFormFields
//   - mfa.totp.upstream_field (when mfa.mode=totp_field)               -> same allowlist
//   - session.token_locations[*] where in:cookie                       -> Capture.SessionCookies
//   - proxy.token_query_key / form_action_contains / max_body_bytes    -> Capture.* knobs
//   - phishing_facet.login_page_url                                    -> Upstream
//   - session.success_indicators                                       -> SuccessIndicators
//
// It assumes the spec already passed import validation and the runtime gate
// (InstantiateFlow); it still fails closed on any structural surprise so a
// malformed stored row can never produce a half-configured proxy.
func Compile(spec map[string]any) (Compiled, error) {
	var c Compiled

	auth, ok := asMap(spec["auth"])
	if !ok {
		return Compiled{}, fmt.Errorf("%w: auth section missing", errCompile)
	}
	c.AuthMethod, _ = auth["method"].(string)
	c.LoginPath, _ = auth["login_path"].(string)
	if !strings.HasPrefix(c.LoginPath, "/") {
		return Compiled{}, fmt.Errorf("%w: auth.login_path must be an absolute path", errCompile)
	}

	// Credential allowlist: captured form fields, in declared order, deduped.
	seen := map[string]bool{}
	addField := func(name string) {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		c.Capture.CredentialFormFields = append(c.Capture.CredentialFormFields, name)
	}
	if fields, ok := asList(auth["fields"]); ok {
		for _, raw := range fields {
			f, ok := asMap(raw)
			if !ok {
				continue
			}
			capture, _ := f["capture"].(bool)
			if !capture {
				continue
			}
			up, _ := f["upstream_field"].(string)
			addField(up)
		}
	}

	// MFA TOTP joins the SAME credential mechanism when mode=totp_field.
	if mfa, ok := asMap(spec["mfa"]); ok {
		if mode, _ := mfa["mode"].(string); mode == "totp_field" {
			if totp, ok := asMap(mfa["totp"]); ok {
				up, _ := totp["upstream_field"].(string)
				addField(up)
			}
		}
	}

	// Session cookies (shape, names only).
	sess, ok := asMap(spec["session"])
	if !ok {
		return Compiled{}, fmt.Errorf("%w: session section missing", errCompile)
	}
	cookieSeen := map[string]bool{}
	if toks, ok := asList(sess["token_locations"]); ok {
		for _, raw := range toks {
			tok, ok := asMap(raw)
			if !ok {
				continue
			}
			if in, _ := tok["in"].(string); in != "cookie" {
				continue
			}
			name, _ := tok["name"].(string)
			name = strings.TrimSpace(name)
			if name == "" || cookieSeen[name] {
				continue
			}
			cookieSeen[name] = true
			c.SessionCookieNames = append(c.SessionCookieNames, name)
			c.Capture.SessionCookies = append(c.Capture.SessionCookies, name)
		}
	}

	// Success indicators (evaluated in declared order).
	inds, ok := asList(sess["success_indicators"])
	if !ok || len(inds) == 0 {
		return Compiled{}, fmt.Errorf("%w: session.success_indicators missing", errCompile)
	}
	for i, raw := range inds {
		ind, ok := asMap(raw)
		if !ok {
			return Compiled{}, fmt.Errorf("%w: success_indicators[%d] is not a mapping", errCompile, i)
		}
		typ, _ := ind["type"].(string)
		out := Indicator{Type: typ}
		switch typ {
		case IndicatorCookieSet:
			out.Name, _ = ind["name"].(string)
		case IndicatorURLRedirect:
			out.Location, _ = ind["location"].(string)
		case IndicatorStatusCode:
			out.Code, _ = asInt(ind["code"])
		case IndicatorBodyRegex:
			pat, _ := ind["pattern"].(string)
			re, err := regexp.Compile(pat)
			if err != nil {
				return Compiled{}, fmt.Errorf("%w: success_indicators[%d] bad regex: %v", errCompile, i, err)
			}
			out.Pattern = re
			c.NeedsBody = true
		default:
			return Compiled{}, fmt.Errorf("%w: success_indicators[%d] unknown type %q", errCompile, i, typ)
		}
		c.SuccessIndicators = append(c.SuccessIndicators, out)
	}

	// proxy.* knobs (all optional; apply engineconfig defaults).
	c.Capture.TokenQueryKey = DefaultTokenQueryKey
	c.Capture.MaxBodyBytes = DefaultMaxBodyBytes
	if proxy, ok := asMap(spec["proxy"]); ok {
		if k, ok := proxy["token_query_key"].(string); ok && k != "" {
			c.Capture.TokenQueryKey = k
		}
		if fa, ok := proxy["form_action_contains"].(string); ok {
			c.Capture.FormActionContains = fa
		}
		if mb, ok := asInt(proxy["max_body_bytes"]); ok && mb > 0 {
			c.Capture.MaxBodyBytes = int64(mb)
		}
	}

	// Upstream from the phishing facet's login page URL.
	facet, ok := asMap(spec["phishing_facet"])
	if !ok {
		return Compiled{}, fmt.Errorf("%w: phishing_facet section missing", errCompile)
	}
	lpu, _ := facet["login_page_url"].(string)
	up, err := parseUpstream(lpu)
	if err != nil {
		return Compiled{}, fmt.Errorf("%w: %v", errCompile, err)
	}
	c.Upstream = up
	c.LoginPageURL = lpu
	c.CloneStrategy, _ = facet["clone_strategy"].(string)
	c.AssetPolicy, _ = facet["asset_policy"].(string)

	return c, nil
}

// parseUpstream derives the real origin to proxy to from an absolute http(s) URL.
func parseUpstream(raw string) (Upstream, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Upstream{}, fmt.Errorf("login_page_url parse: %w", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return Upstream{}, fmt.Errorf("login_page_url must be an absolute http(s) URL")
	}
	port := 0
	if ps := u.Port(); ps != "" {
		p, perr := strconv.Atoi(ps)
		if perr != nil || p < 1 || p > 65535 {
			return Upstream{}, fmt.Errorf("login_page_url has an invalid port %q", ps)
		}
		port = p
	} else if u.Scheme == "https" {
		port = 443
	} else {
		port = 80
	}
	return Upstream{Scheme: u.Scheme, Host: u.Hostname(), Port: port}, nil
}

// --- generic accessors (JSON-decoded map shapes) --------------------------

func asMap(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

func asList(v any) ([]any, bool) {
	l, ok := v.([]any)
	return l, ok
}

func asInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		if n == float64(int(n)) {
			return int(n), true
		}
	}
	return 0, false
}
