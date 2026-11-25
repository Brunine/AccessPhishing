package aitmproxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"testing"
	"time"

	"phishforge/internal/engineconfig"
)

// specFromJSON decodes a JSON object into the canonical map shape the proxy
// receives from the stored profile (numbers as float64, like json.Unmarshal).
func specFromJSON(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("decode spec: %v", err)
	}
	return m
}

const baseForm = `{
  "version":1,
  "metadata":{"name":"owa"},
  "auth":{
    "login_path":"/owa/auth/logon.aspx",
    "method":"form",
    "fields":[
      {"selector":"input[name=username]","upstream_field":"username","capture":true},
      {"selector":"input[name=password]","upstream_field":"password","capture":true},
      {"selector":"input[name=flags]","upstream_field":"flags","capture":false}
    ]
  },
  "session":{
    "success_indicators":[{"type":"cookie_set","name":"cadata"}],
    "token_locations":[
      {"in":"cookie","name":"cadata"},
      {"in":"header","name":"X-Thing"}
    ]
  },
  "mfa":{"mode":"none"},
  "phishing_facet":{"login_page_url":"https://outlook.office.com/owa/auth/logon.aspx","clone_strategy":"mirror","asset_policy":"proxy"}
}`

func TestCompileMapping(t *testing.T) {
	c, err := Compile(specFromJSON(t, baseForm))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	// §4.1: capture:true upstream_field -> CredentialFormFields (order preserved,
	// non-captured field excluded).
	if got, want := c.Capture.CredentialFormFields, []string{"username", "password"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("credential fields: got %v want %v", got, want)
	}
	// §4.1: token_locations in=cookie -> SessionCookies (header excluded).
	if got, want := c.Capture.SessionCookies, []string{"cadata"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("session cookies: got %v want %v", got, want)
	}
	// proxy defaults.
	if c.Capture.TokenQueryKey != DefaultTokenQueryKey {
		t.Fatalf("token key default: got %q", c.Capture.TokenQueryKey)
	}
	if c.Capture.MaxBodyBytes != DefaultMaxBodyBytes {
		t.Fatalf("max body default: got %d", c.Capture.MaxBodyBytes)
	}
	if c.Capture.FormActionContains != "" {
		t.Fatalf("form_action_contains should be empty, got %q", c.Capture.FormActionContains)
	}
	// Upstream from phishing_facet.login_page_url (default https port 443).
	if c.Upstream != (Upstream{Scheme: "https", Host: "outlook.office.com", Port: 443}) {
		t.Fatalf("upstream: got %+v", c.Upstream)
	}
	if c.LoginPath != "/owa/auth/logon.aspx" {
		t.Fatalf("login_path: got %q", c.LoginPath)
	}
	if c.NeedsBody {
		t.Fatalf("NeedsBody should be false without a body_regex indicator")
	}
}

func TestCompileTOTPJoinsCredentialMechanism(t *testing.T) {
	spec := specFromJSON(t, `{
      "version":1,"metadata":{"name":"owa"},
      "auth":{"login_path":"/l","method":"form","fields":[
        {"selector":"input[name=u]","upstream_field":"username","capture":true}]},
      "session":{"success_indicators":[{"type":"cookie_set","name":"c"}],
        "token_locations":[{"in":"cookie","name":"c"}]},
      "mfa":{"mode":"totp_field","totp":{"selector":"input[name=otp]","upstream_field":"otp"}},
      "phishing_facet":{"login_page_url":"https://x.test/l","clone_strategy":"mirror","asset_policy":"proxy"}
    }`)
	c, err := Compile(spec)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	got := append([]string(nil), c.Capture.CredentialFormFields...)
	sort.Strings(got)
	if want := []string{"otp", "username"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("totp should join credential allowlist: got %v want %v", got, want)
	}
}

func TestCompileProxyKnobsAndUpstreamPort(t *testing.T) {
	spec := specFromJSON(t, `{
      "version":1,"metadata":{"name":"x"},
      "auth":{"login_path":"/signin","method":"form","fields":[
        {"selector":"input[name=u]","upstream_field":"u","capture":true}]},
      "session":{"success_indicators":[{"type":"status_code","code":302}],
        "token_locations":[{"in":"cookie","name":"sid"}]},
      "mfa":{"mode":"none"},
      "phishing_facet":{"login_page_url":"http://portal.test:8443/signin","clone_strategy":"mirror","asset_policy":"proxy"},
      "proxy":{"token_query_key":"tok","form_action_contains":"signin","max_body_bytes":1024}
    }`)
	c, err := Compile(spec)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if c.Capture.TokenQueryKey != "tok" {
		t.Fatalf("token key: got %q", c.Capture.TokenQueryKey)
	}
	if c.Capture.FormActionContains != "signin" {
		t.Fatalf("form_action_contains: got %q", c.Capture.FormActionContains)
	}
	if c.Capture.MaxBodyBytes != 1024 {
		t.Fatalf("max body: got %d", c.Capture.MaxBodyBytes)
	}
	if c.Upstream != (Upstream{Scheme: "http", Host: "portal.test", Port: 8443}) {
		t.Fatalf("upstream: got %+v", c.Upstream)
	}
}

func TestCompileFailsClosed(t *testing.T) {
	cases := map[string]string{
		"bad login_page_url": `{"version":1,"metadata":{"name":"x"},
          "auth":{"login_path":"/l","method":"form","fields":[{"selector":"input[name=u]","upstream_field":"u","capture":true}]},
          "session":{"success_indicators":[{"type":"cookie_set","name":"c"}],"token_locations":[{"in":"cookie","name":"c"}]},
          "mfa":{"mode":"none"},
          "phishing_facet":{"login_page_url":"not-a-url","clone_strategy":"mirror","asset_policy":"proxy"}}`,
		"no success indicators": `{"version":1,"metadata":{"name":"x"},
          "auth":{"login_path":"/l","method":"form","fields":[{"selector":"input[name=u]","upstream_field":"u","capture":true}]},
          "session":{"success_indicators":[],"token_locations":[{"in":"cookie","name":"c"}]},
          "mfa":{"mode":"none"},
          "phishing_facet":{"login_page_url":"https://x.test/","clone_strategy":"mirror","asset_policy":"proxy"}}`,
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Compile(specFromJSON(t, s)); err == nil {
				t.Fatalf("expected compile to fail closed for %s", name)
			}
		})
	}
}

// --- token stripping ------------------------------------------------------

func TestTakeTokenStrips(t *testing.T) {
	in := NewInstanceFromCompiled(Compiled{Capture: engineconfig.Capture{TokenQueryKey: "_pft"}}, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/x?_pft=abc123&foo=1&bar=2", nil)
	tok := in.takeToken(req)
	if tok != "abc123" {
		t.Fatalf("token: got %q want abc123", tok)
	}
	q := req.URL.Query()
	if q.Has("_pft") {
		t.Fatalf("token param should be stripped, raw=%q", req.URL.RawQuery)
	}
	if q.Get("foo") != "1" || q.Get("bar") != "2" {
		t.Fatalf("other params must survive, raw=%q", req.URL.RawQuery)
	}
}

// --- success-indicator evaluation matrix ----------------------------------

type fakeSink struct {
	calls []sinkCall
}

type sinkCall struct {
	kind    string
	token   string
	payload map[string]any
}

func (f *fakeSink) Capture(_ context.Context, kind, token string, payload map[string]any, _ time.Time) {
	f.calls = append(f.calls, sinkCall{kind: kind, token: token, payload: payload})
}

// respWith builds a response carrying a token in its request context (as the
// capture middleware would set), plus the given status/headers.
func respWith(status int, header http.Header) *http.Response {
	req := httptest.NewRequest(http.MethodPost, "/owa/auth/logon.aspx", nil)
	req = req.WithContext(context.WithValue(req.Context(), tokenKey{}, "victim-tok"))
	if header == nil {
		header = http.Header{}
	}
	return &http.Response{StatusCode: status, Header: header, Request: req}
}

func TestSuccessIndicatorMatrix(t *testing.T) {
	cookieComp := Compiled{
		SuccessIndicators:  []Indicator{{Type: IndicatorCookieSet, Name: "cadata"}},
		SessionCookieNames: []string{"cadata"},
		Upstream:           Upstream{Scheme: "https", Host: "outlook.office.com", Port: 443},
	}
	statusComp := Compiled{
		SuccessIndicators:  []Indicator{{Type: IndicatorStatusCode, Code: 302}},
		SessionCookieNames: []string{"cadata"},
		Upstream:           Upstream{Scheme: "https", Host: "h", Port: 443},
	}
	redirComp := Compiled{
		SuccessIndicators:  []Indicator{{Type: IndicatorURLRedirect, Location: "/owa/"}},
		SessionCookieNames: []string{"cadata"},
		Upstream:           Upstream{Scheme: "https", Host: "h", Port: 443},
	}

	t.Run("cookie_set fires with cookie names", func(t *testing.T) {
		sink := &fakeSink{}
		in := NewInstanceFromCompiled(cookieComp, sink, nil)
		h := http.Header{}
		h.Add("Set-Cookie", "cadata=SECRETVALUE; Path=/; HttpOnly")
		_ = in.modifyResponse(respWith(200, h))
		if len(sink.calls) != 1 {
			t.Fatalf("want 1 session event, got %d", len(sink.calls))
		}
		call := sink.calls[0]
		if call.kind != KindSession || call.token != "victim-tok" {
			t.Fatalf("unexpected call: %+v", call)
		}
		cookies, _ := call.payload["cookies"].(map[string]string)
		if _, ok := cookies["cadata"]; !ok || len(cookies) != 1 {
			t.Fatalf("expected cookie NAME cadata only, got %+v", call.payload)
		}
		// The secret value must never appear anywhere in the payload.
		if cookies["cadata"] != "" {
			t.Fatalf("cookie value must not be carried, got %q", cookies["cadata"])
		}
		if call.payload["host"] != "outlook.office.com" {
			t.Fatalf("host should be the non-secret upstream host, got %v", call.payload["host"])
		}
	})

	t.Run("status_code fires", func(t *testing.T) {
		sink := &fakeSink{}
		in := NewInstanceFromCompiled(statusComp, sink, nil)
		_ = in.modifyResponse(respWith(302, nil))
		if len(sink.calls) != 1 {
			t.Fatalf("status indicator should fire, got %d calls", len(sink.calls))
		}
	})

	t.Run("url_redirect fires on Location substring", func(t *testing.T) {
		sink := &fakeSink{}
		in := NewInstanceFromCompiled(redirComp, sink, nil)
		h := http.Header{}
		h.Set("Location", "https://outlook.office.com/owa/#path")
		_ = in.modifyResponse(respWith(302, h))
		if len(sink.calls) != 1 {
			t.Fatalf("redirect indicator should fire, got %d calls", len(sink.calls))
		}
	})

	t.Run("no match -> no event", func(t *testing.T) {
		sink := &fakeSink{}
		in := NewInstanceFromCompiled(cookieComp, sink, nil)
		h := http.Header{}
		h.Add("Set-Cookie", "unrelated=1")
		_ = in.modifyResponse(respWith(200, h))
		if len(sink.calls) != 0 {
			t.Fatalf("no indicator should fire, got %d calls", len(sink.calls))
		}
	})

	t.Run("no token -> no event even on success", func(t *testing.T) {
		sink := &fakeSink{}
		in := NewInstanceFromCompiled(cookieComp, sink, nil)
		req := httptest.NewRequest(http.MethodPost, "/owa/auth/logon.aspx", nil) // no token in ctx
		h := http.Header{}
		h.Add("Set-Cookie", "cadata=x")
		_ = in.modifyResponse(&http.Response{StatusCode: 200, Header: h, Request: req})
		if len(sink.calls) != 0 {
			t.Fatalf("missing token must suppress capture, got %d calls", len(sink.calls))
		}
	})
}
