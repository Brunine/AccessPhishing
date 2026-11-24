package profiles

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Severity of a validation violation.
const (
	SeverityError = "error"
	SeverityWarn  = "warn"
)

// Violation is one failed rule, carrying the exact VALIDATION.md rule ID.
type Violation struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Path     string `json:"path,omitempty"`
}

// Result collects every violation found in one pass (errors and warnings).
type Result struct {
	Violations []Violation `json:"violations"`
}

// HasErrors reports whether any error-severity violation was recorded. Warnings
// alone do not block an import.
func (r Result) HasErrors() bool {
	for _, v := range r.Violations {
		if v.Severity == SeverityError {
			return true
		}
	}
	return false
}

// Codes returns the violation IDs in order (for logs/tests).
func (r Result) Codes() []string {
	out := make([]string, len(r.Violations))
	for i, v := range r.Violations {
		out[i] = v.ID
	}
	return out
}

func (r *Result) add(id, sev, path, format string, a ...any) {
	r.Violations = append(r.Violations, Violation{
		ID: id, Severity: sev, Path: path, Message: fmt.Sprintf(format, a...),
	})
}
func (r *Result) err(id, path, format string, a ...any)  { r.add(id, SeverityError, path, format, a...) }
func (r *Result) warn(id, path, format string, a ...any) { r.add(id, SeverityWarn, path, format, a...) }

var (
	nameRe     = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	upstreamRe = regexp.MustCompile(`^[A-Za-z_][\w.\[\]-]{0,127}$`)
	bareSelRe  = regexp.MustCompile(`^[A-Za-z_][\w-]{0,63}$`)
	qualSelRe  = regexp.MustCompile(`^(name|id)=[A-Za-z_][\w-]{0,63}$`)
	cssSelRe   = regexp.MustCompile(`^(input|select|textarea)(\[[a-zA-Z0-9_-]+=[^\]]{1,64}\])?$`)
)

// Allowed key sets per known object (SCHEMA-UNKNOWN-KEY). oauth2/saml are
// reserved free-form maps and are intentionally not descended into.
var (
	topKeys     = set("version", "metadata", "auth", "session", "mfa", "phishing_facet", "proxy")
	metaKeys    = set("name", "vendor", "product", "notes")
	authKeys    = set("login_path", "method", "fields", "oauth2", "saml")
	fieldKeys   = set("selector", "upstream_field", "capture")
	sessKeys    = set("success_indicators", "token_locations", "refresh_endpoints")
	indKeys     = set("type", "name", "location", "code", "pattern")
	tokKeys     = set("in", "name", "sensitive")
	mfaKeys     = set("mode", "totp")
	totpKeys    = set("selector", "upstream_field")
	facetKeys   = set("login_page_url", "clone_strategy", "asset_policy", "detectable_hooks")
	proxyKeys   = set("token_query_key", "form_action_contains", "max_body_bytes")
	authMethods = set("form", "oauth2_code", "saml_post", "ntlm", "basic")
	succTypes   = set("cookie_set", "url_redirect", "status_code", "body_regex")
	tokenIns    = set("cookie", "header", "body", "query")
	mfaModes    = set("none", "totp_field", "push_intercept", "custom")
	cloneStrats = set("mirror", "template", "llm_assisted")
	assetPols   = set("proxy", "inline", "strip")

	// SECRETS-NO-CREDS denylist terms (case-insensitive substring on key names)
	// and the structural schema keys exempted from it (the only allowed keys
	// that legitimately contain a denylist term).
	credTerms   = []string{"password", "passwd", "secret", "token", "api_key", "credential"}
	credExempt  = set("token_locations", "token_query_key")
	noValueKeys = set("value", "secret", "token")
)

// ValidateBytes parses a raw profile document and runs every rule. It returns
// the parsed spec (nil on a parse/size failure) and the collected Result. A
// parse or size failure is reported as an error-severity violation with a
// schema rule ID, so callers get a uniform Result.
func ValidateBytes(raw []byte) (map[string]any, Result) {
	var res Result
	if len(raw) > MaxSpecBytes {
		res.err("SCHEMA-SIZE-LIMIT", "", "document is %d bytes, limit is %d", len(raw), MaxSpecBytes)
		return nil, res
	}
	spec, err := ParseYAML(raw)
	if err != nil {
		res.err("SCHEMA-PARSE", "", "%v", err)
		return nil, res
	}
	Validate(spec, &res)
	return spec, res
}

// Validate runs every import-time rule against an already-parsed spec, appending
// violations to res. The two *-UNSUPPORTED runtime checks (auth/mfa method) are
// deliberately NOT enforced here — a reserved-method profile is storable but is
// refused at launch by InstantiateFlow (rulings 1 & 2). META-NAME-UNIQUE is
// enforced by the DB unique constraint, not here.
func Validate(spec map[string]any, res *Result) {
	// SECRETS-NO-CREDS: recursive key-name denylist over the whole document.
	scanCredKeys(spec, "", res)

	// SCHEMA-UNKNOWN-KEY (top level).
	unknownKeys(spec, topKeys, "", res)

	// SCHEMA-SECTIONS-REQUIRED.
	for _, s := range []string{"metadata", "auth", "session", "mfa", "phishing_facet"} {
		if _, ok := spec[s]; !ok {
			res.err("SCHEMA-SECTIONS-REQUIRED", s, "%s section is required", s)
		}
	}

	validateVersion(spec, res)
	validateMetadata(spec, res)
	validateAuth(spec, res)
	validateSession(spec, res)
	validateMFA(spec, res)
	validateFacet(spec, res)
	validateProxy(spec, res)
}

func validateVersion(spec map[string]any, res *Result) {
	v, ok := spec["version"]
	if !ok {
		res.err("SCHEMA-VERSION-REQUIRED", "version", "version is required")
		return
	}
	n, ok := asInt(v)
	if !ok {
		res.err("SCHEMA-VERSION-REQUIRED", "version", "version must be an integer")
		return
	}
	if n != 1 {
		res.err("SCHEMA-VERSION-UNSUPPORTED", "version", "version %d is unsupported (v1 parser)", n)
	}
}

func validateMetadata(spec map[string]any, res *Result) {
	m, ok := asMap(spec["metadata"])
	if !ok {
		return // missing/!map already handled by SECTIONS-REQUIRED
	}
	unknownKeys(m, metaKeys, "metadata", res)

	name, _ := m["name"].(string)
	if strings.TrimSpace(name) == "" {
		res.err("META-NAME-REQUIRED", "metadata.name", "metadata.name is required")
	} else if !nameRe.MatchString(name) {
		res.err("META-NAME-SYNTAX", "metadata.name", "metadata.name %q must match ^[a-z0-9][a-z0-9_-]{0,63}$", name)
	}
	if notes, ok := m["notes"].(string); ok && len(notes) > 2048 {
		res.warn("META-NOTES-SIZE", "metadata.notes", "metadata.notes is %d chars, over the 2048 soft limit", len(notes))
	}
}

func validateAuth(spec map[string]any, res *Result) {
	a, ok := asMap(spec["auth"])
	if !ok {
		return
	}
	unknownKeys(a, authKeys, "auth", res)

	// login_path
	lp, ok := a["login_path"].(string)
	switch {
	case !ok || lp == "":
		res.err("AUTH-LOGINPATH-REQUIRED", "auth.login_path", "auth.login_path is required")
	case !strings.HasPrefix(lp, "/"):
		res.err("AUTH-LOGINPATH-REQUIRED", "auth.login_path", "auth.login_path must be an absolute path starting with /")
	case len(lp) > 2048 || strings.Contains(lp, "://"):
		res.err("AUTH-LOGINPATH-REQUIRED", "auth.login_path", "auth.login_path must be a path (<=2048 chars, no scheme/host)")
	}

	// method
	method, ok := a["method"].(string)
	if !ok || method == "" {
		res.err("AUTH-METHOD-REQUIRED", "auth.method", "auth.method is required")
	} else if !authMethods[method] {
		res.err("AUTH-METHOD-KNOWN", "auth.method", "auth.method %q is not a recognized method", method)
	}

	// fields (required only for the form method)
	fields, hasFields := asList(a["fields"])
	if method == "form" {
		if !hasFields || len(fields) == 0 {
			res.err("AUTH-FORM-FIELDS-REQUIRED", "auth.fields", "auth.fields is required and non-empty for method=form")
		}
	}
	if hasFields && len(fields) > 32 {
		res.err("AUTH-FIELDS-COUNT", "auth.fields", "auth.fields has %d entries, max 32", len(fields))
	}

	// per-field rules + upstream uniqueness + at-least-one-capture
	seenUpstream := map[string]bool{}
	anyCapture := false
	for i, raw := range fields {
		path := fmt.Sprintf("auth.fields[%d]", i)
		f, ok := asMap(raw)
		if !ok {
			res.err("AUTH-FIELD-SELECTOR-REQUIRED", path, "field must be a mapping")
			continue
		}
		unknownKeys(f, fieldKeys, path, res)

		sel, _ := f["selector"].(string)
		if strings.TrimSpace(sel) == "" {
			res.err("AUTH-FIELD-SELECTOR-REQUIRED", path+".selector", "selector is required")
		} else if !validSelector(sel) {
			res.err("SELECTOR-SYNTAX", path+".selector", "selector %q is not a permitted form", sel)
		}

		up, _ := f["upstream_field"].(string)
		if strings.TrimSpace(up) == "" {
			res.err("AUTH-FIELD-UPSTREAM-REQUIRED", path+".upstream_field", "upstream_field is required")
		} else {
			if !upstreamRe.MatchString(up) {
				res.err("AUTH-FIELD-UPSTREAM-SYNTAX", path+".upstream_field", "upstream_field %q must match ^[A-Za-z_][\\w.\\[\\]-]{0,127}$", up)
			}
			if seenUpstream[up] {
				res.err("AUTH-FIELD-UPSTREAM-UNIQUE", path+".upstream_field", "upstream_field %q is duplicated", up)
			}
			seenUpstream[up] = true
		}

		if cap, ok := f["capture"].(bool); ok && cap {
			anyCapture = true
		}

		// SECRETS-NO-VALUES on a field entry.
		checkNoValueKeys(f, path, res)
	}
	if method == "form" && hasFields && len(fields) > 0 && !anyCapture {
		res.warn("AUTH-CAPTURE-ATLEAST-ONE", "auth.fields", "no field has capture: true (a form profile that captures nothing is likely a mistake)")
	}

	// MFA totp upstream participates in uniqueness (checked here so the field
	// set is complete); the mfa section validates its own presence/syntax.
	if up := totpUpstream(spec); up != "" {
		if seenUpstream[up] {
			res.err("AUTH-FIELD-UPSTREAM-UNIQUE", "mfa.totp.upstream_field", "upstream_field %q collides with an auth field", up)
		}
	}
}

func validateSession(spec map[string]any, res *Result) {
	s, ok := asMap(spec["session"])
	if !ok {
		return
	}
	unknownKeys(s, sessKeys, "session", res)

	inds, hasInds := asList(s["success_indicators"])
	if !hasInds || len(inds) == 0 {
		res.err("SESSION-SUCCESS-REQUIRED", "session.success_indicators", "session.success_indicators is required and non-empty")
	}
	cookieSetNames := map[string]bool{}
	for i, raw := range inds {
		path := fmt.Sprintf("session.success_indicators[%d]", i)
		ind, ok := asMap(raw)
		if !ok {
			res.err("SESSION-SUCCESS-TYPE", path, "indicator must be a mapping")
			continue
		}
		unknownKeys(ind, indKeys, path, res)
		typ, _ := ind["type"].(string)
		if !succTypes[typ] {
			res.err("SESSION-SUCCESS-TYPE", path+".type", "type %q is not a recognized success indicator", typ)
			continue
		}
		switch typ {
		case "cookie_set":
			name, _ := ind["name"].(string)
			if name == "" {
				res.err("SESSION-SUCCESS-FIELDS", path, "cookie_set requires name")
			} else {
				cookieSetNames[name] = true
			}
		case "url_redirect":
			if loc, _ := ind["location"].(string); loc == "" {
				res.err("SESSION-SUCCESS-FIELDS", path, "url_redirect requires location")
			}
		case "status_code":
			code, ok := asInt(ind["code"])
			if !ok || code < 100 || code > 599 {
				res.err("SESSION-SUCCESS-FIELDS", path, "status_code requires code in 100..599")
			}
		case "body_regex":
			pat, _ := ind["pattern"].(string)
			if pat == "" || len(pat) > 512 {
				res.err("SESSION-SUCCESS-FIELDS", path, "body_regex requires pattern (1..512 chars)")
			} else if _, err := regexp.Compile(pat); err != nil {
				res.err("SESSION-SUCCESS-FIELDS", path, "body_regex pattern is not valid RE2: %v", err)
			}
		}
	}

	toks, hasToks := asList(s["token_locations"])
	if !hasToks || len(toks) == 0 {
		res.err("SESSION-TOKENS-REQUIRED", "session.token_locations", "session.token_locations is required and non-empty")
	}
	cookieTokenNames := map[string]bool{}
	cookieCount := 0
	for i, raw := range toks {
		path := fmt.Sprintf("session.token_locations[%d]", i)
		tok, ok := asMap(raw)
		if !ok {
			res.err("SESSION-TOKEN-IN", path, "token location must be a mapping")
			continue
		}
		unknownKeys(tok, tokKeys, path, res)
		in, _ := tok["in"].(string)
		name, _ := tok["name"].(string)
		if !tokenIns[in] {
			res.err("SESSION-TOKEN-IN", path+".in", "in %q is not one of cookie|header|body|query", in)
		}
		if name == "" || len(name) > 128 {
			res.err("SESSION-TOKEN-IN", path+".name", "name is required (<=128 chars)")
		}
		if in == "cookie" {
			cookieCount++
			if name != "" {
				cookieTokenNames[name] = true
			}
		}
		checkNoValueKeys(tok, path, res)
	}
	if cookieCount > 32 {
		res.err("SESSION-COOKIES-COUNT", "session.token_locations", "%d cookie token locations, max 32", cookieCount)
	}

	// SESSION-INDICATOR-INTERSECT: every cookie_set success name must be a
	// cookie token location.
	for name := range cookieSetNames {
		if !cookieTokenNames[name] {
			res.err("SESSION-INDICATOR-INTERSECT", "session", "cookie_set success indicator %q has no matching cookie token_location", name)
		}
	}

	// refresh_endpoints
	if rel, ok := asList(s["refresh_endpoints"]); ok {
		if len(rel) > 16 {
			res.err("SESSION-REFRESH-PATHS", "session.refresh_endpoints", "%d entries, max 16", len(rel))
		}
		for i, raw := range rel {
			p, _ := raw.(string)
			if !strings.HasPrefix(p, "/") {
				res.err("SESSION-REFRESH-PATHS", fmt.Sprintf("session.refresh_endpoints[%d]", i), "must be an absolute path starting with /")
			}
		}
	}
}

func validateMFA(spec map[string]any, res *Result) {
	m, ok := asMap(spec["mfa"])
	if !ok {
		return
	}
	unknownKeys(m, mfaKeys, "mfa", res)

	mode, ok := m["mode"].(string)
	if !ok || mode == "" {
		res.err("MFA-MODE-REQUIRED", "mfa.mode", "mfa.mode is required")
		return
	}
	if !mfaModes[mode] {
		res.err("MFA-MODE-KNOWN", "mfa.mode", "mfa.mode %q is not a recognized mode", mode)
		return
	}

	totp, hasTotp := asMap(m["totp"])
	nonEmptyTotp := hasTotp && len(totp) > 0

	if mode == "totp_field" {
		if !nonEmptyTotp {
			res.err("MFA-TOTP-REQUIRED", "mfa.totp", "mode=totp_field requires mfa.totp.selector and mfa.totp.upstream_field")
		} else {
			unknownKeys(totp, totpKeys, "mfa.totp", res)
			sel, _ := totp["selector"].(string)
			up, _ := totp["upstream_field"].(string)
			if strings.TrimSpace(sel) == "" || !validSelector(sel) {
				res.err("MFA-TOTP-REQUIRED", "mfa.totp.selector", "mfa.totp.selector is required and must be a permitted selector")
			}
			if strings.TrimSpace(up) == "" || !upstreamRe.MatchString(up) {
				res.err("MFA-TOTP-REQUIRED", "mfa.totp.upstream_field", "mfa.totp.upstream_field is required and must match the upstream grammar")
			}
			checkNoValueKeys(totp, "mfa.totp", res)
		}
		res.warn("MFA-TOTP-CAPTURED", "mfa.totp", "mode=totp_field: the TOTP upstream_field is captured into the same creds event as credentials")
	} else if nonEmptyTotp {
		res.err("MFA-TOTP-CONSISTENCY", "mfa.totp", "mfa.totp is set but mode is %q (not totp_field)", mode)
	}
}

func validateFacet(spec map[string]any, res *Result) {
	f, ok := asMap(spec["phishing_facet"])
	if !ok {
		return
	}
	unknownKeys(f, facetKeys, "phishing_facet", res)

	lpu, _ := f["login_page_url"].(string)
	strat, _ := f["clone_strategy"].(string)
	policy, _ := f["asset_policy"].(string)
	if lpu == "" || strat == "" || policy == "" {
		res.err("FACET-REQUIRED", "phishing_facet", "login_page_url, clone_strategy, and asset_policy are all required")
	}
	if lpu != "" {
		if len(lpu) > 2048 || !validHTTPURL(lpu) {
			res.err("FACET-URL-SYNTAX", "phishing_facet.login_page_url", "login_page_url must be an absolute http(s):// URL (<=2048 chars)")
		}
	}
	if strat != "" && !cloneStrats[strat] {
		res.err("FACET-CLONE-STRATEGY", "phishing_facet.clone_strategy", "clone_strategy %q is not one of mirror|template|llm_assisted", strat)
	}
	if policy != "" && !assetPols[policy] {
		res.err("FACET-ASSET-POLICY", "phishing_facet.asset_policy", "asset_policy %q is not one of proxy|inline|strip", policy)
	}
	if hooks, ok := asList(f["detectable_hooks"]); ok && len(hooks) > 32 {
		res.warn("FACET-HOOKS-COUNT", "phishing_facet.detectable_hooks", "%d entries, over the soft limit of 32", len(hooks))
	}
}

func validateProxy(spec map[string]any, res *Result) {
	p, ok := asMap(spec["proxy"])
	if !ok {
		return // optional section
	}
	unknownKeys(p, proxyKeys, "proxy", res)
	if k, ok := p["token_query_key"].(string); ok && len(k) > 64 {
		res.err("PROXY-TOKENKEY-SIZE", "proxy.token_query_key", "token_query_key is %d chars, max 64", len(k))
	}
	if fa, ok := p["form_action_contains"].(string); ok && len(fa) > 256 {
		res.err("PROXY-FORMACTION-SIZE", "proxy.form_action_contains", "form_action_contains is %d chars, max 256", len(fa))
	}
	if mb, ok := p["max_body_bytes"]; ok {
		n, isInt := asInt(mb)
		if !isInt || n < 0 || n > 1<<20 {
			res.err("PROXY-MAXBODY-RANGE", "proxy.max_body_bytes", "max_body_bytes must be an integer in 0..1048576")
		}
	}
}

// --- secrets scanning -----------------------------------------------------

// scanCredKeys recursively flags any key whose name contains a denylist term
// (SECRETS-NO-CREDS), except the structural schema keys in credExempt. It walks
// every level, including the reserved x- namespace, so a secret hidden under an
// annotation key is still caught.
func scanCredKeys(v any, path string, res *Result) {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			kp := joinPath(path, k)
			lk := strings.ToLower(k)
			if !credExempt[lk] {
				for _, term := range credTerms {
					if strings.Contains(lk, term) {
						res.err("SECRETS-NO-CREDS", kp, "key %q matches the credential denylist term %q — profiles never carry secret values", k, term)
						break
					}
				}
			}
			scanCredKeys(val, kp, res)
		}
	case []any:
		for i, val := range t {
			scanCredKeys(val, fmt.Sprintf("%s[%d]", path, i), res)
		}
	}
}

// checkNoValueKeys enforces SECRETS-NO-VALUES on a token_location / field entry:
// it must not carry a value/secret/token key (shape, never values).
func checkNoValueKeys(m map[string]any, path string, res *Result) {
	for k := range m {
		if noValueKeys[strings.ToLower(k)] {
			res.err("SECRETS-NO-VALUES", joinPath(path, k), "entry must not carry a %q key — profiles describe shape, not values", k)
		}
	}
}

// --- helpers --------------------------------------------------------------

func validSelector(s string) bool {
	return bareSelRe.MatchString(s) || qualSelRe.MatchString(s) || cssSelRe.MatchString(s)
}

func validHTTPURL(s string) bool {
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	return (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

func totpUpstream(spec map[string]any) string {
	up, _ := mapStr(spec, "mfa", "totp", "upstream_field")
	return up
}

// unknownKeys flags any key of m not in allowed, except x- prefixed keys.
func unknownKeys(m map[string]any, allowed map[string]bool, path string, res *Result) {
	for k := range m {
		if strings.HasPrefix(k, "x-") {
			continue
		}
		if !allowed[k] {
			res.err("SCHEMA-UNKNOWN-KEY", joinPath(path, k), "unknown key %q (only x- prefixed extension keys are permitted here)", k)
		}
	}
}

func set(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, s := range items {
		m[s] = true
	}
	return m
}

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

func joinPath(base, key string) string {
	if base == "" {
		return key
	}
	return base + "." + key
}
