package aitmproxy

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestMatchesLoginAction(t *testing.T) {
	cases := []struct {
		action, loginPath, contains string
		want                        bool
	}{
		{"", "/l", "", false},
		{"/l", "/l", "", true},      // already-proxied action (idempotent)
		{"/other", "/l", "", false}, // path mismatch, no substring rule
		{"https://up.test/owa/auth/logon.aspx", "/owa/auth/logon.aspx", "logon.aspx", true}, // substring match
		{"https://up.test/owa/other", "/owa/auth/logon.aspx", "logon.aspx", false},          // substring mismatch
		{"/owa/auth/logon.aspx", "/owa/auth/logon.aspx", "logon.aspx", true},
	}
	for _, c := range cases {
		if got := matchesLoginAction(c.action, c.loginPath, c.contains); got != c.want {
			t.Errorf("matchesLoginAction(%q,%q,%q)=%v want %v", c.action, c.loginPath, c.contains, got, c.want)
		}
	}
}

func TestInternalPath(t *testing.T) {
	const host = "up.test"
	cases := []struct {
		raw      string
		wantPath string
		wantOK   bool
	}{
		{"/a/b", "/a/b", true},
		{"a/b", "a/b", true},
		{"https://up.test/a?x=1", "/a?x=1", true},
		{"https://up.test/", "/", true},
		{"https://other.test/a", "", false},
		{"//up.test/a", "/a", true},
		{"//cdn.test/a", "", false},
		{"#frag", "", false},
		{"mailto:x@y.test", "", false},
		{"javascript:void(0)", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		gotPath, gotOK := internalPath(c.raw, host)
		if gotOK != c.wantOK || gotPath != c.wantPath {
			t.Errorf("internalPath(%q)=(%q,%v) want (%q,%v)", c.raw, gotPath, gotOK, c.wantPath, c.wantOK)
		}
	}
}

func TestRewriteAsset(t *testing.T) {
	const host = "up.test"
	cases := []struct {
		raw, policy, want string
	}{
		{"https://up.test/s.css", "proxy", "/s.css"},
		{"https://cdn.test/s.css", "proxy", "https://cdn.test/s.css"},
		{"css/s.css", "proxy", "css/s.css"},
		{"//up.test/s.js", "proxy", "/s.js"},
		{"https://up.test/s.css", "strip", ""},
		{"https://cdn.test/s.css", "strip", ""},
		{"//cdn.test/s.js", "strip", ""},
		{"css/s.css", "strip", "css/s.css"},
		{"data:image/png;base64,AAAA", "strip", "data:image/png;base64,AAAA"},
		{"https://up.test/s.css", "inline", "/s.css"}, // inline behaves as proxy in Phase 2
	}
	for _, c := range cases {
		got := rewriteAsset(c.raw, rewriteOpts{upstreamHost: host, assetPolicy: c.policy})
		if got != c.want {
			t.Errorf("rewriteAsset(%q,%s)=%q want %q", c.raw, c.policy, got, c.want)
		}
	}
}

func TestAppendQueryParamPreservesExisting(t *testing.T) {
	got := appendQueryParam("/l?a=1", "_pft", tokenSentinel)
	if !strings.Contains(got, "a=1") || !strings.Contains(got, "_pft="+tokenSentinel) {
		t.Fatalf("appendQueryParam lost a param: %q", got)
	}
	got2 := appendQueryParam("/l", "_pft", tokenSentinel)
	if got2 != "/l?_pft="+tokenSentinel {
		t.Fatalf("appendQueryParam bare: %q", got2)
	}
}

func TestRewriteHTMLEndToEnd(t *testing.T) {
	src := `<!doctype html><html><head>
<link rel="stylesheet" href="https://up.test/app.css">
<link rel="stylesheet" href="https://cdn.test/vendor.css">
</head><body>
<form method="post" action="https://up.test/owa/auth/logon.aspx">
  <input name="username"><input name="password">
</form>
<a href="/help">Help</a>
<a href="https://up.test/about">About</a>
<a href="https://evil-not-ours.test/x">External</a>
<img src="https://up.test/logo.png">
<script src="https://cdn.test/a.js"></script>
</body></html>`

	out, err := rewriteHTML([]byte(src), rewriteOpts{
		upstreamHost:       "up.test",
		loginPath:          "/owa/auth/logon.aspx",
		formActionContains: "logon.aspx",
		tokenKey:           "_pft",
		assetPolicy:        "proxy",
	})
	if err != nil {
		t.Fatalf("rewriteHTML: %v", err)
	}
	s := string(out)

	// Form action -> login path + token sentinel.
	if !strings.Contains(s, `action="/owa/auth/logon.aspx?_pft=`+tokenSentinel+`"`) {
		t.Errorf("form action not rewritten with token sentinel:\n%s", s)
	}
	// Internal anchors carry the token; the external one does not change.
	if !strings.Contains(s, `href="/help?_pft=`+tokenSentinel+`"`) {
		t.Errorf("relative anchor not tokenized:\n%s", s)
	}
	if !strings.Contains(s, `href="/about?_pft=`+tokenSentinel+`"`) {
		t.Errorf("upstream-absolute anchor not root-relative + tokenized:\n%s", s)
	}
	if !strings.Contains(s, `href="https://evil-not-ours.test/x"`) {
		t.Errorf("external anchor must be unchanged:\n%s", s)
	}
	// Assets: upstream-absolute -> root-relative (proxy); external untouched.
	if !strings.Contains(s, `href="/app.css"`) {
		t.Errorf("upstream stylesheet not proxied:\n%s", s)
	}
	if !strings.Contains(s, `href="https://cdn.test/vendor.css"`) {
		t.Errorf("external stylesheet must be unchanged:\n%s", s)
	}
	if !strings.Contains(s, `src="/logo.png"`) {
		t.Errorf("upstream img not proxied:\n%s", s)
	}
	if !strings.Contains(s, `src="https://cdn.test/a.js"`) {
		t.Errorf("external script must be unchanged:\n%s", s)
	}

	// Deterministic: same input twice -> identical output.
	out2, _ := rewriteHTML([]byte(src), rewriteOpts{
		upstreamHost: "up.test", loginPath: "/owa/auth/logon.aspx",
		formActionContains: "logon.aspx", tokenKey: "_pft", assetPolicy: "proxy",
	})
	if string(out2) != s {
		t.Error("rewriteHTML is not deterministic")
	}
}

func TestRewriteHTMLFormActionContainsMismatch(t *testing.T) {
	src := `<form action="/unrelated/path"><input name="x"></form>`
	out, err := rewriteHTML([]byte(src), rewriteOpts{
		upstreamHost: "up.test", loginPath: "/owa/auth/logon.aspx",
		formActionContains: "logon.aspx", tokenKey: "_pft", assetPolicy: "proxy",
	})
	if err != nil {
		t.Fatalf("rewriteHTML: %v", err)
	}
	if !strings.Contains(string(out), `action="/unrelated/path"`) {
		t.Errorf("non-login form action must be left unchanged:\n%s", out)
	}
}

func TestResolveCloneAssetBoundary(t *testing.T) {
	base := t.TempDir()
	cases := []struct {
		sub    string
		wantOK bool
	}{
		{"index.html", true},
		{"assets/app.css", true},
		{"/index.html", true},
		{"../secret", false},
		{"/../../etc/passwd", false},
		{"a/../../../etc/passwd", false},
		{"", false},
	}
	for _, c := range cases {
		full, ok := resolveCloneAsset(base, c.sub)
		if ok != c.wantOK {
			t.Errorf("resolveCloneAsset(%q)=%v want %v (full=%q)", c.sub, ok, c.wantOK, full)
			continue
		}
		if ok && !strings.HasPrefix(full, base+string(filepath.Separator)) {
			t.Errorf("resolveCloneAsset(%q) escaped base: %q", c.sub, full)
		}
	}
}
