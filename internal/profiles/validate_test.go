package profiles

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// baseSpec returns a fresh, fully-valid profile map on every call so a test can
// mutate it in isolation.
func baseSpec() map[string]any {
	return map[string]any{
		"version": 1,
		"metadata": map[string]any{
			"name":    "owa-login",
			"vendor":  "Microsoft",
			"product": "Outlook Web App",
		},
		"auth": map[string]any{
			"login_path": "/owa/auth/logon.aspx",
			"method":     "form",
			"fields": []any{
				map[string]any{"selector": "input[name=username]", "upstream_field": "username", "capture": true},
				map[string]any{"selector": "input[name=password]", "upstream_field": "password", "capture": true},
			},
		},
		"session": map[string]any{
			"success_indicators": []any{
				map[string]any{"type": "cookie_set", "name": "cadata"},
			},
			"token_locations": []any{
				map[string]any{"in": "cookie", "name": "cadata", "sensitive": true},
			},
		},
		"mfa": map[string]any{"mode": "none"},
		"phishing_facet": map[string]any{
			"login_page_url": "https://outlook.office.com/owa/auth/logon.aspx",
			"clone_strategy": "mirror",
			"asset_policy":   "proxy",
		},
	}
}

func validateCodes(m map[string]any) []string {
	var res Result
	Validate(m, &res)
	return res.Codes()
}

func hasCode(codes []string, id string) bool {
	for _, c := range codes {
		if c == id {
			return true
		}
	}
	return false
}

// auth returns the auth submap for convenient mutation.
func authOf(m map[string]any) map[string]any  { return m["auth"].(map[string]any) }
func sessOf(m map[string]any) map[string]any  { return m["session"].(map[string]any) }
func mfaOf(m map[string]any) map[string]any   { return m["mfa"].(map[string]any) }
func metaOf(m map[string]any) map[string]any  { return m["metadata"].(map[string]any) }
func facetOf(m map[string]any) map[string]any { return m["phishing_facet"].(map[string]any) }
func fieldsOf(m map[string]any) []any         { return authOf(m)["fields"].([]any) }

func TestValidate_CleanBaseHasNoErrors(t *testing.T) {
	var res Result
	Validate(baseSpec(), &res)
	if res.HasErrors() {
		t.Fatalf("clean base must have no errors, got %v", res.Violations)
	}
}

func TestValidate_RuleMatrix(t *testing.T) {
	bigFields := func() []any {
		out := make([]any, 33)
		for i := range out {
			out[i] = map[string]any{"selector": "f" + itoa(i), "upstream_field": "f" + itoa(i), "capture": false}
		}
		return out
	}
	bigCookies := func() []any {
		out := make([]any, 33)
		for i := range out {
			out[i] = map[string]any{"in": "cookie", "name": "c" + itoa(i)}
		}
		return out
	}

	cases := []struct {
		name       string
		mutate     func(m map[string]any)
		wantCode   string
		wantSev    string // "error" or "warn"
		cleanOfErr bool   // when wantSev == warn, assert no error-severity
	}{
		{"SCHEMA-VERSION-REQUIRED", func(m map[string]any) { delete(m, "version") }, "SCHEMA-VERSION-REQUIRED", "error", false},
		{"SCHEMA-VERSION-UNSUPPORTED", func(m map[string]any) { m["version"] = 2 }, "SCHEMA-VERSION-UNSUPPORTED", "error", false},
		{"SCHEMA-UNKNOWN-KEY", func(m map[string]any) { m["bogus"] = 1 }, "SCHEMA-UNKNOWN-KEY", "error", false},
		{"SCHEMA-SECTIONS-REQUIRED", func(m map[string]any) { delete(m, "mfa") }, "SCHEMA-SECTIONS-REQUIRED", "error", false},

		{"META-NAME-REQUIRED", func(m map[string]any) { metaOf(m)["name"] = "" }, "META-NAME-REQUIRED", "error", false},
		{"META-NAME-SYNTAX", func(m map[string]any) { metaOf(m)["name"] = "Bad Name" }, "META-NAME-SYNTAX", "error", false},
		{"META-NOTES-SIZE", func(m map[string]any) { metaOf(m)["notes"] = strings.Repeat("x", 2049) }, "META-NOTES-SIZE", "warn", true},

		{"AUTH-METHOD-REQUIRED", func(m map[string]any) { delete(authOf(m), "method") }, "AUTH-METHOD-REQUIRED", "error", false},
		{"AUTH-METHOD-KNOWN", func(m map[string]any) { authOf(m)["method"] = "telepathy" }, "AUTH-METHOD-KNOWN", "error", false},
		{"AUTH-LOGINPATH-REQUIRED", func(m map[string]any) { delete(authOf(m), "login_path") }, "AUTH-LOGINPATH-REQUIRED", "error", false},
		{"AUTH-LOGINPATH-REQUIRED/url", func(m map[string]any) { authOf(m)["login_path"] = "https://evil/x" }, "AUTH-LOGINPATH-REQUIRED", "error", false},
		{"AUTH-FORM-FIELDS-REQUIRED", func(m map[string]any) { delete(authOf(m), "fields") }, "AUTH-FORM-FIELDS-REQUIRED", "error", false},
		{"AUTH-FIELD-SELECTOR-REQUIRED", func(m map[string]any) { fieldsOf(m)[0].(map[string]any)["selector"] = "" }, "AUTH-FIELD-SELECTOR-REQUIRED", "error", false},
		{"AUTH-FIELD-UPSTREAM-REQUIRED", func(m map[string]any) { delete(fieldsOf(m)[0].(map[string]any), "upstream_field") }, "AUTH-FIELD-UPSTREAM-REQUIRED", "error", false},
		{"AUTH-FIELD-UPSTREAM-SYNTAX", func(m map[string]any) { fieldsOf(m)[0].(map[string]any)["upstream_field"] = "bad field!" }, "AUTH-FIELD-UPSTREAM-SYNTAX", "error", false},
		{"AUTH-FIELD-UPSTREAM-UNIQUE", func(m map[string]any) { fieldsOf(m)[1].(map[string]any)["upstream_field"] = "username" }, "AUTH-FIELD-UPSTREAM-UNIQUE", "error", false},
		{"AUTH-CAPTURE-ATLEAST-ONE", func(m map[string]any) {
			fieldsOf(m)[0].(map[string]any)["capture"] = false
			fieldsOf(m)[1].(map[string]any)["capture"] = false
		}, "AUTH-CAPTURE-ATLEAST-ONE", "warn", true},
		{"AUTH-FIELDS-COUNT", func(m map[string]any) { authOf(m)["fields"] = bigFields() }, "AUTH-FIELDS-COUNT", "error", false},
		{"SELECTOR-SYNTAX", func(m map[string]any) { fieldsOf(m)[0].(map[string]any)["selector"] = "div > span" }, "SELECTOR-SYNTAX", "error", false},

		{"SESSION-SUCCESS-REQUIRED", func(m map[string]any) { sessOf(m)["success_indicators"] = []any{} }, "SESSION-SUCCESS-REQUIRED", "error", false},
		{"SESSION-SUCCESS-TYPE", func(m map[string]any) { sessOf(m)["success_indicators"].([]any)[0].(map[string]any)["type"] = "magic" }, "SESSION-SUCCESS-TYPE", "error", false},
		{"SESSION-SUCCESS-FIELDS", func(m map[string]any) { delete(sessOf(m)["success_indicators"].([]any)[0].(map[string]any), "name") }, "SESSION-SUCCESS-FIELDS", "error", false},
		{"SESSION-TOKENS-REQUIRED", func(m map[string]any) { sessOf(m)["token_locations"] = []any{} }, "SESSION-TOKENS-REQUIRED", "error", false},
		{"SESSION-TOKEN-IN", func(m map[string]any) { sessOf(m)["token_locations"].([]any)[0].(map[string]any)["in"] = "telepathy" }, "SESSION-TOKEN-IN", "error", false},
		{"SESSION-INDICATOR-INTERSECT", func(m map[string]any) { sessOf(m)["token_locations"].([]any)[0].(map[string]any)["name"] = "other" }, "SESSION-INDICATOR-INTERSECT", "error", false},
		{"SESSION-COOKIES-COUNT", func(m map[string]any) {
			// keep the intersect happy by also adding cadata among the 33
			cs := bigCookies()
			cs[0].(map[string]any)["name"] = "cadata"
			sessOf(m)["token_locations"] = cs
		}, "SESSION-COOKIES-COUNT", "error", false},
		{"SESSION-REFRESH-PATHS", func(m map[string]any) { sessOf(m)["refresh_endpoints"] = []any{"no-slash"} }, "SESSION-REFRESH-PATHS", "error", false},

		{"MFA-MODE-REQUIRED", func(m map[string]any) { delete(mfaOf(m), "mode") }, "MFA-MODE-REQUIRED", "error", false},
		{"MFA-MODE-KNOWN", func(m map[string]any) { mfaOf(m)["mode"] = "smsotp" }, "MFA-MODE-KNOWN", "error", false},
		{"MFA-TOTP-REQUIRED", func(m map[string]any) { mfaOf(m)["mode"] = "totp_field" }, "MFA-TOTP-REQUIRED", "error", false},
		{"MFA-TOTP-CONSISTENCY", func(m map[string]any) {
			mfaOf(m)["totp"] = map[string]any{"selector": "otp", "upstream_field": "otp"}
		}, "MFA-TOTP-CONSISTENCY", "error", false},
		{"MFA-TOTP-CAPTURED", func(m map[string]any) {
			mfaOf(m)["mode"] = "totp_field"
			mfaOf(m)["totp"] = map[string]any{"selector": "otp", "upstream_field": "otp"}
		}, "MFA-TOTP-CAPTURED", "warn", true},

		{"FACET-REQUIRED", func(m map[string]any) { delete(facetOf(m), "clone_strategy") }, "FACET-REQUIRED", "error", false},
		{"FACET-URL-SYNTAX", func(m map[string]any) { facetOf(m)["login_page_url"] = "/relative" }, "FACET-URL-SYNTAX", "error", false},
		{"FACET-CLONE-STRATEGY", func(m map[string]any) { facetOf(m)["clone_strategy"] = "xerox" }, "FACET-CLONE-STRATEGY", "error", false},
		{"FACET-ASSET-POLICY", func(m map[string]any) { facetOf(m)["asset_policy"] = "burn" }, "FACET-ASSET-POLICY", "error", false},
		{"FACET-HOOKS-COUNT", func(m map[string]any) { facetOf(m)["detectable_hooks"] = manyStrings(33) }, "FACET-HOOKS-COUNT", "warn", true},

		{"PROXY-TOKENKEY-SIZE", func(m map[string]any) { m["proxy"] = map[string]any{"token_query_key": strings.Repeat("k", 65)} }, "PROXY-TOKENKEY-SIZE", "error", false},
		{"PROXY-FORMACTION-SIZE", func(m map[string]any) { m["proxy"] = map[string]any{"form_action_contains": strings.Repeat("a", 257)} }, "PROXY-FORMACTION-SIZE", "error", false},
		{"PROXY-MAXBODY-RANGE", func(m map[string]any) { m["proxy"] = map[string]any{"max_body_bytes": 1 << 21} }, "PROXY-MAXBODY-RANGE", "error", false},

		{"SECRETS-NO-VALUES", func(m map[string]any) { sessOf(m)["token_locations"].([]any)[0].(map[string]any)["value"] = "leak" }, "SECRETS-NO-VALUES", "error", false},
		{"SECRETS-NO-CREDS", func(m map[string]any) { m["x-api_key"] = "AKIA..." }, "SECRETS-NO-CREDS", "error", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := baseSpec()
			tc.mutate(m)
			var res Result
			Validate(m, &res)
			if !hasCode(res.Codes(), tc.wantCode) {
				t.Fatalf("want code %s, got %v", tc.wantCode, res.Violations)
			}
			// Severity check for the targeted code.
			for _, v := range res.Violations {
				if v.ID == tc.wantCode && v.Severity != tc.wantSev {
					t.Fatalf("code %s: want severity %s, got %s", tc.wantCode, tc.wantSev, v.Severity)
				}
			}
			if tc.cleanOfErr && res.HasErrors() {
				t.Fatalf("warn case %s unexpectedly produced an error: %v", tc.wantCode, res.Violations)
			}
		})
	}
}

// TestValidate_TokenKeysNotFlaggedByDenylist proves the SECRETS-NO-CREDS denylist
// exempts the structural schema keys that contain "token" (token_locations,
// token_query_key) — otherwise the valid schema itself would be rejected.
func TestValidate_TokenKeysNotFlaggedByDenylist(t *testing.T) {
	m := baseSpec()
	m["proxy"] = map[string]any{"token_query_key": "_pft"}
	codes := validateCodes(m)
	if hasCode(codes, "SECRETS-NO-CREDS") {
		t.Fatalf("structural token keys must not trip SECRETS-NO-CREDS; got %v", codes)
	}
}

func TestInstantiateFlow(t *testing.T) {
	mk := func(method, mode string) map[string]any {
		m := baseSpec()
		authOf(m)["method"] = method
		if method != "form" {
			delete(authOf(m), "fields")
		}
		mfaOf(m)["mode"] = mode
		return m
	}
	cases := []struct {
		method, mode string
		wantErr      error
	}{
		{"form", "none", nil},
		{"basic", "none", nil},
		{"form", "totp_field", nil},
		{"oauth2_code", "none", ErrAuthMethodUnsupported},
		{"saml_post", "none", ErrAuthMethodUnsupported},
		{"form", "push_intercept", ErrMFAMethodUnsupported},
		{"form", "custom", ErrMFAMethodUnsupported},
	}
	for _, tc := range cases {
		t.Run(tc.method+"/"+tc.mode, func(t *testing.T) {
			err := InstantiateFlow(mk(tc.method, tc.mode))
			if tc.wantErr == nil && err != nil {
				t.Fatalf("want nil, got %v", err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("want %v, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestChecksum_StableAcrossKeyOrder(t *testing.T) {
	a := []byte("version: 1\nmetadata:\n  name: x\n  vendor: V\n")
	b := []byte("metadata:\n  vendor: V\n  name: x\nversion: 1\n")
	ma, err := ParseYAML(a)
	if err != nil {
		t.Fatal(err)
	}
	mb, err := ParseYAML(b)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := ChecksumOf(ma)
	cb, _ := ChecksumOf(mb)
	if ca != cb {
		t.Fatalf("checksum must be stable across key order: %s != %s", ca, cb)
	}
	if len(ca) != 64 {
		t.Fatalf("checksum must be hex sha256 (64 chars), got %d", len(ca))
	}
}

// TestWorkedExampleIsValid proves the committed OWA worked example validates
// clean (the schema docs and the validator agree).
func TestWorkedExampleIsValid(t *testing.T) {
	path := filepath.Join("..", "..", "docs", "PROFILES", "examples", "owa.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("example not found (%v)", err)
	}
	spec, res := ValidateBytes(raw)
	if res.HasErrors() {
		t.Fatalf("owa.yaml must validate clean, got %v", res.Violations)
	}
	// It uses totp_field, which is runtime-supported.
	if err := InstantiateFlow(spec); err != nil {
		t.Fatalf("owa.yaml must instantiate at runtime: %v", err)
	}
}

func manyStrings(n int) []any {
	out := make([]any, n)
	for i := range out {
		out[i] = "hook" + itoa(i)
	}
	return out
}

func itoa(i int) string { return fmt.Sprintf("%d", i) }
