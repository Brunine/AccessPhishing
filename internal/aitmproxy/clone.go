package aitmproxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// assetPrefix is the reserved path namespace under which a campaign's generated
// clone assets are served. Only files inside the campaign's clone directory are
// reachable here; traversal outside it is rejected.
const assetPrefix = "/__clone/"

// Clone-generation errors mapped by the HTTP layer.
var (
	// ErrCloneStrategyUnsupported is returned for clone_strategy=llm_assisted
	// (runtime-unsupported in Phase 2 → proxy start 501, same as M10b MFA).
	ErrCloneStrategyUnsupported = errors.New("aitmproxy: clone strategy unsupported at runtime")
	// ErrUpstreamFetch is returned when the login page cannot be fetched/cloned
	// at proxy start → fail closed (no listener, no placeholder).
	ErrUpstreamFetch = errors.New("aitmproxy: upstream login page fetch failed")
)

// cloneState is a campaign's generated login-page clone (snapshot at start).
type cloneState struct {
	dir         string    // <baseDir>/<campaignID>
	index       []byte    // rewritten HTML, served with the token injected
	hash        string    // sha256 hex of the rewritten HTML (the snapshot)
	generatedAt time.Time // when the clone was generated
	fetchOK     bool      // whether the upstream fetch succeeded
	ready       bool      // whether a clone is available to serve
}

// GenerateClone fetches the profile's login page, applies the deterministic
// static transform, and stores the result in the campaign's clone directory. It
// must run AFTER the profile's InstantiateFlow gate (checksum validated) and
// BEFORE the listener is started, so a fetch failure fails the whole start
// closed (no placeholder is ever served).
//
// Only the profile-declared login_page_url is ever fetched (SSRF-safe: never a
// victim-supplied URL), its host must equal the compiled upstream host, the body
// is bounded by the profile's proxy.max_body_bytes, and redirects are not
// followed (the client is configured to return the last response).
func (in *Instance) GenerateClone(ctx context.Context, client *http.Client, baseDir, campaignID string) error {
	switch in.compiled.CloneStrategy {
	case "mirror", "template":
		// static transform (deterministic)
	case "llm_assisted":
		return ErrCloneStrategyUnsupported
	default:
		return fmt.Errorf("%w: unknown clone_strategy %q", ErrCloneStrategyUnsupported, in.compiled.CloneStrategy)
	}

	raw, err := in.fetchLoginPage(ctx, client)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUpstreamFetch, err)
	}

	rewritten, err := rewriteHTML(raw, rewriteOpts{
		upstreamHost:       in.compiled.Upstream.Host,
		loginPath:          in.compiled.LoginPath,
		formActionContains: in.compiled.Capture.FormActionContains,
		tokenKey:           in.compiled.Capture.TokenQueryKey,
		assetPolicy:        in.compiled.AssetPolicy,
	})
	if err != nil {
		return fmt.Errorf("%w: rewrite: %v", ErrUpstreamFetch, err)
	}

	dir := filepath.Join(baseDir, campaignID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("aitmproxy: clone dir: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.html"), rewritten, 0o600); err != nil {
		return fmt.Errorf("aitmproxy: write clone: %w", err)
	}

	sum := sha256.Sum256(rewritten)
	in.clone = cloneState{
		dir:         dir,
		index:       rewritten,
		hash:        hex.EncodeToString(sum[:]),
		generatedAt: time.Now().UTC(),
		fetchOK:     true,
		ready:       true,
	}
	return nil
}

// fetchLoginPage GETs the profile's login_page_url (profile-authored, never
// victim-supplied), rejecting a host that does not match the compiled upstream
// and reading a bounded body.
func (in *Instance) fetchLoginPage(ctx context.Context, client *http.Client) ([]byte, error) {
	u, err := url.Parse(in.compiled.LoginPageURL)
	if err != nil {
		return nil, fmt.Errorf("parse login_page_url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("login_page_url must be http(s)")
	}
	if !strings.EqualFold(u.Hostname(), in.compiled.Upstream.Host) {
		// Defense in depth: the compiler derives the upstream from this URL, so
		// this can only trip if the two are tampered out of sync.
		return nil, fmt.Errorf("login_page_url host %q does not match upstream %q", u.Hostname(), in.compiled.Upstream.Host)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, in.compiled.LoginPageURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("upstream returned status %d", resp.StatusCode)
	}
	cap := in.compiled.Capture.MaxBodyBytes
	if cap <= 0 {
		cap = DefaultMaxBodyBytes
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, cap))
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("upstream returned an empty body")
	}
	return body, nil
}

// Cleanup removes the campaign's clone directory. Called on proxy stop.
func (in *Instance) Cleanup() {
	if in.clone.dir != "" {
		_ = os.RemoveAll(in.clone.dir)
	}
}

// CloneInfo exposes the clone snapshot state for status reporting.
func (in *Instance) CloneInfo() (hash string, generatedAt time.Time, fetchOK, ready bool) {
	return in.clone.hash, in.clone.generatedAt, in.clone.fetchOK, in.clone.ready
}

// resolveCloneAsset maps a requested asset sub-path to an absolute path strictly
// inside campaignDir, rejecting any traversal. ok is false for anything that
// would escape the directory.
func resolveCloneAsset(campaignDir, reqSubPath string) (string, bool) {
	sub := strings.TrimPrefix(reqSubPath, "/")
	if sub == "" {
		return "", false
	}
	// Reject any explicit traversal segment outright (the HTTP mux also cleans
	// "." / ".." before routing; this is defense in depth).
	for _, seg := range strings.Split(sub, "/") {
		if seg == ".." {
			return "", false
		}
	}
	clean := strings.TrimPrefix(path.Clean("/"+sub), "/")
	if clean == "" {
		return "", false
	}
	full := filepath.Join(campaignDir, filepath.FromSlash(clean))
	rel, err := filepath.Rel(campaignDir, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", false
	}
	return full, true
}
