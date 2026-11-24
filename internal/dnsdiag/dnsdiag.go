// Package dnsdiag provides pure, injectable DNS and TLS diagnostics for the
// domain inventory. All lookups go through a Resolver interface (satisfied by
// *net.Resolver) so unit tests can supply a fake and never touch the network.
//
// These functions are diagnostic, not authoritative: TLS inspection uses
// InsecureSkipVerify because we are reading a presented certificate to report
// on it, not validating a trust chain. Every network call takes a hard timeout.
// No HTTP fetches and no shell-outs are performed here.
package dnsdiag

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Resolver is the subset of *net.Resolver used for diagnostics. A fake
// implementation drives the unit tests.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupNS(ctx context.Context, name string) ([]*net.NS, error)
}

// DefaultResolver is the standard library resolver.
var DefaultResolver Resolver = net.DefaultResolver

// ErrNoCertificate is returned when a TLS handshake yields no peer certificate.
var ErrNoCertificate = errors.New("dnsdiag: no peer certificate presented")

// TXT returns every TXT record for domain.
func TXT(ctx context.Context, res Resolver, domain string) ([]string, error) {
	recs, err := res.LookupTXT(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("dnsdiag: lookup TXT %q: %w", domain, err)
	}
	return recs, nil
}

// CheckOwnership reports whether any TXT record for domain equals expectedValue
// exactly (no substring or prefix matching). It also returns the raw records so
// a caller can surface them for debugging. A lookup error is returned as-is.
func CheckOwnership(ctx context.Context, res Resolver, domain, expectedValue string) (bool, []string, error) {
	recs, err := res.LookupTXT(ctx, domain)
	if err != nil {
		return false, nil, fmt.Errorf("dnsdiag: lookup TXT %q: %w", domain, err)
	}
	for _, r := range recs {
		if r == expectedValue {
			return true, recs, nil
		}
	}
	return false, recs, nil
}

// SPF returns the first TXT record that begins with "v=spf1", or "" when none
// is published. A lookup error is returned.
func SPF(ctx context.Context, res Resolver, domain string) (string, error) {
	recs, err := res.LookupTXT(ctx, domain)
	if err != nil {
		return "", fmt.Errorf("dnsdiag: lookup SPF %q: %w", domain, err)
	}
	return firstWithPrefix(recs, "v=spf1"), nil
}

// DMARC returns the DMARC policy TXT record at _dmarc.<domain> (one beginning
// with "v=DMARC1"), or "" when none is published.
func DMARC(ctx context.Context, res Resolver, domain string) (string, error) {
	name := "_dmarc." + domain
	recs, err := res.LookupTXT(ctx, name)
	if err != nil {
		return "", fmt.Errorf("dnsdiag: lookup DMARC %q: %w", name, err)
	}
	return firstWithPrefix(recs, "v=DMARC1"), nil
}

// DKIM returns the DKIM TXT record at <selector>._domainkey.<domain>, joined
// when the record is split into multiple strings, or "" when none is published.
func DKIM(ctx context.Context, res Resolver, domain, selector string) (string, error) {
	name := selector + "._domainkey." + domain
	recs, err := res.LookupTXT(ctx, name)
	if err != nil {
		return "", fmt.Errorf("dnsdiag: lookup DKIM %q: %w", name, err)
	}
	if len(recs) == 0 {
		return "", nil
	}
	// A DKIM record is frequently chunked; concatenation reconstructs it.
	return strings.Join(recs, ""), nil
}

// Nameservers returns the authoritative nameserver hostnames for domain, with
// any trailing dot stripped.
func Nameservers(ctx context.Context, res Resolver, domain string) ([]string, error) {
	nss, err := res.LookupNS(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("dnsdiag: lookup NS %q: %w", domain, err)
	}
	out := make([]string, 0, len(nss))
	for _, ns := range nss {
		out = append(out, strings.TrimSuffix(ns.Host, "."))
	}
	return out, nil
}

// firstWithPrefix returns the first record whose (case-insensitive, space-
// trimmed) prefix matches, else "".
func firstWithPrefix(recs []string, prefix string) string {
	lp := strings.ToLower(prefix)
	for _, r := range recs {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(r)), lp) {
			return r
		}
	}
	return ""
}

// TLSInfo is a read-only summary of a presented leaf certificate.
type TLSInfo struct {
	SubjectCN       string    `json:"subject_cn"`
	SANs            []string  `json:"sans"`
	Issuer          string    `json:"issuer"`
	NotBefore       time.Time `json:"not_before"`
	NotAfter        time.Time `json:"not_after"`
	DaysUntilExpiry int       `json:"days_until_expiry"`
	CoversDomain    bool      `json:"covers_domain"`
}

// tlsDialContext is overridable in tests. It dials a TLS connection and returns
// the presented peer certificates. Production uses a real dialer; it is never
// pointed at a user-supplied host (callers pass only the stored domain name).
var tlsDialContext = func(ctx context.Context, addr string, timeout time.Duration) ([]*x509.Certificate, error) {
	d := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		// InsecureSkipVerify: we are DIAGNOSING the presented certificate (to
		// report CN/SANs/expiry), not validating a trust chain. This endpoint
		// never establishes trust on the basis of this handshake.
		Config: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // diagnostic inspection only
	}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	tc, ok := conn.(*tls.Conn)
	if !ok {
		return nil, errors.New("dnsdiag: not a TLS connection")
	}
	return tc.ConnectionState().PeerCertificates, nil
}

// TLS dials host:port, inspects the presented leaf certificate, and returns a
// TLSInfo. The handshake is bounded by ctx and timeout. Malformed certificates
// never panic; a typed error is returned instead.
//
// SECURITY: callers pass only an inventory domain name (never a user-supplied
// host), and the port is constrained to 443/853 at the handler. This keeps the
// diagnostic from being usable as an SSRF or port-scan primitive.
func TLS(ctx context.Context, host string, port int, timeout time.Duration) (TLSInfo, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	certs, err := tlsDialContext(ctx, addr, timeout)
	if err != nil {
		return TLSInfo{}, fmt.Errorf("dnsdiag: tls dial %q: %w", addr, err)
	}
	if len(certs) == 0 || certs[0] == nil {
		return TLSInfo{}, ErrNoCertificate
	}
	return certToInfo(certs[0], host, time.Now()), nil
}

// certToInfo maps a leaf certificate to a TLSInfo relative to now. Pure and
// table-testable.
func certToInfo(cert *x509.Certificate, domain string, now time.Time) TLSInfo {
	sans := append([]string(nil), cert.DNSNames...)
	return TLSInfo{
		SubjectCN:       cert.Subject.CommonName,
		SANs:            sans,
		Issuer:          cert.Issuer.CommonName,
		NotBefore:       cert.NotBefore,
		NotAfter:        cert.NotAfter,
		DaysUntilExpiry: int(cert.NotAfter.Sub(now).Hours() / 24),
		CoversDomain:    sansCoverDomain(cert.DNSNames, cert.Subject.CommonName, domain),
	}
}

// sansCoverDomain reports whether any SAN (or, as a fallback, the subject CN)
// covers domain. A single leftmost wildcard label matches exactly one label,
// per RFC 6125 (so *.example.com covers a.example.com but not example.com or
// a.b.example.com). Matching is case-insensitive.
func sansCoverDomain(sans []string, cn, domain string) bool {
	d := strings.ToLower(strings.TrimSuffix(domain, "."))
	candidates := make([]string, 0, len(sans)+1)
	candidates = append(candidates, sans...)
	if cn != "" {
		candidates = append(candidates, cn)
	}
	for _, raw := range candidates {
		if hostMatches(strings.ToLower(strings.TrimSuffix(raw, ".")), d) {
			return true
		}
	}
	return false
}

// hostMatches reports whether pattern (possibly a leftmost wildcard) matches
// host exactly.
func hostMatches(pattern, host string) bool {
	if pattern == host {
		return true
	}
	if !strings.HasPrefix(pattern, "*.") {
		return false
	}
	suffix := pattern[1:] // ".example.com"
	if !strings.HasSuffix(host, suffix) {
		return false
	}
	label := host[:len(host)-len(suffix)]
	// Wildcard covers exactly one non-empty label (no embedded dot).
	return label != "" && !strings.Contains(label, ".")
}
