package dnsdiag

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net"
	"testing"
	"time"
)

// fakeResolver injects canned TXT/NS answers; no network is touched.
type fakeResolver struct {
	txt map[string][]string
	ns  map[string][]*net.NS
	err error
}

func (f fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	v, ok := f.txt[name]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	return v, nil
}

func (f fakeResolver) LookupNS(_ context.Context, name string) ([]*net.NS, error) {
	if f.err != nil {
		return nil, f.err
	}
	v, ok := f.ns[name]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	return v, nil
}

func TestCheckOwnership(t *testing.T) {
	res := fakeResolver{txt: map[string][]string{
		"_phishforge.acme.com": {"unrelated=1", "pf-domain-verify=abc123"},
	}}
	ctx := context.Background()

	ok, recs, err := CheckOwnership(ctx, res, "_phishforge.acme.com", "pf-domain-verify=abc123")
	if err != nil || !ok {
		t.Fatalf("exact match: ok=%v err=%v", ok, err)
	}
	if len(recs) != 2 {
		t.Fatalf("records returned: want 2, got %d", len(recs))
	}

	// Substring / prefix must NOT match (exact comparison only).
	if ok, _, _ := CheckOwnership(ctx, res, "_phishforge.acme.com", "pf-domain-verify=abc"); ok {
		t.Fatal("prefix should not match")
	}
	if ok, _, _ := CheckOwnership(ctx, res, "_phishforge.acme.com", "abc123"); ok {
		t.Fatal("substring should not match")
	}

	// Missing host -> lookup error surfaced.
	if _, _, err := CheckOwnership(ctx, res, "_phishforge.absent.com", "x"); err == nil {
		t.Fatal("missing host: want error")
	}
}

func TestSPFDMARCDKIM(t *testing.T) {
	res := fakeResolver{txt: map[string][]string{
		"acme.com":                {"something", "v=spf1 include:_spf.google.com ~all"},
		"_dmarc.acme.com":         {"v=DMARC1; p=reject"},
		"sel._domainkey.acme.com": {"v=DKIM1; k=rsa; ", "p=MIIB"},
		"nospf.com":               {"random text"},
		"_dmarc.nodmarc.com":      {"not a dmarc record"},
	}}
	ctx := context.Background()

	if got, err := SPF(ctx, res, "acme.com"); err != nil || got != "v=spf1 include:_spf.google.com ~all" {
		t.Fatalf("SPF found: got %q err %v", got, err)
	}
	if got, err := SPF(ctx, res, "nospf.com"); err != nil || got != "" {
		t.Fatalf("SPF absent: want empty, got %q err %v", got, err)
	}
	if got, err := DMARC(ctx, res, "acme.com"); err != nil || got != "v=DMARC1; p=reject" {
		t.Fatalf("DMARC found: got %q err %v", got, err)
	}
	if got, err := DMARC(ctx, res, "nodmarc.com"); err != nil || got != "" {
		t.Fatalf("DMARC absent (malformed): want empty, got %q err %v", got, err)
	}
	// DKIM chunks are concatenated.
	if got, err := DKIM(ctx, res, "acme.com", "sel"); err != nil || got != "v=DKIM1; k=rsa; p=MIIB" {
		t.Fatalf("DKIM join: got %q err %v", got, err)
	}
	// DKIM absent selector -> lookup error.
	if _, err := DKIM(ctx, res, "acme.com", "missing"); err == nil {
		t.Fatal("DKIM missing selector: want error")
	}
}

func TestNameservers(t *testing.T) {
	res := fakeResolver{ns: map[string][]*net.NS{
		"acme.com": {{Host: "ns1.acme.com."}, {Host: "ns2.acme.com."}},
	}}
	got, err := Nameservers(context.Background(), res, "acme.com")
	if err != nil {
		t.Fatalf("ns: %v", err)
	}
	if len(got) != 2 || got[0] != "ns1.acme.com" || got[1] != "ns2.acme.com" {
		t.Fatalf("ns trailing dot not stripped: %v", got)
	}
}

func TestResolverErrorPropagates(t *testing.T) {
	res := fakeResolver{err: errors.New("boom")}
	if _, err := TXT(context.Background(), res, "x.com"); err == nil {
		t.Fatal("want propagated resolver error")
	}
}

func TestSANCoverage(t *testing.T) {
	cases := []struct {
		name   string
		sans   []string
		cn     string
		domain string
		want   bool
	}{
		{"exact SAN", []string{"acme.com"}, "", "acme.com", true},
		{"case-insensitive", []string{"ACME.com"}, "", "acme.com", true},
		{"wildcard one label", []string{"*.acme.com"}, "", "mail.acme.com", true},
		{"wildcard does not cover apex", []string{"*.acme.com"}, "", "acme.com", false},
		{"wildcard does not cover two labels", []string{"*.acme.com"}, "", "a.b.acme.com", false},
		{"cn fallback", []string{}, "acme.com", "acme.com", true},
		{"no coverage", []string{"other.com"}, "nope.com", "acme.com", false},
		{"trailing dot normalized", []string{"acme.com."}, "", "acme.com", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sansCoverDomain(c.sans, c.cn, c.domain); got != c.want {
				t.Fatalf("sansCoverDomain(%v,%q,%q)=%v want %v", c.sans, c.cn, c.domain, got, c.want)
			}
		})
	}
}

func TestCertToInfo(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cert := &x509.Certificate{
		Subject:   pkix.Name{CommonName: "acme.com"},
		Issuer:    pkix.Name{CommonName: "Let's Encrypt R3"},
		DNSNames:  []string{"acme.com", "*.acme.com"},
		NotBefore: now.Add(-24 * time.Hour),
		NotAfter:  now.Add(30 * 24 * time.Hour),
	}
	info := certToInfo(cert, "mail.acme.com", now)
	if info.SubjectCN != "acme.com" || info.Issuer != "Let's Encrypt R3" {
		t.Fatalf("subject/issuer: %+v", info)
	}
	if len(info.SANs) != 2 {
		t.Fatalf("SANs: %v", info.SANs)
	}
	if info.DaysUntilExpiry != 30 {
		t.Fatalf("days until expiry: want 30, got %d", info.DaysUntilExpiry)
	}
	if !info.CoversDomain {
		t.Fatal("mail.acme.com should be covered by *.acme.com")
	}
}
