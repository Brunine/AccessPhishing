package integration

import (
	"context"
	"net"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"phishforge/internal/api"
	"phishforge/internal/crypto"
)

// seedDomainStatus forces a domain's stored status directly, standing in for a
// lifecycle step whose live dependency (a real published TXT record) the
// black-box harness cannot satisfy with the system resolver.
func seedDomainStatus(t *testing.T, ctx context.Context, pool *pgxpool.Pool, domainID uuid.UUID, status string) {
	t.Helper()
	if _, err := pool.Exec(ctx,
		`UPDATE domains SET status = $2::domain_status WHERE id = $1`, domainID, status); err != nil {
		t.Fatalf("seed domain status %q: %v", status, err)
	}
}

// stubResolver is a programmable dnsdiag.Resolver for injecting TXT answers.
type stubResolver struct {
	mu  sync.Mutex
	txt map[string][]string
}

func newStubResolver() *stubResolver { return &stubResolver{txt: map[string][]string{}} }

func (s *stubResolver) set(name string, recs []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.txt[name] = recs
}

func (s *stubResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok := s.txt[strings.TrimSuffix(name, ".")]; ok {
		return v, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (s *stubResolver) LookupNS(_ context.Context, name string) ([]*net.NS, error) {
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

// newAPIWithResolver builds an httptest server with an injected DNS resolver.
func newAPIWithResolver(t *testing.T, pool *pgxpool.Pool, res *stubResolver) *httptest.Server {
	t.Helper()
	cip, err := crypto.New(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	return httptest.NewServer(api.NewServer(api.Deps{
		Pool: pool, BaseURL: "http://base.local", Cipher: cip, Enqueuer: &fakeEnqueuer{}, Resolver: res,
	}).Router())
}
