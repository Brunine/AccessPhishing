package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"phishforge/internal/api"
	"phishforge/internal/apikey"
	"phishforge/internal/crypto"
	"phishforge/internal/dnsdiag"
	"phishforge/internal/domain"
	"phishforge/internal/tenant"
)

// --- helpers --------------------------------------------------------------

// insertDomain creates a domain row directly in the given status/expiry.
func insertDomain(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID, createdBy uuid.UUID, name, status string, expiresAt *time.Time) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := pool.QueryRow(ctx,
		`INSERT INTO domains (tenant_id, name, status, expires_at, created_by)
		 VALUES ($1, $2, $3::domain_status, $4, $5) RETURNING id`,
		tenantID, name, status, expiresAt, createdBy).Scan(&id)
	if err != nil {
		t.Fatalf("insert domain %q: %v", name, err)
	}
	return id
}

func insertAssignment(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID, domainID, engagementID uuid.UUID, status string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := pool.QueryRow(ctx,
		`INSERT INTO domain_assignments (tenant_id, domain_id, engagement_id, status)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		tenantID, domainID, engagementID, status).Scan(&id)
	if err != nil {
		t.Fatalf("insert assignment: %v", err)
	}
	return id
}

func domainStatus(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id uuid.UUID) string {
	t.Helper()
	var s string
	if err := pool.QueryRow(ctx, `SELECT status::text FROM domains WHERE id = $1`, id).Scan(&s); err != nil {
		t.Fatalf("read domain status: %v", err)
	}
	return s
}

func domainTLSStatus(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id uuid.UUID) *string {
	t.Helper()
	var s *string
	if err := pool.QueryRow(ctx, `SELECT tls_status FROM domains WHERE id = $1`, id).Scan(&s); err != nil {
		t.Fatalf("read tls_status: %v", err)
	}
	return s
}

// newAPIWithTLS builds an httptest server with an injected TLS inspector and a
// chosen expiring threshold, so the diagnostics TLS derivation is deterministic.
func newAPIWithTLS(t *testing.T, pool *pgxpool.Pool,
	inspector func(ctx context.Context, host string, port int, timeout time.Duration) (dnsdiag.TLSInfo, error),
	threshold time.Duration) *httptest.Server {
	t.Helper()
	cip, err := crypto.New(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	return httptest.NewServer(api.NewServer(api.Deps{
		Pool: pool, BaseURL: "http://base.local", Cipher: cip, Enqueuer: &fakeEnqueuer{},
		TLSInspector: inspector, TLSExpiringThreshold: threshold,
	}).Router())
}

// --- Task 1: expiry roll --------------------------------------------------

// TestDomainExpiryRoll verifies the roller transitions lapsed verified/active/
// suspended domains to expired (tenant-wide), leaves other rows untouched, and
// writes a from/to audit entry per transitioned row.
func TestDomainExpiryRoll(t *testing.T) {
	pool := setupDB(t)
	ctx := context.Background()

	tenants := tenant.NewRepository()
	tn, err := tenants.Create(ctx, pool, "Roll Co", "roll-"+short())
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	uid := createUser(t, ctx, pool, tn.ID, "op@roll.test", "operator")

	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(720 * time.Hour)

	// Should roll (lapsed + rollable status):
	dVerified := insertDomain(t, ctx, pool, tn.ID, uid, "v-"+short()+".com", "verified", &past)
	dActive := insertDomain(t, ctx, pool, tn.ID, uid, "a-"+short()+".com", "active", &past)
	dSuspended := insertDomain(t, ctx, pool, tn.ID, uid, "s-"+short()+".com", "suspended", &past)
	// Should NOT roll:
	dPendingPast := insertDomain(t, ctx, pool, tn.ID, uid, "p-"+short()+".com", "pending_verification", &past)
	dActiveFuture := insertDomain(t, ctx, pool, tn.ID, uid, "af-"+short()+".com", "active", &future)
	dActiveNoExpiry := insertDomain(t, ctx, pool, tn.ID, uid, "an-"+short()+".com", "active", nil)
	dRetiredPast := insertDomain(t, ctx, pool, tn.ID, uid, "r-"+short()+".com", "retired", &past)

	n, err := domain.NewRoller(pool).RollOnce(ctx)
	if err != nil {
		t.Fatalf("RollOnce: %v", err)
	}
	if n != 3 {
		t.Fatalf("rolled count: want 3, got %d", n)
	}

	for _, id := range []uuid.UUID{dVerified, dActive, dSuspended} {
		if s := domainStatus(t, ctx, pool, id); s != "expired" {
			t.Fatalf("domain %s: want expired, got %q", id, s)
		}
	}
	// Untouched rows keep their status.
	for id, want := range map[uuid.UUID]string{
		dPendingPast:    "pending_verification",
		dActiveFuture:   "active",
		dActiveNoExpiry: "active",
		dRetiredPast:    "retired",
	} {
		if s := domainStatus(t, ctx, pool, id); s != want {
			t.Fatalf("domain %s: want %q (unchanged), got %q", id, want, s)
		}
	}

	// One audit per transitioned row, with from/to metadata.
	if c := count(t, ctx, pool, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='domain.expire'`, tn.ID); c != 3 {
		t.Fatalf("domain.expire audit count: want 3, got %d", c)
	}
	var from, to string
	if err := pool.QueryRow(ctx,
		`SELECT metadata->>'from', metadata->>'to' FROM audit_log WHERE action='domain.expire' AND target_id=$1`,
		dSuspended.String()).Scan(&from, &to); err != nil {
		t.Fatalf("read expire audit metadata: %v", err)
	}
	if from != "suspended" || to != "expired" {
		t.Fatalf("expire audit metadata: want suspended->expired, got %s->%s", from, to)
	}

	// Idempotent: a second pass transitions nothing.
	if n2, err := domain.NewRoller(pool).RollOnce(ctx); err != nil || n2 != 0 {
		t.Fatalf("second RollOnce: want (0,nil), got (%d,%v)", n2, err)
	}
}

// --- Task 2: TLS derivation -----------------------------------------------

// TestDomainTLSDerivation verifies diagnostics derives + persists a tls_status
// and audits only when it changes.
func TestDomainTLSDerivation(t *testing.T) {
	pool := setupDB(t)
	ctx := context.Background()

	tenants := tenant.NewRepository()
	tn, _ := tenants.Create(ctx, pool, "TLS Co", "tls-"+short())
	uid := createUser(t, ctx, pool, tn.ID, "op@tls.test", "operator")
	keys := apikey.NewService(pool)
	tok, _, _ := keys.Create(ctx, tn.ID, uid, "op")

	// A cert that expires in 10 days; with a 30-day threshold this derives
	// "expiring".
	notAfter := time.Now().Add(10 * 24 * time.Hour)
	var inspectCalls int
	var lastHost string
	inspector := func(_ context.Context, host string, _ int, _ time.Duration) (dnsdiag.TLSInfo, error) {
		inspectCalls++
		lastHost = host
		return dnsdiag.TLSInfo{NotAfter: notAfter, CoversDomain: true}, nil
	}
	srv := newAPIWithTLS(t, pool, inspector, 30*24*time.Hour)
	defer srv.Close()

	dID := insertDomain(t, ctx, pool, tn.ID, uid, "diag-"+short()+".com", "verified", nil)
	dName := func() string {
		var n string
		_ = pool.QueryRow(ctx, `SELECT name FROM domains WHERE id=$1`, dID).Scan(&n)
		return n
	}()

	// First diagnostics: NULL -> expiring, persisted + audited.
	code, body := do(t, srv.URL, http.MethodGet, "/api/v1/domains/"+dID.String()+"/diagnostics", tok, nil)
	if code != http.StatusOK {
		t.Fatalf("diagnostics: want 200, got %d (%s)", code, body)
	}
	var rep struct {
		TLSStatus string `json:"tls_status"`
	}
	mustJSON(t, body, &rep)
	if rep.TLSStatus != "expiring" {
		t.Fatalf("response tls_status: want expiring, got %q", rep.TLSStatus)
	}
	if got := domainTLSStatus(t, ctx, pool, dID); got == nil || *got != "expiring" {
		t.Fatalf("persisted tls_status: want expiring, got %v", got)
	}
	if lastHost != dName {
		t.Fatalf("inspector host: want %q (stored name only), got %q", dName, lastHost)
	}
	if c := count(t, ctx, pool, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='domain.tls_status'`, tn.ID); c != 1 {
		t.Fatalf("tls_status audit after first call: want 1, got %d", c)
	}

	// Second diagnostics: unchanged (expiring -> expiring) => no new audit.
	if code, _ := do(t, srv.URL, http.MethodGet, "/api/v1/domains/"+dID.String()+"/diagnostics", tok, nil); code != http.StatusOK {
		t.Fatalf("second diagnostics: want 200, got %d", code)
	}
	if c := count(t, ctx, pool, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='domain.tls_status'`, tn.ID); c != 1 {
		t.Fatalf("tls_status audit after unchanged call: want 1 (no new), got %d", c)
	}
	if inspectCalls != 2 {
		t.Fatalf("inspector calls: want 2, got %d", inspectCalls)
	}
}

// --- Task 3: engagement domain listing ------------------------------------

// TestEngagementDomainListing verifies the listing excludes revoked assignments
// and 404s on a cross-tenant engagement id.
func TestEngagementDomainListing(t *testing.T) {
	pool := setupDB(t)
	ctx := context.Background()

	tenants := tenant.NewRepository()
	keys := apikey.NewService(pool)

	tnA, _ := tenants.Create(ctx, pool, "A Co", "a-"+short())
	aUID := createUser(t, ctx, pool, tnA.ID, "op@a.test", "operator")
	aTok, _, _ := keys.Create(ctx, tnA.ID, aUID, "a-op")

	tnB, _ := tenants.Create(ctx, pool, "B Co", "b-"+short())
	bUID := createUser(t, ctx, pool, tnB.ID, "op@b.test", "operator")
	bTok, _, _ := keys.Create(ctx, tnB.ID, bUID, "b-op")

	srv, _ := newAPI(t, pool)
	defer srv.Close()

	engA := seedAuthorizedEngagement(t, ctx, pool, tnA.ID, aUID)

	// Three domains assigned to engA: authorized, pending, revoked.
	dAuth := insertDomain(t, ctx, pool, tnA.ID, aUID, "auth-"+short()+".com", "active", nil)
	dPend := insertDomain(t, ctx, pool, tnA.ID, aUID, "pend-"+short()+".com", "verified", nil)
	dRevoked := insertDomain(t, ctx, pool, tnA.ID, aUID, "rev-"+short()+".com", "verified", nil)
	insertAssignment(t, ctx, pool, tnA.ID, dAuth, engA, "authorized")
	insertAssignment(t, ctx, pool, tnA.ID, dPend, engA, "pending")
	insertAssignment(t, ctx, pool, tnA.ID, dRevoked, engA, "revoked")

	code, body := do(t, srv.URL, http.MethodGet, "/api/v1/engagements/"+engA.String()+"/domains", aTok, nil)
	if code != http.StatusOK {
		t.Fatalf("list engagement domains: want 200, got %d (%s)", code, body)
	}
	var out struct {
		Items []struct {
			DomainID         uuid.UUID `json:"domain_id"`
			AssignmentStatus string    `json:"assignment_status"`
		} `json:"items"`
	}
	mustJSON(t, body, &out)
	if len(out.Items) != 2 {
		t.Fatalf("want 2 non-revoked items, got %d", len(out.Items))
	}
	seen := map[uuid.UUID]string{}
	for _, it := range out.Items {
		seen[it.DomainID] = it.AssignmentStatus
	}
	if seen[dAuth] != "authorized" || seen[dPend] != "pending" {
		t.Fatalf("unexpected items: %+v", seen)
	}
	if _, ok := seen[dRevoked]; ok {
		t.Fatalf("revoked assignment should be excluded")
	}

	// Cross-tenant: B cannot see A's engagement -> 404.
	if code, _ := do(t, srv.URL, http.MethodGet, "/api/v1/engagements/"+engA.String()+"/domains", bTok, nil); code != http.StatusNotFound {
		t.Fatalf("cross-tenant list: want 404, got %d", code)
	}
	// Unknown engagement id -> 404.
	if code, _ := do(t, srv.URL, http.MethodGet, "/api/v1/engagements/"+uuid.New().String()+"/domains", aTok, nil); code != http.StatusNotFound {
		t.Fatalf("unknown engagement list: want 404, got %d", code)
	}
}
