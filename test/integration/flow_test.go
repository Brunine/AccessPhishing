// Package integration exercises the HTTP + repository stack end-to-end against
// a throwaway database created from the migrations.
//
// It is skipped unless TEST_DATABASE_URL points at a maintenance database
// (e.g. postgres://phishforge:devpass@localhost:5432/postgres?sslmode=disable);
// the test creates and drops its own phishforge_test_<ns> database.
package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"phishforge/internal/api"
	"phishforge/internal/apikey"
	"phishforge/internal/crypto"
	"phishforge/internal/events"
	"phishforge/internal/tenant"
)

// fakeEnqueuer records campaign-send enqueues instead of touching Redis.
type fakeEnqueuer struct {
	mu    sync.Mutex
	sends []uuid.UUID
}

func (f *fakeEnqueuer) EnqueueCampaignSend(_ context.Context, _ uuid.UUID, campaignID uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sends = append(f.sends, campaignID)
	return nil
}

func (f *fakeEnqueuer) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sends)
}

// newAPI builds an httptest server with a real cipher and a fake enqueuer.
func newAPI(t *testing.T, pool *pgxpool.Pool) (*httptest.Server, *fakeEnqueuer) {
	t.Helper()
	cip, err := crypto.New(strings.Repeat("ab", 32)) // 64 hex chars = 32 bytes
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	enq := &fakeEnqueuer{}
	srv := httptest.NewServer(api.NewServer(api.Deps{
		Pool: pool, BaseURL: "http://base.local", Cipher: cip, Enqueuer: enq,
	}).Router())
	return srv, enq
}

func TestCampaignEventFlow(t *testing.T) {
	pool := setupDB(t)
	ctx := context.Background()

	// 1. tenant + users + keys (bootstrap via services/SQL).
	tenants := tenant.NewRepository()
	tn, err := tenants.Create(ctx, pool, "Acme Pentest", "acme-"+short())
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	adminID := createUser(t, ctx, pool, tn.ID, "admin@acme.test", "admin")
	opID := createUser(t, ctx, pool, tn.ID, "op@acme.test", "operator")
	viewerID := createUser(t, ctx, pool, tn.ID, "viewer@acme.test", "viewer")

	keys := apikey.NewService(pool)
	adminTok, _, err := keys.Create(ctx, tn.ID, adminID, "admin-key")
	if err != nil {
		t.Fatalf("admin key: %v", err)
	}
	opTok, _, err := keys.Create(ctx, tn.ID, opID, "op-key")
	if err != nil {
		t.Fatalf("op key: %v", err)
	}
	viewerTok, _, err := keys.Create(ctx, tn.ID, viewerID, "viewer-key")
	if err != nil {
		t.Fatalf("viewer key: %v", err)
	}

	srv, _ := newAPI(t, pool)
	defer srv.Close()

	// --- auth + RBAC ---
	if code, body := do(t, srv.URL, http.MethodGet, "/api/v1/campaigns", "", nil); code != http.StatusUnauthorized {
		t.Fatalf("no key: want 401, got %d (%s)", code, body)
	}
	if code, body := do(t, srv.URL, http.MethodGet, "/api/v1/campaigns", "pf_bogus.deadbeef", nil); code != http.StatusUnauthorized {
		t.Fatalf("bad key: want 401, got %d (%s)", code, body)
	}
	if code, body := do(t, srv.URL, http.MethodPost, "/api/v1/campaigns", viewerTok, map[string]any{"name": "x"}); code != http.StatusForbidden {
		t.Fatalf("viewer create: want 403, got %d (%s)", code, body)
	}
	if code, body := do(t, srv.URL, http.MethodPost, "/api/v1/tenants", opTok, map[string]any{"name": "N", "slug": "s"}); code != http.StatusForbidden {
		t.Fatalf("operator->tenants: want 403, got %d (%s)", code, body)
	}
	if code, body := do(t, srv.URL, http.MethodPost, "/api/v1/tenants", adminTok, map[string]any{"name": "Beta", "slug": "beta-" + short()}); code != http.StatusCreated {
		t.Fatalf("admin create tenant: want 201, got %d (%s)", code, body)
	}

	// --- operator creates & transitions a campaign ---
	code, body := do(t, srv.URL, http.MethodPost, "/api/v1/campaigns", opTok, map[string]any{"name": "Q4 Sim"})
	if code != http.StatusCreated {
		t.Fatalf("create campaign: want 201, got %d (%s)", code, body)
	}
	var camp struct {
		ID       uuid.UUID `json:"id"`
		TenantID uuid.UUID `json:"tenant_id"`
		Status   string    `json:"status"`
	}
	mustJSON(t, body, &camp)
	if camp.Status != "draft" {
		t.Fatalf("new campaign status: want draft, got %q", camp.Status)
	}
	if camp.TenantID != tn.ID {
		t.Fatalf("campaign tenant scoping: want %s, got %s", tn.ID, camp.TenantID)
	}
	if code, body := do(t, srv.URL, http.MethodPatch, "/api/v1/campaigns/"+camp.ID.String(), opTok, map[string]any{"status": "running"}); code != http.StatusOK {
		t.Fatalf("patch status: want 200, got %d (%s)", code, body)
	}
	if code, _ := do(t, srv.URL, http.MethodPatch, "/api/v1/campaigns/"+camp.ID.String(), opTok, map[string]any{"status": "bogus"}); code != http.StatusBadRequest {
		t.Fatalf("patch invalid status: want 400, got %d", code)
	}

	// --- event state machine ---
	contactID := createContact(t, ctx, pool, tn.ID, "victim@target.test")
	er := events.NewRepository(pool)
	for _, et := range []events.Type{events.TypeSent, events.TypeDelivered, events.TypeOpened, events.TypeClicked} {
		if _, err := er.Append(ctx, events.NewEvent{TenantID: tn.ID, CampaignID: camp.ID, ContactID: contactID, Type: et}); err != nil {
			t.Fatalf("append %s: %v", et, err)
		}
	}
	if got := targetState(t, ctx, pool, camp.ID, contactID); got != "clicked" {
		t.Fatalf("projected state: want clicked, got %q", got)
	}
	// regression must be rejected
	if _, err := er.Append(ctx, events.NewEvent{TenantID: tn.ID, CampaignID: camp.ID, ContactID: contactID, Type: events.TypeSent}); !errors.Is(err, events.ErrInvalidTransition) {
		t.Fatalf("regression: want ErrInvalidTransition, got %v", err)
	}
	// forward skip allowed: clicked -> session_hijacked
	if _, err := er.Append(ctx, events.NewEvent{TenantID: tn.ID, CampaignID: camp.ID, ContactID: contactID, Type: events.TypeSessionHijacked}); err != nil {
		t.Fatalf("forward skip: %v", err)
	}
	if got := targetState(t, ctx, pool, camp.ID, contactID); got != "session_hijacked" {
		t.Fatalf("projected state after skip: want session_hijacked, got %q", got)
	}

	if n := count(t, ctx, pool, `SELECT count(*) FROM events WHERE campaign_id=$1`, camp.ID); n != 5 {
		t.Fatalf("event count: want 5, got %d", n)
	}
	if n := count(t, ctx, pool, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='campaign.create'`, tn.ID); n != 1 {
		t.Fatalf("campaign.create audit: want 1, got %d", n)
	}
	if n := count(t, ctx, pool, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='apikey.create'`, tn.ID); n != 3 {
		t.Fatalf("apikey.create audit: want 3, got %d", n)
	}
}

// --- DB harness -----------------------------------------------------------

func setupDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	admin := os.Getenv("TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}
	ctx := context.Background()

	adminPool, err := pgxpool.New(ctx, admin)
	if err != nil {
		t.Fatalf("connect maintenance db: %v", err)
	}
	defer adminPool.Close()

	dbName := fmt.Sprintf("phishforge_test_%d", time.Now().UnixNano())
	if _, err := adminPool.Exec(ctx, "CREATE DATABASE "+quoteIdent(dbName)); err != nil {
		t.Fatalf("create test db: %v", err)
	}

	u, err := url.Parse(admin)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	u.Path = "/" + dbName
	pool, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}
	applyMigrations(t, ctx, pool)

	t.Cleanup(func() {
		pool.Close()
		ap, err := pgxpool.New(context.Background(), admin)
		if err == nil {
			_, _ = ap.Exec(context.Background(), "DROP DATABASE IF EXISTS "+quoteIdent(dbName)+" WITH (FORCE)")
			ap.Close()
		}
	})
	return pool
}

func applyMigrations(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve caller for migrations path")
	}
	dir := filepath.Join(filepath.Dir(file), "..", "..", "migrations")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}
	var ups []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".up.sql") {
			ups = append(ups, e.Name())
		}
	}
	sort.Strings(ups)
	for _, name := range ups {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if _, err := pool.Exec(ctx, string(b)); err != nil {
			t.Fatalf("apply %s: %v", name, err)
		}
	}
}

// --- helpers --------------------------------------------------------------

func createUser(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID uuid.UUID, email, role string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := pool.QueryRow(ctx,
		`INSERT INTO users (tenant_id, email, role) VALUES ($1, $2, $3::user_role) RETURNING id`,
		tenantID, email, role).Scan(&id)
	if err != nil {
		t.Fatalf("create user %s: %v", email, err)
	}
	return id
}

// seedAuthorizedEngagement inserts an already-authorized engagement directly
// (bypassing the operator->admin workflow) so launch/send happy paths have a
// valid authorization container to bind. createdBy must be an existing user.
func seedAuthorizedEngagement(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID, createdBy uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := pool.QueryRow(ctx,
		`INSERT INTO engagements (tenant_id, name, client_name, status, authorized_at, authorized_by, created_by)
		 VALUES ($1, $2, $3, 'authorized', now(), $4, $4) RETURNING id`,
		tenantID, "Engagement "+short(), "Client Co", createdBy).Scan(&id)
	if err != nil {
		t.Fatalf("seed authorized engagement: %v", err)
	}
	return id
}

func createContact(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID uuid.UUID, email string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := pool.QueryRow(ctx,
		`INSERT INTO contacts (tenant_id, email) VALUES ($1, $2) RETURNING id`,
		tenantID, email).Scan(&id)
	if err != nil {
		t.Fatalf("create contact: %v", err)
	}
	return id
}

func targetState(t *testing.T, ctx context.Context, pool *pgxpool.Pool, campaignID, contactID uuid.UUID) string {
	t.Helper()
	var s string
	err := pool.QueryRow(ctx,
		`SELECT state::text FROM campaign_targets WHERE campaign_id=$1 AND contact_id=$2`,
		campaignID, contactID).Scan(&s)
	if err != nil {
		t.Fatalf("read target state: %v", err)
	}
	return s
}

func count(t *testing.T, ctx context.Context, pool *pgxpool.Pool, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

func do(t *testing.T, base, method, path, token string, body any) (int, string) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, base+path, rdr)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("X-API-Key", token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func mustJSON(t *testing.T, body string, dst any) {
	t.Helper()
	if err := json.Unmarshal([]byte(body), dst); err != nil {
		t.Fatalf("unmarshal %q: %v", body, err)
	}
}

func quoteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

func short() string { return strings.ReplaceAll(uuid.NewString(), "-", "")[:8] }
