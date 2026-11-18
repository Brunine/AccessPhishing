// Package integration runs against a real PostgreSQL when
// PF_TEST_DATABASE_URL is set (e.g. the dev compose DB).
package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	
	"phishforge/internal/engine"
	"phishforge/internal/engineconfig"
	"phishforge/internal/enginerepo"
)

// TestMain doubles as the child helper for engine-mode re-execution.
func TestMain(m *testing.M) {
	if os.Getenv("PF_ENGINE_HELPER") == "1" {
		if os.Getenv("PF_ENGINE_MODE") == "sleep" {
			time.Sleep(60 * time.Second)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("PF_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("PF_TEST_DATABASE_URL not set; skipping integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestEngineLifecycle(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	tenantID := uuid.New()

	// A tenant row is required by the FK.
	_, err := pool.Exec(ctx,
		`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`,
		tenantID, "it-engines-"+uuid.NewString()[:8], "it-eng-"+uuid.NewString()[:8])
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1`, tenantID)
	})

	repo := enginerepo.NewRepository()
	e, err := repo.Create(ctx, pool, tenantID, "it-engine", "kind: helper\n")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Start against this test binary in helper mode.
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	mgr := engine.New(exe, 0, 10*time.Millisecond)
	cfg := engineconfig.Config{
		Kind:          "helper",
		Env:           map[string]string{"PF_ENGINE_HELPER": "1", "PF_ENGINE_MODE": "sleep"},
		StopTimeoutMs: 3000,
	}
	if err := mgr.Start(e.ID.String(), cfg); err != nil {
		t.Fatalf("start: %v", err)
	}
	if !mgr.Running(e.ID.String()) {
		t.Fatal("engine not running after start")
	}
	if _, err := repo.SetStatus(ctx, pool, tenantID, e.ID, "running", nil, nil); err != nil {
		t.Fatalf("set status running: %v", err)
	}

	if err := mgr.Stop(e.ID.String()); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if mgr.Running(e.ID.String()) {
		t.Fatal("engine still running after stop")
	}

	if err := repo.Delete(ctx, pool, tenantID, e.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := repo.GetByID(ctx, pool, tenantID, e.ID); err != enginerepo.ErrNotFound {
		t.Fatalf("get after delete: %v", err)
	}
}