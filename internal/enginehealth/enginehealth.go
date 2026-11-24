// Package enginehealth persists and polls engine runtime health snapshots
// (migration 0018). The snapshot is the durable surface shared by the API
// (which records start/stop transitions from its in-process supervisor) and
// the worker (which records periodic poll ticks); see the migration header.
package enginehealth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"phishforge/internal/db"
)

// ErrNotFound is returned when no snapshot exists for an engine yet.
var ErrNotFound = errors.New("enginehealth: not found")

// Snapshot is one engine_health row.
type Snapshot struct {
	EngineID         uuid.UUID  `json:"engine_id"`
	TenantID         uuid.UUID  `json:"tenant_id"`
	AdapterKind      string     `json:"adapter_kind"`
	Status           string     `json:"status"`
	Detail           string     `json:"detail"`
	LastTransitionAt *time.Time `json:"last_transition_at,omitempty"`
	LastPollAt       *time.Time `json:"last_poll_at,omitempty"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// Repository provides snapshot persistence. Stateless; tenant-scoped reads.
type Repository struct{}

// NewRepository returns an engine health repository.
func NewRepository() *Repository { return &Repository{} }

const cols = `engine_id, tenant_id, adapter_kind, status, detail, last_transition_at, last_poll_at, updated_at`

func scan(row pgx.Row) (Snapshot, error) {
	var s Snapshot
	if err := row.Scan(&s.EngineID, &s.TenantID, &s.AdapterKind, &s.Status,
		&s.Detail, &s.LastTransitionAt, &s.LastPollAt, &s.UpdatedAt); err != nil {
		return Snapshot{}, err
	}
	return s, nil
}

// Get loads a tenant-scoped snapshot, or ErrNotFound.
func (r *Repository) Get(ctx context.Context, q db.Querier, tenantID, engineID uuid.UUID) (Snapshot, error) {
	const sql = `SELECT ` + cols + ` FROM engine_health WHERE tenant_id = $1 AND engine_id = $2`
	s, err := scan(q.QueryRow(ctx, sql, tenantID, engineID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Snapshot{}, ErrNotFound
	}
	if err != nil {
		return Snapshot{}, fmt.Errorf("enginehealth: get: %w", err)
	}
	return s, nil
}

// RecordTransition upserts the snapshot for a lifecycle transition (start/stop),
// setting adapter_kind/status/detail and last_transition_at. last_poll_at is
// preserved. Called from the API.
func (r *Repository) RecordTransition(ctx context.Context, q db.Querier, tenantID, engineID uuid.UUID,
	adapterKind, status, detail string, at time.Time) error {
	const sql = `
INSERT INTO engine_health (engine_id, tenant_id, adapter_kind, status, detail, last_transition_at)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (engine_id) DO UPDATE SET
  adapter_kind       = EXCLUDED.adapter_kind,
  status             = EXCLUDED.status,
  detail             = EXCLUDED.detail,
  last_transition_at = EXCLUDED.last_transition_at`
	_, err := q.Exec(ctx, sql, engineID, tenantID, adapterKind, status, detail, at)
	if err != nil {
		return fmt.Errorf("enginehealth: record transition: %w", err)
	}
	return nil
}

// RecordPoll upserts the snapshot for a poller tick, setting status/detail and
// last_poll_at. adapter_kind and last_transition_at are preserved on an
// existing row (a fresh row defaults adapter_kind to 'builtin'). Called from
// the worker, which has no access to the API's in-process supervisor.
func (r *Repository) RecordPoll(ctx context.Context, q db.Querier, tenantID, engineID uuid.UUID,
	status, detail string, at time.Time) error {
	const sql = `
INSERT INTO engine_health (engine_id, tenant_id, status, detail, last_poll_at)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (engine_id) DO UPDATE SET
  status       = EXCLUDED.status,
  detail       = EXCLUDED.detail,
  last_poll_at = EXCLUDED.last_poll_at`
	_, err := q.Exec(ctx, sql, engineID, tenantID, status, detail, at)
	if err != nil {
		return fmt.Errorf("enginehealth: record poll: %w", err)
	}
	return nil
}

// Poller records a health heartbeat for every engine on a fixed cadence. It
// runs in the worker process and derives status from the engines table (it
// cannot see the API's in-process supervisor), so its value is the durable
// last_poll_at heartbeat plus a best-effort status when no live adapter view
// is available (e.g. after an API restart).
type Poller struct {
	pool *pgxpool.Pool
	repo *Repository
}

// NewPoller builds a poller over a connection pool.
func NewPoller(pool *pgxpool.Pool) *Poller {
	return &Poller{pool: pool, repo: NewRepository()}
}

// PollOnce records a poll tick for every engine row and returns the count
// polled. It is safe to call on an empty inventory (returns 0, nil).
func (p *Poller) PollOnce(ctx context.Context) (int, error) {
	rows, err := p.pool.Query(ctx, `SELECT id, tenant_id, status FROM engines`)
	if err != nil {
		return 0, fmt.Errorf("enginehealth: poll list: %w", err)
	}
	type eng struct {
		id       uuid.UUID
		tenantID uuid.UUID
		status   string
	}
	var engines []eng
	for rows.Next() {
		var e eng
		if err := rows.Scan(&e.id, &e.tenantID, &e.status); err != nil {
			rows.Close()
			return 0, fmt.Errorf("enginehealth: poll scan: %w", err)
		}
		engines = append(engines, e)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("enginehealth: poll iterate: %w", err)
	}

	now := time.Now().UTC()
	n := 0
	for _, e := range engines {
		if err := p.repo.RecordPoll(ctx, p.pool, e.tenantID, e.id,
			StatusForRow(e.status), "poller tick", now); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// StatusForRow maps a DB engine_status enum value onto the adapter-level health
// vocabulary used in snapshots. Exported so the API maps consistently.
func StatusForRow(engineStatus string) string {
	switch engineStatus {
	case "running":
		return "running"
	case "starting":
		return "starting"
	case "stopped":
		return "stopped"
	case "error", "stopped_failed":
		return "failed"
	default:
		return "unknown"
	}
}
