// Package enginerepo persists managed engine records (M5 part 1): a
// validated YAML config plus lifecycle status per tenant.
package enginerepo

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"phishforge/internal/db"
)

// ErrNotFound is returned when an engine does not exist within the tenant.
var ErrNotFound = errors.New("enginerepo: not found")

// Engine is a registered engine row.
type Engine struct {
	ID         uuid.UUID  `json:"id"`
	TenantID   uuid.UUID  `json:"tenant_id"`
	Name       string     `json:"name"`
	Config     string     `json:"config"`
	Status     string     `json:"status"`
	LastError  *string    `json:"last_error,omitempty"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

// ValidStatus reports whether s is a valid engine_status enum value.
func ValidStatus(s string) bool {
	switch s {
	case "stopped", "starting", "running", "error", "stopped_failed":
		return true
	default:
		return false
	}
}

// Repository provides engine persistence. Stateless; tenant-scoped.
type Repository struct{}

// NewRepository returns an engine repository.
func NewRepository() *Repository { return &Repository{} }

const cols = `id, tenant_id, name, config, status, last_error, started_at, created_at, updated_at`

func scanEngine(row pgx.Row) (Engine, error) {
	var e Engine
	if err := row.Scan(&e.ID, &e.TenantID, &e.Name, &e.Config, &e.Status,
		&e.LastError, &e.StartedAt, &e.CreatedAt, &e.UpdatedAt); err != nil {
		return Engine{}, err
	}
	return e, nil
}

// Create inserts a new engine (status 'stopped') and returns the row.
func (r *Repository) Create(ctx context.Context, q db.Querier, tenantID uuid.UUID, name, config string) (Engine, error) {
	const sql = `
INSERT INTO engines (tenant_id, name, config)
VALUES ($1, $2, $3)
RETURNING ` + cols
	e, err := scanEngine(q.QueryRow(ctx, sql, tenantID, name, config))
	if err != nil {
		return Engine{}, fmt.Errorf("enginerepo: create: %w", err)
	}
	return e, nil
}

// GetByID loads an engine within a tenant, or ErrNotFound.
func (r *Repository) GetByID(ctx context.Context, q db.Querier, tenantID, id uuid.UUID) (Engine, error) {
	const sql = `SELECT ` + cols + ` FROM engines WHERE tenant_id = $1 AND id = $2`
	e, err := scanEngine(q.QueryRow(ctx, sql, tenantID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Engine{}, ErrNotFound
	}
	if err != nil {
		return Engine{}, fmt.Errorf("enginerepo: get by id: %w", err)
	}
	return e, nil
}

// List returns a tenant's engines, newest first.
func (r *Repository) List(ctx context.Context, q db.Querier, tenantID uuid.UUID, limit, offset int) ([]Engine, error) {
	const sql = `SELECT ` + cols + ` FROM engines WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`
	rows, err := q.Query(ctx, sql, tenantID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("enginerepo: list: %w", err)
	}
	defer rows.Close()

	out := make([]Engine, 0)
	for rows.Next() {
		e, err := scanEngine(rows)
		if err != nil {
			return nil, fmt.Errorf("enginerepo: scan: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("enginerepo: iterate: %w", err)
	}
	return out, nil
}

// SetStatus updates lifecycle status and optional error/started_at, or
// ErrNotFound. Pass nil for fields that should not change.
func (r *Repository) SetStatus(ctx context.Context, q db.Querier, tenantID, id uuid.UUID,
	status string, lastErr *string, startedAt *time.Time) (Engine, error) {
	const sql = `
UPDATE engines SET
  status = $3::engine_status,
  last_error = COALESCE($4, last_error),
  started_at = COALESCE($5, started_at),
  updated_at = now()
WHERE tenant_id = $1 AND id = $2
RETURNING ` + cols
	e, err := scanEngine(q.QueryRow(ctx, sql, tenantID, id, status, lastErr, startedAt))
	if errors.Is(err, pgx.ErrNoRows) {
		return Engine{}, ErrNotFound
	}
	if err != nil {
		return Engine{}, fmt.Errorf("enginerepo: set status: %w", err)
	}
	return e, nil
}

// ClearError resets last_error to NULL (used on successful start).
func (r *Repository) ClearError(ctx context.Context, q db.Querier, tenantID, id uuid.UUID) error {
	const sql = `UPDATE engines SET last_error = NULL, updated_at = now()
	             WHERE tenant_id = $1 AND id = $2`
	ct, err := q.Exec(ctx, sql, tenantID, id)
	if err != nil {
		return fmt.Errorf("enginerepo: clear error: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Delete removes an engine row within a tenant, or ErrNotFound.
func (r *Repository) Delete(ctx context.Context, q db.Querier, tenantID, id uuid.UUID) error {
	const sql = `DELETE FROM engines WHERE tenant_id = $1 AND id = $2`
	ct, err := q.Exec(ctx, sql, tenantID, id)
	if err != nil {
		return fmt.Errorf("enginerepo: delete: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetCallbackHash stores the SHA-256 hex hash of the engine's per-run
// callback token (minted at start, cleared at stop).
func (r *Repository) SetCallbackHash(ctx context.Context, q db.Querier, tenantID, id uuid.UUID, hash string) error {
	const sql = `UPDATE engines SET callback_token_hash = $3, updated_at = now()
	             WHERE tenant_id = $1 AND id = $2`
	ct, err := q.Exec(ctx, sql, tenantID, id, hash)
	if err != nil {
		return fmt.Errorf("enginerepo: set callback hash: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ClearCallbackHash removes the callback token hash (used on stop).
func (r *Repository) ClearCallbackHash(ctx context.Context, q db.Querier, tenantID, id uuid.UUID) error {
	const sql = `UPDATE engines SET callback_token_hash = NULL, updated_at = now()
	             WHERE tenant_id = $1 AND id = $2`
	ct, err := q.Exec(ctx, sql, tenantID, id)
	if err != nil {
		return fmt.Errorf("enginerepo: clear callback hash: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// CallbackHashByID returns the stored callback token hash for an engine.
// Deliberately NOT tenant-scoped: the bearer token itself is the
// authenticator for the public ingest endpoint; the engine id in the URL is
// only a lookup key. Returns ErrNotFound when no engine exists or no token
// is configured (engine not running).
func (r *Repository) CallbackHashByID(ctx context.Context, q db.Querier, id uuid.UUID) (string, error) {
	var hash *string
	err := q.QueryRow(ctx,
		`SELECT callback_token_hash FROM engines WHERE id = $1`, id).Scan(&hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("enginerepo: callback hash: %w", err)
	}
	if hash == nil || *hash == "" {
		return "", ErrNotFound
	}
	return *hash, nil
}