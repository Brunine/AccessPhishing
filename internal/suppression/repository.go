// Package suppression holds the per-tenant do-not-contact list.
package suppression

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"phishforge/internal/db"
)

// ErrNotFound is returned when an entry does not exist within the tenant.
var ErrNotFound = errors.New("suppression: not found")

// Entry is a suppressed email within a tenant.
type Entry struct {
	ID        uuid.UUID `json:"id"`
	TenantID  uuid.UUID `json:"tenant_id"`
	Email     string    `json:"email"`
	Reason    *string   `json:"reason,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// Repository provides suppression-list persistence. Stateless; scoped by tenant.
type Repository struct{}

// NewRepository returns a suppression repository.
func NewRepository() *Repository { return &Repository{} }

const cols = `id, tenant_id, email, reason, created_at`

func scanEntry(row pgx.Row) (Entry, error) {
	var e Entry
	if err := row.Scan(&e.ID, &e.TenantID, &e.Email, &e.Reason, &e.CreatedAt); err != nil {
		return Entry{}, err
	}
	return e, nil
}

// Add inserts or updates a suppression entry (idempotent on tenant+email).
func (r *Repository) Add(ctx context.Context, q db.Querier, tenantID uuid.UUID, email, reason string) (Entry, error) {
	var reasonArg any
	if reason != "" {
		reasonArg = reason
	}
	const sql = `INSERT INTO suppression_lists (tenant_id, email, reason) VALUES ($1, $2, $3)
	             ON CONFLICT (tenant_id, email) DO UPDATE SET reason = EXCLUDED.reason
	             RETURNING ` + cols
	e, err := scanEntry(q.QueryRow(ctx, sql, tenantID, email, reasonArg))
	if err != nil {
		return Entry{}, fmt.Errorf("suppression: add: %w", err)
	}
	return e, nil
}

// Remove deletes a suppression entry by email within a tenant, or ErrNotFound.
func (r *Repository) Remove(ctx context.Context, q db.Querier, tenantID uuid.UUID, email string) error {
	const sql = `DELETE FROM suppression_lists WHERE tenant_id = $1 AND email = $2`
	tag, err := q.Exec(ctx, sql, tenantID, email)
	if err != nil {
		return fmt.Errorf("suppression: remove: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// List returns a tenant's suppression entries, newest first.
func (r *Repository) List(ctx context.Context, q db.Querier, tenantID uuid.UUID, limit, offset int) ([]Entry, error) {
	const sql = `SELECT ` + cols + ` FROM suppression_lists WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`
	rows, err := q.Query(ctx, sql, tenantID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("suppression: list: %w", err)
	}
	defer rows.Close()

	out := make([]Entry, 0)
	for rows.Next() {
		e, err := scanEntry(rows)
		if err != nil {
			return nil, fmt.Errorf("suppression: scan: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("suppression: iterate: %w", err)
	}
	return out, nil
}

// IsSuppressed reports whether email is suppressed for the tenant (case-insensitive).
func (r *Repository) IsSuppressed(ctx context.Context, q db.Querier, tenantID uuid.UUID, email string) (bool, error) {
	var ok bool
	const sql = `SELECT EXISTS (SELECT 1 FROM suppression_lists WHERE tenant_id = $1 AND lower(email) = lower($2))`
	if err := q.QueryRow(ctx, sql, tenantID, email).Scan(&ok); err != nil {
		return false, fmt.Errorf("suppression: check: %w", err)
	}
	return ok, nil
}
