// Package group holds the contact-group model and its tenant-scoped repository.
package group

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"phishforge/internal/db"
)

// ErrNotFound is returned when a group does not exist within the tenant.
var ErrNotFound = errors.New("group: not found")

// Group is a named collection of contacts within a tenant.
type Group struct {
	ID        uuid.UUID `json:"id"`
	TenantID  uuid.UUID `json:"tenant_id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// Repository provides group persistence. Stateless; scoped by tenant_id.
type Repository struct{}

// NewRepository returns a group repository.
func NewRepository() *Repository { return &Repository{} }

const cols = `id, tenant_id, name, created_at`

func scanGroup(row pgx.Row) (Group, error) {
	var g Group
	if err := row.Scan(&g.ID, &g.TenantID, &g.Name, &g.CreatedAt); err != nil {
		return Group{}, err
	}
	return g, nil
}

// Create inserts a group and returns the stored row.
func (r *Repository) Create(ctx context.Context, q db.Querier, tenantID uuid.UUID, name string) (Group, error) {
	const sql = `INSERT INTO contact_groups (tenant_id, name) VALUES ($1, $2) RETURNING ` + cols
	g, err := scanGroup(q.QueryRow(ctx, sql, tenantID, name))
	if err != nil {
		return Group{}, fmt.Errorf("group: create: %w", err)
	}
	return g, nil
}

// GetByID loads a group within a tenant, or ErrNotFound.
func (r *Repository) GetByID(ctx context.Context, q db.Querier, tenantID, id uuid.UUID) (Group, error) {
	const sql = `SELECT ` + cols + ` FROM contact_groups WHERE tenant_id = $1 AND id = $2`
	g, err := scanGroup(q.QueryRow(ctx, sql, tenantID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Group{}, ErrNotFound
	}
	if err != nil {
		return Group{}, fmt.Errorf("group: get by id: %w", err)
	}
	return g, nil
}

// List returns a tenant's groups, newest first.
func (r *Repository) List(ctx context.Context, q db.Querier, tenantID uuid.UUID, limit, offset int) ([]Group, error) {
	const sql = `SELECT ` + cols + ` FROM contact_groups WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`
	rows, err := q.Query(ctx, sql, tenantID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("group: list: %w", err)
	}
	defer rows.Close()

	out := make([]Group, 0)
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			return nil, fmt.Errorf("group: scan: %w", err)
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("group: iterate: %w", err)
	}
	return out, nil
}

// Delete removes a group within a tenant (contacts are detached via
// ON DELETE SET NULL), or ErrNotFound.
func (r *Repository) Delete(ctx context.Context, q db.Querier, tenantID, id uuid.UUID) error {
	const sql = `DELETE FROM contact_groups WHERE tenant_id = $1 AND id = $2`
	tag, err := q.Exec(ctx, sql, tenantID, id)
	if err != nil {
		return fmt.Errorf("group: delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
