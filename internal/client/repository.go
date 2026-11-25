package client

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"phishforge/internal/db"
)

// Repository provides client persistence. It is stateless; each method takes a
// db.Querier (pool or transaction) and is scoped by tenant_id.
type Repository struct{}

// NewRepository returns a client repository.
func NewRepository() *Repository { return &Repository{} }

const cols = `id, tenant_id, name, contact_email, notes, created_at, updated_at`

func scan(row pgx.Row) (Client, error) {
	var c Client
	if err := row.Scan(&c.ID, &c.TenantID, &c.Name, &c.ContactEmail, &c.Notes, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return Client{}, err
	}
	return c, nil
}

// Create inserts a new client and returns the stored row. The caller is
// responsible for normalizing and validating in (see Input.Normalize/Validate).
func (r *Repository) Create(ctx context.Context, q db.Querier, tenantID uuid.UUID, in Input) (Client, error) {
	const sql = `INSERT INTO clients (tenant_id, name, contact_email, notes)
	             VALUES ($1, $2, $3, $4)
	             RETURNING ` + cols
	c, err := scan(q.QueryRow(ctx, sql, tenantID, in.Name, in.ContactEmail, in.Notes))
	if err != nil {
		return Client{}, fmt.Errorf("client: create: %w", err)
	}
	return c, nil
}

// GetByID loads a client by id within a tenant, or ErrNotFound.
func (r *Repository) GetByID(ctx context.Context, q db.Querier, tenantID, id uuid.UUID) (Client, error) {
	const sql = `SELECT ` + cols + ` FROM clients WHERE tenant_id = $1 AND id = $2`
	c, err := scan(q.QueryRow(ctx, sql, tenantID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Client{}, ErrNotFound
	}
	if err != nil {
		return Client{}, fmt.Errorf("client: get by id: %w", err)
	}
	return c, nil
}

// List returns a tenant's clients, newest first.
func (r *Repository) List(ctx context.Context, q db.Querier, tenantID uuid.UUID, limit, offset int) ([]Client, error) {
	const sql = `SELECT ` + cols + ` FROM clients WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`
	rows, err := q.Query(ctx, sql, tenantID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("client: list: %w", err)
	}
	defer rows.Close()
	out := make([]Client, 0)
	for rows.Next() {
		c, err := scan(rows)
		if err != nil {
			return nil, fmt.Errorf("client: scan: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("client: iterate: %w", err)
	}
	return out, nil
}

// Update edits the mutable fields of a client and returns the stored row, or
// ErrNotFound. The caller normalizes and validates in beforehand.
func (r *Repository) Update(ctx context.Context, q db.Querier, tenantID, id uuid.UUID, in Input) (Client, error) {
	const sql = `UPDATE clients
	             SET name = $3, contact_email = $4, notes = $5, updated_at = now()
	             WHERE tenant_id = $1 AND id = $2
	             RETURNING ` + cols
	c, err := scan(q.QueryRow(ctx, sql, tenantID, id, in.Name, in.ContactEmail, in.Notes))
	if errors.Is(err, pgx.ErrNoRows) {
		return Client{}, ErrNotFound
	}
	if err != nil {
		return Client{}, fmt.Errorf("client: update: %w", err)
	}
	return c, nil
}

// Delete removes a client within a tenant, or ErrNotFound. The caller must have
// already verified no engagement references it (see CountEngagements).
func (r *Repository) Delete(ctx context.Context, q db.Querier, tenantID, id uuid.UUID) error {
	tag, err := q.Exec(ctx, `DELETE FROM clients WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	if err != nil {
		return fmt.Errorf("client: delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// CountEngagements returns how many engagements in the tenant reference the
// client. Used to refuse deletion (409) while the client is still in use.
func (r *Repository) CountEngagements(ctx context.Context, q db.Querier, tenantID, id uuid.UUID) (int, error) {
	var n int
	const sql = `SELECT count(*) FROM engagements WHERE tenant_id = $1 AND client_id = $2`
	if err := q.QueryRow(ctx, sql, tenantID, id).Scan(&n); err != nil {
		return 0, fmt.Errorf("client: count engagements: %w", err)
	}
	return n, nil
}

// Exists reports whether a client with id exists within the tenant. Used to
// validate an engagement's optional client_id binding.
func (r *Repository) Exists(ctx context.Context, q db.Querier, tenantID, id uuid.UUID) (bool, error) {
	var exists bool
	const sql = `SELECT EXISTS (SELECT 1 FROM clients WHERE tenant_id = $1 AND id = $2)`
	if err := q.QueryRow(ctx, sql, tenantID, id).Scan(&exists); err != nil {
		return false, fmt.Errorf("client: exists: %w", err)
	}
	return exists, nil
}
