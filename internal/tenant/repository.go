// Package tenant holds the tenant model and its data-access repository.
package tenant

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is returned when a tenant does not exist.
var ErrNotFound = errors.New("tenant: not found")

// Tenant is a customer workspace. All other data is scoped to a tenant.
type Tenant struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Repository provides tenant persistence over a pgx pool.
type Repository struct {
	pool *pgxpool.Pool
}

// NewRepository returns a tenant repository backed by pool.
func NewRepository(pool *pgxpool.Pool) *Repository { return &Repository{pool: pool} }

const tenantColumns = `id, name, slug, status, created_at, updated_at`

func scanTenant(row pgx.Row) (Tenant, error) {
	var t Tenant
	if err := row.Scan(&t.ID, &t.Name, &t.Slug, &t.Status, &t.CreatedAt, &t.UpdatedAt); err != nil {
		return Tenant{}, err
	}
	return t, nil
}

// Create inserts a new tenant and returns the stored row.
func (r *Repository) Create(ctx context.Context, name, slug string) (Tenant, error) {
	const q = `INSERT INTO tenants (name, slug) VALUES ($1, $2) RETURNING ` + tenantColumns
	t, err := scanTenant(r.pool.QueryRow(ctx, q, name, slug))
	if err != nil {
		return Tenant{}, fmt.Errorf("tenant: create: %w", err)
	}
	return t, nil
}

// GetByID loads a tenant by id, or ErrNotFound.
func (r *Repository) GetByID(ctx context.Context, id uuid.UUID) (Tenant, error) {
	const q = `SELECT ` + tenantColumns + ` FROM tenants WHERE id = $1`
	t, err := scanTenant(r.pool.QueryRow(ctx, q, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Tenant{}, ErrNotFound
	}
	if err != nil {
		return Tenant{}, fmt.Errorf("tenant: get by id: %w", err)
	}
	return t, nil
}

// List returns tenants ordered by creation time, newest first.
func (r *Repository) List(ctx context.Context, limit, offset int) ([]Tenant, error) {
	const q = `SELECT ` + tenantColumns + ` FROM tenants ORDER BY created_at DESC LIMIT $1 OFFSET $2`
	rows, err := r.pool.Query(ctx, q, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("tenant: list: %w", err)
	}
	defer rows.Close()

	var out []Tenant
	for rows.Next() {
		t, err := scanTenant(rows)
		if err != nil {
			return nil, fmt.Errorf("tenant: scan: %w", err)
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("tenant: iterate: %w", err)
	}
	return out, nil
}
