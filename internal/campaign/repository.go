// Package campaign holds the campaign model and its tenant-scoped repository.
package campaign

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is returned when a campaign does not exist within the tenant.
var ErrNotFound = errors.New("campaign: not found")

// Campaign is a phishing-simulation campaign owned by a single tenant.
type Campaign struct {
	ID        uuid.UUID `json:"id"`
	TenantID  uuid.UUID `json:"tenant_id"`
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	CreatedBy uuid.UUID `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Repository provides campaign persistence over a pgx pool. Every query is
// scoped by tenant_id to enforce tenant isolation at the data layer.
type Repository struct {
	pool *pgxpool.Pool
}

// NewRepository returns a campaign repository backed by pool.
func NewRepository(pool *pgxpool.Pool) *Repository { return &Repository{pool: pool} }

const campaignColumns = `id, tenant_id, name, status, created_by, created_at, updated_at`

func scanCampaign(row pgx.Row) (Campaign, error) {
	var c Campaign
	if err := row.Scan(&c.ID, &c.TenantID, &c.Name, &c.Status, &c.CreatedBy, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return Campaign{}, err
	}
	return c, nil
}

// Create inserts a new campaign for a tenant and returns the stored row.
func (r *Repository) Create(ctx context.Context, tenantID, createdBy uuid.UUID, name string) (Campaign, error) {
	const q = `INSERT INTO campaigns (tenant_id, name, created_by) VALUES ($1, $2, $3) RETURNING ` + campaignColumns
	c, err := scanCampaign(r.pool.QueryRow(ctx, q, tenantID, name, createdBy))
	if err != nil {
		return Campaign{}, fmt.Errorf("campaign: create: %w", err)
	}
	return c, nil
}

// GetByID loads a campaign by id within a tenant, or ErrNotFound.
func (r *Repository) GetByID(ctx context.Context, tenantID, id uuid.UUID) (Campaign, error) {
	const q = `SELECT ` + campaignColumns + ` FROM campaigns WHERE tenant_id = $1 AND id = $2`
	c, err := scanCampaign(r.pool.QueryRow(ctx, q, tenantID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Campaign{}, ErrNotFound
	}
	if err != nil {
		return Campaign{}, fmt.Errorf("campaign: get by id: %w", err)
	}
	return c, nil
}

// ListByTenant returns a tenant's campaigns, newest first.
func (r *Repository) ListByTenant(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]Campaign, error) {
	const q = `SELECT ` + campaignColumns + ` FROM campaigns WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`
	rows, err := r.pool.Query(ctx, q, tenantID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("campaign: list: %w", err)
	}
	defer rows.Close()

	var out []Campaign
	for rows.Next() {
		c, err := scanCampaign(rows)
		if err != nil {
			return nil, fmt.Errorf("campaign: scan: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("campaign: iterate: %w", err)
	}
	return out, nil
}

// UpdateStatus transitions a campaign's lifecycle status within a tenant.
func (r *Repository) UpdateStatus(ctx context.Context, tenantID, id uuid.UUID, status string) error {
	const q = `UPDATE campaigns SET status = $3, updated_at = now() WHERE tenant_id = $1 AND id = $2`
	tag, err := r.pool.Exec(ctx, q, tenantID, id, status)
	if err != nil {
		return fmt.Errorf("campaign: update status: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
