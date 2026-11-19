// Package campaign holds the campaign model and its tenant-scoped repository.
package campaign

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"phishforge/internal/db"
)

// ErrNotFound is returned when a campaign does not exist within the tenant.
var ErrNotFound = errors.New("campaign: not found")

// ValidStatus reports whether s is a valid campaign_status enum value.
func ValidStatus(s string) bool {
	switch s {
	case "draft", "scheduled", "running", "paused", "completed", "archived":
		return true
	default:
		return false
	}
}

// Campaign is a campaign owned by a single tenant.
type Campaign struct {
	ID               uuid.UUID  `json:"id"`
	TenantID         uuid.UUID  `json:"tenant_id"`
	Name             string     `json:"name"`
	Status           string     `json:"status"`
	LandingURL       *string    `json:"landing_url,omitempty"`
	TemplateID       *uuid.UUID `json:"template_id,omitempty"`
	SendingProfileID *uuid.UUID `json:"sending_profile_id,omitempty"`
	EngineID         *uuid.UUID `json:"engine_id,omitempty"`
	CreatedBy        uuid.UUID  `json:"created_by"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// Repository provides campaign persistence. It is stateless; each method takes
// a db.Querier (pool or transaction). Every query is scoped by tenant_id.
type Repository struct{}

// NewRepository returns a campaign repository.
func NewRepository() *Repository { return &Repository{} }

const campaignColumns = `id, tenant_id, name, status, landing_url, template_id, sending_profile_id, engine_id, created_by, created_at, updated_at`

func scanCampaign(row pgx.Row) (Campaign, error) {
	var (
		c   Campaign
		tpl uuid.NullUUID
		sp  uuid.NullUUID
		eng uuid.NullUUID
	)
	if err := row.Scan(&c.ID, &c.TenantID, &c.Name, &c.Status, &c.LandingURL, &tpl, &sp, &eng, &c.CreatedBy, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return Campaign{}, err
	}
	if tpl.Valid {
		id := tpl.UUID
		c.TemplateID = &id
	}
	if sp.Valid {
		id := sp.UUID
		c.SendingProfileID = &id
	}
	if eng.Valid {
		id := eng.UUID
		c.EngineID = &id
	}
	return c, nil
}

// Create inserts a new campaign for a tenant and returns the stored row.
func (r *Repository) Create(ctx context.Context, q db.Querier, tenantID, createdBy uuid.UUID, name string) (Campaign, error) {
	const sql = `INSERT INTO campaigns (tenant_id, name, created_by) VALUES ($1, $2, $3) RETURNING ` + campaignColumns
	c, err := scanCampaign(q.QueryRow(ctx, sql, tenantID, name, createdBy))
	if err != nil {
		return Campaign{}, fmt.Errorf("campaign: create: %w", err)
	}
	return c, nil
}

// GetByID loads a campaign by id within a tenant, or ErrNotFound.
func (r *Repository) GetByID(ctx context.Context, q db.Querier, tenantID, id uuid.UUID) (Campaign, error) {
	const sql = `SELECT ` + campaignColumns + ` FROM campaigns WHERE tenant_id = $1 AND id = $2`
	c, err := scanCampaign(q.QueryRow(ctx, sql, tenantID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Campaign{}, ErrNotFound
	}
	if err != nil {
		return Campaign{}, fmt.Errorf("campaign: get by id: %w", err)
	}
	return c, nil
}

// ListByTenant returns a tenant's campaigns, newest first.
func (r *Repository) ListByTenant(ctx context.Context, q db.Querier, tenantID uuid.UUID, limit, offset int) ([]Campaign, error) {
	const sql = `SELECT ` + campaignColumns + ` FROM campaigns WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`
	rows, err := q.Query(ctx, sql, tenantID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("campaign: list: %w", err)
	}
	defer rows.Close()

	out := make([]Campaign, 0)
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
func (r *Repository) UpdateStatus(ctx context.Context, q db.Querier, tenantID, id uuid.UUID, status string) error {
	const sql = `UPDATE campaigns SET status = $3::campaign_status, updated_at = now() WHERE tenant_id = $1 AND id = $2`
	tag, err := q.Exec(ctx, sql, tenantID, id, status)
	if err != nil {
		return fmt.Errorf("campaign: update status: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// MarkScheduled transitions a campaign to 'scheduled' and sets the send config
// (landing_url, template, sending profile). Nil values keep the existing value.
// It is used by the launch flow.
func (r *Repository) MarkScheduled(ctx context.Context, q db.Querier, tenantID, id uuid.UUID, landingURL *string, templateID, profileID *uuid.UUID) error {
	const sql = `UPDATE campaigns
	             SET status = 'scheduled',
	                 landing_url = COALESCE($3, landing_url),
	                 template_id = COALESCE($4, template_id),
	                 sending_profile_id = COALESCE($5, sending_profile_id),
	                 updated_at = now()
	             WHERE tenant_id = $1 AND id = $2`
	tag, err := q.Exec(ctx, sql, tenantID, id, landingURL, templateID, profileID)
	if err != nil {
		return fmt.Errorf("campaign: mark scheduled: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetEngine binds (engineID non-nil) or unbinds (nil) an engine to a
// campaign. Returns ErrNotFound if the campaign does not exist.
func (r *Repository) SetEngine(ctx context.Context, q db.Querier, tenantID, campaignID uuid.UUID, engineID *uuid.UUID) error {
	const sql = `UPDATE campaigns SET engine_id = $3, updated_at = now()
	             WHERE tenant_id = $1 AND id = $2`
	tag, err := q.Exec(ctx, sql, tenantID, campaignID, engineID)
	if err != nil {
		return fmt.Errorf("campaign: set engine: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// LandingURLByID returns a campaign's landing URL by id (no tenant scope, for
// the public tracking redirect which is already authorized by recipient token).
func (r *Repository) LandingURLByID(ctx context.Context, q db.Querier, id uuid.UUID) (*string, error) {
	var url *string
	err := q.QueryRow(ctx, `SELECT landing_url FROM campaigns WHERE id = $1`, id).Scan(&url)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("campaign: landing url: %w", err)
	}
	return url, nil
}


// LandingRedirectByID returns a campaign's landing URL and engine binding by
// id (no tenant scope; the public tracking redirect is authorized by the
// recipient token). The engine binding decides whether the victim token is
// passed through to the landing page as _pft.
func (r *Repository) LandingRedirectByID(ctx context.Context, q db.Querier, id uuid.UUID) (*string, *uuid.UUID, error) {
	var (
		url *string
		eng uuid.NullUUID
	)
	err := q.QueryRow(ctx,
		`SELECT landing_url, engine_id FROM campaigns WHERE id = $1`, id).Scan(&url, &eng)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, fmt.Errorf("campaign: landing redirect: %w", err)
	}
	var engineID *uuid.UUID
	if eng.Valid {
		id2 := eng.UUID
		engineID = &id2
	}
	return url, engineID, nil
}