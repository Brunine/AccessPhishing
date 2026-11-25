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
	"phishforge/internal/engagement"
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

// ValidChannel reports whether s is a campaign channel the create path accepts.
// The column reuses the event_channel enum, but a campaign is only ever created
// as 'email' (the default vector, including SMS campaigns, whose SMS-ness comes
// from the bound sending profile) or 'qr' (M9b quishing). auth/system are event
// channels, never campaign channels.
func ValidChannel(s string) bool {
	switch s {
	case "email", "qr":
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
	Channel          string     `json:"channel"`
	LandingURL       *string    `json:"landing_url,omitempty"`
	TemplateID       *uuid.UUID `json:"template_id,omitempty"`
	SendingProfileID *uuid.UUID `json:"sending_profile_id,omitempty"`
	EngineID         *uuid.UUID `json:"engine_id,omitempty"`
	EngagementID     *uuid.UUID `json:"engagement_id,omitempty"`
	// EngagementStatus is the derived (effective) status label of the bound
	// engagement — active/authorized/expired/terminated/etc. — populated on
	// list/detail reads when an engagement is bound, nil otherwise.
	EngagementStatus *string   `json:"engagement_status,omitempty"`
	CreatedBy        uuid.UUID `json:"created_by"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// Repository provides campaign persistence. It is stateless; each method takes
// a db.Querier (pool or transaction). Every query is scoped by tenant_id.
type Repository struct{}

// NewRepository returns a campaign repository.
func NewRepository() *Repository { return &Repository{} }

const campaignColumns = `id, tenant_id, name, status, channel, landing_url, template_id, sending_profile_id, engine_id, engagement_id, created_by, created_at, updated_at`

// joinedColumns adds the bound engagement's stored status + expiry so the
// derived effective label can be computed in Go without an N+1 lookup.
const joinedColumns = `c.id, c.tenant_id, c.name, c.status, c.channel, c.landing_url, c.template_id, c.sending_profile_id, c.engine_id, c.engagement_id, c.created_by, c.created_at, c.updated_at, e.status, e.expires_at`

// scanCampaign scans the base columns (used by RETURNING, no engagement join).
func scanCampaign(row pgx.Row) (Campaign, error) {
	var (
		c   Campaign
		tpl uuid.NullUUID
		sp  uuid.NullUUID
		eng uuid.NullUUID
		eid uuid.NullUUID
	)
	if err := row.Scan(&c.ID, &c.TenantID, &c.Name, &c.Status, &c.Channel, &c.LandingURL, &tpl, &sp, &eng, &eid, &c.CreatedBy, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return Campaign{}, err
	}
	setOpt(&c.TemplateID, tpl)
	setOpt(&c.SendingProfileID, sp)
	setOpt(&c.EngineID, eng)
	setOpt(&c.EngagementID, eid)
	return c, nil
}

// scanCampaignJoined scans the base columns plus the bound engagement's status
// and expiry, and populates the derived EngagementStatus label.
func scanCampaignJoined(row pgx.Row) (Campaign, error) {
	var (
		c         Campaign
		tpl       uuid.NullUUID
		sp        uuid.NullUUID
		eng       uuid.NullUUID
		eid       uuid.NullUUID
		engStatus *string
		engExpiry *time.Time
	)
	if err := row.Scan(&c.ID, &c.TenantID, &c.Name, &c.Status, &c.Channel, &c.LandingURL, &tpl, &sp, &eng, &eid, &c.CreatedBy, &c.CreatedAt, &c.UpdatedAt, &engStatus, &engExpiry); err != nil {
		return Campaign{}, err
	}
	setOpt(&c.TemplateID, tpl)
	setOpt(&c.SendingProfileID, sp)
	setOpt(&c.EngineID, eng)
	setOpt(&c.EngagementID, eid)
	if engStatus != nil {
		label := string(engagement.Engagement{
			Status:    engagement.Status(*engStatus),
			ExpiresAt: engExpiry,
		}.Effective(time.Now().UTC()))
		c.EngagementStatus = &label
	}
	return c, nil
}

func setOpt(dst **uuid.UUID, n uuid.NullUUID) {
	if n.Valid {
		id := n.UUID
		*dst = &id
	}
}

// Create inserts a new campaign for a tenant and returns the stored row. An
// optional engagementID binds the campaign to its authorizing engagement at
// creation time; the caller is responsible for validating same-tenant ownership.
// channel is the delivery vector ('email' or 'qr'); an empty value defaults to
// 'email'. The caller is responsible for validating channel (see ValidChannel).
func (r *Repository) Create(ctx context.Context, q db.Querier, tenantID, createdBy uuid.UUID, name, channel string, engagementID *uuid.UUID) (Campaign, error) {
	if channel == "" {
		channel = "email"
	}
	const sql = `INSERT INTO campaigns (tenant_id, name, channel, created_by, engagement_id)
	             VALUES ($1, $2, $3::event_channel, $4, $5) RETURNING ` + campaignColumns
	c, err := scanCampaign(q.QueryRow(ctx, sql, tenantID, name, channel, createdBy, engagementID))
	if err != nil {
		return Campaign{}, fmt.Errorf("campaign: create: %w", err)
	}
	return c, nil
}

// GetByID loads a campaign by id within a tenant, or ErrNotFound.
func (r *Repository) GetByID(ctx context.Context, q db.Querier, tenantID, id uuid.UUID) (Campaign, error) {
	const sql = `SELECT ` + joinedColumns + `
	             FROM campaigns c LEFT JOIN engagements e ON e.id = c.engagement_id
	             WHERE c.tenant_id = $1 AND c.id = $2`
	c, err := scanCampaignJoined(q.QueryRow(ctx, sql, tenantID, id))
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
	const sql = `SELECT ` + joinedColumns + `
	             FROM campaigns c LEFT JOIN engagements e ON e.id = c.engagement_id
	             WHERE c.tenant_id = $1 ORDER BY c.created_at DESC LIMIT $2 OFFSET $3`
	rows, err := q.Query(ctx, sql, tenantID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("campaign: list: %w", err)
	}
	defer rows.Close()

	out := make([]Campaign, 0)
	for rows.Next() {
		c, err := scanCampaignJoined(rows)
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

// SetEngagement binds (engagementID non-nil) or unbinds (nil) an engagement to
// a campaign within a tenant. Returns ErrNotFound if the campaign is absent.
func (r *Repository) SetEngagement(ctx context.Context, q db.Querier, tenantID, campaignID uuid.UUID, engagementID *uuid.UUID) error {
	const sql = `UPDATE campaigns SET engagement_id = $3, updated_at = now() WHERE tenant_id = $1 AND id = $2`
	tag, err := q.Exec(ctx, sql, tenantID, campaignID, engagementID)
	if err != nil {
		return fmt.Errorf("campaign: set engagement: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
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

// SetLaunchProfile records the app profile a campaign was launched against,
// freezing its checksum + revision on the campaign (M10b Phase 3). These values
// are the forensic stamp: a later profile import never rewrites them, so an
// in-flight campaign keeps its launch-time checksum. Returns ErrNotFound if the
// campaign is absent in the tenant.
func (r *Repository) SetLaunchProfile(ctx context.Context, q db.Querier, tenantID, campaignID, profileID uuid.UUID, checksum string, version int) error {
	const sql = `UPDATE campaigns
	             SET app_profile_id = $3, profile_checksum = $4, profile_version = $5, updated_at = now()
	             WHERE tenant_id = $1 AND id = $2`
	tag, err := q.Exec(ctx, sql, tenantID, campaignID, profileID, checksum, version)
	if err != nil {
		return fmt.Errorf("campaign: set launch profile: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ProfileStampByCampaignID returns a campaign's frozen profile checksum and
// version by id (no tenant scope; the engine-event ingest path is already
// authorized by the per-run bearer token + recipient token). Both are nil when
// the campaign was launched without a bound profile.
func (r *Repository) ProfileStampByCampaignID(ctx context.Context, q db.Querier, id uuid.UUID) (checksum *string, version *int, err error) {
	err = q.QueryRow(ctx,
		`SELECT profile_checksum, profile_version FROM campaigns WHERE id = $1`, id).Scan(&checksum, &version)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, fmt.Errorf("campaign: profile stamp: %w", err)
	}
	return checksum, version, nil
}

// AppProfileBindingByID returns the application profile a campaign is bound to
// (set at launch via SetLaunchProfile), tenant-scoped. The pointer is nil when
// the campaign was launched without a bound profile. Used by the M5 AiTM proxy
// to resolve which profile to compile and serve.
func (r *Repository) AppProfileBindingByID(ctx context.Context, q db.Querier, tenantID, campaignID uuid.UUID) (*uuid.UUID, error) {
	var ap uuid.NullUUID
	err := q.QueryRow(ctx,
		`SELECT app_profile_id FROM campaigns WHERE tenant_id = $1 AND id = $2`,
		tenantID, campaignID).Scan(&ap)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("campaign: app profile binding: %w", err)
	}
	if ap.Valid {
		id := ap.UUID
		return &id, nil
	}
	return nil, nil
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

// LandingRedirectByID returns a campaign's landing URL, engine binding, and
// delivery channel by id (no tenant scope; the public tracking redirect is
// authorized by the recipient token). The engine binding decides whether the
// victim token is passed through to the landing page as _pft; the channel lets
// the tracking handler record a QR scan (scanned) before the click.
func (r *Repository) LandingRedirectByID(ctx context.Context, q db.Querier, id uuid.UUID) (*string, *uuid.UUID, string, error) {
	var (
		url     *string
		eng     uuid.NullUUID
		channel string
	)
	err := q.QueryRow(ctx,
		`SELECT landing_url, engine_id, channel::text FROM campaigns WHERE id = $1`, id).Scan(&url, &eng, &channel)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, "", ErrNotFound
	}
	if err != nil {
		return nil, nil, "", fmt.Errorf("campaign: landing redirect: %w", err)
	}
	var engineID *uuid.UUID
	if eng.Valid {
		id2 := eng.UUID
		engineID = &id2
	}
	return url, engineID, channel, nil
}
