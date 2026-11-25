package domain

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"phishforge/internal/db"
)

// Input carries the editable fields for Create/Update.
type Input struct {
	Name         string
	Registrar    *string
	RegisteredAt *time.Time
	ExpiresAt    *time.Time
	DNSProvider  *string
	Nameservers  []string
	TLSStatus    *string
	Notes        *string
}

// Repository provides domain-inventory persistence. It is stateless; each
// method takes a db.Querier (pool or transaction) and is scoped by tenant_id.
type Repository struct{}

// NewRepository returns a domain repository.
func NewRepository() *Repository { return &Repository{} }

const cols = `id, tenant_id, name, registrar, status, registered_at, expires_at,
              dns_provider, nameservers, tls_status, notes, created_by, created_at, updated_at`

func scan(row pgx.Row) (Domain, error) {
	var d Domain
	d.Nameservers = []string{}
	if err := row.Scan(
		&d.ID, &d.TenantID, &d.Name, &d.Registrar, &d.Status, &d.RegisteredAt, &d.ExpiresAt,
		&d.DNSProvider, &d.Nameservers, &d.TLSStatus, &d.Notes, &d.CreatedBy, &d.CreatedAt, &d.UpdatedAt,
	); err != nil {
		return Domain{}, err
	}
	if d.Nameservers == nil {
		d.Nameservers = []string{}
	}
	return d, nil
}

// Create inserts a new domain in the given status and returns the stored row.
func (r *Repository) Create(ctx context.Context, q db.Querier, tenantID, createdBy uuid.UUID, status Status, in Input) (Domain, error) {
	ns := in.Nameservers
	if ns == nil {
		ns = []string{}
	}
	const sql = `INSERT INTO domains
	    (tenant_id, name, registrar, status, registered_at, expires_at, dns_provider, nameservers, tls_status, notes, created_by)
	    VALUES ($1, $2, $3, $4::domain_status, $5, $6, $7, $8, $9, $10, $11)
	    RETURNING ` + cols
	d, err := scan(q.QueryRow(ctx, sql,
		tenantID, in.Name, in.Registrar, string(status), in.RegisteredAt, in.ExpiresAt,
		in.DNSProvider, ns, in.TLSStatus, in.Notes, createdBy))
	if err != nil {
		return Domain{}, fmt.Errorf("domain: create: %w", err)
	}
	return d, nil
}

// GetByID loads a domain by id within a tenant, or ErrNotFound.
func (r *Repository) GetByID(ctx context.Context, q db.Querier, tenantID, id uuid.UUID) (Domain, error) {
	const sql = `SELECT ` + cols + ` FROM domains WHERE tenant_id = $1 AND id = $2`
	d, err := scan(q.QueryRow(ctx, sql, tenantID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Domain{}, ErrNotFound
	}
	if err != nil {
		return Domain{}, fmt.Errorf("domain: get by id: %w", err)
	}
	return d, nil
}

// List returns a tenant's domains, newest first.
func (r *Repository) List(ctx context.Context, q db.Querier, tenantID uuid.UUID, limit, offset int) ([]Domain, error) {
	const sql = `SELECT ` + cols + ` FROM domains WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`
	rows, err := q.Query(ctx, sql, tenantID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("domain: list: %w", err)
	}
	defer rows.Close()
	out := make([]Domain, 0)
	for rows.Next() {
		d, err := scan(rows)
		if err != nil {
			return nil, fmt.Errorf("domain: scan: %w", err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("domain: iterate: %w", err)
	}
	return out, nil
}

// Update edits the mutable metadata fields (not status). The caller validates
// the status separately via SetStatus.
func (r *Repository) Update(ctx context.Context, q db.Querier, tenantID, id uuid.UUID, in Input) (Domain, error) {
	ns := in.Nameservers
	if ns == nil {
		ns = []string{}
	}
	const sql = `UPDATE domains
	    SET name = $3, registrar = $4, registered_at = $5, expires_at = $6,
	        dns_provider = $7, nameservers = $8, tls_status = $9, notes = $10, updated_at = now()
	    WHERE tenant_id = $1 AND id = $2
	    RETURNING ` + cols
	d, err := scan(q.QueryRow(ctx, sql,
		tenantID, id, in.Name, in.Registrar, in.RegisteredAt, in.ExpiresAt,
		in.DNSProvider, ns, in.TLSStatus, in.Notes))
	if errors.Is(err, pgx.ErrNoRows) {
		return Domain{}, ErrNotFound
	}
	if err != nil {
		return Domain{}, fmt.Errorf("domain: update: %w", err)
	}
	return d, nil
}

// SetStatus writes a new status. The caller enforces that the transition is
// allowed before calling.
func (r *Repository) SetStatus(ctx context.Context, q db.Querier, tenantID, id uuid.UUID, status Status) (Domain, error) {
	const sql = `UPDATE domains SET status = $3::domain_status, updated_at = now()
	             WHERE tenant_id = $1 AND id = $2 RETURNING ` + cols
	d, err := scan(q.QueryRow(ctx, sql, tenantID, id, string(status)))
	if errors.Is(err, pgx.ErrNoRows) {
		return Domain{}, ErrNotFound
	}
	if err != nil {
		return Domain{}, fmt.Errorf("domain: set status: %w", err)
	}
	return d, nil
}

// UpdateTLSStatus persists a derived tls_status for a domain, scoped by tenant.
// It is a narrow write that never touches the lifecycle status; values are
// constrained by the 0017 domains.tls_status CHECK. Returns ErrNotFound when no
// row matched.
func (r *Repository) UpdateTLSStatus(ctx context.Context, q db.Querier, tenantID, id uuid.UUID, status string) error {
	const sql = `UPDATE domains SET tls_status = $3, updated_at = now() WHERE tenant_id = $1 AND id = $2`
	tag, err := q.Exec(ctx, sql, tenantID, id, status)
	if err != nil {
		return fmt.Errorf("domain: update tls status: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Delete hard-deletes a domain row within a tenant. The caller enforces the
// status precondition (CanDelete). Returns ErrNotFound when nothing matched.
func (r *Repository) Delete(ctx context.Context, q db.Querier, tenantID, id uuid.UUID) error {
	const sql = `DELETE FROM domains WHERE tenant_id = $1 AND id = $2`
	tag, err := q.Exec(ctx, sql, tenantID, id)
	if err != nil {
		return fmt.Errorf("domain: delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// --- assignments ----------------------------------------------------------

const asgCols = `id, tenant_id, domain_id, engagement_id, status, authorized_by, authorized_at, notes, created_at, updated_at`

func scanAssignment(row pgx.Row) (Assignment, error) {
	var (
		a      Assignment
		authBy uuid.NullUUID
	)
	if err := row.Scan(
		&a.ID, &a.TenantID, &a.DomainID, &a.EngagementID, &a.Status, &authBy, &a.AuthorizedAt, &a.Notes, &a.CreatedAt, &a.UpdatedAt,
	); err != nil {
		return Assignment{}, err
	}
	if authBy.Valid {
		id := authBy.UUID
		a.AuthorizedBy = &id
	}
	return a, nil
}

// Assign creates a pending assignment binding a domain to an engagement.
func (r *Repository) Assign(ctx context.Context, q db.Querier, tenantID, domainID, engagementID uuid.UUID, notes *string) (Assignment, error) {
	const sql = `INSERT INTO domain_assignments (tenant_id, domain_id, engagement_id, notes)
	             VALUES ($1, $2, $3, $4) RETURNING ` + asgCols
	a, err := scanAssignment(q.QueryRow(ctx, sql, tenantID, domainID, engagementID, notes))
	if err != nil {
		return Assignment{}, fmt.Errorf("domain: assign: %w", err)
	}
	return a, nil
}

// GetAssignment loads one assignment by id, scoped to tenant + domain.
func (r *Repository) GetAssignment(ctx context.Context, q db.Querier, tenantID, domainID, id uuid.UUID) (Assignment, error) {
	const sql = `SELECT ` + asgCols + ` FROM domain_assignments WHERE tenant_id = $1 AND domain_id = $2 AND id = $3`
	a, err := scanAssignment(q.QueryRow(ctx, sql, tenantID, domainID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Assignment{}, ErrNotFound
	}
	if err != nil {
		return Assignment{}, fmt.Errorf("domain: get assignment: %w", err)
	}
	return a, nil
}

// ListAssignments returns a domain's assignments, newest first.
func (r *Repository) ListAssignments(ctx context.Context, q db.Querier, tenantID, domainID uuid.UUID) ([]Assignment, error) {
	const sql = `SELECT ` + asgCols + ` FROM domain_assignments WHERE tenant_id = $1 AND domain_id = $2 ORDER BY created_at DESC`
	rows, err := q.Query(ctx, sql, tenantID, domainID)
	if err != nil {
		return nil, fmt.Errorf("domain: list assignments: %w", err)
	}
	defer rows.Close()
	out := make([]Assignment, 0)
	for rows.Next() {
		a, err := scanAssignment(rows)
		if err != nil {
			return nil, fmt.Errorf("domain: scan assignment: %w", err)
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("domain: iterate assignments: %w", err)
	}
	return out, nil
}

// CountAuthorizedAssignments returns how many of a domain's assignments are
// authorized (used to gate activation).
func (r *Repository) CountAuthorizedAssignments(ctx context.Context, q db.Querier, tenantID, domainID uuid.UUID) (int, error) {
	const sql = `SELECT count(*) FROM domain_assignments WHERE tenant_id = $1 AND domain_id = $2 AND status = 'authorized'`
	var n int
	if err := q.QueryRow(ctx, sql, tenantID, domainID).Scan(&n); err != nil {
		return 0, fmt.Errorf("domain: count authorized assignments: %w", err)
	}
	return n, nil
}

// SetAssignmentStatus updates an assignment's status. For 'authorized' it also
// records the deciding admin + timestamp; other statuses clear neither. The
// caller validates the transition.
func (r *Repository) SetAssignmentStatus(ctx context.Context, q db.Querier, tenantID, domainID, id uuid.UUID, status AssignmentStatus, authorizedBy *uuid.UUID) (Assignment, error) {
	const sql = `UPDATE domain_assignments
	             SET status = $4,
	                 authorized_by = CASE WHEN $4 = 'authorized' THEN $5 ELSE authorized_by END,
	                 authorized_at = CASE WHEN $4 = 'authorized' THEN now() ELSE authorized_at END,
	                 updated_at = now()
	             WHERE tenant_id = $1 AND domain_id = $2 AND id = $3
	             RETURNING ` + asgCols
	var by uuid.NullUUID
	if authorizedBy != nil {
		by = uuid.NullUUID{UUID: *authorizedBy, Valid: true}
	}
	a, err := scanAssignment(q.QueryRow(ctx, sql, tenantID, domainID, id, string(status), by))
	if errors.Is(err, pgx.ErrNoRows) {
		return Assignment{}, ErrNotFound
	}
	if err != nil {
		return Assignment{}, fmt.Errorf("domain: set assignment status: %w", err)
	}
	return a, nil
}

// ListByEngagement returns the domains assigned to an engagement within a
// tenant, excluding revoked assignments, ordered by domain name. Each row pairs
// a domain summary with its assignment status and authorized_at.
func (r *Repository) ListByEngagement(ctx context.Context, q db.Querier, tenantID, engagementID uuid.UUID) ([]EngagementDomain, error) {
	const sql = `
	SELECT d.id, d.name, d.status, d.tls_status, d.expires_at,
	       a.id, a.status, a.authorized_at
	FROM domain_assignments a
	JOIN domains d ON d.id = a.domain_id
	WHERE a.tenant_id = $1 AND a.engagement_id = $2 AND a.status <> 'revoked'
	ORDER BY d.name ASC`
	rows, err := q.Query(ctx, sql, tenantID, engagementID)
	if err != nil {
		return nil, fmt.Errorf("domain: list by engagement: %w", err)
	}
	defer rows.Close()
	out := make([]EngagementDomain, 0)
	for rows.Next() {
		var e EngagementDomain
		if err := rows.Scan(
			&e.DomainID, &e.Name, &e.Status, &e.TLSStatus, &e.ExpiresAt,
			&e.AssignmentID, &e.AssignmentStatus, &e.AuthorizedAt,
		); err != nil {
			return nil, fmt.Errorf("domain: scan engagement domain: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("domain: iterate engagement domains: %w", err)
	}
	return out, nil
}

// --- verifications --------------------------------------------------------

const verCols = `id, tenant_id, domain_id, method, hostname, expected_value, token, status, verified_at, created_at`

func scanVerification(row pgx.Row) (Verification, error) {
	var v Verification
	if err := row.Scan(
		&v.ID, &v.TenantID, &v.DomainID, &v.Method, &v.Hostname, &v.ExpectedValue, &v.Token, &v.Status, &v.VerifiedAt, &v.CreatedAt,
	); err != nil {
		return Verification{}, err
	}
	return v, nil
}

// ExpirePendingVerifications marks every still-pending verification for a domain
// as expired. Called before issuing a fresh challenge so only one is live.
func (r *Repository) ExpirePendingVerifications(ctx context.Context, q db.Querier, tenantID, domainID uuid.UUID) error {
	const sql = `UPDATE domain_verifications SET status = 'expired'
	             WHERE tenant_id = $1 AND domain_id = $2 AND status = 'pending'`
	if _, err := q.Exec(ctx, sql, tenantID, domainID); err != nil {
		return fmt.Errorf("domain: expire pending verifications: %w", err)
	}
	return nil
}

// CreateVerification inserts a new pending TXT challenge.
func (r *Repository) CreateVerification(ctx context.Context, q db.Querier, tenantID, domainID uuid.UUID, hostname, expectedValue, token string) (Verification, error) {
	const sql = `INSERT INTO domain_verifications (tenant_id, domain_id, method, hostname, expected_value, token)
	             VALUES ($1, $2, 'txt', $3, $4, $5) RETURNING ` + verCols
	v, err := scanVerification(q.QueryRow(ctx, sql, tenantID, domainID, hostname, expectedValue, token))
	if err != nil {
		return Verification{}, fmt.Errorf("domain: create verification: %w", err)
	}
	return v, nil
}

// GetVerification loads one verification by id, scoped to tenant + domain.
func (r *Repository) GetVerification(ctx context.Context, q db.Querier, tenantID, domainID, id uuid.UUID) (Verification, error) {
	const sql = `SELECT ` + verCols + ` FROM domain_verifications WHERE tenant_id = $1 AND domain_id = $2 AND id = $3`
	v, err := scanVerification(q.QueryRow(ctx, sql, tenantID, domainID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Verification{}, ErrNotFound
	}
	if err != nil {
		return Verification{}, fmt.Errorf("domain: get verification: %w", err)
	}
	return v, nil
}

// MarkVerificationResult sets a verification's terminal status. When verified,
// verified_at is stamped.
func (r *Repository) MarkVerificationResult(ctx context.Context, q db.Querier, tenantID, domainID, id uuid.UUID, status VerificationStatus) (Verification, error) {
	const sql = `UPDATE domain_verifications
	             SET status = $4,
	                 verified_at = CASE WHEN $4 = 'verified' THEN now() ELSE verified_at END
	             WHERE tenant_id = $1 AND domain_id = $2 AND id = $3
	             RETURNING ` + verCols
	v, err := scanVerification(q.QueryRow(ctx, sql, tenantID, domainID, id, string(status)))
	if errors.Is(err, pgx.ErrNoRows) {
		return Verification{}, ErrNotFound
	}
	if err != nil {
		return Verification{}, fmt.Errorf("domain: mark verification result: %w", err)
	}
	return v, nil
}
