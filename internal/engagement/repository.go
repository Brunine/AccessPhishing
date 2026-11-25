package engagement

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"phishforge/internal/db"
)

// Input carries the editable fields for Create/Update.
type Input struct {
	Name            string
	ClientName      string
	ClientID        *uuid.UUID
	RoERef          *string
	AuthorizedScope []string
	StartsAt        *time.Time
	ExpiresAt       *time.Time
	Notes           *string
}

// Repository provides engagement persistence. It is stateless; each method
// takes a db.Querier (pool or transaction) and is scoped by tenant_id.
type Repository struct{}

// NewRepository returns an engagement repository.
func NewRepository() *Repository { return &Repository{} }

const cols = `id, tenant_id, name, client_name, client_id, status, roe_reference, authorized_scope,
              authorized_at, authorized_by, starts_at, expires_at, notes, created_by, created_at, updated_at`

func scan(row pgx.Row) (Engagement, error) {
	var (
		e        Engagement
		scopeRaw []byte
		authBy   uuid.NullUUID
		clientID uuid.NullUUID
	)
	if err := row.Scan(
		&e.ID, &e.TenantID, &e.Name, &e.ClientName, &clientID, &e.Status, &e.RoERef, &scopeRaw,
		&e.AuthorizedAt, &authBy, &e.StartsAt, &e.ExpiresAt, &e.Notes, &e.CreatedBy, &e.CreatedAt, &e.UpdatedAt,
	); err != nil {
		return Engagement{}, err
	}
	if clientID.Valid {
		id := clientID.UUID
		e.ClientID = &id
	}
	e.AuthorizedScope = []string{}
	if len(scopeRaw) > 0 {
		if err := json.Unmarshal(scopeRaw, &e.AuthorizedScope); err != nil {
			return Engagement{}, fmt.Errorf("engagement: decode scope: %w", err)
		}
	}
	if authBy.Valid {
		id := authBy.UUID
		e.AuthorizedBy = &id
	}
	e.EffectiveStatus = e.Effective(time.Now().UTC())
	return e, nil
}

func marshalScope(scope []string) (string, error) {
	if scope == nil {
		scope = []string{}
	}
	b, err := json.Marshal(scope)
	if err != nil {
		return "", fmt.Errorf("engagement: encode scope: %w", err)
	}
	return string(b), nil
}

// Create inserts a new draft engagement and returns the stored row.
func (r *Repository) Create(ctx context.Context, q db.Querier, tenantID, createdBy uuid.UUID, in Input) (Engagement, error) {
	scope, err := marshalScope(in.AuthorizedScope)
	if err != nil {
		return Engagement{}, err
	}
	const sql = `INSERT INTO engagements
	    (tenant_id, name, client_name, client_id, roe_reference, authorized_scope, starts_at, expires_at, notes, created_by)
	    VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9, $10)
	    RETURNING ` + cols
	e, err := scan(q.QueryRow(ctx, sql,
		tenantID, in.Name, in.ClientName, in.ClientID, in.RoERef, scope, in.StartsAt, in.ExpiresAt, in.Notes, createdBy))
	if err != nil {
		return Engagement{}, fmt.Errorf("engagement: create: %w", err)
	}
	return e, nil
}

// GetByID loads an engagement by id within a tenant, or ErrNotFound.
func (r *Repository) GetByID(ctx context.Context, q db.Querier, tenantID, id uuid.UUID) (Engagement, error) {
	const sql = `SELECT ` + cols + ` FROM engagements WHERE tenant_id = $1 AND id = $2`
	e, err := scan(q.QueryRow(ctx, sql, tenantID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Engagement{}, ErrNotFound
	}
	if err != nil {
		return Engagement{}, fmt.Errorf("engagement: get by id: %w", err)
	}
	return e, nil
}

// List returns a tenant's engagements, newest first.
func (r *Repository) List(ctx context.Context, q db.Querier, tenantID uuid.UUID, limit, offset int) ([]Engagement, error) {
	const sql = `SELECT ` + cols + ` FROM engagements WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`
	rows, err := q.Query(ctx, sql, tenantID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("engagement: list: %w", err)
	}
	defer rows.Close()
	out := make([]Engagement, 0)
	for rows.Next() {
		e, err := scan(rows)
		if err != nil {
			return nil, fmt.Errorf("engagement: scan: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("engagement: iterate: %w", err)
	}
	return out, nil
}

// Update edits the mutable fields of an engagement. The caller is responsible
// for enforcing that the current status permits editing (see canEdit).
func (r *Repository) Update(ctx context.Context, q db.Querier, tenantID, id uuid.UUID, in Input) (Engagement, error) {
	scope, err := marshalScope(in.AuthorizedScope)
	if err != nil {
		return Engagement{}, err
	}
	const sql = `UPDATE engagements
	    SET name = $3, client_name = $4, client_id = $5, roe_reference = $6, authorized_scope = $7::jsonb,
	        starts_at = $8, expires_at = $9, notes = $10, updated_at = now()
	    WHERE tenant_id = $1 AND id = $2
	    RETURNING ` + cols
	e, err := scan(q.QueryRow(ctx, sql,
		tenantID, id, in.Name, in.ClientName, in.ClientID, in.RoERef, scope, in.StartsAt, in.ExpiresAt, in.Notes))
	if errors.Is(err, pgx.ErrNoRows) {
		return Engagement{}, ErrNotFound
	}
	if err != nil {
		return Engagement{}, fmt.Errorf("engagement: update: %w", err)
	}
	return e, nil
}

// RequestAuthorization moves an engagement to pending_authorization. The caller
// validates the transition (see canRequestAuthorization) before calling.
func (r *Repository) RequestAuthorization(ctx context.Context, q db.Querier, tenantID, id uuid.UUID) (Engagement, error) {
	const sql = `UPDATE engagements SET status = 'pending_authorization', updated_at = now()
	             WHERE tenant_id = $1 AND id = $2 RETURNING ` + cols
	return r.mutate(ctx, q, sql, tenantID, id)
}

// Authorize moves a pending engagement to authorized and records the deciding
// admin + timestamp. Only an admin reaches this path (enforced in the router).
func (r *Repository) Authorize(ctx context.Context, q db.Querier, tenantID, id, authorizedBy uuid.UUID) (Engagement, error) {
	const sql = `UPDATE engagements
	             SET status = 'authorized', authorized_at = now(), authorized_by = $3, updated_at = now()
	             WHERE tenant_id = $1 AND id = $2 RETURNING ` + cols
	e, err := scan(q.QueryRow(ctx, sql, tenantID, id, authorizedBy))
	if errors.Is(err, pgx.ErrNoRows) {
		return Engagement{}, ErrNotFound
	}
	if err != nil {
		return Engagement{}, fmt.Errorf("engagement: authorize: %w", err)
	}
	return e, nil
}

// Terminate moves an engagement to terminated (emergency stop). Terminal.
func (r *Repository) Terminate(ctx context.Context, q db.Querier, tenantID, id uuid.UUID) (Engagement, error) {
	const sql = `UPDATE engagements SET status = 'terminated', updated_at = now()
	             WHERE tenant_id = $1 AND id = $2 RETURNING ` + cols
	return r.mutate(ctx, q, sql, tenantID, id)
}

func (r *Repository) mutate(ctx context.Context, q db.Querier, sql string, args ...any) (Engagement, error) {
	e, err := scan(q.QueryRow(ctx, sql, args...))
	if errors.Is(err, pgx.ErrNoRows) {
		return Engagement{}, ErrNotFound
	}
	if err != nil {
		return Engagement{}, fmt.Errorf("engagement: mutate: %w", err)
	}
	return e, nil
}
