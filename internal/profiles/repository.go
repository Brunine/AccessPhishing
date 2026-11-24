package profiles

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

// ErrNotFound is returned when a profile does not exist within the tenant.
var ErrNotFound = errors.New("profiles: not found")

// Profile is a stored application profile row. Spec is the canonical JSON of the
// validated profile; Version is a monotonic revision per (tenant, name).
type Profile struct {
	ID        uuid.UUID       `json:"id"`
	TenantID  uuid.UUID       `json:"tenant_id"`
	Name      string          `json:"name"`
	Version   int             `json:"version"`
	Spec      json.RawMessage `json:"spec"`
	Checksum  string          `json:"checksum"`
	CreatedBy uuid.UUID       `json:"created_by"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// Repository provides application-profile persistence. Stateless; tenant-scoped.
type Repository struct{}

// NewRepository returns an app-profile repository.
func NewRepository() *Repository { return &Repository{} }

const cols = `id, tenant_id, name, version, spec, checksum, created_by, created_at, updated_at`

func scan(row pgx.Row) (Profile, error) {
	var (
		p    Profile
		spec []byte
	)
	if err := row.Scan(&p.ID, &p.TenantID, &p.Name, &p.Version, &spec, &p.Checksum,
		&p.CreatedBy, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return Profile{}, err
	}
	p.Spec = json.RawMessage(spec)
	return p, nil
}

// Create inserts a new profile revision. The version is the next value for the
// (tenant, name) pair — N+1 — computed atomically in the INSERT.
func (r *Repository) Create(ctx context.Context, q db.Querier, tenantID, createdBy uuid.UUID, name string, canonicalSpec []byte, checksum string) (Profile, error) {
	const sql = `
INSERT INTO app_profiles (tenant_id, name, version, spec, checksum, created_by)
VALUES ($1, $2,
        (SELECT COALESCE(MAX(version), 0) + 1 FROM app_profiles WHERE tenant_id = $1 AND name = $2),
        $3::jsonb, $4, $5)
RETURNING ` + cols
	p, err := scan(q.QueryRow(ctx, sql, tenantID, name, string(canonicalSpec), checksum, createdBy))
	if err != nil {
		return Profile{}, fmt.Errorf("profiles: create: %w", err)
	}
	return p, nil
}

// GetByID loads a profile within a tenant, or ErrNotFound.
func (r *Repository) GetByID(ctx context.Context, q db.Querier, tenantID, id uuid.UUID) (Profile, error) {
	const sql = `SELECT ` + cols + ` FROM app_profiles WHERE tenant_id = $1 AND id = $2`
	p, err := scan(q.QueryRow(ctx, sql, tenantID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Profile{}, ErrNotFound
	}
	if err != nil {
		return Profile{}, fmt.Errorf("profiles: get by id: %w", err)
	}
	return p, nil
}

// List returns a tenant's profiles, newest first.
func (r *Repository) List(ctx context.Context, q db.Querier, tenantID uuid.UUID, limit, offset int) ([]Profile, error) {
	const sql = `SELECT ` + cols + ` FROM app_profiles WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`
	rows, err := q.Query(ctx, sql, tenantID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("profiles: list: %w", err)
	}
	defer rows.Close()

	out := make([]Profile, 0)
	for rows.Next() {
		p, err := scan(rows)
		if err != nil {
			return nil, fmt.Errorf("profiles: scan: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("profiles: iterate: %w", err)
	}
	return out, nil
}

// Update replaces a profile row's spec/checksum in place within a tenant (same
// version), or ErrNotFound. The name is immutable here; a rename is a new import.
func (r *Repository) Update(ctx context.Context, q db.Querier, tenantID, id uuid.UUID, canonicalSpec []byte, checksum string) (Profile, error) {
	const sql = `
UPDATE app_profiles SET spec = $3::jsonb, checksum = $4, updated_at = now()
WHERE tenant_id = $1 AND id = $2
RETURNING ` + cols
	p, err := scan(q.QueryRow(ctx, sql, tenantID, id, string(canonicalSpec), checksum))
	if errors.Is(err, pgx.ErrNoRows) {
		return Profile{}, ErrNotFound
	}
	if err != nil {
		return Profile{}, fmt.Errorf("profiles: update: %w", err)
	}
	return p, nil
}

// Delete removes a profile within a tenant, or ErrNotFound. Campaigns that were
// launched against it keep their frozen checksum (the FK is ON DELETE SET NULL).
func (r *Repository) Delete(ctx context.Context, q db.Querier, tenantID, id uuid.UUID) error {
	const sql = `DELETE FROM app_profiles WHERE tenant_id = $1 AND id = $2`
	tag, err := q.Exec(ctx, sql, tenantID, id)
	if err != nil {
		return fmt.Errorf("profiles: delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
