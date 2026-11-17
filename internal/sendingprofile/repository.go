// Package sendingprofile holds SMTP sending profiles. The SMTP password is
// stored only as an AES-256-GCM envelope (see internal/crypto); the plaintext
// never leaves the create request and is never returned.
package sendingprofile

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"phishforge/internal/db"
)

// ErrNotFound is returned when a profile does not exist within the tenant.
var ErrNotFound = errors.New("sendingprofile: not found")

// ValidTLSMode reports whether m is a valid tls_mode enum value.
func ValidTLSMode(m string) bool {
	switch m {
	case "none", "starttls", "smtps":
		return true
	default:
		return false
	}
}

// Profile is an SMTP sending profile. PassEncrypted is never serialized.
type Profile struct {
	ID           uuid.UUID `json:"id"`
	TenantID     uuid.UUID `json:"tenant_id"`
	Name         string    `json:"name"`
	SMTPHost     string    `json:"smtp_host"`
	SMTPPort     int       `json:"smtp_port"`
	SMTPUser     *string   `json:"smtp_user,omitempty"`
	PassEncrypted *string  `json:"-"`
	FromAddress  string    `json:"from_address"`
	FromName     *string   `json:"from_name,omitempty"`
	TLSMode      string    `json:"tls_mode"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Input carries the fields of a sending profile; PassEncrypted is the sealed
// SMTP password (empty when the server requires no auth).
type Input struct {
	Name          string
	SMTPHost      string
	SMTPPort      int
	SMTPUser      string
	PassEncrypted string
	FromAddress   string
	FromName      string
	TLSMode       string
}

// Repository provides sending-profile persistence. Stateless; tenant-scoped.
type Repository struct{}

// NewRepository returns a sending-profile repository.
func NewRepository() *Repository { return &Repository{} }

const cols = `id, tenant_id, name, smtp_host, smtp_port, smtp_user, smtp_pass_encrypted, from_address, from_name, tls_mode, created_at, updated_at`

func scanProfile(row pgx.Row) (Profile, error) {
	var p Profile
	if err := row.Scan(&p.ID, &p.TenantID, &p.Name, &p.SMTPHost, &p.SMTPPort, &p.SMTPUser,
		&p.PassEncrypted, &p.FromAddress, &p.FromName, &p.TLSMode, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return Profile{}, err
	}
	return p, nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// Create inserts a sending profile and returns it.
func (r *Repository) Create(ctx context.Context, q db.Querier, tenantID uuid.UUID, in Input) (Profile, error) {
	const sql = `INSERT INTO sending_profiles
	             (tenant_id, name, smtp_host, smtp_port, smtp_user, smtp_pass_encrypted, from_address, from_name, tls_mode)
	             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::tls_mode) RETURNING ` + cols
	p, err := scanProfile(q.QueryRow(ctx, sql, tenantID, in.Name, in.SMTPHost, in.SMTPPort,
		nullIfEmpty(in.SMTPUser), nullIfEmpty(in.PassEncrypted), in.FromAddress, nullIfEmpty(in.FromName), in.TLSMode))
	if err != nil {
		return Profile{}, fmt.Errorf("sendingprofile: create: %w", err)
	}
	return p, nil
}

// GetByID loads a profile within a tenant, or ErrNotFound.
func (r *Repository) GetByID(ctx context.Context, q db.Querier, tenantID, id uuid.UUID) (Profile, error) {
	const sql = `SELECT ` + cols + ` FROM sending_profiles WHERE tenant_id = $1 AND id = $2`
	p, err := scanProfile(q.QueryRow(ctx, sql, tenantID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Profile{}, ErrNotFound
	}
	if err != nil {
		return Profile{}, fmt.Errorf("sendingprofile: get by id: %w", err)
	}
	return p, nil
}

// List returns a tenant's profiles, newest first.
func (r *Repository) List(ctx context.Context, q db.Querier, tenantID uuid.UUID, limit, offset int) ([]Profile, error) {
	const sql = `SELECT ` + cols + ` FROM sending_profiles WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`
	rows, err := q.Query(ctx, sql, tenantID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("sendingprofile: list: %w", err)
	}
	defer rows.Close()
	out := make([]Profile, 0)
	for rows.Next() {
		p, err := scanProfile(rows)
		if err != nil {
			return nil, fmt.Errorf("sendingprofile: scan: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sendingprofile: iterate: %w", err)
	}
	return out, nil
}

// Delete removes a profile within a tenant, or ErrNotFound.
func (r *Repository) Delete(ctx context.Context, q db.Querier, tenantID, id uuid.UUID) error {
	tag, err := q.Exec(ctx, `DELETE FROM sending_profiles WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	if err != nil {
		return fmt.Errorf("sendingprofile: delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
