// Package template holds message templates (email/sms/...) with Go
// text/template bodies rendered per recipient at send time.
package template

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"phishforge/internal/db"
)

// ErrNotFound is returned when a template does not exist within the tenant.
var ErrNotFound = errors.New("template: not found")

// ValidKind reports whether k is a valid template_kind enum value.
func ValidKind(k string) bool {
	switch k {
	case "email", "sms", "landing", "phishlet", "script", "voice":
		return true
	default:
		return false
	}
}

// Template is a reusable message template.
type Template struct {
	ID        uuid.UUID `json:"id"`
	TenantID  uuid.UUID `json:"tenant_id"`
	Kind      string    `json:"kind"`
	Name      string    `json:"name"`
	Subject   *string   `json:"subject,omitempty"`
	Body      string    `json:"body"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Input carries the mutable fields of a template.
type Input struct {
	Kind    string
	Name    string
	Subject string
	Body    string
}

// Repository provides template persistence. Stateless; tenant-scoped.
type Repository struct{}

// NewRepository returns a template repository.
func NewRepository() *Repository { return &Repository{} }

const cols = `id, tenant_id, kind, name, subject, body, created_at, updated_at`

func scanTemplate(row pgx.Row) (Template, error) {
	var t Template
	if err := row.Scan(&t.ID, &t.TenantID, &t.Kind, &t.Name, &t.Subject, &t.Body, &t.CreatedAt, &t.UpdatedAt); err != nil {
		return Template{}, err
	}
	return t, nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// Create inserts a template for a user and returns it.
func (r *Repository) Create(ctx context.Context, q db.Querier, tenantID, createdBy uuid.UUID, in Input) (Template, error) {
	const sql = `INSERT INTO templates (tenant_id, kind, name, subject, body, created_by)
	             VALUES ($1, $2::template_kind, $3, $4, $5, $6) RETURNING ` + cols
	t, err := scanTemplate(q.QueryRow(ctx, sql, tenantID, in.Kind, in.Name, nullIfEmpty(in.Subject), in.Body, createdBy))
	if err != nil {
		return Template{}, fmt.Errorf("template: create: %w", err)
	}
	return t, nil
}

// GetByID loads a template within a tenant, or ErrNotFound.
func (r *Repository) GetByID(ctx context.Context, q db.Querier, tenantID, id uuid.UUID) (Template, error) {
	const sql = `SELECT ` + cols + ` FROM templates WHERE tenant_id = $1 AND id = $2`
	t, err := scanTemplate(q.QueryRow(ctx, sql, tenantID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Template{}, ErrNotFound
	}
	if err != nil {
		return Template{}, fmt.Errorf("template: get by id: %w", err)
	}
	return t, nil
}

// List returns a tenant's templates, newest first.
func (r *Repository) List(ctx context.Context, q db.Querier, tenantID uuid.UUID, limit, offset int) ([]Template, error) {
	const sql = `SELECT ` + cols + ` FROM templates WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`
	rows, err := q.Query(ctx, sql, tenantID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("template: list: %w", err)
	}
	defer rows.Close()
	out := make([]Template, 0)
	for rows.Next() {
		t, err := scanTemplate(rows)
		if err != nil {
			return nil, fmt.Errorf("template: scan: %w", err)
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("template: iterate: %w", err)
	}
	return out, nil
}

// Update replaces a template's mutable fields within a tenant, or ErrNotFound.
func (r *Repository) Update(ctx context.Context, q db.Querier, tenantID, id uuid.UUID, in Input) (Template, error) {
	const sql = `UPDATE templates SET kind = $3::template_kind, name = $4, subject = $5, body = $6, updated_at = now()
	             WHERE tenant_id = $1 AND id = $2 RETURNING ` + cols
	t, err := scanTemplate(q.QueryRow(ctx, sql, tenantID, id, in.Kind, in.Name, nullIfEmpty(in.Subject), in.Body))
	if errors.Is(err, pgx.ErrNoRows) {
		return Template{}, ErrNotFound
	}
	if err != nil {
		return Template{}, fmt.Errorf("template: update: %w", err)
	}
	return t, nil
}

// Delete removes a template within a tenant, or ErrNotFound.
func (r *Repository) Delete(ctx context.Context, q db.Querier, tenantID, id uuid.UUID) error {
	tag, err := q.Exec(ctx, `DELETE FROM templates WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	if err != nil {
		return fmt.Errorf("template: delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
