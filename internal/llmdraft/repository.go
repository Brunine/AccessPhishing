// Package llmdraft holds LLM-generated message drafts and their tenant-scoped
// repository. A draft is promoted to a template only after the existing
// approval gate passes (approvals.subject_type = 'llm_draft').
package llmdraft

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"phishforge/internal/db"
)

// ErrNotFound is returned when a draft does not exist within the tenant.
var ErrNotFound = errors.New("llmdraft: not found")

// ValidKind reports whether k is a valid llm_draft_kind enum value.
func ValidKind(k string) bool {
	switch k {
	case "email", "sms", "landing":
		return true
	default:
		return false
	}
}

// Draft is an LLM-generated content record awaiting review.
type Draft struct {
	ID            uuid.UUID  `json:"id"`
	TenantID      uuid.UUID  `json:"tenant_id"`
	CreatedBy     *uuid.UUID `json:"created_by,omitempty"`
	Kind          string     `json:"kind"`
	Name          string     `json:"name"`
	Subject       *string    `json:"subject,omitempty"`
	Body          string     `json:"body"`
	Model         string     `json:"model"`
	PromptSummary string     `json:"prompt_summary"`
	Status        string     `json:"status"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// Input carries the fields of a new draft.
type Input struct {
	Kind          string
	Name          string
	Subject       string
	Body          string
	Model         string
	PromptSummary string
}

// Repository provides draft persistence. Stateless; tenant-scoped.
type Repository struct{}

// NewRepository returns a draft repository.
func NewRepository() *Repository { return &Repository{} }

const cols = `id, tenant_id, created_by, kind, name, subject, body, model, prompt_summary, status, created_at, updated_at`

func scanDraft(row pgx.Row) (Draft, error) {
	var (
		d  Draft
		cb uuid.NullUUID
	)
	if err := row.Scan(&d.ID, &d.TenantID, &cb, &d.Kind, &d.Name, &d.Subject, &d.Body,
		&d.Model, &d.PromptSummary, &d.Status, &d.CreatedAt, &d.UpdatedAt); err != nil {
		return Draft{}, err
	}
	if cb.Valid {
		id := cb.UUID
		d.CreatedBy = &id
	}
	return d, nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// Create inserts a new draft (status 'draft') and returns the stored row.
func (r *Repository) Create(ctx context.Context, q db.Querier, tenantID, createdBy uuid.UUID, in Input) (Draft, error) {
	const sql = `
INSERT INTO llm_drafts (tenant_id, created_by, kind, name, subject, body, model, prompt_summary)
VALUES ($1, $2, $3::llm_draft_kind, $4, $5, $6, $7, $8)
RETURNING ` + cols
	var createdArg any
	if createdBy != uuid.Nil {
		createdArg = createdBy
	}
	d, err := scanDraft(q.QueryRow(ctx, sql, tenantID, createdArg, in.Kind, in.Name,
		nullIfEmpty(in.Subject), in.Body, in.Model, in.PromptSummary))
	if err != nil {
		return Draft{}, fmt.Errorf("llmdraft: create: %w", err)
	}
	return d, nil
}

// GetByID loads a draft within a tenant, or ErrNotFound.
func (r *Repository) GetByID(ctx context.Context, q db.Querier, tenantID, id uuid.UUID) (Draft, error) {
	const sql = `SELECT ` + cols + ` FROM llm_drafts WHERE tenant_id = $1 AND id = $2`
	d, err := scanDraft(q.QueryRow(ctx, sql, tenantID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Draft{}, ErrNotFound
	}
	if err != nil {
		return Draft{}, fmt.Errorf("llmdraft: get by id: %w", err)
	}
	return d, nil
}

// List returns a tenant's drafts, newest first.
func (r *Repository) List(ctx context.Context, q db.Querier, tenantID uuid.UUID, limit, offset int) ([]Draft, error) {
	const sql = `SELECT ` + cols + ` FROM llm_drafts WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`
	rows, err := q.Query(ctx, sql, tenantID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("llmdraft: list: %w", err)
	}
	defer rows.Close()

	out := make([]Draft, 0)
	for rows.Next() {
		d, err := scanDraft(rows)
		if err != nil {
			return nil, fmt.Errorf("llmdraft: scan: %w", err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("llmdraft: iterate: %w", err)
	}
	return out, nil
}

// SetStatus transitions a draft's status within a tenant, or ErrNotFound.
func (r *Repository) SetStatus(ctx context.Context, q db.Querier, tenantID, id uuid.UUID, status string) (Draft, error) {
	const sql = `UPDATE llm_drafts SET status = $3::llm_draft_status, updated_at = now()
	             WHERE tenant_id = $1 AND id = $2 RETURNING ` + cols
	d, err := scanDraft(q.QueryRow(ctx, sql, tenantID, id, status))
	if errors.Is(err, pgx.ErrNoRows) {
		return Draft{}, ErrNotFound
	}
	if err != nil {
		return Draft{}, fmt.Errorf("llmdraft: set status: %w", err)
	}
	return d, nil
}
