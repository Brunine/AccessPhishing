package prompttpl

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

// ErrNotFound is returned when a template does not exist within the tenant.
var ErrNotFound = errors.New("prompttpl: not found")

// Template is a stored prompt template.
type Template struct {
	ID           uuid.UUID  `json:"id"`
	TenantID     uuid.UUID  `json:"tenant_id"`
	Name         string     `json:"name"`
	Kind         string     `json:"kind"`
	SystemPrompt string     `json:"system_prompt"`
	UserTemplate string     `json:"user_template"`
	Variables    []Variable `json:"variables"`
	IsDefault    bool       `json:"is_default"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

// Input carries the mutable fields of a prompt template.
type Input struct {
	Name         string
	Kind         string
	SystemPrompt string
	UserTemplate string
	Variables    []Variable
	IsDefault    bool
}

// Repository provides prompt-template persistence. Stateless; tenant-scoped.
type Repository struct{}

// NewRepository returns a prompt-template repository.
func NewRepository() *Repository { return &Repository{} }

const cols = `id, tenant_id, name, kind, system_prompt, user_template, variables, is_default, created_at, updated_at`

func scanTemplate(row pgx.Row) (Template, error) {
	var (
		t    Template
		vars []byte
	)
	if err := row.Scan(&t.ID, &t.TenantID, &t.Name, &t.Kind, &t.SystemPrompt,
		&t.UserTemplate, &vars, &t.IsDefault, &t.CreatedAt, &t.UpdatedAt); err != nil {
		return Template{}, err
	}
	if len(vars) > 0 {
		if err := json.Unmarshal(vars, &t.Variables); err != nil {
			return Template{}, fmt.Errorf("prompttpl: decode variables: %w", err)
		}
	}
	if t.Variables == nil {
		t.Variables = []Variable{}
	}
	return t, nil
}

func varsJSON(vars []Variable) (string, error) {
	if vars == nil {
		vars = []Variable{}
	}
	b, err := json.Marshal(vars)
	if err != nil {
		return "", fmt.Errorf("prompttpl: encode variables: %w", err)
	}
	return string(b), nil
}

// Create inserts a template and returns the stored row.
func (r *Repository) Create(ctx context.Context, q db.Querier, tenantID uuid.UUID, in Input) (Template, error) {
	vars, err := varsJSON(in.Variables)
	if err != nil {
		return Template{}, err
	}
	const sql = `
INSERT INTO prompt_templates (tenant_id, name, kind, system_prompt, user_template, variables, is_default)
VALUES ($1, $2, $3::llm_draft_kind, $4, $5, $6::jsonb, $7)
RETURNING ` + cols
	t, err := scanTemplate(q.QueryRow(ctx, sql, tenantID, in.Name, in.Kind, in.SystemPrompt, in.UserTemplate, vars, in.IsDefault))
	if err != nil {
		return Template{}, fmt.Errorf("prompttpl: create: %w", err)
	}
	return t, nil
}

// GetByID loads a template within a tenant, or ErrNotFound.
func (r *Repository) GetByID(ctx context.Context, q db.Querier, tenantID, id uuid.UUID) (Template, error) {
	const sql = `SELECT ` + cols + ` FROM prompt_templates WHERE tenant_id = $1 AND id = $2`
	t, err := scanTemplate(q.QueryRow(ctx, sql, tenantID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Template{}, ErrNotFound
	}
	if err != nil {
		return Template{}, fmt.Errorf("prompttpl: get by id: %w", err)
	}
	return t, nil
}

// List returns a tenant's templates, newest first.
func (r *Repository) List(ctx context.Context, q db.Querier, tenantID uuid.UUID, limit, offset int) ([]Template, error) {
	const sql = `SELECT ` + cols + ` FROM prompt_templates WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`
	rows, err := q.Query(ctx, sql, tenantID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("prompttpl: list: %w", err)
	}
	defer rows.Close()

	out := make([]Template, 0)
	for rows.Next() {
		t, err := scanTemplate(rows)
		if err != nil {
			return nil, fmt.Errorf("prompttpl: scan: %w", err)
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("prompttpl: iterate: %w", err)
	}
	return out, nil
}

// Update replaces a template's mutable fields within a tenant, or ErrNotFound.
func (r *Repository) Update(ctx context.Context, q db.Querier, tenantID, id uuid.UUID, in Input) (Template, error) {
	vars, err := varsJSON(in.Variables)
	if err != nil {
		return Template{}, err
	}
	const sql = `
UPDATE prompt_templates
SET name = $3, kind = $4::llm_draft_kind, system_prompt = $5, user_template = $6,
    variables = $7::jsonb, is_default = $8, updated_at = now()
WHERE tenant_id = $1 AND id = $2
RETURNING ` + cols
	t, err := scanTemplate(q.QueryRow(ctx, sql, tenantID, id, in.Name, in.Kind, in.SystemPrompt, in.UserTemplate, vars, in.IsDefault))
	if errors.Is(err, pgx.ErrNoRows) {
		return Template{}, ErrNotFound
	}
	if err != nil {
		return Template{}, fmt.Errorf("prompttpl: update: %w", err)
	}
	return t, nil
}

// Delete removes a template within a tenant, or ErrNotFound.
func (r *Repository) Delete(ctx context.Context, q db.Querier, tenantID, id uuid.UUID) error {
	const sql = `DELETE FROM prompt_templates WHERE tenant_id = $1 AND id = $2`
	tag, err := q.Exec(ctx, sql, tenantID, id)
	if err != nil {
		return fmt.Errorf("prompttpl: delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
