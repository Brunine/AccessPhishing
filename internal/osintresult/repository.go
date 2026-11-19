// Package osintresult persists OSINT collection results, one row per (tenant,
// domain) with upsert-on-recollect semantics.
package osintresult

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"phishforge/internal/db"
)

// Result is a stored OSINT collection for a domain.
type Result struct {
	ID        uuid.UUID       `json:"id"`
	TenantID  uuid.UUID       `json:"tenant_id"`
	Domain    string          `json:"domain"`
	Result    json.RawMessage `json:"result"`
	CreatedBy *uuid.UUID      `json:"created_by,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
}

// Repository provides osint_results persistence. Stateless; tenant-scoped.
type Repository struct{}

// NewRepository returns an osint-result repository.
func NewRepository() *Repository { return &Repository{} }

const cols = `id, tenant_id, domain, result, created_by, created_at`

func scan(row pgx.Row) (Result, error) {
	var (
		r  Result
		cb uuid.NullUUID
	)
	if err := row.Scan(&r.ID, &r.TenantID, &r.Domain, &r.Result, &cb, &r.CreatedAt); err != nil {
		return Result{}, err
	}
	if cb.Valid {
		id := cb.UUID
		r.CreatedBy = &id
	}
	return r, nil
}

// Upsert stores (or refreshes) the result for a (tenant, domain) and returns the
// stored row. result must be valid JSON.
func (r *Repository) Upsert(ctx context.Context, q db.Querier, tenantID uuid.UUID, createdBy uuid.UUID, domain string, result []byte) (Result, error) {
	var createdArg any
	if createdBy != uuid.Nil {
		createdArg = createdBy
	}
	const sql = `
INSERT INTO osint_results (tenant_id, domain, result, created_by)
VALUES ($1, $2, $3::jsonb, $4)
ON CONFLICT (tenant_id, domain)
DO UPDATE SET result = EXCLUDED.result, created_by = EXCLUDED.created_by, created_at = now()
RETURNING ` + cols
	res, err := scan(q.QueryRow(ctx, sql, tenantID, domain, string(result), createdArg))
	if err != nil {
		return Result{}, fmt.Errorf("osintresult: upsert: %w", err)
	}
	return res, nil
}

// List returns a tenant's stored results, newest first.
func (r *Repository) List(ctx context.Context, q db.Querier, tenantID uuid.UUID, limit, offset int) ([]Result, error) {
	const sql = `SELECT ` + cols + ` FROM osint_results WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`
	rows, err := q.Query(ctx, sql, tenantID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("osintresult: list: %w", err)
	}
	defer rows.Close()

	out := make([]Result, 0)
	for rows.Next() {
		res, err := scan(rows)
		if err != nil {
			return nil, fmt.Errorf("osintresult: scan: %w", err)
		}
		out = append(out, res)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("osintresult: iterate: %w", err)
	}
	return out, nil
}
