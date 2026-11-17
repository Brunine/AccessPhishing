// Package approval implements the draft→approved/rejected gate that guards
// sending. A subject (e.g. a template) may not be sent until an approval row
// for it reaches status 'approved'.
package approval

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"phishforge/internal/db"
)

// ErrNotFound is returned when an approval does not exist within the tenant.
var ErrNotFound = errors.New("approval: not found")

// Approval tracks the review state of a subject (e.g. subject_type 'template').
type Approval struct {
	ID          uuid.UUID  `json:"id"`
	TenantID    uuid.UUID  `json:"tenant_id"`
	SubjectType string     `json:"subject_type"`
	SubjectID   uuid.UUID  `json:"subject_id"`
	Status      string     `json:"status"`
	RequestedBy *uuid.UUID `json:"requested_by,omitempty"`
	DecidedBy   *uuid.UUID `json:"decided_by,omitempty"`
	DecidedAt   *time.Time `json:"decided_at,omitempty"`
	Notes       *string    `json:"notes,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// Repository provides approval persistence. Stateless; tenant-scoped.
type Repository struct{}

// NewRepository returns an approval repository.
func NewRepository() *Repository { return &Repository{} }

const cols = `id, tenant_id, subject_type, subject_id, status, requested_by, decided_by, decided_at, notes, created_at, updated_at`

func scanApproval(row pgx.Row) (Approval, error) {
	var (
		a   Approval
		req uuid.NullUUID
		dec uuid.NullUUID
	)
	if err := row.Scan(&a.ID, &a.TenantID, &a.SubjectType, &a.SubjectID, &a.Status, &req, &dec, &a.DecidedAt, &a.Notes, &a.CreatedAt, &a.UpdatedAt); err != nil {
		return Approval{}, err
	}
	if req.Valid {
		id := req.UUID
		a.RequestedBy = &id
	}
	if dec.Valid {
		id := dec.UUID
		a.DecidedBy = &id
	}
	return a, nil
}

// Request creates a pending ('draft') approval for a subject.
func (r *Repository) Request(ctx context.Context, q db.Querier, tenantID, requestedBy uuid.UUID, subjectType string, subjectID uuid.UUID) (Approval, error) {
	const sql = `INSERT INTO approvals (tenant_id, subject_type, subject_id, status, requested_by)
	             VALUES ($1, $2, $3, 'draft', $4) RETURNING ` + cols
	a, err := scanApproval(q.QueryRow(ctx, sql, tenantID, subjectType, subjectID, requestedBy))
	if err != nil {
		return Approval{}, fmt.Errorf("approval: request: %w", err)
	}
	return a, nil
}

// Decide sets an approval to 'approved' or 'rejected' with the deciding actor.
func (r *Repository) Decide(ctx context.Context, q db.Querier, tenantID, id, decidedBy uuid.UUID, status, notes string) (Approval, error) {
	const sql = `UPDATE approvals
	             SET status = $3::approval_status, decided_by = $4, decided_at = now(), notes = $5, updated_at = now()
	             WHERE tenant_id = $1 AND id = $2 RETURNING ` + cols
	var notesArg any
	if notes != "" {
		notesArg = notes
	}
	a, err := scanApproval(q.QueryRow(ctx, sql, tenantID, id, status, decidedBy, notesArg))
	if errors.Is(err, pgx.ErrNoRows) {
		return Approval{}, ErrNotFound
	}
	if err != nil {
		return Approval{}, fmt.Errorf("approval: decide: %w", err)
	}
	return a, nil
}

// List returns a tenant's approvals, newest first.
func (r *Repository) List(ctx context.Context, q db.Querier, tenantID uuid.UUID, limit, offset int) ([]Approval, error) {
	const sql = `SELECT ` + cols + ` FROM approvals WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`
	rows, err := q.Query(ctx, sql, tenantID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("approval: list: %w", err)
	}
	defer rows.Close()
	out := make([]Approval, 0)
	for rows.Next() {
		a, err := scanApproval(rows)
		if err != nil {
			return nil, fmt.Errorf("approval: scan: %w", err)
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("approval: iterate: %w", err)
	}
	return out, nil
}

// IsApproved reports whether an 'approved' row exists for the subject.
func (r *Repository) IsApproved(ctx context.Context, q db.Querier, tenantID uuid.UUID, subjectType string, subjectID uuid.UUID) (bool, error) {
	var ok bool
	const sql = `SELECT EXISTS (
	               SELECT 1 FROM approvals
	               WHERE tenant_id = $1 AND subject_type = $2 AND subject_id = $3 AND status = 'approved')`
	if err := q.QueryRow(ctx, sql, tenantID, subjectType, subjectID).Scan(&ok); err != nil {
		return false, fmt.Errorf("approval: is approved: %w", err)
	}
	return ok, nil
}
