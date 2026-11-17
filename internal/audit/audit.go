// Package audit records operator actions to the append-only audit_log table.
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"phishforge/internal/db"
)

// Entry is a single audit record. TenantID and Action are required; the actor
// fields are optional to allow auditing of system actions and deleted users.
type Entry struct {
	TenantID   uuid.UUID
	ActorID    uuid.UUID
	ActorEmail string
	Action     string
	TargetType string
	TargetID   string
	Metadata   map[string]any
}

// Write persists e using q (pool or transaction). Passing the same transaction
// as the mutation it describes makes the action and its audit entry atomic.
// The audit_log table is append-only.
func Write(ctx context.Context, q db.Querier, e Entry) error {
	if e.TenantID == uuid.Nil {
		return fmt.Errorf("audit: tenant id is required")
	}
	if e.Action == "" {
		return fmt.Errorf("audit: action is required")
	}

	var actorID any
	if e.ActorID != uuid.Nil {
		actorID = e.ActorID
	}
	var meta any
	if e.Metadata != nil {
		b, err := json.Marshal(e.Metadata)
		if err != nil {
			return fmt.Errorf("audit: marshal metadata: %w", err)
		}
		meta = string(b)
	}

	const sql = `
INSERT INTO audit_log (tenant_id, actor_id, actor_email, action, target_type, target_id, metadata)
VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)`
	if _, err := q.Exec(ctx, sql,
		e.TenantID, actorID, nullIfEmpty(e.ActorEmail), e.Action,
		nullIfEmpty(e.TargetType), nullIfEmpty(e.TargetID), meta,
	); err != nil {
		return fmt.Errorf("audit: insert: %w", err)
	}
	return nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// Record is a stored audit_log row, for read-only listing in the dashboard.
type Record struct {
	ID         uuid.UUID      `json:"id"`
	ActorEmail *string        `json:"actor_email,omitempty"`
	Action     string         `json:"action"`
	TargetType *string        `json:"target_type,omitempty"`
	TargetID   *string        `json:"target_id,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
	CreatedAt  time.Time      `json:"created_at"`
}

// List returns a tenant's most recent audit entries (newest first).
func List(ctx context.Context, q db.Querier, tenantID uuid.UUID, limit int) ([]Record, error) {
	const sql = `
SELECT id, actor_email, action, target_type, target_id, metadata, created_at
FROM audit_log WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2`
	rows, err := q.Query(ctx, sql, tenantID, limit)
	if err != nil {
		return nil, fmt.Errorf("audit: list: %w", err)
	}
	defer rows.Close()

	out := make([]Record, 0)
	for rows.Next() {
		var (
			rec  Record
			meta []byte
		)
		if err := rows.Scan(&rec.ID, &rec.ActorEmail, &rec.Action, &rec.TargetType, &rec.TargetID, &meta, &rec.CreatedAt); err != nil {
			return nil, fmt.Errorf("audit: scan: %w", err)
		}
		if len(meta) > 0 {
			if err := json.Unmarshal(meta, &rec.Metadata); err != nil {
				return nil, fmt.Errorf("audit: decode metadata: %w", err)
			}
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: iterate: %w", err)
	}
	return out, nil
}
