// Package audit records operator actions to the append-only audit_log table.
package audit

import (
	"context"
	"encoding/json"
	"fmt"

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
