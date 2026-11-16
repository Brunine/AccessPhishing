// Package audit records operator actions to the append-only audit_log table.
package audit

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
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

// Logger writes audit entries using a shared connection pool.
type Logger struct {
	pool *pgxpool.Pool
}

// NewLogger returns a Logger backed by pool.
func NewLogger(pool *pgxpool.Pool) *Logger { return &Logger{pool: pool} }

// Record persists e. The audit_log table is append-only; writes never update
// or delete existing rows.
func (l *Logger) Record(ctx context.Context, e Entry) error {
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
	var actorEmail any
	if e.ActorEmail != "" {
		actorEmail = e.ActorEmail
	}
	var meta []byte
	if e.Metadata != nil {
		b, err := json.Marshal(e.Metadata)
		if err != nil {
			return fmt.Errorf("audit: marshal metadata: %w", err)
		}
		meta = b
	}

	const q = `
INSERT INTO audit_log (tenant_id, actor_id, actor_email, action, target_type, target_id, metadata)
VALUES ($1, $2, $3, $4, $5, $6, $7)`
	if _, err := l.pool.Exec(ctx, q,
		e.TenantID, actorID, actorEmail, e.Action,
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
