package domain

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"phishforge/internal/audit"
)

// ExpiryBatchSize bounds how many domains one roll statement transitions, so a
// large backlog is drained in bounded passes rather than one unbounded UPDATE.
const ExpiryBatchSize = 500

// Roller rolls domains whose registration has lapsed (expires_at in the past)
// to 'expired'. It runs in the worker process on a fixed cadence and is
// intentionally NOT tenant-scoped: a lapsed registration is a global fact, so a
// single pass sweeps every tenant. Each transitioned row gets an append-only
// audit entry (system actor, from/to metadata) in the same transaction as the
// status change.
//
// This is a non-interactive system sweep and deliberately sits outside the
// interactive transition guard (internal/domain.allowed), which governs
// operator-driven actions: in particular it expires 'suspended' domains, a
// transition the operator-facing lifecycle does not offer. See
// docs/adr/ADR-0002-domain-expiry.md.
type Roller struct {
	pool *pgxpool.Pool
}

// NewRoller builds an expiry roller over a connection pool.
func NewRoller(pool *pgxpool.Pool) *Roller { return &Roller{pool: pool} }

// rollSQL atomically selects up to $1 lapsed, rollable domains (locking them,
// skipping any a concurrent pass already holds) and flips them to 'expired',
// returning each row's id, tenant, and PRIOR status for the audit trail.
const rollSQL = `
UPDATE domains d
SET status = 'expired', updated_at = now()
FROM (
    SELECT id, status
    FROM domains
    WHERE expires_at IS NOT NULL
      AND expires_at < now()
      AND status IN ('verified', 'active', 'suspended')
    ORDER BY id
    LIMIT $1
    FOR UPDATE SKIP LOCKED
) old
WHERE d.id = old.id
RETURNING d.id, d.tenant_id, old.status::text`

// RollOnce drains every lapsed domain in bounded batches and returns the total
// number transitioned. It is idempotent and safe to call on an empty inventory
// (returns 0, nil): only domains whose expires_at is in the past and whose
// status is verified/active/suspended are affected.
func (r *Roller) RollOnce(ctx context.Context) (int, error) {
	total := 0
	for {
		n, err := r.rollBatch(ctx)
		if err != nil {
			return total, err
		}
		total += n
		if n < ExpiryBatchSize {
			break
		}
	}
	return total, nil
}

// rollBatch transitions one batch (<= ExpiryBatchSize) and writes its audit
// entries in the same transaction, so the status change and its audit trail
// commit together.
func (r *Roller) rollBatch(ctx context.Context) (int, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("domain: expiry roll begin: %w", err)
	}
	defer tx.Rollback(ctx)

	type hit struct {
		id       uuid.UUID
		tenantID uuid.UUID
		from     string
	}
	rows, err := tx.Query(ctx, rollSQL, ExpiryBatchSize)
	if err != nil {
		return 0, fmt.Errorf("domain: expiry roll query: %w", err)
	}
	var hits []hit
	for rows.Next() {
		var h hit
		if err := rows.Scan(&h.id, &h.tenantID, &h.from); err != nil {
			rows.Close()
			return 0, fmt.Errorf("domain: expiry roll scan: %w", err)
		}
		hits = append(hits, h)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("domain: expiry roll iterate: %w", err)
	}

	for _, h := range hits {
		if err := audit.Write(ctx, tx, audit.Entry{
			TenantID:   h.tenantID,
			Action:     "domain.expire",
			TargetType: "domain",
			TargetID:   h.id.String(),
			Metadata:   map[string]any{"from": h.from, "to": string(StatusExpired), "by": "system.expiry_roll"},
		}); err != nil {
			return 0, fmt.Errorf("domain: expiry roll audit: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("domain: expiry roll commit: %w", err)
	}
	return len(hits), nil
}
