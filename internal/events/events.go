// Package events appends victim-state-machine events and projects the current
// per-target state.
//
// Event history (the events table) is append-only and the source of truth;
// campaign_targets.state is a derived cache updated in the same transaction.
//
// Linear progression (monotonic, forward-only):
//
//	pending → sent → delivered → opened → clicked → creds → session_hijacked → post_exploitation
//
// Transition rules:
//   - A linear event is valid if its rank is >= the target's current rank.
//     Forward skips are allowed (telemetry is lossy); regressions are rejected.
//   - bounced / failed are early terminal branches: valid only while the target
//     is still at pending or sent. Once set, no further events are accepted.
//   - reported is a side-channel event: recorded in history, leaves state
//     unchanged, and is rejected only from a terminal (bounced/failed) state.
package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrInvalidTransition is returned when an event is not allowed from the
// target's current state.
var ErrInvalidTransition = errors.New("events: invalid state transition")

// State is a campaign_targets.state value.
type State string

const (
	StatePending          State = "pending"
	StateSent             State = "sent"
	StateDelivered        State = "delivered"
	StateOpened           State = "opened"
	StateClicked          State = "clicked"
	StateCreds            State = "creds"
	StateSessionHijacked  State = "session_hijacked"
	StatePostExploitation State = "post_exploitation"
	StateBounced          State = "bounced"
	StateFailed           State = "failed"
)

// Type is an events.type value.
type Type string

const (
	TypeSent             Type = "sent"
	TypeDelivered        Type = "delivered"
	TypeOpened           Type = "opened"
	TypeClicked          Type = "clicked"
	TypeCreds            Type = "creds"
	TypeSessionHijacked  Type = "session_hijacked"
	TypePostExploitation Type = "post_exploitation"
	TypeBounced          Type = "bounced"
	TypeFailed           Type = "failed"
	TypeReported         Type = "reported"
)

// linearRank orders the forward progression. States not present (bounced,
// failed) are terminal branches handled explicitly.
var linearRank = map[State]int{
	StatePending:          0,
	StateSent:             1,
	StateDelivered:        2,
	StateOpened:           3,
	StateClicked:          4,
	StateCreds:            5,
	StateSessionHijacked:  6,
	StatePostExploitation: 7,
}

// stateForType maps a linear/terminal event type to the state it produces.
var stateForType = map[Type]State{
	TypeSent:             StateSent,
	TypeDelivered:        StateDelivered,
	TypeOpened:           StateOpened,
	TypeClicked:          StateClicked,
	TypeCreds:            StateCreds,
	TypeSessionHijacked:  StateSessionHijacked,
	TypePostExploitation: StatePostExploitation,
	TypeBounced:          StateBounced,
	TypeFailed:           StateFailed,
}

// nextState validates ev against cur and returns the resulting state and
// whether the state advanced.
func nextState(cur State, ev Type) (State, bool, error) {
	if cur == StateBounced || cur == StateFailed {
		return cur, false, ErrInvalidTransition
	}
	switch ev {
	case TypeReported:
		return cur, false, nil
	case TypeBounced, TypeFailed:
		if linearRank[cur] > linearRank[StateSent] {
			return cur, false, ErrInvalidTransition
		}
		return stateForType[ev], true, nil
	default:
		ns, ok := stateForType[ev]
		if !ok {
			return cur, false, fmt.Errorf("events: unknown event type %q", ev)
		}
		nr, ok := linearRank[ns]
		if !ok {
			return cur, false, ErrInvalidTransition
		}
		if nr < linearRank[cur] {
			return cur, false, ErrInvalidTransition
		}
		return ns, ns != cur, nil
	}
}

// NewEvent is an event to append. A zero ContactID records the event without a
// per-target state projection. A zero OccurredAt defaults to now.
type NewEvent struct {
	TenantID   uuid.UUID
	CampaignID uuid.UUID
	ContactID  uuid.UUID
	Type       Type
	Metadata   map[string]any
	OccurredAt time.Time
}

// Event is a stored event row.
type Event struct {
	ID         uuid.UUID  `json:"id"`
	TenantID   uuid.UUID  `json:"tenant_id"`
	CampaignID uuid.UUID  `json:"campaign_id"`
	ContactID  *uuid.UUID `json:"contact_id,omitempty"`
	Type       Type       `json:"type"`
	State      State      `json:"state"`
	OccurredAt time.Time  `json:"occurred_at"`
	CreatedAt  time.Time  `json:"created_at"`
}

// Repository appends events and maintains campaign_targets.
type Repository struct {
	pool *pgxpool.Pool
}

// NewRepository returns an events repository backed by pool.
func NewRepository(pool *pgxpool.Pool) *Repository { return &Repository{pool: pool} }

// ListByTenant returns a tenant's most recent events (newest first), for the
// dashboard activity feed. State is not projected here (it is per-target); the
// Event.State field is left empty.
func (r *Repository) ListByTenant(ctx context.Context, tenantID uuid.UUID, limit int) ([]Event, error) {
	const sql = `
SELECT id, tenant_id, campaign_id, contact_id, type::text, occurred_at, created_at
FROM events WHERE tenant_id = $1 ORDER BY occurred_at DESC LIMIT $2`
	rows, err := r.pool.Query(ctx, sql, tenantID, limit)
	if err != nil {
		return nil, fmt.Errorf("events: list by tenant: %w", err)
	}
	defer rows.Close()

	out := make([]Event, 0)
	for rows.Next() {
		var (
			ev      Event
			typeStr string
			cu      uuid.NullUUID
		)
		if err := rows.Scan(&ev.ID, &ev.TenantID, &ev.CampaignID, &cu, &typeStr, &ev.OccurredAt, &ev.CreatedAt); err != nil {
			return nil, fmt.Errorf("events: scan: %w", err)
		}
		ev.Type = Type(typeStr)
		if cu.Valid {
			id := cu.UUID
			ev.ContactID = &id
		}
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("events: iterate: %w", err)
	}
	return out, nil
}

// Append validates the transition, inserts the event, and updates the target's
// projected state — all in one transaction. It returns ErrInvalidTransition if
// the event is not allowed from the current state.
func (r *Repository) Append(ctx context.Context, in NewEvent) (Event, error) {
	if in.OccurredAt.IsZero() {
		in.OccurredAt = time.Now().UTC()
	}
	hasContact := in.ContactID != uuid.Nil

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return Event{}, fmt.Errorf("events: begin: %w", err)
	}
	defer tx.Rollback(ctx)

	cur := StatePending
	targetExists := false
	if hasContact {
		var curStr string
		err = tx.QueryRow(ctx,
			`SELECT state::text FROM campaign_targets WHERE campaign_id = $1 AND contact_id = $2 FOR UPDATE`,
			in.CampaignID, in.ContactID).Scan(&curStr)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			cur = StatePending
		case err != nil:
			return Event{}, fmt.Errorf("events: load target: %w", err)
		default:
			cur = State(curStr)
			targetExists = true
		}
	}

	ns, _, err := nextState(cur, in.Type)
	if err != nil {
		return Event{}, err
	}

	meta := "{}"
	if in.Metadata != nil {
		b, err := json.Marshal(in.Metadata)
		if err != nil {
			return Event{}, fmt.Errorf("events: marshal metadata: %w", err)
		}
		meta = string(b)
	}

	var contactArg any
	if hasContact {
		contactArg = in.ContactID
	}

	var (
		ev      Event
		typeStr string
		cu      uuid.NullUUID
	)
	const ins = `
INSERT INTO events (tenant_id, campaign_id, contact_id, type, metadata, occurred_at)
VALUES ($1, $2, $3, $4::event_type, $5::jsonb, $6)
RETURNING id, tenant_id, campaign_id, contact_id, type::text, occurred_at, created_at`
	if err := tx.QueryRow(ctx, ins,
		in.TenantID, in.CampaignID, contactArg, string(in.Type), meta, in.OccurredAt).
		Scan(&ev.ID, &ev.TenantID, &ev.CampaignID, &cu, &typeStr, &ev.OccurredAt, &ev.CreatedAt); err != nil {
		return Event{}, fmt.Errorf("events: insert: %w", err)
	}
	ev.Type = Type(typeStr)
	ev.State = ns
	if cu.Valid {
		id := cu.UUID
		ev.ContactID = &id
	}

	if hasContact {
		if targetExists {
			_, err = tx.Exec(ctx,
				`UPDATE campaign_targets SET state = $3::target_state, last_event_at = $4, updated_at = now()
				 WHERE campaign_id = $1 AND contact_id = $2`,
				in.CampaignID, in.ContactID, string(ns), in.OccurredAt)
		} else {
			_, err = tx.Exec(ctx,
				`INSERT INTO campaign_targets (tenant_id, campaign_id, contact_id, state, last_event_at)
				 VALUES ($1, $2, $3, $4::target_state, $5)`,
				in.TenantID, in.CampaignID, in.ContactID, string(ns), in.OccurredAt)
		}
		if err != nil {
			return Event{}, fmt.Errorf("events: upsert target: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return Event{}, fmt.Errorf("events: commit: %w", err)
	}
	return ev, nil
}
