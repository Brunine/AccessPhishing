// Package events appends victim-state-machine events and projects the current
// per-target state.
//
// Event history (the events table) is append-only and the source of truth;
// campaign_targets.state is a derived cache updated in the same transaction.
//
// Linear progression (monotonic, forward-only):
//
//	pending → sent → delivered → opened → scanned → clicked → creds → session_hijacked → post_exploitation
//
// scanned is the QR-scan step: it slots in immediately before clicked. A QR
// scan and the click it triggers arrive on the same /t/{token} hit, so the
// tracking handler records scanned then clicked (see internal/api). A direct
// click with no prior scan is still valid; a scan after a click is a late
// signal and is rejected as a no-op like any other regression.
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
// target's current state. Callers and tests rely on this sentinel, so it is
// retained for transition (as opposed to catalog) rejections.
var ErrInvalidTransition = errors.New("events: invalid state transition")

// ErrUnknownChannelEvent is returned when a (channel, type) pair is not defined
// in the event catalog. Unknown pairs fail closed — they are never recorded.
var ErrUnknownChannelEvent = errors.New("events: unknown channel event")

// Channel is an event_channel value: the delivery/authentication vector an
// event belongs to. The email funnel is the only populated catalog today;
// sms/qr/auth event types arrive in M9a/M9b.
type Channel string

const (
	ChannelEmail  Channel = "email"
	ChannelSMS    Channel = "sms"
	ChannelQR     Channel = "qr"
	ChannelAuth   Channel = "auth"
	ChannelSystem Channel = "system"
)

// State is a campaign_targets.state value.
type State string

const (
	StatePending          State = "pending"
	StateSent             State = "sent"
	StateDelivered        State = "delivered"
	StateOpened           State = "opened"
	StateScanned          State = "scanned"
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
	TypeScanned          Type = "scanned"
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
	StateScanned:          4,
	StateClicked:          5,
	StateCreds:            6,
	StateSessionHijacked:  7,
	StatePostExploitation: 8,
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

// specKind classifies how an event participates in the state machine.
type specKind int

const (
	kindLinear   specKind = iota // forward-only progression (rank-ordered)
	kindSide                     // recorded, never changes state (e.g. reported)
	kindTerminal                 // early-terminal branch (bounced/failed)
)

// eventSpec is a catalog entry: how a (channel, type) pair validates and what
// state it projects. rank is the linear rank for kindLinear (−1 = none);
// projects is the state the event yields ("" = none, for side-channel events).
type eventSpec struct {
	rank     int
	projects State
	kind     specKind
}

// catalog is the channel-scoped event catalog. The email catalog is DERIVED
// from linearRank/stateForType (kept as the single source of truth) so the
// email funnel is provably unchanged. The QR catalog (M9b) holds exactly one
// entry — scanned — the only event that originates on the QR channel; the click
// it triggers is recorded on the email channel like every other click, so the
// qr catalog deliberately does NOT contain clicked (a qr-channel clicked append
// still fails closed). sms/auth/system remain empty and fail closed. Built once
// at init and read-only thereafter.
//
// Cross-channel transitions are sound because linearRank is global: a
// qr-channel scanned (rank 4) advances the shared campaign_targets.state, and
// the following email-channel clicked (rank 5) validates against that state.
var catalog = buildCatalog()

func buildCatalog() map[Channel]map[Type]eventSpec {
	email := make(map[Type]eventSpec, len(stateForType)+1)
	for ev, st := range stateForType {
		if ev == TypeBounced || ev == TypeFailed {
			email[ev] = eventSpec{rank: -1, projects: st, kind: kindTerminal}
			continue
		}
		email[ev] = eventSpec{rank: linearRank[st], projects: st, kind: kindLinear}
	}
	// reported is a side-channel event: recorded, no projection.
	email[TypeReported] = eventSpec{rank: -1, projects: "", kind: kindSide}

	// QR channel (M9b): scanned is a linear step before clicked. Its rank comes
	// from the same global linearRank source of truth, so scanned → clicked
	// (recorded on the email channel) is a valid forward transition.
	qr := map[Type]eventSpec{
		TypeScanned: {rank: linearRank[StateScanned], projects: StateScanned, kind: kindLinear},
	}

	return map[Channel]map[Type]eventSpec{
		ChannelEmail:  email,
		ChannelSMS:    {},
		ChannelQR:     qr,
		ChannelAuth:   {},
		ChannelSystem: {},
	}
}

// nextState validates ev on channel ch against cur and returns the resulting
// state and whether the state advanced. Unknown (channel, type) pairs return
// ErrUnknownChannelEvent (fail closed); disallowed transitions for a known pair
// return ErrInvalidTransition.
func nextState(cur State, ev Type, ch Channel) (State, bool, error) {
	chCatalog, ok := catalog[ch]
	if !ok {
		return cur, false, fmt.Errorf("%w: channel %q", ErrUnknownChannelEvent, ch)
	}
	spec, ok := chCatalog[ev]
	if !ok {
		return cur, false, fmt.Errorf("%w: channel %q type %q", ErrUnknownChannelEvent, ch, ev)
	}

	// A terminal current state rejects everything, including side-channel events.
	if cur == StateBounced || cur == StateFailed {
		return cur, false, ErrInvalidTransition
	}

	switch spec.kind {
	case kindSide:
		return cur, false, nil
	case kindTerminal:
		// Early-terminal branch: valid only while still at pending or sent.
		if linearRank[cur] > linearRank[StateSent] {
			return cur, false, ErrInvalidTransition
		}
		return spec.projects, true, nil
	default: // kindLinear
		if spec.rank < linearRank[cur] {
			return cur, false, ErrInvalidTransition
		}
		return spec.projects, spec.projects != cur, nil
	}
}

// NewEvent is an event to append. A zero ContactID records the event without a
// per-target state projection. A zero OccurredAt defaults to now.
type NewEvent struct {
	TenantID   uuid.UUID
	CampaignID uuid.UUID
	ContactID  uuid.UUID
	Type       Type
	// Channel is the event vector. The zero value is treated as ChannelEmail
	// in Append, so existing callers that do not set it are unaffected.
	Channel    Channel
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
	Channel    Channel    `json:"channel"`
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
SELECT id, tenant_id, campaign_id, contact_id, type::text, channel::text, occurred_at, created_at
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
			chStr   string
			cu      uuid.NullUUID
		)
		if err := rows.Scan(&ev.ID, &ev.TenantID, &ev.CampaignID, &cu, &typeStr, &chStr, &ev.OccurredAt, &ev.CreatedAt); err != nil {
			return nil, fmt.Errorf("events: scan: %w", err)
		}
		ev.Type = Type(typeStr)
		ev.Channel = Channel(chStr)
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
	// Default the channel to email so existing callers that do not set it are
	// unaffected (the email catalog is the only populated one today).
	if in.Channel == "" {
		in.Channel = ChannelEmail
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

	ns, _, err := nextState(cur, in.Type, in.Channel)
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
		chStr   string
		cu      uuid.NullUUID
	)
	const ins = `
INSERT INTO events (tenant_id, campaign_id, contact_id, type, channel, metadata, occurred_at)
VALUES ($1, $2, $3, $4::event_type, $5::event_channel, $6::jsonb, $7)
RETURNING id, tenant_id, campaign_id, contact_id, type::text, channel::text, occurred_at, created_at`
	if err := tx.QueryRow(ctx, ins,
		in.TenantID, in.CampaignID, contactArg, string(in.Type), string(in.Channel), meta, in.OccurredAt).
		Scan(&ev.ID, &ev.TenantID, &ev.CampaignID, &cu, &typeStr, &chStr, &ev.OccurredAt, &ev.CreatedAt); err != nil {
		return Event{}, fmt.Errorf("events: insert: %w", err)
	}
	ev.Type = Type(typeStr)
	ev.Channel = Channel(chStr)
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
