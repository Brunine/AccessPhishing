package events

import (
	"errors"
	"fmt"
	"testing"
)

// allStates and allTypes enumerate the full email domain for exhaustive tests.
var allStates = []State{
	StatePending, StateSent, StateDelivered, StateOpened, StateClicked,
	StateCreds, StateSessionHijacked, StatePostExploitation, StateBounced, StateFailed,
}

var allTypes = []Type{
	TypeSent, TypeDelivered, TypeOpened, TypeClicked, TypeCreds,
	TypeSessionHijacked, TypePostExploitation, TypeBounced, TypeFailed, TypeReported,
}

// oldNextState is a verbatim copy of the pre-refactor (channel-less) transition
// validator. The equivalence test asserts the new channel-scoped nextState
// produces byte-identical results for the email channel across every
// (state, type) pair — the core invariant of this task.
func oldNextState(cur State, ev Type) (State, bool, error) {
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

func TestEmailTransitionEquivalence(t *testing.T) {
	for _, cur := range allStates {
		for _, ev := range allTypes {
			wantState, wantAdv, wantErr := oldNextState(cur, ev)
			gotState, gotAdv, gotErr := nextState(cur, ev, ChannelEmail)

			if (wantErr == nil) != (gotErr == nil) {
				t.Fatalf("(%s,%s): err presence differs: old=%v new=%v", cur, ev, wantErr, gotErr)
			}
			if wantErr != nil {
				// Every rejection in the enumerated email domain is an invalid
				// transition; the new code must keep that sentinel (never
				// ErrUnknownChannelEvent — all email types are catalogued).
				if !errors.Is(gotErr, ErrInvalidTransition) {
					t.Fatalf("(%s,%s): want ErrInvalidTransition, got %v", cur, ev, gotErr)
				}
				if errors.Is(gotErr, ErrUnknownChannelEvent) {
					t.Fatalf("(%s,%s): email event wrongly reported as unknown-channel", cur, ev)
				}
			}
			if gotState != wantState || gotAdv != wantAdv {
				t.Fatalf("(%s,%s): got (%s,%v) want (%s,%v)", cur, ev, gotState, gotAdv, wantState, wantAdv)
			}
		}
	}
}

// TestEmailBoundaryCases documents the key semantics explicitly (beyond the
// exhaustive sweep above).
func TestEmailBoundaryCases(t *testing.T) {
	ok := func(cur State, ev Type, wantState State, wantAdv bool) {
		t.Helper()
		gs, ga, err := nextState(cur, ev, ChannelEmail)
		if err != nil || gs != wantState || ga != wantAdv {
			t.Fatalf("nextState(%s,%s): got (%s,%v,%v), want (%s,%v,nil)", cur, ev, gs, ga, err, wantState, wantAdv)
		}
	}
	reject := func(cur State, ev Type) {
		t.Helper()
		if _, _, err := nextState(cur, ev, ChannelEmail); !errors.Is(err, ErrInvalidTransition) {
			t.Fatalf("nextState(%s,%s): want ErrInvalidTransition, got %v", cur, ev, err)
		}
	}

	// rank equality: re-asserting the same state advances=false, no error.
	ok(StateClicked, TypeClicked, StateClicked, false)
	// skip-forward: clicked -> session_hijacked is allowed.
	ok(StateClicked, TypeSessionHijacked, StateSessionHijacked, true)
	// regression: delivered -> sent rejected.
	reject(StateDelivered, TypeSent)
	// reported is side-channel: recorded, no state change, no error.
	ok(StateClicked, TypeReported, StateClicked, false)
	// bounced/failed valid from pending and sent only.
	ok(StatePending, TypeBounced, StateBounced, true)
	ok(StateSent, TypeFailed, StateFailed, true)
	// bounced/failed rejected once past sent.
	reject(StateClicked, TypeBounced)
	reject(StateOpened, TypeFailed)
	// terminal current state rejects everything, including reported.
	reject(StateBounced, TypeReported)
	reject(StateFailed, TypeClicked)
}

func TestNonEmailChannelsFailClosed(t *testing.T) {
	for _, ch := range []Channel{ChannelSMS, ChannelQR, ChannelAuth, ChannelSystem} {
		for _, ev := range allTypes {
			_, _, err := nextState(StatePending, ev, ch)
			if !errors.Is(err, ErrUnknownChannelEvent) {
				t.Fatalf("channel %q type %q: want ErrUnknownChannelEvent, got %v", ch, ev, err)
			}
		}
	}
	// An entirely unknown channel also fails closed.
	if _, _, err := nextState(StatePending, TypeClicked, Channel("bogus")); !errors.Is(err, ErrUnknownChannelEvent) {
		t.Fatalf("unknown channel: want ErrUnknownChannelEvent, got %v", err)
	}
}

func TestCatalogShape(t *testing.T) {
	// email has one entry per stateForType type plus reported.
	if got, want := len(catalog[ChannelEmail]), len(stateForType)+1; got != want {
		t.Fatalf("email catalog size: got %d want %d", got, want)
	}
	for _, ch := range []Channel{ChannelSMS, ChannelQR, ChannelAuth, ChannelSystem} {
		if len(catalog[ch]) != 0 {
			t.Fatalf("channel %q catalog should be empty, got %d entries", ch, len(catalog[ch]))
		}
	}
	// Spot-check kinds are derived correctly from the source-of-truth maps.
	if catalog[ChannelEmail][TypeClicked].kind != kindLinear {
		t.Fatal("clicked should be linear")
	}
	if catalog[ChannelEmail][TypeReported].kind != kindSide {
		t.Fatal("reported should be side-channel")
	}
	if catalog[ChannelEmail][TypeBounced].kind != kindTerminal {
		t.Fatal("bounced should be terminal")
	}
	if catalog[ChannelEmail][TypeClicked].rank != linearRank[StateClicked] {
		t.Fatal("clicked rank must match linearRank source of truth")
	}
}
