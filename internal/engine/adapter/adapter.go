// Package adapter puts a pluggable driver behind each engine record so the
// platform can supervise heterogeneous engines through one lifecycle contract.
//
// This milestone (M10a groundwork) ships exactly one driver — the builtin
// local-subprocess supervisor (internal/engine.Manager). Real external
// red-team engine drivers (M10 proper) register additional adapters under
// their engine "kind" without touching the handlers.
//
// Resolution is keyed by the engine config's `kind`. A Registry fails closed
// (ErrUnknownKind) on an unregistered kind unless a fallback adapter is
// installed — consistent with events.ErrUnknownChannelEvent. In this milestone
// the API installs the kind-agnostic builtin adapter as the fallback (it
// launches the single configured ENGINE_BINARY_PATH regardless of the declared
// kind), so existing engines keep working; M10 can drop the fallback to
// enforce a strict per-kind allow-list.
package adapter

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"phishforge/internal/engine"
	"phishforge/internal/engineconfig"
)

// Status is the adapter-level health vocabulary. It is intentionally distinct
// from the DB engine_status enum and from engine.State: it is what a driver
// reports about a running instance, mapped onto the persisted snapshot.
type Status string

const (
	StatusUnknown  Status = "unknown"  // not tracked by this instance
	StatusStarting Status = "starting" // up but restarting / not yet stable
	StatusRunning  Status = "running"  // up and stable
	StatusStopped  Status = "stopped"  // exited cleanly / stopped by operator
	StatusFailed   Status = "failed"   // crashed or restarts exhausted
)

// Health is a point-in-time adapter health report for one engine instance.
type Health struct {
	Status Status `json:"status"`
	Detail string `json:"detail"`
	// Live is true when the adapter currently tracks an instance for the id in
	// this process. When false, callers fall back to the persisted snapshot.
	Live bool `json:"live"`
}

// ErrUnknownKind is returned when no adapter is registered for an engine kind
// and no fallback is configured. Unknown kinds fail closed — they are never
// started.
var ErrUnknownKind = errors.New("engine/adapter: unknown engine kind")

// Adapter drives one class of engines behind a uniform lifecycle. id is the
// engine row UUID string (the Manager keys processes by it).
type Adapter interface {
	// Kind is the adapter's registration key.
	Kind() string
	// Start launches the engine instance for id with the validated config.
	Start(ctx context.Context, id string, cfg engineconfig.Config) error
	// Stop terminates the engine instance for id.
	Stop(ctx context.Context, id string) error
	// Health reports the adapter's current view of id.
	Health(ctx context.Context, id string) Health
}

// Registry resolves an Adapter by engine kind. Safe for concurrent use.
type Registry struct {
	mu       sync.RWMutex
	byKind   map[string]Adapter
	fallback Adapter
}

// NewRegistry returns an empty registry (no fallback — strict fail-closed).
func NewRegistry() *Registry {
	return &Registry{byKind: make(map[string]Adapter)}
}

// Register maps a.Kind() to a (a later registration of the same kind wins).
func (r *Registry) Register(a Adapter) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byKind[a.Kind()] = a
}

// SetFallback installs an adapter used for any kind without an explicit
// registration. Passing nil restores strict fail-closed resolution.
func (r *Registry) SetFallback(a Adapter) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fallback = a
}

// Get resolves the adapter for kind: an explicit registration first, then the
// fallback, else ErrUnknownKind.
func (r *Registry) Get(kind string) (Adapter, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if a, ok := r.byKind[kind]; ok {
		return a, nil
	}
	if r.fallback != nil {
		return r.fallback, nil
	}
	return nil, fmt.Errorf("%w: %q", ErrUnknownKind, kind)
}

// BuiltinKind is the registration key of the local-subprocess adapter.
const BuiltinKind = "builtin"

// Builtin drives engines as supervised local subprocesses via engine.Manager.
// It is kind-agnostic — it launches the single configured ENGINE_BINARY_PATH
// regardless of the declared engine kind — so the API installs it as the
// registry fallback for this milestone.
type Builtin struct {
	mgr *engine.Manager
}

// NewBuiltin wraps a Manager as an Adapter. mgr must be non-nil.
func NewBuiltin(mgr *engine.Manager) *Builtin { return &Builtin{mgr: mgr} }

// Kind implements Adapter.
func (b *Builtin) Kind() string { return BuiltinKind }

// Start implements Adapter. It returns the Manager's sentinel errors unchanged
// (engine.ErrNoBinary / engine.ErrAlreadyRunning) so the HTTP layer maps them
// to the same 503 / 409 responses as before.
func (b *Builtin) Start(_ context.Context, id string, cfg engineconfig.Config) error {
	return b.mgr.Start(id, cfg)
}

// Stop implements Adapter.
func (b *Builtin) Stop(_ context.Context, id string) error {
	return b.mgr.Stop(id)
}

// Health implements Adapter by mapping the Manager's process status.
func (b *Builtin) Health(_ context.Context, id string) Health {
	st, live := b.mgr.Status(id)
	return healthFromStatus(st, live)
}

// healthFromStatus is the pure mapping from a Manager status to adapter Health
// (extracted for unit testing without a real process).
func healthFromStatus(st engine.Status, live bool) Health {
	if !live {
		return Health{Status: StatusUnknown, Live: false, Detail: "no tracked process in this instance"}
	}
	switch st.State {
	case engine.StateRunning:
		if st.Restarts > 0 {
			return Health{
				Status: StatusStarting,
				Live:   true,
				Detail: fmt.Sprintf("running after %d restart(s), pid %d", st.Restarts, st.Pid),
			}
		}
		return Health{Status: StatusRunning, Live: true, Detail: fmt.Sprintf("running, pid %d", st.Pid)}
	case engine.StateExited:
		return Health{Status: StatusStopped, Live: true, Detail: "process exited"}
	default: // engine.StateFailed
		detail := "process failed"
		if st.ExitErr != "" {
			detail = st.ExitErr
		}
		return Health{Status: StatusFailed, Live: true, Detail: detail}
	}
}
