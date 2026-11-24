package adapter

import (
	"context"
	"errors"
	"testing"
	"time"

	"phishforge/internal/engine"
	"phishforge/internal/engineconfig"
)

// fakeAdapter records dispatch and satisfies Adapter without a real process.
type fakeAdapter struct {
	kind     string
	started  []string
	stopped  []string
	health   Health
	startErr error
}

func (f *fakeAdapter) Kind() string { return f.kind }
func (f *fakeAdapter) Start(_ context.Context, id string, _ engineconfig.Config) error {
	f.started = append(f.started, id)
	return f.startErr
}
func (f *fakeAdapter) Stop(_ context.Context, id string) error {
	f.stopped = append(f.stopped, id)
	return nil
}
func (f *fakeAdapter) Health(_ context.Context, _ string) Health { return f.health }

func TestRegistryFailsClosedOnUnknownKind(t *testing.T) {
	reg := NewRegistry()
	// No registration, no fallback => unknown kind fails closed.
	if _, err := reg.Get("evilginx"); !errors.Is(err, ErrUnknownKind) {
		t.Fatalf("unknown kind: want ErrUnknownKind, got %v", err)
	}
}

func TestRegistryDispatchesKnownKind(t *testing.T) {
	reg := NewRegistry()
	fa := &fakeAdapter{kind: "evilginx"}
	reg.Register(fa)

	got, err := reg.Get("evilginx")
	if err != nil {
		t.Fatalf("get known kind: %v", err)
	}
	if got != fa {
		t.Fatalf("get: want the registered adapter")
	}
	// Dispatch reaches the right adapter.
	if err := got.Start(context.Background(), "eng-1", engineconfig.Config{}); err != nil {
		t.Fatalf("start: %v", err)
	}
	if len(fa.started) != 1 || fa.started[0] != "eng-1" {
		t.Fatalf("dispatch: want started [eng-1], got %v", fa.started)
	}

	// An unmapped kind still fails closed when no fallback is set.
	if _, err := reg.Get("other"); !errors.Is(err, ErrUnknownKind) {
		t.Fatalf("other kind: want ErrUnknownKind, got %v", err)
	}
}

func TestRegistryFallbackResolvesAnyKind(t *testing.T) {
	reg := NewRegistry()
	fb := &fakeAdapter{kind: BuiltinKind}
	reg.SetFallback(fb)

	for _, kind := range []string{"", "proxy", "helper", "anything"} {
		got, err := reg.Get(kind)
		if err != nil {
			t.Fatalf("fallback get %q: %v", kind, err)
		}
		if got != fb {
			t.Fatalf("fallback get %q: want fallback adapter", kind)
		}
	}

	// An explicit registration still wins over the fallback.
	explicit := &fakeAdapter{kind: "proxy"}
	reg.Register(explicit)
	got, err := reg.Get("proxy")
	if err != nil {
		t.Fatalf("explicit over fallback: %v", err)
	}
	if got != explicit {
		t.Fatalf("explicit registration must win over fallback")
	}
}

func TestHealthFromStatus(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name       string
		st         engine.Status
		live       bool
		wantStatus Status
	}{
		{"not live", engine.Status{}, false, StatusUnknown},
		{"running stable", engine.Status{State: engine.StateRunning, Pid: 42, StartedAt: now}, true, StatusRunning},
		{"running after restart", engine.Status{State: engine.StateRunning, Pid: 43, Restarts: 2}, true, StatusStarting},
		{"exited", engine.Status{State: engine.StateExited}, true, StatusStopped},
		{"failed", engine.Status{State: engine.StateFailed, ExitErr: "exit status 1"}, true, StatusFailed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := healthFromStatus(c.st, c.live)
			if h.Status != c.wantStatus {
				t.Fatalf("status: want %q, got %q", c.wantStatus, h.Status)
			}
			if h.Live != c.live {
				t.Fatalf("live: want %v, got %v", c.live, h.Live)
			}
			if c.wantStatus == StatusFailed && h.Detail != "exit status 1" {
				t.Fatalf("failed detail: want exit status 1, got %q", h.Detail)
			}
		})
	}
}
