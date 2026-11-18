// Package engine is a generic subprocess supervisor: it launches a configured
// binary with validated args/env, captures bounded stdout/stderr, applies a
// restart policy on unexpected exits, and performs graceful-then-forced
// stops. It is storage-agnostic — the API layer maps engine rows to manager
// ids. Part 1 only: no network/listener behavior of any kind.
package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"phishforge/internal/engineconfig"
)

// Errors returned by the manager.
var (
	ErrAlreadyRunning = errors.New("engine: process already running")
	ErrNotRunning     = errors.New("engine: process not running")
	ErrNoBinary       = errors.New("engine: binary path not configured")
)

// Ring buffer sizes for captured output.
const (
	stdoutRingSize = 16 << 10
	stderrRingSize = 16 << 10
)

// State is the manager-level process state (distinct from the DB enum).
type State string

const (
	StateRunning State = "running"
	StateExited  State = "exited"
	StateFailed  State = "failed" // exited non-zero or restarts exhausted
)

// Status is a point-in-time snapshot of a managed process.
type Status struct {
	State      State
	Pid        int
	StartedAt  time.Time
	ExitedAt   *time.Time
	ExitErr    string
	Restarts   int // restarts performed for the current Start call
}

// Manager supervises child processes keyed by caller-chosen ids (the API
// uses engine row UUID strings). Safe for concurrent use.
type Manager struct {
	mu          sync.Mutex
	procs       map[string]*proc
	binaryPath  string
	maxRestarts int
	backoff     time.Duration
}

type proc struct {
	id        string
	cfg       engineconfig.Config
	cmd       *exec.Cmd
	stdout    *ring
	stderr    *ring
	startedAt time.Time
	exitedAt  atomic.Pointer[time.Time]
	exitErr   atomic.Pointer[error]
	restarts  int
	// userStopped is set when Stop is requested; the restart loop honors it.
	userStopped atomic.Bool
	done        chan struct{}
}

// New creates a Manager. binaryPath empty => Start returns ErrNoBinary
// (the API maps this to 503 "engine binary not configured").
func New(binaryPath string, maxRestarts int, backoff time.Duration) *Manager {
	if maxRestarts < 0 {
		maxRestarts = 0
	}
	if backoff < 10*time.Millisecond {
		backoff = 10 * time.Millisecond
	}
	return &Manager{
		procs:       make(map[string]*proc),
		binaryPath:  binaryPath,
		maxRestarts: maxRestarts,
		backoff:     backoff,
	}
}

// Start launches the binary for id with the validated config. The process
// runs under a supervisor goroutine implementing the restart policy.
func (m *Manager) Start(id string, cfg engineconfig.Config) error {
	if m.binaryPath == "" {
		return ErrNoBinary
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("engine: config invalid: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.procs[id]; ok {
		select {
		case <-p.done:
			delete(m.procs, id) // finished run; allow restart
		default:
			return ErrAlreadyRunning
		}
	}

	p, err := m.spawn(id, cfg)
	if err != nil {
		return err
	}
	m.procs[id] = p
	go m.supervise(p)
	return nil
}

// spawn builds and starts one child process instance.
func (m *Manager) spawn(id string, cfg engineconfig.Config) (*proc, error) {
	cmd := exec.Command(m.binaryPath, cfg.Args...)
	cmd.Env = append(os.Environ(), envPairs(cfg.Env)...)

	p := &proc{
		id:        id,
		cfg:       cfg,
		cmd:       cmd,
		stdout:    newRing(stdoutRingSize),
		stderr:    newRing(stderrRingSize),
		startedAt: time.Now(),
		done:      make(chan struct{}),
	}
	cmd.Stdout = p.stdout
	cmd.Stderr = p.stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("engine: start %s: %w", cfg.Kind, err)
	}
	go func() {
		err := cmd.Wait()
		if err != nil {
			p.exitErr.Store(&err)
		}
		now := time.Now()
		p.exitedAt.Store(&now)
		close(p.done)
	}()
	return p, nil
}

func envPairs(env map[string]string) []string {
	out := make([]string, 0, len(env))
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	return out
}

// supervise applies the restart policy until the user stops the engine or
// attempts are exhausted.
func (m *Manager) supervise(p *proc) {
	attempts := 0
	for {
		<-p.done
		if p.userStopped.Load() {
			return
		}
		if attempts >= m.maxRestarts {
			return // stays in StateFailed; restarts recorded
		}
		attempts++
		p.restarts = attempts

		time.Sleep(m.backoff)

		next, err := m.spawn(p.id, p.cfg)
		if err != nil {
			return // spawn failed; process stays failed
		}
		next.restarts = attempts
		next.userStopped.Store(p.userStopped.Load())

		m.mu.Lock()
		if cur, ok := m.procs[p.id]; ok && cur == p {
			m.procs[p.id] = next
		}
		m.mu.Unlock()

		if next.userStopped.Load() {
			_ = m.kill(next)
			return
		}
		p = next
	}
}

// stopDeadline exists only to keep supervise simple; it returns a closed
// channel after d (d<=0 means never within this call).
func stopDeadline(ctx context.Context, _ time.Duration) <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	<-ch // unreachable: immediately drained below in practice
	return ch
}

// Stop gracefully terminates the process for id: interrupt (SIGTERM on
// Unix), then hard-kill after the config's stop timeout. Returns
// ErrNotRunning if no live process exists.
func (m *Manager) Stop(id string) error {
	m.mu.Lock()
	p, ok := m.procs[id]
	m.mu.Unlock()
	if !ok {
		return ErrNotRunning
	}
	p.userStopped.Store(true)
	return m.gracefulStop(p, time.Duration(p.cfg.StopTimeoutMs)*time.Millisecond)
}

func (m *Manager) gracefulStop(p *proc, timeout time.Duration) error {
	select {
	case <-p.done:
		return nil // already exited
	default:
	}
	if err := interrupt(p.cmd); err != nil {
		// Fallback: hard kill (Windows has no SIGTERM delivery).
		_ = p.cmd.Process.Kill()
	}
	select {
	case <-p.done:
		return nil
	case <-time.After(timeout):
		_ = m.kill(p)
		select {
		case <-p.done:
			return nil
		case <-time.After(2 * time.Second):
			return fmt.Errorf("engine: process %s did not exit after kill", p.id)
		}
	}
}

func interrupt(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return errors.New("engine: no process")
	}
	// os.Interrupt maps to SIGTERM on Unix; on Windows this returns an
	// error, and the caller falls back to Kill.
	return cmd.Process.Signal(os.Interrupt)
}

func (m *Manager) kill(p *proc) error {
	m.mu.Lock()
	cmd := p.cmd
	m.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	_ = cmd.Process.Kill()
	return nil
}

// Status reports the current state of id, or false when never started
// (or already reaped).
func (m *Manager) Status(id string) (Status, bool) {
	m.mu.Lock()
	p, ok := m.procs[id]
	m.mu.Unlock()
	if !ok {
		return Status{}, false
	}
	select {
	case <-p.done:
		st := Status{StartedAt: p.startedAt, Restarts: p.restarts}
		if t := p.exitedAt.Load(); t != nil {
			st.ExitedAt = t
		}
		if e := p.exitErr.Load(); e != nil && (*e != nil) {
			st.ExitErr = (*e).Error()
			st.State = StateFailed
		} else {
			st.State = StateExited
		}
		return st, true
	default:
		return Status{State: StateRunning, Pid: p.cmd.Process.Pid, StartedAt: p.startedAt, Restarts: p.restarts}, true
	}
}

// Logs returns the captured stdout and stderr tails for id.
func (m *Manager) Logs(id string) (stdout, stderr []byte, ok bool) {
	m.mu.Lock()
	p, ok := m.procs[id]
	m.mu.Unlock()
	if !ok {
		return nil, nil, false
	}
	return p.stdout.bytes(), p.stderr.bytes(), true
}

// Remove drops bookkeeping for id entirely (called after a DB delete).
// A live process is killed first.
func (m *Manager) Remove(id string) error {
	m.mu.Lock()
	p, ok := m.procs[id]
	if ok {
		delete(m.procs, id)
	}
	m.mu.Unlock()
	if !ok {
		return ErrNotRunning
	}
	p.userStopped.Store(true)
	select {
	case <-p.done:
	default:
		_ = m.gracefulStop(p, time.Duration(p.cfg.StopTimeoutMs)*time.Millisecond)
	}
	return nil
}

// Running reports whether id has a live process.
func (m *Manager) Running(id string) bool {
	st, ok := m.Status(id)
	return ok && st.State == StateRunning
}

