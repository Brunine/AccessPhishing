package aitmproxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Lifecycle errors.
var (
	// ErrAlreadyRunning is returned when a campaign already has a live proxy.
	ErrAlreadyRunning = errors.New("aitmproxy: proxy already running for campaign")
	// ErrNotRunning is returned when no proxy is live for a campaign.
	ErrNotRunning = errors.New("aitmproxy: no proxy running for campaign")
	// ErrNoPort is returned when every port in the configured range is taken.
	ErrNoPort = errors.New("aitmproxy: no free port in the configured range")
)

// Default listener host for Phase 1. The proxy runs in-process and is bound to
// localhost; production exposure is via per-campaign VPS + redirectors (M5
// later / deploy concern), never by binding this process to the public internet.
const defaultListenHost = "127.0.0.1"

// RunState is a point-in-time view of a campaign's proxy.
type RunState struct {
	Running   bool      `json:"running"`
	Addr      string    `json:"addr,omitempty"`       // host:port the listener bound
	Port      int       `json:"port,omitempty"`       // allocated port
	StartedAt time.Time `json:"started_at,omitempty"` // when the listener came up
	Upstream  string    `json:"upstream,omitempty"`   // scheme://host:port forwarded to
	// Clone snapshot (M5 Phase 2): the login-page clone generated at start.
	CloneSnapshotHash string    `json:"clone_snapshot_hash,omitempty"`
	CloneGeneratedAt  time.Time `json:"clone_generated_at,omitempty"`
	UpstreamFetchOK   bool      `json:"upstream_fetch_ok,omitempty"`
}

// Manager owns the in-process AiTM proxies, one listener per campaign, with
// ports drawn from a configured range. Safe for concurrent use.
type Manager struct {
	mu         sync.Mutex
	running    map[string]*running
	minPort    int
	maxPort    int
	listenHost string
	logger     *slog.Logger
}

type running struct {
	inst      *Instance
	srv       *http.Server
	ln        net.Listener
	port      int
	startedAt time.Time
}

// NewManager builds a proxy manager serving ports in [minPort, maxPort]. An
// invalid or empty range falls back to 9100–9199.
func NewManager(minPort, maxPort int, logger *slog.Logger) *Manager {
	if minPort <= 0 || maxPort <= 0 || maxPort < minPort {
		minPort, maxPort = 9100, 9199
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{
		running:    make(map[string]*running),
		minPort:    minPort,
		maxPort:    maxPort,
		listenHost: defaultListenHost,
		logger:     logger,
	}
}

// Start binds a free port and serves inst for campaignID until Stop. It returns
// ErrAlreadyRunning if a proxy is already live for the campaign, or ErrNoPort
// when the range is exhausted.
func (m *Manager) Start(campaignID string, inst *Instance) (RunState, error) {
	if m == nil {
		return RunState{}, ErrNotRunning
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.running[campaignID]; ok {
		return RunState{}, ErrAlreadyRunning
	}

	ln, port, err := m.listen()
	if err != nil {
		return RunState{}, err
	}

	srv := &http.Server{
		Handler:           inst.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	r := &running{inst: inst, srv: srv, ln: ln, port: port, startedAt: time.Now().UTC()}
	m.running[campaignID] = r

	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			m.logger.Error("aitmproxy serve ended", "campaign", campaignID, "err", err)
		}
	}()

	m.logger.Info("aitmproxy started", "campaign", campaignID, "addr", ln.Addr().String(),
		"upstream", r.inst.compiled.Upstream.Scheme+"://"+r.inst.compiled.Upstream.Host)
	return m.stateLocked(r), nil
}

// listen scans the configured port range for a bindable port. The caller holds
// m.mu, so ports already in m.running are skipped before any syscall.
func (m *Manager) listen() (net.Listener, int, error) {
	used := make(map[int]bool, len(m.running))
	for _, r := range m.running {
		used[r.port] = true
	}
	for port := m.minPort; port <= m.maxPort; port++ {
		if used[port] {
			continue
		}
		ln, err := net.Listen("tcp", net.JoinHostPort(m.listenHost, strconv.Itoa(port)))
		if err != nil {
			continue // port busy (another process) — try the next
		}
		return ln, port, nil
	}
	return nil, 0, ErrNoPort
}

// Stop gracefully shuts down the campaign's proxy and frees its port. Returns
// ErrNotRunning if none is live.
func (m *Manager) Stop(ctx context.Context, campaignID string) error {
	if m == nil {
		return ErrNotRunning
	}
	m.mu.Lock()
	r, ok := m.running[campaignID]
	if ok {
		delete(m.running, campaignID)
	}
	m.mu.Unlock()
	if !ok {
		return ErrNotRunning
	}
	sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	err := r.srv.Shutdown(sctx)
	// Remove the campaign's generated clone assets once the listener is down.
	r.inst.Cleanup()
	m.logger.Info("aitmproxy stopped", "campaign", campaignID, "port", r.port)
	return err
}

// Status returns the campaign's proxy state; ok is false when none is live.
func (m *Manager) Status(campaignID string) (RunState, bool) {
	if m == nil {
		return RunState{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.running[campaignID]
	if !ok {
		return RunState{Running: false}, false
	}
	return m.stateLocked(r), true
}

// Running reports whether a campaign has a live proxy.
func (m *Manager) Running(campaignID string) bool {
	_, ok := m.Status(campaignID)
	return ok
}

// StopAll shuts down every live proxy (process shutdown). Best-effort.
func (m *Manager) StopAll(ctx context.Context) {
	if m == nil {
		return
	}
	m.mu.Lock()
	ids := make([]string, 0, len(m.running))
	for id := range m.running {
		ids = append(ids, id)
	}
	m.mu.Unlock()
	for _, id := range ids {
		_ = m.Stop(ctx, id)
	}
}

// stateLocked builds a RunState from a running entry (caller holds m.mu).
func (m *Manager) stateLocked(r *running) RunState {
	up := r.inst.compiled.Upstream
	hash, generatedAt, fetchOK, _ := r.inst.CloneInfo()
	return RunState{
		Running:           true,
		Addr:              r.ln.Addr().String(),
		Port:              r.port,
		StartedAt:         r.startedAt,
		Upstream:          fmt.Sprintf("%s://%s:%d", up.Scheme, up.Host, up.Port),
		CloneSnapshotHash: hash,
		CloneGeneratedAt:  generatedAt,
		UpstreamFetchOK:   fetchOK,
	}
}
