package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"phishforge/internal/auth"
	"phishforge/internal/engine/adapter"
	"phishforge/internal/engineconfig"
	"phishforge/internal/enginehealth"
	"phishforge/internal/enginerepo"
	"phishforge/internal/httpx"
)

// resolveEngineAdapter resolves the adapter for a stored engine config. It
// parses the config best-effort for its kind (an empty kind still resolves to
// the fallback). Returns nil only when the registry fails closed (no adapter
// and no fallback — i.e. no supervisor wired, or a strict registry).
func (s *Server) resolveEngineAdapter(config string) adapter.Adapter {
	kind := ""
	if cfg, err := engineconfig.Parse([]byte(config)); err == nil {
		kind = cfg.Kind
	}
	ad, err := s.engineReg.Get(kind)
	if err != nil {
		return nil
	}
	return ad
}

// engineHealthResponse is the GET /engines/{id}/health body: the live adapter
// view (when this instance tracks the process) overlaid on the persisted
// snapshot and the authoritative engine row.
type engineHealthResponse struct {
	EngineID         uuid.UUID  `json:"engine_id"`
	Status           string     `json:"status"`        // adapter health vocab
	Detail           string     `json:"detail"`        // adapter-reported detail
	Live             bool       `json:"live"`          // tracked in this instance
	AdapterKind      string     `json:"adapter_kind"`  // driving adapter
	EngineKind       string     `json:"engine_kind"`   // declared kind in config
	EngineStatus     string     `json:"engine_status"` // DB engine_status enum
	LastTransitionAt *time.Time `json:"last_transition_at,omitempty"`
	LastPollAt       *time.Time `json:"last_poll_at,omitempty"`
	StartedAt        *time.Time `json:"started_at,omitempty"`
	LastError        *string    `json:"last_error,omitempty"`
}

// engineHealthStatus returns an engine's runtime health. Read-only: like the
// domain diagnostics endpoint, it is not audited.
func (s *Server) engineHealthStatus(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}

	e, err := s.engineRepo.GetByID(r.Context(), s.pool, p.TenantID, id)
	if errors.Is(err, enginerepo.ErrNotFound) {
		httpx.Problem(w, r, http.StatusNotFound, "not found", "engine not found")
		return
	}
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "get engine")
		return
	}

	// Declared kind (best-effort) and the resolved driving adapter.
	kind := ""
	if cfg, perr := engineconfig.Parse([]byte(e.Config)); perr == nil {
		kind = cfg.Kind
	}

	resp := engineHealthResponse{
		EngineID:     id,
		EngineKind:   kind,
		EngineStatus: e.Status,
		StartedAt:    e.StartedAt,
		LastError:    e.LastError,
		AdapterKind:  adapter.BuiltinKind,
	}

	// Persisted snapshot (may not exist yet — treat ErrNotFound as empty).
	snap, serr := s.engineHealth.Get(r.Context(), s.pool, p.TenantID, id)
	haveSnap := serr == nil
	if haveSnap {
		resp.LastTransitionAt = snap.LastTransitionAt
		resp.LastPollAt = snap.LastPollAt
		if snap.AdapterKind != "" {
			resp.AdapterKind = snap.AdapterKind
		}
	}

	// Live adapter view, when this instance supervises the process.
	var live adapter.Health
	if ad, aerr := s.engineReg.Get(kind); aerr == nil {
		live = ad.Health(r.Context(), id.String())
		resp.AdapterKind = ad.Kind()
	}

	switch {
	case live.Live:
		resp.Status = string(live.Status)
		resp.Detail = live.Detail
		resp.Live = true
	case haveSnap && snap.Status != "":
		resp.Status = snap.Status
		resp.Detail = snap.Detail
	default:
		resp.Status = enginehealth.StatusForRow(e.Status)
	}

	httpx.JSON(w, http.StatusOK, resp)
}
