package api

import (
	"errors"
	"net/http"
	"time"
	"strings"

	"phishforge/internal/audit"
	"phishforge/internal/auth"
	"phishforge/internal/engine"
	"phishforge/internal/engineconfig"
	"phishforge/internal/enginerepo"
	"phishforge/internal/httpx"
)

// engineStatusRow maps a live manager status onto the DB engine_status enum.
// A running process with recent restart activity is surfaced as 'starting'
// so callers never see a transient 'error' window between restart attempts.
func engineStatusRow(rowStatus string, st engine.Status, live bool) string {
	if !live {
		if rowStatus == "running" || rowStatus == "starting" {
			// Manager lost the process (e.g. API restart): report stopped.
			return "stopped"
		}
		return rowStatus
	}
	switch st.State {
	case engine.StateRunning:
		if st.Restarts > 0 {
			return "starting"
		}
		return "running"
	case engine.StateExited:
		return "stopped"
	default: // StateFailed
		return "stopped_failed"
	}
}

type createEngineBody struct {
	Name   string `json:"name"`
	Config string `json:"config"`
}

func (s *Server) createEngine(w http.ResponseWriter, r *http.Request) {
	var in createEngineBody
	if !decode(w, r, &in) {
		return
	}
	if in.Name == "" {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "name is required")
		return
	}
	if _, err := engineconfig.Parse([]byte(in.Config)); err != nil {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid engine config", err.Error())
		return
	}
	p, _ := auth.FromContext(r.Context())

	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "begin transaction")
		return
	}
	defer tx.Rollback(r.Context())

	e, err := s.engineRepo.Create(r.Context(), tx, p.TenantID, in.Name, in.Config)
	if err != nil {
		if isUniqueViolation(err) {
			httpx.Problem(w, r, http.StatusConflict, "conflict", "an engine with this name already exists")
			return
		}
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "create engine")
		return
	}
	if err := audit.Write(r.Context(), tx, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: "engine.create", TargetType: "engine", TargetID: e.ID.String(),
		Metadata: map[string]any{"name": e.Name},
	}); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "commit")
		return
	}
	httpx.JSON(w, http.StatusCreated, e)
}

func (s *Server) listEngines(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	limit, offset := parsePage(r)
	items, err := s.engineRepo.List(r.Context(), s.pool, p.TenantID, limit, offset)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "list engines")
		return
	}
	// Reconcile live status for any engine currently in the manager.
	for i := range items {
		if st, live := s.engines.Status(items[i].ID.String()); live {
			items[i].Status = engineStatusRow(items[i].Status, st, true)
		}
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": items, "limit": limit, "offset": offset})
}

func (s *Server) getEngine(w http.ResponseWriter, r *http.Request) {
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
	if st, live := s.engines.Status(id.String()); live {
		e.Status = engineStatusRow(e.Status, st, true)
	}
	httpx.JSON(w, http.StatusOK, e)
}

// startEngine launches the configured binary after re-validating the stored
// config. The manager is the single owner of the child process; the DB row
// mirrors lifecycle state for the dashboard.
func (s *Server) startEngine(w http.ResponseWriter, r *http.Request) {
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
	if s.engines == nil {
		httpx.Problem(w, r, http.StatusServiceUnavailable, "unavailable", "engine binary not configured (set ENGINE_BINARY_PATH)")
		return
	}

	// Parse (not just Validate) so defaults are applied — stored configs may
	// omit optional fields.
	cfg, err := engineconfig.Parse([]byte(e.Config))
	if err != nil {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid engine config", err.Error())
		return
	}

	// M5 batch C: mint a per-run callback token, persist only its hash, and
	// inject token + ingest URL into the engine's environment.
	callbackToken, tokenHash, err := newEngineCallbackToken()
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "generate callback token")
		return
	}
	for _, k := range []string{"ENGINE_CALLBACK_TOKEN", "ORCHESTRATOR_CALLBACK_URL"} {
		if _, exists := cfg.Env[k]; !exists && len(cfg.Env) >= engineconfig.MaxEnvEntries {
			httpx.Problem(w, r, http.StatusBadRequest, "invalid engine config",
				"env has no room for required callback variables (max 32 entries)")
			return
		}
	}
	if err := s.engineRepo.SetCallbackHash(r.Context(), s.pool, p.TenantID, id, tokenHash); err != nil {
		if errors.Is(err, enginerepo.ErrNotFound) {
			httpx.Problem(w, r, http.StatusNotFound, "not found", "engine not found")
			return
		}
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "store callback token hash")
		return
	}
	cfg.Env["ENGINE_CALLBACK_TOKEN"] = callbackToken
	cfg.Env["ORCHESTRATOR_CALLBACK_URL"] = strings.TrimRight(s.baseURL, "/") +
		"/api/v1/engines/" + id.String() + "/events"
	cfg.Env["ENGINE_ID"] = id.String()

	err = s.engines.Start(id.String(), cfg)
	switch {
	case errors.Is(err, engine.ErrNoBinary):
		_ = s.engineRepo.ClearCallbackHash(r.Context(), s.pool, p.TenantID, id)
		httpx.Problem(w, r, http.StatusServiceUnavailable, "unavailable", "engine binary not configured (set ENGINE_BINARY_PATH)")
		return
	case errors.Is(err, engine.ErrAlreadyRunning):
		_ = s.engineRepo.ClearCallbackHash(r.Context(), s.pool, p.TenantID, id)
		httpx.Problem(w, r, http.StatusConflict, "conflict", "engine is already running")
		return
	case err != nil:
		_ = s.engineRepo.ClearCallbackHash(r.Context(), s.pool, p.TenantID, id)
		msg := err.Error()
		if _, uerr := s.engineRepo.SetStatus(r.Context(), s.pool, p.TenantID, id, "error", &msg, nil); uerr != nil {
			httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "record engine error")
			return
		}
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "start engine: "+err.Error())
		return
	}

	now := time.Now().UTC()
	e, err = s.engineRepo.SetStatus(r.Context(), s.pool, p.TenantID, id, "running", nil, &now)
	if err != nil {
		// Process is live but the row update failed; surface the inconsistency.
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "mark engine running")
		return
	}
	_ = s.engineRepo.ClearError(r.Context(), s.pool, p.TenantID, id)

	if err := audit.Write(r.Context(), s.pool, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: "engine.start", TargetType: "engine", TargetID: id.String(),
	}); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}
	httpx.JSON(w, http.StatusOK, e)
}

func (s *Server) stopEngine(w http.ResponseWriter, r *http.Request) {
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

	_, live := s.engines.Status(id.String())
	if live {
		if err := s.engines.Stop(id.String()); err != nil {
			httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "stop engine: "+err.Error())
			return
		}
		// Settle state after stop: clean exit => stopped, else stopped_failed.
		newStatus := "stopped"
		var lastErr *string
		if st2, live2 := s.engines.Status(id.String()); live2 && st2.State == engine.StateFailed {
			newStatus = "stopped_failed"
			msg := st2.ExitErr
			lastErr = &msg
		}
		e, err = s.engineRepo.SetStatus(r.Context(), s.pool, p.TenantID, id, newStatus, lastErr, nil)
	} else if e.Status == "running" || e.Status == "starting" {
		// Stale row (manager lost the process, e.g. API restart).
		e, err = s.engineRepo.SetStatus(r.Context(), s.pool, p.TenantID, id, "stopped", nil, nil)
	} else {
		httpx.Problem(w, r, http.StatusConflict, "conflict", "engine is not running")
		return
	}
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "update engine status")
		return
	}

	// The stopped engine's token is dead; drop its hash so the ingest
	// endpoint rejects late replays.
	_ = s.engineRepo.ClearCallbackHash(r.Context(), s.pool, p.TenantID, id)

	if err := audit.Write(r.Context(), s.pool, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: "engine.stop", TargetType: "engine", TargetID: id.String(),
	}); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}
	httpx.JSON(w, http.StatusOK, e)
}

func (s *Server) deleteEngine(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}

	// Kill the live process first so no orphan survives the row delete.
	if _, live := s.engines.Status(id.String()); live {
		if err := s.engines.Remove(id.String()); err != nil && !errors.Is(err, engine.ErrNotRunning) {
			httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "remove engine process")
			return
		}
	}

	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "begin transaction")
		return
	}
	defer tx.Rollback(r.Context())

	if err := s.engineRepo.Delete(r.Context(), tx, p.TenantID, id); err != nil {
		if errors.Is(err, enginerepo.ErrNotFound) {
			httpx.Problem(w, r, http.StatusNotFound, "not found", "engine not found")
			return
		}
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "delete engine")
		return
	}
	if err := audit.Write(r.Context(), tx, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: "engine.delete", TargetType: "engine", TargetID: id.String(),
	}); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "commit")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) engineLogs(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	stdout, stderr, live := s.engines.Logs(id.String())
	if !live {
		httpx.Problem(w, r, http.StatusConflict, "conflict", "engine has no live or recent process in this API instance")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{
		"stdout": string(stdout),
		"stderr": string(stderr),
	})
}
