package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"phishforge/internal/aitmproxy"
	"phishforge/internal/audit"
	"phishforge/internal/auth"
	"phishforge/internal/campaign"
	"phishforge/internal/events"
	"phishforge/internal/httpx"
	"phishforge/internal/profiles"
)

// Capture implements aitmproxy.CaptureSink. It routes one in-process AiTM proxy
// capture event through the SAME names-only ingest path the external engine
// reporter uses (ingestCapture -> sanitizeEnginePayload strips values; the
// launch-time profile checksum/version are stamped), tagged source="proxy". The
// proxy therefore cannot widen the capture boundary. Best-effort, like the
// public tracking path: an unattributable capture (stale token, rejected
// transition) is dropped, never surfaced to the victim's connection.
func (s *Server) Capture(ctx context.Context, kind, token string, payload map[string]any, ts time.Time) {
	var evType events.Type
	switch kind {
	case aitmproxy.KindCreds:
		evType = events.TypeCreds
	case aitmproxy.KindSession:
		evType = events.TypeSessionHijacked
	default:
		return
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return
	}
	_, _ = s.ingestCapture(ctx, evType, token, ts, raw, "proxy")
}

// --- M5 Phase 1 AiTM proxy lifecycle (operator, tenant-scoped, audited) ----

// startCampaignProxy compiles the campaign's bound application profile and
// brings up an in-process reverse proxy on a port from the configured range.
// Fail closed: the campaign must be bound to an authorized engagement and to a
// runtime-supported profile (mirroring the launch gate — 403/409 engagement,
// 409 missing profile, 409/501 unsupported auth/MFA method).
func (s *Server) startCampaignProxy(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	if s.aitm == nil {
		httpx.Problem(w, r, http.StatusServiceUnavailable, "unavailable", "AiTM proxy runtime is not configured")
		return
	}

	camp, err := s.campaigns.GetByID(r.Context(), s.pool, p.TenantID, id)
	if errors.Is(err, campaign.ErrNotFound) {
		httpx.Problem(w, r, http.StatusNotFound, "not found", "campaign not found")
		return
	}
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "load campaign")
		return
	}

	// Engagement authorization gate: a proxy may only run for a campaign bound to
	// an authorized, unexpired engagement (403 unbound/unauthorized, 409 expired/
	// terminated). Checked before resolving the profile.
	if !s.checkEngagementGate(w, r, s.pool, p.TenantID, camp) {
		return
	}

	profileID, err := s.campaigns.AppProfileBindingByID(r.Context(), s.pool, p.TenantID, id)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "resolve profile binding")
		return
	}
	if profileID == nil {
		httpx.Problem(w, r, http.StatusConflict, "conflict",
			"campaign has no bound application profile; launch it with app_profile_id first")
		return
	}
	prof, err := s.appProfiles.GetByID(r.Context(), s.pool, p.TenantID, *profileID)
	if errors.Is(err, profiles.ErrNotFound) {
		httpx.Problem(w, r, http.StatusConflict, "conflict", "bound application profile no longer exists")
		return
	}
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "load profile")
		return
	}

	// Runtime instantiation gate (M10b): reserved auth/MFA methods are storable
	// but not servable. Same 409/501 mapping as launch.
	if err := profiles.InstantiateFlowJSON(prof.Spec); err != nil {
		switch {
		case errors.Is(err, profiles.ErrAuthMethodUnsupported):
			httpx.Problem(w, r, http.StatusConflict, "conflict",
				profiles.CodeAuthMethodUnsupported+": profile auth method is not supported at runtime (form/basic only)")
		case errors.Is(err, profiles.ErrMFAMethodUnsupported):
			httpx.Problem(w, r, http.StatusNotImplemented, "not implemented",
				profiles.CodeMFAMethodUnsupported+": profile MFA mode is not supported at runtime (none/totp_field only)")
		default:
			httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "instantiate profile")
		}
		return
	}

	// Compile the stored canonical spec into a servable instance (fail closed on
	// any structural surprise).
	var spec map[string]any
	if err := json.Unmarshal(prof.Spec, &spec); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "decode profile spec")
		return
	}
	inst, err := aitmproxy.NewInstance(spec, s, nil)
	if err != nil {
		httpx.Problem(w, r, http.StatusConflict, "conflict", "profile could not be compiled for serving: "+err.Error())
		return
	}

	state, err := s.aitm.Start(id.String(), inst)
	switch {
	case errors.Is(err, aitmproxy.ErrAlreadyRunning):
		httpx.Problem(w, r, http.StatusConflict, "conflict", "a proxy is already running for this campaign")
		return
	case errors.Is(err, aitmproxy.ErrNoPort):
		httpx.Problem(w, r, http.StatusServiceUnavailable, "unavailable", "no free proxy port in the configured range")
		return
	case err != nil:
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "start proxy")
		return
	}

	if err := audit.Write(r.Context(), s.pool, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: "campaign.proxy.start", TargetType: "campaign", TargetID: id.String(),
		Metadata: map[string]any{"profile_id": profileID.String(), "port": state.Port, "upstream": state.Upstream},
	}); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}
	httpx.JSON(w, http.StatusOK, state)
}

// stopCampaignProxy tears down the campaign's running proxy and frees its port.
func (s *Server) stopCampaignProxy(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	if s.aitm == nil {
		httpx.Problem(w, r, http.StatusServiceUnavailable, "unavailable", "AiTM proxy runtime is not configured")
		return
	}
	// Tenant-scope the action: only a campaign in the caller's tenant can be
	// stopped (prevents cross-tenant teardown by campaign id).
	if _, err := s.campaigns.GetByID(r.Context(), s.pool, p.TenantID, id); err != nil {
		if errors.Is(err, campaign.ErrNotFound) {
			httpx.Problem(w, r, http.StatusNotFound, "not found", "campaign not found")
			return
		}
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "load campaign")
		return
	}

	if err := s.aitm.Stop(r.Context(), id.String()); err != nil {
		if errors.Is(err, aitmproxy.ErrNotRunning) {
			httpx.Problem(w, r, http.StatusConflict, "conflict", "no proxy is running for this campaign")
			return
		}
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "stop proxy")
		return
	}
	if err := audit.Write(r.Context(), s.pool, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: "campaign.proxy.stop", TargetType: "campaign", TargetID: id.String(),
	}); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}
	httpx.JSON(w, http.StatusOK, aitmproxy.RunState{Running: false})
}

// proxyStatus reports the running state of a campaign's proxy (read-only, not
// audited — mirrors the other read endpoints).
func (s *Server) proxyStatus(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	if _, err := s.campaigns.GetByID(r.Context(), s.pool, p.TenantID, id); err != nil {
		if errors.Is(err, campaign.ErrNotFound) {
			httpx.Problem(w, r, http.StatusNotFound, "not found", "campaign not found")
			return
		}
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "load campaign")
		return
	}
	if s.aitm == nil {
		httpx.JSON(w, http.StatusOK, aitmproxy.RunState{Running: false})
		return
	}
	state, _ := s.aitm.Status(id.String())
	httpx.JSON(w, http.StatusOK, state)
}
