package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"phishforge/internal/audit"
	"phishforge/internal/auth"
	"phishforge/internal/campaign"
	"phishforge/internal/engine"
	"phishforge/internal/engineconfig"
	"phishforge/internal/enginerepo"
	"phishforge/internal/httpx"
)

type bindEngineBody struct {
	EngineID   string  `json:"engine_id"`   // required; empty string unbinds
	PublicHost *string `json:"public_host"` // optional override for URL resolution
}

// bindEngine attaches or detaches an engine to/from a campaign. Binding
// requires the engine to exist in the tenant and carry a listener section
// (otherwise the campaign's links cannot resolve to the engine URL).
func (s *Server) bindEngine(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var in bindEngineBody
	if !decode(w, r, &in) {
		return
	}

	var engID *uuid.UUID
	var eng enginerepo.Engine
	if in.EngineID != "" {
		eid, err := uuid.Parse(in.EngineID)
		if err != nil {
			httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "engine_id must be a UUID")
			return
		}
		eng, err = s.engineRepo.GetByID(r.Context(), s.pool, p.TenantID, eid)
		if errors.Is(err, enginerepo.ErrNotFound) {
			httpx.Problem(w, r, http.StatusNotFound, "not found", "engine not found")
			return
		}
		if err != nil {
			httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "get engine")
			return
		}
		cfg, err := engineconfig.Parse([]byte(eng.Config))
		if err != nil {
			httpx.Problem(w, r, http.StatusBadRequest, "invalid engine config", err.Error())
			return
		}
		if cfg.Listener == nil {
			httpx.Problem(w, r, http.StatusUnprocessableEntity, "unprocessable",
				"engine has no listener section; links cannot resolve to it")
			return
		}
		engID = &eid
	}

	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "begin transaction")
		return
	}
	defer tx.Rollback(r.Context())

	if err := s.campaigns.SetEngine(r.Context(), tx, p.TenantID, id, engID); err != nil {
		if errors.Is(err, campaign.ErrNotFound) {
			httpx.Problem(w, r, http.StatusNotFound, "not found", "campaign not found")
			return
		}
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "bind engine")
		return
	}

	action := "campaign.engine.unbind"
	if engID != nil {
		action = "campaign.engine.bind"
	}
	if err := audit.Write(r.Context(), tx, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: action, TargetType: "campaign", TargetID: id.String(),
		Metadata: map[string]any{"engine_id": in.EngineID},
	}); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "commit")
		return
	}

	// Respond with the resolved runtime view (empty when unbound).
	c, err := s.campaigns.GetByID(r.Context(), s.pool, p.TenantID, id)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "reload campaign")
		return
	}
	host := ""
	if in.PublicHost != nil {
		host = *in.PublicHost
	}
	httpx.JSON(w, http.StatusOK, s.campaignEngineView(r.Context(), c, host))
}

// getEngineForCampaign returns the bound engine plus its resolved runtime
// endpoints (live status included) for the campaign detail view.
func (s *Server) getEngineForCampaign(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	c, err := s.campaigns.GetByID(r.Context(), s.pool, p.TenantID, id)
	if errors.Is(err, campaign.ErrNotFound) {
		httpx.Problem(w, r, http.StatusNotFound, "not found", "campaign not found")
		return
	}
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "get campaign")
		return
	}
	httpx.JSON(w, http.StatusOK, s.campaignEngineView(r.Context(), c, r.URL.Query().Get("public_host")))
}

// campaignEngineView resolves the bound engine into a JSON view. A nil
// binding returns {"engine": null}. When the engine row cannot be re-parsed
// (config edited out of band), the view degrades to just the id/name.
func (s *Server) campaignEngineView(ctx context.Context, c campaign.Campaign, publicHost string) map[string]any {
	if c.EngineID == nil {
		return map[string]any{"engine": nil}
	}
	eng, err := s.engineRepo.GetByID(ctx, s.pool, c.TenantID, *c.EngineID)
	if err != nil {
		return map[string]any{"engine": map[string]any{"id": c.EngineID.String()}}
	}
	view := map[string]any{
		"id":     eng.ID,
		"name":   eng.Name,
		"status": eng.Status,
	}
	if cfg, perr := engineconfig.Parse([]byte(eng.Config)); perr == nil {
		rt := engine.RuntimeOf(cfg)
		view["runtime"] = rt
		view["public_url"] = engine.PublicURL(cfg, publicHost)
	}
	return map[string]any{"engine": view}
}
