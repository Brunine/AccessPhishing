package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"phishforge/internal/audit"
	"phishforge/internal/auth"
	"phishforge/internal/campaign"
	"phishforge/internal/httpx"
	"phishforge/internal/tenant"
)

// --- tenants (admin, platform-level) -------------------------------------

func (s *Server) createTenant(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Name == "" || in.Slug == "" {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "name and slug are required")
		return
	}
	p, _ := auth.FromContext(r.Context())

	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "begin transaction")
		return
	}
	defer tx.Rollback(r.Context())

	t, err := s.tenants.Create(r.Context(), tx, in.Name, in.Slug)
	if err != nil {
		if isUniqueViolation(err) {
			httpx.Problem(w, r, http.StatusConflict, "conflict", "slug already in use")
			return
		}
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "create tenant")
		return
	}
	if err := audit.Write(r.Context(), tx, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: "tenant.create", TargetType: "tenant", TargetID: t.ID.String(),
		Metadata: map[string]any{"name": t.Name, "slug": t.Slug},
	}); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "commit")
		return
	}
	httpx.JSON(w, http.StatusCreated, t)
}

func (s *Server) listTenants(w http.ResponseWriter, r *http.Request) {
	limit, offset := parsePage(r)
	items, err := s.tenants.List(r.Context(), s.pool, limit, offset)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "list tenants")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": items, "limit": limit, "offset": offset})
}

func (s *Server) getTenant(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	t, err := s.tenants.GetByID(r.Context(), s.pool, id)
	if errors.Is(err, tenant.ErrNotFound) {
		httpx.Problem(w, r, http.StatusNotFound, "not found", "tenant not found")
		return
	}
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "get tenant")
		return
	}
	httpx.JSON(w, http.StatusOK, t)
}

// --- campaigns (operator, tenant-scoped from principal) ------------------

func (s *Server) createCampaign(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name         string     `json:"name"`
		EngagementID *uuid.UUID `json:"engagement_id"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Name == "" {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "name is required")
		return
	}
	p, _ := auth.FromContext(r.Context())

	// A bound engagement_id must reference a same-tenant engagement (following
	// the group_id precedent). We never trust the id from the body without this.
	if in.EngagementID != nil {
		if _, err := s.engagements.GetByID(r.Context(), s.pool, p.TenantID, *in.EngagementID); err != nil {
			httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "engagement_id not found in tenant")
			return
		}
	}

	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "begin transaction")
		return
	}
	defer tx.Rollback(r.Context())

	c, err := s.campaigns.Create(r.Context(), tx, p.TenantID, p.UserID, in.Name, in.EngagementID)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "create campaign")
		return
	}
	meta := map[string]any{"name": c.Name}
	if in.EngagementID != nil {
		meta["engagement_id"] = in.EngagementID.String()
	}
	if err := audit.Write(r.Context(), tx, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: "campaign.create", TargetType: "campaign", TargetID: c.ID.String(),
		Metadata: meta,
	}); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "commit")
		return
	}
	httpx.JSON(w, http.StatusCreated, c)
}

func (s *Server) listCampaigns(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	limit, offset := parsePage(r)
	items, err := s.campaigns.ListByTenant(r.Context(), s.pool, p.TenantID, limit, offset)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "list campaigns")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": items, "limit": limit, "offset": offset})
}

func (s *Server) getCampaign(w http.ResponseWriter, r *http.Request) {
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
	httpx.JSON(w, http.StatusOK, c)
}

// patchCampaign updates a campaign's status and/or its bound engagement. Both
// fields are optional; at least one must be present. Rebinding an engagement is
// only allowed while the campaign is still a draft (after launch it is 409, to
// keep the authorization audit trail stable).
func (s *Server) patchCampaign(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Status       *string    `json:"status"`
		EngagementID *uuid.UUID `json:"engagement_id"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Status == nil && in.EngagementID == nil {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "provide status and/or engagement_id")
		return
	}
	if in.Status != nil && !campaign.ValidStatus(*in.Status) {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "invalid campaign status")
		return
	}
	p, _ := auth.FromContext(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}

	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "begin transaction")
		return
	}
	defer tx.Rollback(r.Context())

	camp, err := s.campaigns.GetByID(r.Context(), tx, p.TenantID, id)
	if errors.Is(err, campaign.ErrNotFound) {
		httpx.Problem(w, r, http.StatusNotFound, "not found", "campaign not found")
		return
	}
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "load campaign")
		return
	}

	if in.EngagementID != nil {
		if _, err := s.engagements.GetByID(r.Context(), tx, p.TenantID, *in.EngagementID); err != nil {
			httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "engagement_id not found in tenant")
			return
		}
		if camp.Status != "draft" {
			httpx.Problem(w, r, http.StatusConflict, "conflict", "cannot change the engagement after launch")
			return
		}
		if err := s.campaigns.SetEngagement(r.Context(), tx, p.TenantID, id, in.EngagementID); err != nil {
			httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "bind engagement")
			return
		}
		if err := audit.Write(r.Context(), tx, audit.Entry{
			TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
			Action: "campaign.engagement.bind", TargetType: "campaign", TargetID: id.String(),
			Metadata: map[string]any{"engagement_id": in.EngagementID.String()},
		}); err != nil {
			httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
			return
		}
	}

	if in.Status != nil {
		if err := s.campaigns.UpdateStatus(r.Context(), tx, p.TenantID, id, *in.Status); err != nil {
			httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "update status")
			return
		}
		if err := audit.Write(r.Context(), tx, audit.Entry{
			TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
			Action: "campaign.status.update", TargetType: "campaign", TargetID: id.String(),
			Metadata: map[string]any{"status": *in.Status},
		}); err != nil {
			httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
			return
		}
	}

	c, err := s.campaigns.GetByID(r.Context(), tx, p.TenantID, id)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "reload campaign")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "commit")
		return
	}
	httpx.JSON(w, http.StatusOK, c)
}

// --- helpers --------------------------------------------------------------

func decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request body", err.Error())
		return false
	}
	return true
}

func parseID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "invalid id")
		return uuid.Nil, false
	}
	return id, true
}

func parsePage(r *http.Request) (limit, offset int) {
	limit, offset = 50, 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 {
			limit = n
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	return limit, offset
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
