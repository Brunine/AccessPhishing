package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"phishforge/internal/audit"
	"phishforge/internal/auth"
	"phishforge/internal/campaign"
	"phishforge/internal/db"
	"phishforge/internal/engagement"
	"phishforge/internal/httpx"
)

// engagementBody is the create/patch request body. starts_at/expires_at are
// RFC 3339 timestamps; all fields but name/client_name are optional.
type engagementBody struct {
	Name            string     `json:"name"`
	ClientName      string     `json:"client_name"`
	RoERef          *string    `json:"roe_reference"`
	AuthorizedScope []string   `json:"authorized_scope"`
	StartsAt        *time.Time `json:"starts_at"`
	ExpiresAt       *time.Time `json:"expires_at"`
	Notes           *string    `json:"notes"`
}

func (b engagementBody) toInput() engagement.Input {
	return engagement.Input{
		Name: b.Name, ClientName: b.ClientName, RoERef: b.RoERef,
		AuthorizedScope: b.AuthorizedScope, StartsAt: b.StartsAt, ExpiresAt: b.ExpiresAt, Notes: b.Notes,
	}
}

// validate checks the shared field rules for create/patch.
func (b engagementBody) validate(w http.ResponseWriter, r *http.Request) bool {
	if b.Name == "" || b.ClientName == "" {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "name and client_name are required")
		return false
	}
	if b.ExpiresAt != nil && b.StartsAt != nil && b.ExpiresAt.Before(*b.StartsAt) {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "expires_at must not be before starts_at")
		return false
	}
	if err := engagement.ValidateScope(b.AuthorizedScope); err != nil {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", err.Error())
		return false
	}
	return true
}

func (s *Server) createEngagement(w http.ResponseWriter, r *http.Request) {
	var b engagementBody
	if !decode(w, r, &b) {
		return
	}
	if !b.validate(w, r) {
		return
	}
	p, _ := auth.FromContext(r.Context())

	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "begin transaction")
		return
	}
	defer tx.Rollback(r.Context())

	e, err := s.engagements.Create(r.Context(), tx, p.TenantID, p.UserID, b.toInput())
	if err != nil {
		if isUniqueViolation(err) {
			httpx.Problem(w, r, http.StatusConflict, "conflict", "engagement name already exists for this tenant")
			return
		}
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "create engagement")
		return
	}
	if err := audit.Write(r.Context(), tx, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: "engagement.create", TargetType: "engagement", TargetID: e.ID.String(),
		Metadata: map[string]any{"name": e.Name, "client_name": e.ClientName},
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

func (s *Server) listEngagements(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	limit, offset := parsePage(r)
	items, err := s.engagements.List(r.Context(), s.pool, p.TenantID, limit, offset)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "list engagements")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": items, "limit": limit, "offset": offset})
}

func (s *Server) getEngagement(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	e, err := s.engagements.GetByID(r.Context(), s.pool, p.TenantID, id)
	if errors.Is(err, engagement.ErrNotFound) {
		httpx.Problem(w, r, http.StatusNotFound, "not found", "engagement not found")
		return
	}
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "get engagement")
		return
	}
	httpx.JSON(w, http.StatusOK, e)
}

func (s *Server) patchEngagement(w http.ResponseWriter, r *http.Request) {
	var b engagementBody
	if !decode(w, r, &b) {
		return
	}
	if !b.validate(w, r) {
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

	cur, err := s.engagements.GetByID(r.Context(), tx, p.TenantID, id)
	if errors.Is(err, engagement.ErrNotFound) {
		httpx.Problem(w, r, http.StatusNotFound, "not found", "engagement not found")
		return
	}
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "load engagement")
		return
	}
	if !cur.CanEdit() {
		httpx.Problem(w, r, http.StatusConflict, "conflict", "a terminated engagement cannot be edited")
		return
	}

	e, err := s.engagements.Update(r.Context(), tx, p.TenantID, id, b.toInput())
	if err != nil {
		if isUniqueViolation(err) {
			httpx.Problem(w, r, http.StatusConflict, "conflict", "engagement name already exists for this tenant")
			return
		}
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "update engagement")
		return
	}
	if err := audit.Write(r.Context(), tx, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: "engagement.update", TargetType: "engagement", TargetID: id.String(),
	}); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "commit")
		return
	}
	httpx.JSON(w, http.StatusOK, e)
}

func (s *Server) requestEngagementAuthorization(w http.ResponseWriter, r *http.Request) {
	s.engagementTransition(w, r, "engagement.request_authorization",
		func(e engagement.Engagement) bool { return e.CanRequestAuthorization() },
		func(ctx reqCtx) (engagement.Engagement, error) {
			return s.engagements.RequestAuthorization(ctx.r.Context(), ctx.tx, ctx.tenantID, ctx.id)
		})
}

func (s *Server) authorizeEngagement(w http.ResponseWriter, r *http.Request) {
	s.engagementTransition(w, r, "engagement.authorize",
		func(e engagement.Engagement) bool { return e.CanAuthorize() },
		func(ctx reqCtx) (engagement.Engagement, error) {
			return s.engagements.Authorize(ctx.r.Context(), ctx.tx, ctx.tenantID, ctx.id, ctx.actorID)
		})
}

func (s *Server) terminateEngagement(w http.ResponseWriter, r *http.Request) {
	s.engagementTransition(w, r, "engagement.terminate",
		func(e engagement.Engagement) bool { return e.CanTerminate() },
		func(ctx reqCtx) (engagement.Engagement, error) {
			return s.engagements.Terminate(ctx.r.Context(), ctx.tx, ctx.tenantID, ctx.id)
		})
}

// reqCtx bundles the values a transition mutator needs.
type reqCtx struct {
	r        *http.Request
	tx       db.Querier
	tenantID uuid.UUID
	actorID  uuid.UUID
	id       uuid.UUID
}

// engagementTransition is the shared skeleton for the three lifecycle actions:
// load within a tx, validate the transition is allowed from the current status
// (409 otherwise), apply the mutation, and audit with the previous + new
// status. The guard runs server-side regardless of client behavior.
func (s *Server) engagementTransition(
	w http.ResponseWriter, r *http.Request, action string,
	allowed func(engagement.Engagement) bool,
	mutate func(reqCtx) (engagement.Engagement, error),
) {
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

	cur, err := s.engagements.GetByID(r.Context(), tx, p.TenantID, id)
	if errors.Is(err, engagement.ErrNotFound) {
		httpx.Problem(w, r, http.StatusNotFound, "not found", "engagement not found")
		return
	}
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "load engagement")
		return
	}
	if !allowed(cur) {
		httpx.Problem(w, r, http.StatusConflict, "conflict",
			"action not allowed from status '"+string(cur.Status)+"'")
		return
	}

	e, err := mutate(reqCtx{r: r, tx: tx, tenantID: p.TenantID, actorID: p.UserID, id: id})
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "apply transition")
		return
	}
	if err := audit.Write(r.Context(), tx, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: action, TargetType: "engagement", TargetID: id.String(),
		Metadata: map[string]any{"from": string(cur.Status), "to": string(e.Status)},
	}); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "commit")
		return
	}
	httpx.JSON(w, http.StatusOK, e)
}

// checkEngagementGate verifies the campaign is bound to an engagement that is
// authorized and unexpired, writing the appropriate problem+json and returning
// false otherwise. Missing binding / not-authorized -> 403; expired /
// terminated -> 409. q is the active transaction or pool.
func (s *Server) checkEngagementGate(w http.ResponseWriter, r *http.Request, q db.Querier, tenantID uuid.UUID, camp campaign.Campaign) bool {
	if camp.EngagementID == nil {
		httpx.Problem(w, r, http.StatusForbidden, "forbidden",
			"campaign has no bound engagement; bind an authorized engagement before launch or send")
		return false
	}
	eng, err := s.engagements.GetByID(r.Context(), q, tenantID, *camp.EngagementID)
	if errors.Is(err, engagement.ErrNotFound) {
		httpx.Problem(w, r, http.StatusForbidden, "forbidden",
			"bound engagement no longer exists; bind an authorized engagement")
		return false
	}
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "load engagement")
		return false
	}
	switch chk := eng.CheckCampaignLaunchable(time.Now().UTC()); {
	case chk == nil:
		return true
	case errors.Is(chk, engagement.ErrEngagementNotAuthorized):
		httpx.Problem(w, r, http.StatusForbidden, "forbidden",
			"bound engagement is not authorized; request and obtain authorization first")
		return false
	case errors.Is(chk, engagement.ErrEngagementExpired):
		httpx.Problem(w, r, http.StatusConflict, "conflict", "bound engagement authorization has expired")
		return false
	case errors.Is(chk, engagement.ErrEngagementTerminated):
		httpx.Problem(w, r, http.StatusConflict, "conflict", "bound engagement has been terminated")
		return false
	default:
		httpx.Problem(w, r, http.StatusForbidden, "forbidden", "bound engagement is not usable")
		return false
	}
}
