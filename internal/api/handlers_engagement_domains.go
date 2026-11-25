package api

import (
	"errors"
	"net/http"

	"phishforge/internal/auth"
	"phishforge/internal/engagement"
	"phishforge/internal/httpx"
)

// listEngagementDomains returns the domains assigned to an engagement, each with
// its assignment status and authorized_at, excluding revoked assignments. It is
// tenant-scoped: an unknown or cross-tenant engagement id is 404 (not 403),
// matching the engagement GET. A bad id is 400 (parseID).
func (s *Server) listEngagementDomains(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}

	// Resolve the engagement within the tenant first so a cross-tenant id is a
	// 404 rather than an empty 200.
	if _, err := s.engagements.GetByID(r.Context(), s.pool, p.TenantID, id); errors.Is(err, engagement.ErrNotFound) {
		httpx.Problem(w, r, http.StatusNotFound, "not found", "engagement not found")
		return
	} else if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "load engagement")
		return
	}

	items, err := s.domains.ListByEngagement(r.Context(), s.pool, p.TenantID, id)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "list engagement domains")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": items})
}
