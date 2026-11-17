package api

import (
	"errors"
	"net/http"
	"strconv"

	"phishforge/internal/audit"
	"phishforge/internal/auth"
	"phishforge/internal/campaign"
	"phishforge/internal/httpx"
)

// defaultActivityLimit caps the activity feed when no limit is supplied.
const defaultActivityLimit = 50

// maxActivityLimit is the hard ceiling on a single activity page.
const maxActivityLimit = 500

// campaignTargets returns a campaign's recipients with their projected per-
// recipient state (from the events projection), for the campaign detail view.
// Read-only, operator, tenant-scoped.
func (s *Server) campaignTargets(w http.ResponseWriter, r *http.Request) {
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
	items, err := s.recipients.ListStateByCampaign(r.Context(), s.pool, p.TenantID, id)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "list targets")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": items})
}

// activity returns a tenant's recent audit entries and victim-state events for
// the dashboard activity feed. Read-only, operator, tenant-scoped.
func (s *Server) activity(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	limit := defaultActivityLimit
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > maxActivityLimit {
		limit = maxActivityLimit
	}

	entries, err := audit.List(r.Context(), s.pool, p.TenantID, limit)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "list audit")
		return
	}
	evs, err := s.events.ListByTenant(r.Context(), p.TenantID, limit)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "list events")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{
		"audit":  entries,
		"events": evs,
	})
}
