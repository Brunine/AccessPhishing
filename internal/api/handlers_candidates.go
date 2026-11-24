package api

import (
	"errors"
	"net/http"
	"time"

	"phishforge/internal/audit"
	"phishforge/internal/auth"
	"phishforge/internal/candidate"
	"phishforge/internal/engagement"
	"phishforge/internal/httpx"
)

// collectCandidates enqueues an engagement-scoped domain-candidate discovery
// run. It is gated exactly like campaign launch: the engagement must exist,
// be authorized (403 otherwise), be unexpired and non-terminated (409
// otherwise), and declare at least one authorized_scope entry (409 otherwise).
// The work runs asynchronously in the worker; this returns 202 Accepted.
func (s *Server) collectCandidates(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	if s.osint == nil {
		httpx.Problem(w, r, http.StatusServiceUnavailable, "unavailable",
			"candidate discovery needs the OSINT service (set OSINT_BASE_URL)")
		return
	}

	eng, err := s.engagements.GetByID(r.Context(), s.pool, p.TenantID, id)
	if errors.Is(err, engagement.ErrNotFound) {
		httpx.Problem(w, r, http.StatusNotFound, "not found", "engagement not found")
		return
	}
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "load engagement")
		return
	}
	if !s.engagementCandidateGate(w, r, eng) {
		return
	}
	if len(eng.AuthorizedScope) == 0 {
		httpx.Problem(w, r, http.StatusConflict, "conflict",
			"engagement has no authorized_scope to discover candidates from")
		return
	}

	if err := s.enqueuer.EnqueueCandidateCollect(r.Context(), p.TenantID, id, p.UserID); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "enqueue discovery job")
		return
	}
	if err := s.auditView(r, "candidate.collect.enqueue", "engagement", id.String()); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}
	httpx.JSON(w, http.StatusAccepted, map[string]any{
		"status":        "queued",
		"engagement_id": id,
		"message":       "candidate discovery queued; poll GET /engagements/{id}/candidates for results",
	})
}

// engagementCandidateGate mirrors the campaign launch gate (403 unauthorized,
// 409 expired/terminated) for an engagement loaded directly.
func (s *Server) engagementCandidateGate(w http.ResponseWriter, r *http.Request, eng engagement.Engagement) bool {
	switch chk := eng.CheckCampaignLaunchable(time.Now().UTC()); {
	case chk == nil:
		return true
	case errors.Is(chk, engagement.ErrEngagementNotAuthorized):
		httpx.Problem(w, r, http.StatusForbidden, "forbidden",
			"engagement is not authorized; request and obtain authorization first")
	case errors.Is(chk, engagement.ErrEngagementExpired):
		httpx.Problem(w, r, http.StatusConflict, "conflict", "engagement authorization has expired")
	case errors.Is(chk, engagement.ErrEngagementTerminated):
		httpx.Problem(w, r, http.StatusConflict, "conflict", "engagement has been terminated")
	default:
		httpx.Problem(w, r, http.StatusForbidden, "forbidden", "engagement is not usable")
	}
	return false
}

// listCandidates returns an engagement's ranked candidates, each with its
// registrar price quotes (batched; no N+1).
func (s *Server) listCandidates(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	if _, err := s.engagements.GetByID(r.Context(), s.pool, p.TenantID, id); err != nil {
		if errors.Is(err, engagement.ErrNotFound) {
			httpx.Problem(w, r, http.StatusNotFound, "not found", "engagement not found")
			return
		}
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "load engagement")
		return
	}

	items, err := s.candidates.ListByEngagement(r.Context(), s.pool, p.TenantID, id)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "list candidates")
		return
	}
	quotes, err := s.candidates.ListQuotesByEngagement(r.Context(), s.pool, p.TenantID, id)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "list quotes")
		return
	}
	for i := range items {
		items[i].Quotes = quotes[items[i].ID]
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": items})
}

// getCandidate returns one candidate with its quotes.
func (s *Server) getCandidate(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	cid, ok := parseUUIDParam(w, r, "cid")
	if !ok {
		return
	}
	c, err := s.candidates.GetByID(r.Context(), s.pool, p.TenantID, id, cid)
	if errors.Is(err, candidate.ErrNotFound) {
		httpx.Problem(w, r, http.StatusNotFound, "not found", "candidate not found")
		return
	}
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "get candidate")
		return
	}
	quotes, err := s.candidates.ListQuotesByEngagement(r.Context(), s.pool, p.TenantID, id)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "list quotes")
		return
	}
	c.Quotes = quotes[c.ID]
	httpx.JSON(w, http.StatusOK, c)
}

// selectCandidate records the operator's pick (-> selected). The operator then
// purchases externally and imports via the existing /domains flow.
func (s *Server) selectCandidate(w http.ResponseWriter, r *http.Request) {
	s.candidateDecision(w, r, "candidate.select", candidate.StatusSelected,
		func(c candidate.Candidate) bool { return c.CanSelect() })
}

// rejectCandidate dismisses a candidate (-> rejected).
func (s *Server) rejectCandidate(w http.ResponseWriter, r *http.Request) {
	s.candidateDecision(w, r, "candidate.reject", candidate.StatusRejected,
		func(c candidate.Candidate) bool { return c.CanReject() })
}

// candidateDecision is the shared operator pick/reject skeleton: load within a
// tx, check the guard (409 otherwise), set the status, and audit {from,to}.
func (s *Server) candidateDecision(w http.ResponseWriter, r *http.Request, action string, target candidate.Status, allow func(candidate.Candidate) bool) {
	p, _ := auth.FromContext(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	cid, ok := parseUUIDParam(w, r, "cid")
	if !ok {
		return
	}

	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "begin transaction")
		return
	}
	defer tx.Rollback(r.Context())

	cur, err := s.candidates.GetByID(r.Context(), tx, p.TenantID, id, cid)
	if errors.Is(err, candidate.ErrNotFound) {
		httpx.Problem(w, r, http.StatusNotFound, "not found", "candidate not found")
		return
	}
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "load candidate")
		return
	}
	if !allow(cur) {
		httpx.Problem(w, r, http.StatusConflict, "conflict",
			"action not allowed from status '"+string(cur.Status)+"'")
		return
	}

	upd, err := s.candidates.SetStatus(r.Context(), tx, p.TenantID, id, cid, target)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "update candidate")
		return
	}
	if err := audit.Write(r.Context(), tx, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: action, TargetType: "domain_candidate", TargetID: cid.String(),
		Metadata: map[string]any{"engagement_id": id.String(), "name": cur.Name, "from": string(cur.Status), "to": string(upd.Status)},
	}); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "commit")
		return
	}
	httpx.JSON(w, http.StatusOK, upd)
}

// listRegistrars returns the global registrar catalog (read-only).
func (s *Server) listRegistrars(w http.ResponseWriter, r *http.Request) {
	items, err := s.candidates.ListProviders(r.Context(), s.pool)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "list registrars")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": items})
}
