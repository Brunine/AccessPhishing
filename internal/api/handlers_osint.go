package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"phishforge/internal/audit"
	"phishforge/internal/auth"
	"phishforge/internal/httpx"
)

// osintStatus reports reachability of the OSINT service.
func (s *Server) osintStatus(w http.ResponseWriter, r *http.Request) {
	if s.osint == nil {
		httpx.Problem(w, r, http.StatusServiceUnavailable, "unavailable", "OSINT not configured (set OSINT_BASE_URL)")
		return
	}
	status := "ok"
	if err := s.osint.Health(r.Context()); err != nil {
		status = "down"
	}
	if err := s.auditView(r, "osint.status", "osint", ""); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"service": status})
}

// osintCollect kicks off a passive collection for a domain and upserts the
// result. The orchestrator does no scanning itself — it delegates to the
// service, which aggregates public info (crt.sh/subfinder, lookalike
// generation, RDAP).
func (s *Server) osintCollect(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Domain string `json:"domain"`
	}
	if !decode(w, r, &b) {
		return
	}
	domain := strings.TrimSpace(strings.ToLower(b.Domain))
	if domain == "" || !strings.Contains(domain, ".") || strings.ContainsAny(domain, " /:") {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "a valid domain is required")
		return
	}
	if s.osint == nil {
		httpx.Problem(w, r, http.StatusServiceUnavailable, "unavailable", "OSINT not configured (set OSINT_BASE_URL)")
		return
	}
	p, _ := auth.FromContext(r.Context())

	collected, err := s.osint.Collect(r.Context(), domain)
	if err != nil {
		// The service is an optional dependency: unreachable or failing => 503.
		httpx.Problem(w, r, http.StatusServiceUnavailable, "unavailable", "osint collection failed: "+err.Error())
		return
	}
	payload, err := json.Marshal(collected)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "encode result")
		return
	}

	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "begin transaction")
		return
	}
	defer tx.Rollback(r.Context())

	stored, err := s.osintResults.Upsert(r.Context(), tx, p.TenantID, p.UserID, domain, payload)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "store result")
		return
	}
	if err := audit.Write(r.Context(), tx, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: "osint.collect", TargetType: "osint_result", TargetID: stored.ID.String(),
		Metadata: map[string]any{"domain": domain},
	}); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "commit")
		return
	}
	httpx.JSON(w, http.StatusCreated, stored)
}

// osintResultsList returns a tenant's stored collection results.
func (s *Server) osintResultsList(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	limit, offset := parsePage(r)
	items, err := s.osintResults.List(r.Context(), s.pool, p.TenantID, limit, offset)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "list results")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": items, "limit": limit, "offset": offset})
}
