package api

import (
	"encoding/csv"
	"errors"
	"fmt"
	"net/http"
	"time"

	"phishforge/internal/audit"
	"phishforge/internal/auth"
	"phishforge/internal/campaign"
	"phishforge/internal/httpx"
)

// auditView records a read-only report access (best-effort, non-transactional).
func (s *Server) auditView(r *http.Request, action, targetType, targetID string) error {
	p, _ := auth.FromContext(r.Context())
	return audit.Write(r.Context(), s.pool, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: action, TargetType: targetType, TargetID: targetID,
	})
}

// campaignReport returns the full KPI set + timeline for a campaign.
func (s *Server) campaignReport(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	id, ok := parseID(w, r)
	if !ok {
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

	bucket := r.URL.Query().Get("bucket")
	rep, err := s.reports.Campaign(r.Context(), s.pool, p.TenantID, id, camp.Name, camp.Status, bucket)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "build report")
		return
	}
	if err := s.auditView(r, "report.view", "campaign", id.String()); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}
	httpx.JSON(w, http.StatusOK, rep)
}

// campaignReportCSV returns a flat per-recipient drilldown export.
func (s *Server) campaignReportCSV(w http.ResponseWriter, r *http.Request) {
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

	rows, err := s.reports.Recipients(r.Context(), s.pool, p.TenantID, id)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "build export")
		return
	}
	if err := s.auditView(r, "report.export", "campaign", id.String()); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"campaign-%s.csv\"", id.String()))
	w.WriteHeader(http.StatusOK)

	cw := csv.NewWriter(w)
	_ = cw.Write([]string{
		"email", "state", "sent_at", "delivered_at", "opened_at",
		"clicked_at", "creds_at", "session_hijacked_at", "last_event_at",
	})
	for _, row := range rows {
		_ = cw.Write([]string{
			row.Email, row.State,
			fmtTime(row.SentAt), fmtTime(row.DeliveredAt), fmtTime(row.OpenedAt),
			fmtTime(row.ClickedAt), fmtTime(row.CredsAt), fmtTime(row.SessionHijackedAt),
			fmtTime(row.LastEventAt),
		})
	}
	cw.Flush()
}

// tenantSummary returns the portfolio rollup for the caller's own tenant.
func (s *Server) tenantSummary(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	// Tenant-scoped: an operator may only read their own tenant's summary.
	if id != p.TenantID {
		httpx.Problem(w, r, http.StatusForbidden, "forbidden", "cannot read another tenant's summary")
		return
	}
	sum, err := s.reports.TenantSummary(r.Context(), s.pool, p.TenantID)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "build summary")
		return
	}
	if err := s.auditView(r, "report.tenant_summary", "tenant", id.String()); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}
	httpx.JSON(w, http.StatusOK, sum)
}

func fmtTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
