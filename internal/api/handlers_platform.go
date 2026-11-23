package api

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"time"

	"phishforge/internal/httpx"
	"phishforge/internal/pdfexport"
	"phishforge/internal/tenant"
)

// Platform endpoints give internal platform admins a cross-tenant view. In this
// self-hosted, internal platform the admin role is platform-level (the existing
// /tenants list/get are admin-gated and cross-tenant); these endpoints extend
// that to read-only KPI oversight across all tenants. All are audited.

// platformTenants lists every tenant with its headline KPI rollup.
func (s *Server) platformTenants(w http.ResponseWriter, r *http.Request) {
	items, err := s.reports.PlatformOverview(r.Context(), s.pool)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "platform overview")
		return
	}
	if err := s.auditView(r, "platform.overview", "platform", ""); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": items})
}

// platformTenantSummary returns any tenant's KPI rollup (admin cross-tenant).
func (s *Server) platformTenantSummary(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	if _, err := s.tenants.GetByID(r.Context(), s.pool, id); err != nil {
		if errors.Is(err, tenant.ErrNotFound) {
			httpx.Problem(w, r, http.StatusNotFound, "not found", "tenant not found")
			return
		}
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "load tenant")
		return
	}
	sum, err := s.reports.TenantSummary(r.Context(), s.pool, id)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "build summary")
		return
	}
	if err := s.auditView(r, "platform.tenant_summary", "tenant", id.String()); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}
	httpx.JSON(w, http.StatusOK, sum)
}

// platformTenantSummaryPDF renders any tenant's executive PDF (admin cross-tenant).
func (s *Server) platformTenantSummaryPDF(w http.ResponseWriter, r *http.Request) {
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
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "load tenant")
		return
	}
	sum, err := s.reports.TenantSummary(r.Context(), s.pool, id)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "build summary")
		return
	}
	osint, err := s.osintResults.List(r.Context(), s.pool, id, pdfexport.MaxOSINTRows, 0)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "load osint")
		return
	}
	if err := s.auditView(r, "platform.tenant_summary.pdf", "tenant", id.String()); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}
	meta := pdfexport.Meta{TenantName: t.Name, GeneratedAt: time.Now().UTC()}
	fname := fmt.Sprintf("tenant-%s-%s.pdf", sanitizeFilename(t.Name), time.Now().UTC().Format("20060102"))
	s.writePDF(w, r, fname, func(buf *bytes.Buffer) error {
		return pdfexport.TenantPDF(buf, meta, sum, osint)
	})
}
