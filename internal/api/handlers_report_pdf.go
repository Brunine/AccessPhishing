package api

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"phishforge/internal/auth"
	"phishforge/internal/campaign"
	"phishforge/internal/httpx"
	"phishforge/internal/pdfexport"
)

func sanitizeFilename(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '_':
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		out = "report"
	}
	if len(out) > 60 {
		out = out[:60]
	}
	return out
}

func (s *Server) tenantName(r *http.Request) string {
	p, _ := auth.FromContext(r.Context())
	t, err := s.tenants.GetByID(r.Context(), s.pool, p.TenantID)
	if err != nil {
		return "Tenant " + p.TenantID.String()[:8]
	}
	return t.Name
}

// writePDF renders to a buffer (to catch errors before headers are sent), sets
// the PDF headers, and writes. gofpdf builds the document fully in memory, so
// buffering is inherent; this also lets us return a clean error on failure.
func (s *Server) writePDF(w http.ResponseWriter, r *http.Request, filename string, render func(*bytes.Buffer) error) {
	var buf bytes.Buffer
	if err := render(&buf); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "render pdf")
		return
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", buf.Len()))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}

// campaignReportPDF renders a single-campaign executive PDF.
func (s *Server) campaignReportPDF(w http.ResponseWriter, r *http.Request) {
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
	recipients, err := s.reports.Recipients(r.Context(), s.pool, p.TenantID, id)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "build drilldown")
		return
	}
	if err := s.auditView(r, "report.pdf", "campaign", id.String()); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}

	meta := pdfexport.Meta{TenantName: s.tenantName(r), GeneratedAt: time.Now().UTC()}
	fname := fmt.Sprintf("campaign-%s-%s.pdf", sanitizeFilename(camp.Name), time.Now().UTC().Format("20060102"))
	s.writePDF(w, r, fname, func(buf *bytes.Buffer) error {
		return pdfexport.CampaignPDF(buf, meta, rep, recipients)
	})
}

// tenantSummaryPDF renders a tenant-level executive PDF (own tenant only).
func (s *Server) tenantSummaryPDF(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	if id != p.TenantID {
		httpx.Problem(w, r, http.StatusForbidden, "forbidden", "cannot read another tenant's summary")
		return
	}
	sum, err := s.reports.TenantSummary(r.Context(), s.pool, p.TenantID)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "build summary")
		return
	}
	osint, err := s.osintResults.List(r.Context(), s.pool, p.TenantID, pdfexport.MaxOSINTRows, 0)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "load osint")
		return
	}
	if err := s.auditView(r, "report.tenant_summary.pdf", "tenant", id.String()); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}

	name := s.tenantName(r)
	meta := pdfexport.Meta{TenantName: name, GeneratedAt: time.Now().UTC()}
	fname := fmt.Sprintf("tenant-%s-%s.pdf", sanitizeFilename(name), time.Now().UTC().Format("20060102"))
	s.writePDF(w, r, fname, func(buf *bytes.Buffer) error {
		return pdfexport.TenantPDF(buf, meta, sum, osint)
	})
}
