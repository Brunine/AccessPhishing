package api

import (
	"context"
	"errors"
	"net/http"

	"phishforge/internal/auth"
	"phishforge/internal/dnsdiag"
	"phishforge/internal/domain"
	"phishforge/internal/httpx"
)

// diagDNS is the DNS section of a diagnostics response.
type diagDNS struct {
	Nameservers []string `json:"nameservers"`
	SPF         string   `json:"spf"`
	DMARC       string   `json:"dmarc"`
	DKIM        *string  `json:"dkim"`
	DKIMNote    string   `json:"dkim_note"`
}

// domainDiagnostics runs live DNS/TLS diagnostics for a domain and returns a
// structured report. It is read-only (no audit, mirroring the report
// endpoints). Warnings (e.g. a verified domain with no SPF) are separated from
// errors (lookup/dial failures), so a domain with no DNS yields a 200 with
// populated errors[] rather than a 500.
//
// SSRF/port-scan safety: every lookup and the TLS dial target the stored domain
// name only — never a user-supplied host — and TLS is dialed on 443 alone.
func (s *Server) domainDiagnostics(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	d, err := s.domains.GetByID(r.Context(), s.pool, p.TenantID, id)
	if errors.Is(err, domain.ErrNotFound) {
		httpx.Problem(w, r, http.StatusNotFound, "not found", "domain not found")
		return
	}
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "get domain")
		return
	}

	warnings := []string{}
	errs := []string{}
	ownershipVerified := d.Status == domain.StatusVerified || d.Status == domain.StatusActive ||
		d.Status == domain.StatusSuspended

	dns := diagDNS{
		Nameservers: []string{},
		DKIM:        nil,
		DKIMNote:    "no DKIM selector configured for this domain yet",
	}

	// DNS lookups share one bounded context.
	dctx, dcancel := context.WithTimeout(r.Context(), s.diagTimeout)
	defer dcancel()

	if ns, err := dnsdiag.Nameservers(dctx, s.resolver, d.Name); err != nil {
		errs = append(errs, "nameservers: "+err.Error())
	} else {
		dns.Nameservers = ns
	}

	if spf, err := dnsdiag.SPF(dctx, s.resolver, d.Name); err != nil {
		errs = append(errs, "spf: "+err.Error())
	} else {
		dns.SPF = spf
		if spf == "" && ownershipVerified {
			warnings = append(warnings, "no SPF record published")
		}
	}

	if dmarc, err := dnsdiag.DMARC(dctx, s.resolver, d.Name); err != nil {
		errs = append(errs, "dmarc: "+err.Error())
	} else {
		dns.DMARC = dmarc
		if dmarc == "" && ownershipVerified {
			warnings = append(warnings, "no DMARC record published")
		}
	}

	// TLS inspection on 443 only (constrained host + port — not SSRF-able).
	var tlsInfo *dnsdiag.TLSInfo
	tctx, tcancel := context.WithTimeout(r.Context(), s.diagTimeout)
	defer tcancel()
	if info, err := dnsdiag.TLS(tctx, d.Name, 443, s.diagTimeout); err != nil {
		errs = append(errs, "tls: "+err.Error())
	} else {
		tlsInfo = &info
		if !info.CoversDomain {
			warnings = append(warnings, "TLS certificate does not cover the domain")
		}
	}

	httpx.JSON(w, http.StatusOK, map[string]any{
		"domain":    d.Name,
		"status":    string(d.Status),
		"dns":       dns,
		"tls":       tlsInfo,
		"ownership": map[string]any{"verified": ownershipVerified},
		"warnings":  warnings,
		"errors":    errs,
	})
}
