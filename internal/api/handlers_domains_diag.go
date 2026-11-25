package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"phishforge/internal/audit"
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
	now := time.Now().UTC()
	info, tlsErr := s.tlsInspect(tctx, d.Name, 443, s.diagTimeout)
	var derivedTLS string
	if tlsErr != nil {
		errs = append(errs, "tls: "+tlsErr.Error())
		derivedTLS = domain.DeriveTLSStatus(tlsErr, time.Time{}, s.tlsThreshold, now)
	} else {
		tlsInfo = &info
		if !info.CoversDomain {
			warnings = append(warnings, "TLS certificate does not cover the domain")
		}
		derivedTLS = domain.DeriveTLSStatus(nil, info.NotAfter, s.tlsThreshold, now)
	}

	// Persist the derived tls_status, and audit, ONLY when it differs from the
	// stored value. The domain lifecycle status is never touched from TLS.
	if d.TLSStatus == nil || *d.TLSStatus != derivedTLS {
		if err := s.persistTLSStatus(r, p, d, derivedTLS); err != nil {
			httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "persist tls status")
			return
		}
	}

	httpx.JSON(w, http.StatusOK, map[string]any{
		"domain":     d.Name,
		"status":     string(d.Status),
		"dns":        dns,
		"tls":        tlsInfo,
		"tls_status": derivedTLS,
		"ownership":  map[string]any{"verified": ownershipVerified},
		"warnings":   warnings,
		"errors":     errs,
	})
}

// persistTLSStatus writes the derived tls_status and an audit entry (from/to)
// in one transaction, so the change and its audit trail commit together. Called
// only when the derived value differs from what is stored.
func (s *Server) persistTLSStatus(r *http.Request, p auth.Principal, d domain.Domain, derived string) error {
	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		return err
	}
	defer tx.Rollback(r.Context())

	if err := s.domains.UpdateTLSStatus(r.Context(), tx, p.TenantID, d.ID, derived); err != nil {
		return err
	}
	var from any
	if d.TLSStatus != nil {
		from = *d.TLSStatus
	}
	if err := audit.Write(r.Context(), tx, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: "domain.tls_status", TargetType: "domain", TargetID: d.ID.String(),
		Metadata: map[string]any{"from": from, "to": derived},
	}); err != nil {
		return err
	}
	return tx.Commit(r.Context())
}
