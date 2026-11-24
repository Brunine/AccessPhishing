package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"phishforge/internal/audit"
	"phishforge/internal/auth"
	"phishforge/internal/db"
	"phishforge/internal/dnsdiag"
	"phishforge/internal/domain"
	"phishforge/internal/engagement"
	"phishforge/internal/httpx"
)

// validTLSStatus mirrors the migration CHECK on domains.tls_status.
func validTLSStatus(s string) bool {
	switch s {
	case "none", "pending", "valid", "expiring", "invalid":
		return true
	default:
		return false
	}
}

// domainCreateBody is the manual-import request body. Only name is required.
// status, when given, is restricted to the pre-verification stages.
type domainCreateBody struct {
	Name         string     `json:"name"`
	Registrar    *string    `json:"registrar"`
	Status       *string    `json:"status"`
	RegisteredAt *time.Time `json:"registered_at"`
	ExpiresAt    *time.Time `json:"expires_at"`
	DNSProvider  *string    `json:"dns_provider"`
	Nameservers  []string   `json:"nameservers"`
	Notes        *string    `json:"notes"`
}

func (s *Server) createDomain(w http.ResponseWriter, r *http.Request) {
	var b domainCreateBody
	if !decode(w, r, &b) {
		return
	}
	name := domain.NormalizeName(b.Name)
	if !domain.ValidName(name) {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "name must be a valid domain")
		return
	}
	// Manual import lands in pending_verification (purchase already happened);
	// candidate/pending_purchase are settable for M8d forward-compat only.
	status := domain.StatusPendingVerification
	if b.Status != nil {
		if !domain.ValidCreateStatus(*b.Status) {
			httpx.Problem(w, r, http.StatusBadRequest, "invalid request",
				"status must be one of candidate, pending_purchase, pending_verification")
			return
		}
		status = domain.Status(*b.Status)
	}
	if b.ExpiresAt != nil && b.RegisteredAt != nil && b.ExpiresAt.Before(*b.RegisteredAt) {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "expires_at must not be before registered_at")
		return
	}
	p, _ := auth.FromContext(r.Context())

	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "begin transaction")
		return
	}
	defer tx.Rollback(r.Context())

	d, err := s.domains.Create(r.Context(), tx, p.TenantID, p.UserID, status, domain.Input{
		Name: name, Registrar: b.Registrar, RegisteredAt: b.RegisteredAt, ExpiresAt: b.ExpiresAt,
		DNSProvider: b.DNSProvider, Nameservers: b.Nameservers, Notes: b.Notes,
	})
	if err != nil {
		if isUniqueViolation(err) {
			httpx.Problem(w, r, http.StatusConflict, "conflict", "domain already exists for this tenant")
			return
		}
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "create domain")
		return
	}
	if err := audit.Write(r.Context(), tx, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: "domain.create", TargetType: "domain", TargetID: d.ID.String(),
		Metadata: map[string]any{"name": d.Name, "status": string(d.Status)},
	}); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "commit")
		return
	}
	httpx.JSON(w, http.StatusCreated, d)
}

func (s *Server) listDomains(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	limit, offset := parsePage(r)
	items, err := s.domains.List(r.Context(), s.pool, p.TenantID, limit, offset)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "list domains")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": items, "limit": limit, "offset": offset})
}

func (s *Server) getDomain(w http.ResponseWriter, r *http.Request) {
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
	httpx.JSON(w, http.StatusOK, d)
}

// domainPatchBody carries editable metadata plus an optional status change.
// name is intentionally not editable (it anchors the verification hostname).
type domainPatchBody struct {
	Registrar    *string    `json:"registrar"`
	Status       *string    `json:"status"`
	RegisteredAt *time.Time `json:"registered_at"`
	ExpiresAt    *time.Time `json:"expires_at"`
	DNSProvider  *string    `json:"dns_provider"`
	Nameservers  []string   `json:"nameservers"`
	TLSStatus    *string    `json:"tls_status"`
	Notes        *string    `json:"notes"`
}

func (s *Server) patchDomain(w http.ResponseWriter, r *http.Request) {
	var b domainPatchBody
	if !decode(w, r, &b) {
		return
	}
	if b.TLSStatus != nil && *b.TLSStatus != "" && !validTLSStatus(*b.TLSStatus) {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request",
			"tls_status must be one of none, pending, valid, expiring, invalid")
		return
	}
	if b.Status != nil && !domain.ValidStatus(*b.Status) {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "invalid status")
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

	cur, err := s.domains.GetByID(r.Context(), tx, p.TenantID, id)
	if errors.Is(err, domain.ErrNotFound) {
		httpx.Problem(w, r, http.StatusNotFound, "not found", "domain not found")
		return
	}
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "load domain")
		return
	}

	// Apply the metadata update (keeping the existing name).
	d, err := s.domains.Update(r.Context(), tx, p.TenantID, id, domain.Input{
		Name: cur.Name, Registrar: b.Registrar, RegisteredAt: b.RegisteredAt, ExpiresAt: b.ExpiresAt,
		DNSProvider: b.DNSProvider, Nameservers: b.Nameservers, TLSStatus: b.TLSStatus, Notes: b.Notes,
	})
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "update domain")
		return
	}

	// Optional PATCH-permitted status transition. The verified/active/suspended/
	// retired transitions are reached only through their dedicated endpoints;
	// PATCH may only advance the pre-verification stages or mark an expired
	// domain whose expires_at has passed.
	if b.Status != nil && domain.Status(*b.Status) != cur.Status {
		target := domain.Status(*b.Status)
		if !patchStatusAllowed(d, target, time.Now().UTC()) {
			httpx.Problem(w, r, http.StatusConflict, "conflict",
				"status transition '"+string(cur.Status)+"' -> '"+string(target)+"' is not permitted via PATCH")
			return
		}
		d, err = s.domains.SetStatus(r.Context(), tx, p.TenantID, id, target)
		if err != nil {
			httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "update status")
			return
		}
	}

	if err := audit.Write(r.Context(), tx, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: "domain.update", TargetType: "domain", TargetID: id.String(),
		Metadata: map[string]any{"status": string(d.Status)},
	}); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "commit")
		return
	}
	httpx.JSON(w, http.StatusOK, d)
}

// patchStatusAllowed reports whether a status change is allowed through PATCH
// (as opposed to the dedicated lifecycle endpoints). d carries the post-update
// expires_at used for the expiry gate.
func patchStatusAllowed(d domain.Domain, target domain.Status, now time.Time) bool {
	switch target {
	case domain.StatusPendingPurchase:
		return d.Status == domain.StatusCandidate
	case domain.StatusPendingVerification:
		return d.Status == domain.StatusCandidate || d.Status == domain.StatusPendingPurchase
	case domain.StatusExpired:
		return d.CanExpire(now)
	default:
		return false
	}
}

func (s *Server) deleteDomain(w http.ResponseWriter, r *http.Request) {
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

	cur, err := s.domains.GetByID(r.Context(), tx, p.TenantID, id)
	if errors.Is(err, domain.ErrNotFound) {
		httpx.Problem(w, r, http.StatusNotFound, "not found", "domain not found")
		return
	}
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "load domain")
		return
	}
	if !cur.CanDelete() {
		httpx.Problem(w, r, http.StatusConflict, "conflict",
			"an active domain cannot be deleted; suspend or retire it first")
		return
	}
	if err := s.domains.Delete(r.Context(), tx, p.TenantID, id); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "delete domain")
		return
	}
	if err := audit.Write(r.Context(), tx, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: "domain.delete", TargetType: "domain", TargetID: id.String(),
		Metadata: map[string]any{"name": cur.Name, "status": string(cur.Status)},
	}); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "commit")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- verification ---------------------------------------------------------

func genVerificationToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (s *Server) createDomainVerification(w http.ResponseWriter, r *http.Request) {
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

	d, err := s.domains.GetByID(r.Context(), tx, p.TenantID, id)
	if errors.Is(err, domain.ErrNotFound) {
		httpx.Problem(w, r, http.StatusNotFound, "not found", "domain not found")
		return
	}
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "load domain")
		return
	}
	if !d.CanRequestVerification() {
		httpx.Problem(w, r, http.StatusConflict, "conflict",
			"verification can only be requested while the domain is pending_verification (status '"+string(d.Status)+"')")
		return
	}

	token, err := genVerificationToken()
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "generate token")
		return
	}
	// The TXT value the operator publishes; CheckOwnership matches it exactly.
	txtRecord := "pf-domain-verify=" + token
	hostname := "_phishforge." + d.Name

	if err := s.domains.ExpirePendingVerifications(r.Context(), tx, p.TenantID, id); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "expire prior verifications")
		return
	}
	v, err := s.domains.CreateVerification(r.Context(), tx, p.TenantID, id, hostname, txtRecord, token)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "create verification")
		return
	}
	// Audit records the verification row id, never the token (secret).
	if err := audit.Write(r.Context(), tx, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: "domain.verification.create", TargetType: "domain_verification", TargetID: v.ID.String(),
		Metadata: map[string]any{"domain_id": id.String(), "hostname": hostname},
	}); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "commit")
		return
	}
	httpx.JSON(w, http.StatusCreated, map[string]any{
		"id":         v.ID,
		"hostname":   hostname,
		"token":      txtRecord,
		"txt_record": txtRecord,
	})
}

func (s *Server) checkDomainVerification(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	vid, ok := parseUUIDParam(w, r, "vid")
	if !ok {
		return
	}

	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "begin transaction")
		return
	}
	defer tx.Rollback(r.Context())

	d, err := s.domains.GetByID(r.Context(), tx, p.TenantID, id)
	if errors.Is(err, domain.ErrNotFound) {
		httpx.Problem(w, r, http.StatusNotFound, "not found", "domain not found")
		return
	}
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "load domain")
		return
	}
	v, err := s.domains.GetVerification(r.Context(), tx, p.TenantID, id, vid)
	if errors.Is(err, domain.ErrNotFound) {
		httpx.Problem(w, r, http.StatusNotFound, "not found", "verification not found")
		return
	}
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "load verification")
		return
	}
	if v.Status != domain.VerificationPending {
		httpx.Problem(w, r, http.StatusConflict, "conflict",
			"verification is not pending (status '"+string(v.Status)+"')")
		return
	}

	// SSRF/port-scan safety: the lookup host is always the stored verification
	// hostname (_phishforge.<domain>); no user-supplied host is dialed.
	ctx, cancel := context.WithTimeout(r.Context(), s.diagTimeout)
	defer cancel()
	okOwn, records, lookupErr := dnsdiag.CheckOwnership(ctx, s.resolver, v.Hostname, v.ExpectedValue)

	result := domain.VerificationVerified
	if lookupErr != nil || !okOwn {
		result = domain.VerificationFailed
	}

	if _, err := s.domains.MarkVerificationResult(r.Context(), tx, p.TenantID, id, vid, result); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "record verification result")
		return
	}

	promoted := false
	if result == domain.VerificationVerified {
		if !d.CanMarkVerified() {
			httpx.Problem(w, r, http.StatusConflict, "conflict",
				"domain is not pending_verification (status '"+string(d.Status)+"')")
			return
		}
		if _, err := s.domains.SetStatus(r.Context(), tx, p.TenantID, id, domain.StatusVerified); err != nil {
			httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "promote domain")
			return
		}
		promoted = true
	}

	if err := audit.Write(r.Context(), tx, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: "domain.verification.check", TargetType: "domain_verification", TargetID: vid.String(),
		Metadata: map[string]any{"domain_id": id.String(), "result": string(result), "promoted": promoted},
	}); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "commit")
		return
	}

	resp := map[string]any{"verified": result == domain.VerificationVerified, "txt_records": records}
	if lookupErr != nil {
		resp["lookup_error"] = lookupErr.Error()
	}
	httpx.JSON(w, http.StatusOK, resp)
}

// --- assignments ----------------------------------------------------------

func (s *Server) assignDomain(w http.ResponseWriter, r *http.Request) {
	var b struct {
		EngagementID uuid.UUID `json:"engagement_id"`
		Notes        *string   `json:"notes"`
	}
	if !decode(w, r, &b) {
		return
	}
	if b.EngagementID == uuid.Nil {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "engagement_id is required")
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

	d, err := s.domains.GetByID(r.Context(), tx, p.TenantID, id)
	if errors.Is(err, domain.ErrNotFound) {
		httpx.Problem(w, r, http.StatusNotFound, "not found", "domain not found")
		return
	}
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "load domain")
		return
	}
	if !d.CanAssign() {
		httpx.Problem(w, r, http.StatusConflict, "conflict",
			"domain must be verified before it can be assigned (status '"+string(d.Status)+"')")
		return
	}

	// The engagement must be same-tenant (400 otherwise) and authorized/active
	// (409 otherwise). Ownership (above) and authorization (here) are enforced
	// independently.
	eng, err := s.engagements.GetByID(r.Context(), tx, p.TenantID, b.EngagementID)
	if errors.Is(err, engagement.ErrNotFound) {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "engagement_id not found in tenant")
		return
	}
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "load engagement")
		return
	}
	if chk := eng.CheckCampaignLaunchable(time.Now().UTC()); chk != nil {
		httpx.Problem(w, r, http.StatusConflict, "conflict",
			"engagement is not authorized for assignment: "+chk.Error())
		return
	}

	a, err := s.domains.Assign(r.Context(), tx, p.TenantID, id, b.EngagementID, b.Notes)
	if err != nil {
		if isUniqueViolation(err) {
			httpx.Problem(w, r, http.StatusConflict, "conflict", "domain is already assigned to this engagement")
			return
		}
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "assign domain")
		return
	}
	if err := audit.Write(r.Context(), tx, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: "domain.assign", TargetType: "domain_assignment", TargetID: a.ID.String(),
		Metadata: map[string]any{"domain_id": id.String(), "engagement_id": b.EngagementID.String()},
	}); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "commit")
		return
	}
	httpx.JSON(w, http.StatusCreated, a)
}

func (s *Server) listDomainAssignments(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	if _, err := s.domains.GetByID(r.Context(), s.pool, p.TenantID, id); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			httpx.Problem(w, r, http.StatusNotFound, "not found", "domain not found")
			return
		}
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "load domain")
		return
	}
	items, err := s.domains.ListAssignments(r.Context(), s.pool, p.TenantID, id)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "list assignments")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) authorizeDomainAssignment(w http.ResponseWriter, r *http.Request) {
	s.domainAssignmentDecision(w, r, "domain.assignment.authorize", domain.AssignmentAuthorized)
}

func (s *Server) revokeDomainAssignment(w http.ResponseWriter, r *http.Request) {
	s.domainAssignmentDecision(w, r, "domain.assignment.revoke", domain.AssignmentRevoked)
}

// domainAssignmentDecision is the shared admin skeleton for assignment
// authorize/revoke: pending -> authorized, authorized -> revoked. Any other
// current status is a 409.
func (s *Server) domainAssignmentDecision(w http.ResponseWriter, r *http.Request, action string, target domain.AssignmentStatus) {
	p, _ := auth.FromContext(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	aid, ok := parseUUIDParam(w, r, "aid")
	if !ok {
		return
	}

	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "begin transaction")
		return
	}
	defer tx.Rollback(r.Context())

	a, err := s.domains.GetAssignment(r.Context(), tx, p.TenantID, id, aid)
	if errors.Is(err, domain.ErrNotFound) {
		httpx.Problem(w, r, http.StatusNotFound, "not found", "assignment not found")
		return
	}
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "load assignment")
		return
	}

	switch target {
	case domain.AssignmentAuthorized:
		if a.Status == domain.AssignmentAuthorized {
			httpx.Problem(w, r, http.StatusConflict, "conflict", domain.ErrAssignmentAlreadyAuthorized.Error())
			return
		}
		if a.Status != domain.AssignmentPending {
			httpx.Problem(w, r, http.StatusConflict, "conflict",
				"only a pending assignment can be authorized (status '"+string(a.Status)+"')")
			return
		}
	case domain.AssignmentRevoked:
		if a.Status != domain.AssignmentAuthorized {
			httpx.Problem(w, r, http.StatusConflict, "conflict",
				"only an authorized assignment can be revoked (status '"+string(a.Status)+"')")
			return
		}
	}

	var actor *uuid.UUID
	if target == domain.AssignmentAuthorized {
		actor = &p.UserID
	}
	upd, err := s.domains.SetAssignmentStatus(r.Context(), tx, p.TenantID, id, aid, target, actor)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "update assignment")
		return
	}
	if err := audit.Write(r.Context(), tx, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: action, TargetType: "domain_assignment", TargetID: aid.String(),
		Metadata: map[string]any{"domain_id": id.String(), "from": string(a.Status), "to": string(upd.Status)},
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

// --- domain lifecycle (admin) ---------------------------------------------

func (s *Server) activateDomain(w http.ResponseWriter, r *http.Request) {
	s.domainTransition(w, r, "domain.activate", domain.StatusActive,
		func(d domain.Domain) bool { return d.CanActivate() },
		func(ctx context.Context, tx db.Querier, tenantID, domainID uuid.UUID) (int, string, bool) {
			n, err := s.domains.CountAuthorizedAssignments(ctx, tx, tenantID, domainID)
			if err != nil {
				return http.StatusInternalServerError, "count assignments", false
			}
			if n == 0 {
				return http.StatusConflict, "activation requires at least one authorized assignment", false
			}
			return 0, "", true
		})
}

func (s *Server) suspendDomain(w http.ResponseWriter, r *http.Request) {
	s.domainTransition(w, r, "domain.suspend", domain.StatusSuspended,
		func(d domain.Domain) bool { return d.CanSuspend() }, nil)
}

func (s *Server) retireDomain(w http.ResponseWriter, r *http.Request) {
	s.domainTransition(w, r, "domain.retire", domain.StatusRetired,
		func(d domain.Domain) bool { return d.CanRetire() }, nil)
}

// domainTransition is the shared skeleton for the admin status actions: load
// within a tx, check the guard (409 otherwise), run an optional precheck, set
// the status, and audit {from,to}.
func (s *Server) domainTransition(
	w http.ResponseWriter, r *http.Request, action string, target domain.Status,
	allow func(domain.Domain) bool,
	precheck func(ctx context.Context, tx db.Querier, tenantID, domainID uuid.UUID) (int, string, bool),
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

	cur, err := s.domains.GetByID(r.Context(), tx, p.TenantID, id)
	if errors.Is(err, domain.ErrNotFound) {
		httpx.Problem(w, r, http.StatusNotFound, "not found", "domain not found")
		return
	}
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "load domain")
		return
	}
	if !allow(cur) {
		httpx.Problem(w, r, http.StatusConflict, "conflict",
			"action not allowed from status '"+string(cur.Status)+"'")
		return
	}
	if precheck != nil {
		if code, detail, pass := precheck(r.Context(), tx, p.TenantID, id); !pass {
			title := "conflict"
			if code == http.StatusInternalServerError {
				title = "internal error"
			}
			httpx.Problem(w, r, code, title, detail)
			return
		}
	}

	d, err := s.domains.SetStatus(r.Context(), tx, p.TenantID, id, target)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "apply transition")
		return
	}
	if err := audit.Write(r.Context(), tx, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: action, TargetType: "domain", TargetID: id.String(),
		Metadata: map[string]any{"from": string(cur.Status), "to": string(d.Status)},
	}); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "commit")
		return
	}
	httpx.JSON(w, http.StatusOK, d)
}

// parseUUIDParam parses a named chi URL param as a UUID, writing a 400 on error.
func parseUUIDParam(w http.ResponseWriter, r *http.Request, name string) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, name))
	if err != nil {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "invalid "+name)
		return uuid.Nil, false
	}
	return id, true
}
