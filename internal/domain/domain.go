// Package domain models the centralized domain inventory (M8b) and its
// lifecycle. A domain is externally purchased and manually imported, verified
// via a TXT record (ownership), and separately assigned to and authorized for
// an engagement (authorization). Ownership and authorization are INDEPENDENT:
// a verified domain may have no authorized assignment, and the two never
// substitute for one another.
//
// Lifecycle (an explicit state machine; stored transitions only):
//
//		candidate ─► pending_purchase ─► pending_verification ─TXT verify (API)─► verified
//		                                                                            │
//		                                           activate (admin, needs an        │
//		                                           authorized assignment)           ▼
//		                                                        active ◄──reactivate── suspended
//		                                                          │  └──suspend──────────►│
//		   any non-terminal ──────────────retire───────────────► retired (terminal)
//		   active|verified ──expire (PATCH, only when expires_at past)──► expired ─►retired
//
//	  - 'authorized' and 'expired' double as reserved/derived labels; the stored
//	    path a domain follows in this milestone is pending_verification ->
//	    verified -> active. Expiry is applied only via PATCH and only when
//	    expires_at is in the past (derive-and-note; no background auto-mutation).
//	  - 'verified' is reachable ONLY through successful TXT verification via the
//	    API, never through PATCH.
package domain

import (
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Status is a domain_status enum value.
type Status string

const (
	StatusCandidate           Status = "candidate"
	StatusPendingPurchase     Status = "pending_purchase"
	StatusPendingVerification Status = "pending_verification"
	StatusVerified            Status = "verified"
	StatusAuthorized          Status = "authorized"
	StatusActive              Status = "active"
	StatusSuspended           Status = "suspended"
	StatusExpired             Status = "expired"
	StatusRetired             Status = "retired"
)

// AssignmentStatus is a domain_assignments.status value.
type AssignmentStatus string

const (
	AssignmentPending    AssignmentStatus = "pending"
	AssignmentAuthorized AssignmentStatus = "authorized"
	AssignmentRevoked    AssignmentStatus = "revoked"
)

// VerificationStatus is a domain_verifications.status value.
type VerificationStatus string

const (
	VerificationPending  VerificationStatus = "pending"
	VerificationVerified VerificationStatus = "verified"
	VerificationFailed   VerificationStatus = "failed"
	VerificationExpired  VerificationStatus = "expired"
)

// Sentinel errors.
var (
	ErrNotFound                    = errors.New("domain: not found")
	ErrInvalidTransition           = errors.New("domain: invalid status transition")
	ErrDomainNotVerified           = errors.New("domain: not verified")
	ErrAssignmentAlreadyAuthorized = errors.New("domain: assignment already authorized")
)

// Domain is a single inventory domain owned by one tenant.
type Domain struct {
	ID           uuid.UUID  `json:"id"`
	TenantID     uuid.UUID  `json:"tenant_id"`
	Name         string     `json:"name"`
	Registrar    *string    `json:"registrar,omitempty"`
	Status       Status     `json:"status"`
	RegisteredAt *time.Time `json:"registered_at,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	DNSProvider  *string    `json:"dns_provider,omitempty"`
	Nameservers  []string   `json:"nameservers"`
	TLSStatus    *string    `json:"tls_status,omitempty"`
	Notes        *string    `json:"notes,omitempty"`
	CreatedBy    uuid.UUID  `json:"created_by"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

// Assignment binds a domain to an engagement.
type Assignment struct {
	ID           uuid.UUID        `json:"id"`
	TenantID     uuid.UUID        `json:"tenant_id"`
	DomainID     uuid.UUID        `json:"domain_id"`
	EngagementID uuid.UUID        `json:"engagement_id"`
	Status       AssignmentStatus `json:"status"`
	AuthorizedBy *uuid.UUID       `json:"authorized_by,omitempty"`
	AuthorizedAt *time.Time       `json:"authorized_at,omitempty"`
	Notes        *string          `json:"notes,omitempty"`
	CreatedAt    time.Time        `json:"created_at"`
	UpdatedAt    time.Time        `json:"updated_at"`
}

// EngagementDomain is a domain summary joined with its (non-revoked) assignment
// to an engagement, returned by the engagement domain listing.
type EngagementDomain struct {
	DomainID         uuid.UUID        `json:"domain_id"`
	Name             string           `json:"name"`
	Status           Status           `json:"status"`
	TLSStatus        *string          `json:"tls_status,omitempty"`
	ExpiresAt        *time.Time       `json:"expires_at,omitempty"`
	AssignmentID     uuid.UUID        `json:"assignment_id"`
	AssignmentStatus AssignmentStatus `json:"assignment_status"`
	AuthorizedAt     *time.Time       `json:"authorized_at,omitempty"`
}

// Verification is one TXT ownership challenge.
type Verification struct {
	ID            uuid.UUID          `json:"id"`
	TenantID      uuid.UUID          `json:"tenant_id"`
	DomainID      uuid.UUID          `json:"domain_id"`
	Method        string             `json:"method"`
	Hostname      string             `json:"hostname"`
	ExpectedValue string             `json:"expected_value"`
	Token         string             `json:"token"`
	Status        VerificationStatus `json:"status"`
	VerifiedAt    *time.Time         `json:"verified_at,omitempty"`
	CreatedAt     time.Time          `json:"created_at"`
}

// allowed is the single source of truth for stored status transitions. Each
// endpoint applies the subset it permits plus extra preconditions (an
// authorized assignment for activate; expires_at in the past for expire). It is
// exhaustively exercised by the transition-matrix unit test.
var allowed = map[Status][]Status{
	StatusCandidate:           {StatusPendingPurchase, StatusPendingVerification, StatusRetired},
	StatusPendingPurchase:     {StatusPendingVerification, StatusRetired},
	StatusPendingVerification: {StatusVerified, StatusRetired},
	StatusVerified:            {StatusAuthorized, StatusActive, StatusExpired, StatusRetired},
	StatusAuthorized:          {StatusActive, StatusExpired, StatusRetired},
	StatusActive:              {StatusSuspended, StatusExpired, StatusRetired},
	StatusSuspended:           {StatusActive, StatusRetired},
	StatusExpired:             {StatusRetired},
	StatusRetired:             {},
}

// ValidStatus reports whether s is a storable domain_status.
func ValidStatus(s string) bool {
	switch Status(s) {
	case StatusCandidate, StatusPendingPurchase, StatusPendingVerification,
		StatusVerified, StatusAuthorized, StatusActive, StatusSuspended,
		StatusExpired, StatusRetired:
		return true
	default:
		return false
	}
}

// ValidCreateStatus reports whether s is a status a manual import may be created
// in. Only the pre-verification stages are settable at create; everything past
// pending_verification is reached through the lifecycle, not by assertion.
func ValidCreateStatus(s string) bool {
	switch Status(s) {
	case StatusCandidate, StatusPendingPurchase, StatusPendingVerification:
		return true
	default:
		return false
	}
}

// CanTransition reports whether from -> to is a defined stored transition. A
// no-op (from == to) is not a transition and returns false.
func CanTransition(from, to Status) bool {
	for _, s := range allowed[from] {
		if s == to {
			return true
		}
	}
	return false
}

// CanRequestVerification reports whether a new TXT challenge may be created:
// only while the domain awaits verification.
func (d Domain) CanRequestVerification() bool {
	return d.Status == StatusPendingVerification
}

// CanMarkVerified reports whether a successful TXT check may promote the domain
// to verified (pending_verification -> verified).
func (d Domain) CanMarkVerified() bool {
	return CanTransition(d.Status, StatusVerified)
}

// CanAuthorize reports whether the domain is in a state where an assignment may
// be authorized against it (verified -> authorized is defined). It does not, by
// itself, authorize anything — assignment authorization is a separate admin
// action; this guards the domain side.
func (d Domain) CanAuthorize() bool {
	return CanTransition(d.Status, StatusAuthorized)
}

// CanAssign reports whether a domain may be attached to an engagement: it must
// be at least verified (verified or active; a suspended domain takes no new
// assignments).
func (d Domain) CanAssign() bool {
	return d.Status == StatusVerified || d.Status == StatusActive
}

// CanActivate reports whether the domain may move to active. This covers both
// first activation (verified -> active) and reactivation (suspended -> active);
// the handler additionally requires at least one authorized assignment.
func (d Domain) CanActivate() bool {
	return CanTransition(d.Status, StatusActive)
}

// CanSuspend reports whether the domain may be suspended (active -> suspended).
func (d Domain) CanSuspend() bool {
	return CanTransition(d.Status, StatusSuspended)
}

// CanRetire reports whether the domain may be retired. Any non-terminal status
// may retire; retired is terminal.
func (d Domain) CanRetire() bool {
	return CanTransition(d.Status, StatusRetired)
}

// CanExpire reports whether the domain may be marked expired at now: a defined
// transition (from active or verified) AND expires_at set and in the past.
// Used by PATCH only.
func (d Domain) CanExpire(now time.Time) bool {
	return CanTransition(d.Status, StatusExpired) &&
		d.ExpiresAt != nil && !now.Before(*d.ExpiresAt)
}

// CanDelete reports whether the domain row may be hard-deleted. Deletion is
// allowed from every status except active (an active domain must be suspended
// or retired first).
func (d Domain) CanDelete() bool {
	return d.Status != StatusActive
}

// IsExpiredByDate reports whether the domain's expires_at is in the past at now,
// regardless of stored status. This is a derived signal for display; it never
// auto-mutates the stored status.
func (d Domain) IsExpiredByDate(now time.Time) bool {
	return d.ExpiresAt != nil && !now.Before(*d.ExpiresAt)
}

// nameRe matches a lowercase hostname (domain) label sequence, mirroring the
// bare-domain rule used by engagement.ValidateScope.
var nameRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// NormalizeName lowercases and trims a domain name for storage and comparison.
func NormalizeName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// ValidName reports whether name is a syntactically valid, already-normalized
// (lowercase) bare domain. Callers normalize first.
func ValidName(name string) bool {
	return nameRe.MatchString(name)
}
