// Package engagement models the authorization container for campaigns.
//
// An engagement is an authorized testing engagement against a client. A
// campaign may not be launched or sent until it is bound to an engagement that
// is authorized, not past its expiry, and not terminated.
//
// Lifecycle (an explicit state machine, mirroring internal/events):
//
//		draft ──request-authorization──► pending_authorization ──authorize(admin)──► authorized
//		  └───────────────────────── terminate(admin) ──────────────────────────► terminated
//
//	  - 'active' is DERIVED, never stored: an authorized engagement whose
//	    expires_at (if set) is in the future and which is not terminated.
//	  - 'expired' is DERIVED at the point of use (launch/send), never stored:
//	    an authorized engagement whose expires_at is in the past. A background
//	    job to persist 'expired' may arrive later; it is out of scope here.
//	  - terminated is terminal: no re-authorization.
package engagement

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Status is an engagement_status enum value.
type Status string

const (
	StatusDraft      Status = "draft"
	StatusPending    Status = "pending_authorization"
	StatusAuthorized Status = "authorized"
	StatusActive     Status = "active" // derived label only; never stored
	StatusExpired    Status = "expired"
	StatusTerminated Status = "terminated"
)

// Sentinel errors returned by the launch/send enforcement check. Handlers map
// them to HTTP status codes: not-authorized -> 403, expired/terminated -> 409.
var (
	// ErrNoEngagement means a campaign has no bound engagement.
	ErrNoEngagement = errors.New("engagement: campaign has no bound engagement")
	// ErrEngagementNotAuthorized means the bound engagement is not yet authorized.
	ErrEngagementNotAuthorized = errors.New("engagement: not authorized")
	// ErrEngagementExpired means the bound engagement is past its expiry.
	ErrEngagementExpired = errors.New("engagement: authorization expired")
	// ErrEngagementTerminated means the bound engagement was terminated.
	ErrEngagementTerminated = errors.New("engagement: terminated")
)

// ErrNotFound is returned when an engagement does not exist within the tenant.
var ErrNotFound = errors.New("engagement: not found")

// ErrInvalidTransition is returned when a lifecycle action is not allowed from
// the engagement's current status.
var ErrInvalidTransition = errors.New("engagement: invalid status transition")

// Engagement is an authorized testing engagement owned by a single tenant.
type Engagement struct {
	ID              uuid.UUID  `json:"id"`
	TenantID        uuid.UUID  `json:"tenant_id"`
	Name            string     `json:"name"`
	ClientName      string     `json:"client_name"`
	ClientID        *uuid.UUID `json:"client_id,omitempty"`
	Status          Status     `json:"status"`
	RoERef          *string    `json:"roe_reference,omitempty"`
	AuthorizedScope []string   `json:"authorized_scope"`
	AuthorizedAt    *time.Time `json:"authorized_at,omitempty"`
	AuthorizedBy    *uuid.UUID `json:"authorized_by,omitempty"`
	StartsAt        *time.Time `json:"starts_at,omitempty"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	Notes           *string    `json:"notes,omitempty"`
	CreatedBy       uuid.UUID  `json:"created_by"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	// EffectiveStatus is the derived status label (active/expired computed from
	// status + expires_at). It is populated on read and never persisted.
	EffectiveStatus Status `json:"effective_status"`
}

// ValidStatus reports whether s is a storable engagement_status.
func ValidStatus(s string) bool {
	switch Status(s) {
	case StatusDraft, StatusPending, StatusAuthorized, StatusActive, StatusExpired, StatusTerminated:
		return true
	default:
		return false
	}
}

// IsExpired reports whether the engagement is past its expiry at now. An
// engagement with no expires_at never expires.
func (e Engagement) IsExpired(now time.Time) bool {
	return e.ExpiresAt != nil && !now.Before(*e.ExpiresAt)
}

// IsActive reports whether the engagement is currently usable: authorized, not
// terminated, and not past its expiry.
func (e Engagement) IsActive(now time.Time) bool {
	return e.Status == StatusAuthorized && !e.IsExpired(now)
}

// Effective returns the derived status label for display: terminated as-is,
// an authorized-but-expired engagement as 'expired', an authorized-and-current
// one as 'active', otherwise the stored status.
func (e Engagement) Effective(now time.Time) Status {
	if e.Status == StatusTerminated {
		return StatusTerminated
	}
	if e.Status == StatusAuthorized {
		if e.IsExpired(now) {
			return StatusExpired
		}
		return StatusActive
	}
	return e.Status
}

// CheckCampaignLaunchable reports whether a campaign bound to this engagement
// may be launched or sent at now, returning a sentinel error otherwise.
func (e Engagement) CheckCampaignLaunchable(now time.Time) error {
	switch {
	case e.Status == StatusTerminated:
		return ErrEngagementTerminated
	case e.Status != StatusAuthorized:
		return ErrEngagementNotAuthorized
	case e.IsExpired(now):
		return ErrEngagementExpired
	default:
		return nil
	}
}

// CanRequestAuthorization reports whether request-authorization is allowed from
// the current status (draft or pending_authorization).
func (e Engagement) CanRequestAuthorization() bool {
	return e.Status == StatusDraft || e.Status == StatusPending
}

// CanAuthorize reports whether authorize is allowed (pending_authorization).
func (e Engagement) CanAuthorize() bool { return e.Status == StatusPending }

// CanTerminate reports whether terminate is allowed: any non-terminal status
// (anything except already terminated).
func (e Engagement) CanTerminate() bool { return e.Status != StatusTerminated }

// CanEdit reports whether PATCH is allowed from the current status. Editing is
// permitted in draft/pending_authorization/authorized; a terminated engagement
// is immutable.
func (e Engagement) CanEdit() bool { return e.Status != StatusTerminated }

// scopeEntry matches a bare domain or wildcard domain, e.g. acme.com or
// *.acme.com. URL-form entries (with a scheme) are validated via net/url.
var scopeEntry = regexp.MustCompile(`^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$`)

// ValidateScope checks that every entry is a syntactically valid URL (with an
// http/https scheme and a host) or a bare/wildcard domain. It returns an error
// naming the first invalid entry. An empty slice is valid.
func ValidateScope(scope []string) error {
	for _, raw := range scope {
		s := strings.TrimSpace(raw)
		if s == "" {
			return fmt.Errorf("empty scope entry")
		}
		if strings.Contains(s, "://") {
			u, err := url.Parse(s)
			if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
				return fmt.Errorf("invalid scope URL %q", raw)
			}
			continue
		}
		if !scopeEntry.MatchString(s) {
			return fmt.Errorf("invalid scope domain %q", raw)
		}
	}
	return nil
}
