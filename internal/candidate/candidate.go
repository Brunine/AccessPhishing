// Package candidate implements M8d domain discovery and procurement support:
// engagement-scoped suggestion of lookalike/typo candidate domains, comparable
// registrar price quotes, and deterministic ranking. It never purchases or
// registers anything — the operator picks a ranked candidate, buys it
// externally, and imports it through the existing manual internal/domain flow.
//
// Availability and pricing are always the product of deterministic, verifiable
// sources (the OSINT service's RDAP checks and registrar price APIs). An LLM, if
// configured, may only propose additional candidate NAMES; it is never the
// source of truth for availability, price, or rank.
package candidate

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

// Status is a domain_candidate_status enum value.
type Status string

const (
	// StatusSuggested is a freshly suggested candidate not yet scored.
	StatusSuggested Status = "suggested"
	// StatusScored is a candidate that has been priced and scored.
	StatusScored Status = "scored"
	// StatusSelected is a candidate the operator picked to purchase externally.
	StatusSelected Status = "selected"
	// StatusRejected is a candidate the operator dismissed.
	StatusRejected Status = "rejected"
	// StatusImported marks a candidate whose domain was imported to inventory.
	StatusImported Status = "imported"
)

// Sentinel errors.
var (
	ErrNotFound    = errors.New("candidate: not found")
	ErrNoScope     = errors.New("candidate: engagement has no authorized scope")
	ErrInvalidPick = errors.New("candidate: invalid status transition")
)

// Candidate is one suggested domain for an engagement.
type Candidate struct {
	ID           uuid.UUID       `json:"id"`
	TenantID     uuid.UUID       `json:"tenant_id"`
	EngagementID uuid.UUID       `json:"engagement_id"`
	Source       string          `json:"source"`
	Name         string          `json:"name"`
	Fuzzer       *string         `json:"fuzzer,omitempty"`
	Available    *bool           `json:"available,omitempty"`
	Score        json.RawMessage `json:"score"`
	Rank         *int            `json:"rank,omitempty"`
	Status       Status          `json:"status"`
	Notes        *string         `json:"notes,omitempty"`
	CreatedBy    *uuid.UUID      `json:"created_by,omitempty"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
	// Quotes is populated by the list/get handlers, not stored on the row.
	Quotes []Quote `json:"quotes,omitempty"`
}

// Quote is a stored, normalized registrar price quote for a candidate. Prices
// are in minor units (cents) of Currency; a nil field means unpriced.
type Quote struct {
	ID             uuid.UUID `json:"id"`
	CandidateID    uuid.UUID `json:"candidate_id"`
	Registrar      string    `json:"registrar"`
	Currency       string    `json:"currency"`
	FirstYearCents *int64    `json:"first_year_cents,omitempty"`
	RenewalCents   *int64    `json:"renewal_cents,omitempty"`
	TransferCents  *int64    `json:"transfer_cents,omitempty"`
	Available      *bool     `json:"available,omitempty"`
	QuotedAt       time.Time `json:"quoted_at"`
	CreatedAt      time.Time `json:"created_at"`
}

// Provider is a row from the registrar_providers catalog.
type Provider struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	APIKind   string    `json:"api_kind"`
	Enabled   bool      `json:"enabled"`
	BaseURL   *string   `json:"base_url,omitempty"`
	Notes     *string   `json:"notes,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// ValidStatus reports whether s is a storable domain_candidate_status.
func ValidStatus(s string) bool {
	switch Status(s) {
	case StatusSuggested, StatusScored, StatusSelected, StatusRejected, StatusImported:
		return true
	default:
		return false
	}
}

// CanSelect reports whether a candidate may be selected (picked). Only a scored
// or still-suggested candidate can be selected; a rejected/imported one cannot.
func (c Candidate) CanSelect() bool {
	return c.Status == StatusScored || c.Status == StatusSuggested
}

// CanReject reports whether a candidate may be rejected. Anything that is not
// already rejected or imported may be rejected.
func (c Candidate) CanReject() bool {
	return c.Status != StatusRejected && c.Status != StatusImported
}
