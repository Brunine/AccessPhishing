// Package client holds the client model and its tenant-scoped repository.
//
// A client is a first-class customer record within a tenant. Engagements may
// optionally reference a client (engagements.client_id); a client cannot be
// deleted while any engagement still references it (enforced in the
// application, surfaced as 409).
package client

import (
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

// ErrNotFound is returned when a client does not exist within the tenant.
var ErrNotFound = errors.New("client: not found")

// ErrReferenced is returned when a client cannot be deleted because one or more
// engagements still reference it.
var ErrReferenced = errors.New("client: referenced by one or more engagements")

// NameMaxLen is the maximum length of a client name, in runes.
const NameMaxLen = 200

// Client is a customer record owned by a single tenant.
type Client struct {
	ID           uuid.UUID `json:"id"`
	TenantID     uuid.UUID `json:"tenant_id"`
	Name         string    `json:"name"`
	ContactEmail *string   `json:"contact_email,omitempty"`
	Notes        *string   `json:"notes,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Input carries the mutable fields for Create/Update. A nil ContactEmail/Notes
// stores SQL NULL. Name is normalized (trimmed) by the caller before Validate.
type Input struct {
	Name         string
	ContactEmail *string
	Notes        *string
}

// Normalize trims the name and collapses an empty/whitespace-only ContactEmail
// to nil (stored as NULL). It returns the normalized copy.
func (in Input) Normalize() Input {
	in.Name = strings.TrimSpace(in.Name)
	if in.ContactEmail != nil {
		e := strings.TrimSpace(*in.ContactEmail)
		if e == "" {
			in.ContactEmail = nil
		} else {
			in.ContactEmail = &e
		}
	}
	return in
}

// Validate checks the field rules shared by create and update. It expects an
// already-normalized Input (see Normalize): name required, 1..NameMaxLen runes;
// contact_email, if present, must parse as a single RFC 5322 address.
func (in Input) Validate() error {
	if in.Name == "" {
		return fmt.Errorf("name is required")
	}
	if utf8.RuneCountInString(in.Name) > NameMaxLen {
		return fmt.Errorf("name must be at most %d characters", NameMaxLen)
	}
	if in.ContactEmail != nil {
		if _, err := mail.ParseAddress(*in.ContactEmail); err != nil {
			return fmt.Errorf("contact_email is not a valid email address")
		}
	}
	return nil
}
