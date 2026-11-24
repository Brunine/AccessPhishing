// Package registrar fetches comparable domain price quotes from registrars and
// normalizes them into a single shape. It performs NO purchasing: every adapter
// is read-only and talks only to documented pricing APIs (or an operator-
// provided price list). There is deliberately no checkout, cart, or order path.
//
// A Provider knows how to quote a single domain. Set fans a domain out across
// all configured providers, collecting the quotes it can and the errors it
// cannot (a failing provider never fails the whole comparison). Prices are
// normalized to integer minor units (cents) in the quote currency so the
// ranking in internal/candidate can compare registrars deterministically.
package registrar

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Quote is a normalized price quote for one domain from one registrar. A nil
// price field means the registrar did not price that TLD. Prices are in minor
// units (cents) of Currency.
type Quote struct {
	Registrar      string    `json:"registrar"`
	Domain         string    `json:"domain"`
	TLD            string    `json:"tld"`
	Currency       string    `json:"currency"`
	FirstYearCents *int64    `json:"first_year_cents,omitempty"`
	RenewalCents   *int64    `json:"renewal_cents,omitempty"`
	TransferCents  *int64    `json:"transfer_cents,omitempty"`
	Available      *bool     `json:"available,omitempty"`
	QuotedAt       time.Time `json:"quoted_at"`
}

// Cost3Y returns the three-year total cost (first year + two renewals) in cents
// and whether it could be computed. It requires both a first-year and a renewal
// price; a renewal-less quote cannot be projected and reports ok=false.
func (q Quote) Cost3Y() (int64, bool) {
	if q.FirstYearCents == nil || q.RenewalCents == nil {
		return 0, false
	}
	return *q.FirstYearCents + 2*(*q.RenewalCents), true
}

// Provider quotes a single domain. Implementations must be safe for concurrent
// use and must never mutate remote state.
type Provider interface {
	// Name is the registrar identifier recorded on each quote (e.g. "porkbun").
	Name() string
	// Quote returns a normalized quote for domain, or an error if it could not
	// be obtained (unknown TLD, upstream failure, not configured).
	Quote(ctx context.Context, domain string) (Quote, error)
}

// Set aggregates configured providers.
type Set struct {
	providers []Provider
}

// NewSet builds a Set from the given providers, skipping nil entries (a
// provider constructor returns nil when it is not configured).
func NewSet(providers ...Provider) *Set {
	s := &Set{}
	for _, p := range providers {
		if p != nil {
			s.providers = append(s.providers, p)
		}
	}
	return s
}

// Names returns the configured provider names, in order.
func (s *Set) Names() []string {
	out := make([]string, 0, len(s.providers))
	for _, p := range s.providers {
		out = append(out, p.Name())
	}
	return out
}

// Len reports how many providers are configured.
func (s *Set) Len() int { return len(s.providers) }

// Quote fans domain out across every provider, returning the quotes obtained
// and a per-provider map of errors for those that failed. A provider error is
// never fatal: comparison proceeds with whatever quotes are available.
func (s *Set) Quote(ctx context.Context, domain string) ([]Quote, map[string]string) {
	quotes := make([]Quote, 0, len(s.providers))
	errs := map[string]string{}
	for _, p := range s.providers {
		q, err := p.Quote(ctx, domain)
		if err != nil {
			errs[p.Name()] = err.Error()
			continue
		}
		quotes = append(quotes, q)
	}
	return quotes, errs
}

// TLDOf returns the last dot-separated label of a domain, lowercased. It is a
// deliberate simplification over a full public-suffix split (mirroring the
// OSINT service's leftmost-label fuzzing) and is sufficient for matching a
// registrar's per-TLD price table. Returns "" when there is no dot.
func TLDOf(domain string) string {
	domain = strings.ToLower(strings.Trim(strings.TrimSpace(domain), "."))
	i := strings.LastIndex(domain, ".")
	if i < 0 || i == len(domain)-1 {
		return ""
	}
	return domain[i+1:]
}

// ParsePriceCents converts a decimal price string in major units (e.g. "9.68",
// "12", "1,299.00") to integer minor units (cents). It rejects negative or
// malformed input. Thousands separators (commas) are stripped; the fractional
// part is padded/truncated to exactly two digits.
func ParsePriceCents(s string) (int64, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "$")
	s = strings.ReplaceAll(s, ",", "")
	if s == "" {
		return 0, fmt.Errorf("registrar: empty price")
	}
	neg := strings.HasPrefix(s, "-")
	if neg {
		return 0, fmt.Errorf("registrar: negative price %q", s)
	}
	intPart, fracPart, hasFrac := strings.Cut(s, ".")
	if intPart == "" {
		intPart = "0"
	}
	whole, err := strconv.ParseInt(intPart, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("registrar: invalid price %q: %w", s, err)
	}
	var cents int64
	if hasFrac {
		switch {
		case len(fracPart) == 0:
			// "9." -> treat as 9.00
		case len(fracPart) == 1:
			fracPart += "0"
		case len(fracPart) > 2:
			fracPart = fracPart[:2]
		}
		if fracPart != "" {
			c, err := strconv.ParseInt(fracPart, 10, 64)
			if err != nil {
				return 0, fmt.Errorf("registrar: invalid price fraction %q: %w", s, err)
			}
			cents = c
		}
	}
	return whole*100 + cents, nil
}

// centsPtr is a small helper for building optional price fields.
func centsPtr(c int64) *int64 { return &c }

// tldPrice is the per-TLD price triple shared by the porkbun/cloudflare-style
// JSON price tables ("registration"/"renewal"/"transfer" as decimal strings).
type tldPrice struct {
	Registration string `json:"registration"`
	Renewal      string `json:"renewal"`
	Transfer     string `json:"transfer"`
}

// toQuote converts a tldPrice into a normalized Quote for domain. Unparseable
// individual fields are left nil rather than failing the whole quote.
func (p tldPrice) toQuote(registrar, domain, currency string, at time.Time) Quote {
	q := Quote{
		Registrar: registrar,
		Domain:    strings.ToLower(domain),
		TLD:       TLDOf(domain),
		Currency:  currency,
		QuotedAt:  at,
	}
	if c, err := ParsePriceCents(p.Registration); err == nil {
		q.FirstYearCents = centsPtr(c)
	}
	if c, err := ParsePriceCents(p.Renewal); err == nil {
		q.RenewalCents = centsPtr(c)
	}
	if c, err := ParsePriceCents(p.Transfer); err == nil {
		q.TransferCents = centsPtr(c)
	}
	return q
}
