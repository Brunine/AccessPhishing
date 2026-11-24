package candidate

import (
	"fmt"
	"math"
	"sort"

	"phishforge/internal/registrar"
)

// cost3YReferenceCents is the three-year cost at which the cost bonus reaches
// zero. A free (or near-free) candidate earns the full cost bonus; one costing
// this much or more earns none. $300 over three years = 30000 cents.
const cost3YReferenceCents = 30000

// maxCostBonus is the most a cheap price can add to a candidate's score.
const maxCostBonus = 40.0

// Score is the deterministic scoring breakdown stored on a candidate (jsonb).
// Value is the single comparable number used for ranking; every other field
// explains how it was derived. None of it comes from an LLM.
type Score struct {
	Value             float64  `json:"value"`
	AvailabilityBase  float64  `json:"availability_base"`
	CostBonus         float64  `json:"cost_bonus"`
	Available         *bool    `json:"available"`
	Conflict          bool     `json:"conflict"`
	MinCost3YCents    *int64   `json:"min_cost_3y_cents,omitempty"`
	CheapestRegistrar string   `json:"cheapest_registrar,omitempty"`
	Currency          string   `json:"currency,omitempty"`
	Reasons           []string `json:"reasons"`
}

// ScoreInput is the deterministic input to Compute.
type ScoreInput struct {
	// Available is the RDAP availability (true=unregistered, false=registered,
	// nil=unknown/inconclusive).
	Available *bool
	// Conflict is true when the candidate name already exists in the tenant's
	// domain inventory (a hard disqualifier).
	Conflict bool
	// Quotes are the normalized registrar quotes gathered for the candidate.
	Quotes []registrar.Quote
}

// Compute scores a candidate deterministically. The result is a pure function
// of the input: the same input always yields the same Value. Higher is better.
//
// Model:
//   - conflict (already in inventory) => Value 0, disqualified.
//   - availability base: available=60, unknown=40, registered=10.
//   - cost bonus (only when not conflicting): up to +40, linearly from a free
//     3-year cost down to zero at the reference cost; unpriced earns none.
//   - Value = clamp(base + bonus, 0, 100), rounded to one decimal.
func Compute(in ScoreInput) Score {
	s := Score{Available: in.Available, Conflict: in.Conflict, Currency: "USD", Reasons: []string{}}

	cents, reg, cur, ok := cheapest(in.Quotes)
	if ok {
		s.MinCost3YCents = &cents
		s.CheapestRegistrar = reg
		s.Currency = cur
	}

	if in.Conflict {
		s.AvailabilityBase = 0
		s.CostBonus = 0
		s.Value = 0
		s.Reasons = append(s.Reasons, "already present in this tenant's domain inventory (conflict)")
		return s
	}

	switch {
	case in.Available != nil && *in.Available:
		s.AvailabilityBase = 60
		s.Reasons = append(s.Reasons, "available for registration (RDAP)")
	case in.Available != nil && !*in.Available:
		s.AvailabilityBase = 10
		s.Reasons = append(s.Reasons, "already registered (RDAP)")
	default:
		s.AvailabilityBase = 40
		s.Reasons = append(s.Reasons, "availability unknown/inconclusive")
	}

	if ok {
		s.CostBonus = costBonus(cents)
		s.Reasons = append(s.Reasons,
			fmt.Sprintf("cheapest 3-year cost %s %.2f via %s", cur, float64(cents)/100, reg))
	} else {
		s.CostBonus = 0
		s.Reasons = append(s.Reasons, "no comparable registrar price quote")
	}

	s.Value = round1(clamp(s.AvailabilityBase+s.CostBonus, 0, 100))
	return s
}

// costBonus maps a 3-year cost (cents) to a 0..maxCostBonus bonus, linearly
// decreasing to zero at the reference cost.
func costBonus(cents int64) float64 {
	if cents <= 0 {
		return maxCostBonus
	}
	if cents >= cost3YReferenceCents {
		return 0
	}
	frac := 1 - float64(cents)/float64(cost3YReferenceCents)
	return clamp(maxCostBonus*frac, 0, maxCostBonus)
}

// cheapest returns the lowest computable 3-year cost across quotes, with the
// registrar and currency, or ok=false when none can be computed.
func cheapest(quotes []registrar.Quote) (cents int64, reg, currency string, ok bool) {
	best := int64(math.MaxInt64)
	for _, q := range quotes {
		c, computable := q.Cost3Y()
		if !computable {
			continue
		}
		if c < best {
			best = c
			reg = q.Registrar
			currency = q.Currency
			ok = true
		}
	}
	if !ok {
		return 0, "", "", false
	}
	return best, reg, currency, true
}

// Ranked holds the minimal data needed to order candidates by score.
type Ranked struct {
	Name    string
	Value   float64
	Cost3Y  int64 // math.MaxInt64 when unknown (sorts last on ties)
	HasCost bool
}

// Rank orders candidates by descending Value, then ascending 3-year cost, then
// name, and returns name->rank (1-based). The ordering is total and
// deterministic so re-running discovery yields the same ranks.
func Rank(items []Ranked) map[string]int {
	sorted := make([]Ranked, len(items))
	copy(sorted, items)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if a.Value != b.Value {
			return a.Value > b.Value
		}
		ca := a.Cost3Y
		if !a.HasCost {
			ca = math.MaxInt64
		}
		cb := b.Cost3Y
		if !b.HasCost {
			cb = math.MaxInt64
		}
		if ca != cb {
			return ca < cb
		}
		return a.Name < b.Name
	})
	out := make(map[string]int, len(sorted))
	for i, r := range sorted {
		out[r.Name] = i + 1
	}
	return out
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }
