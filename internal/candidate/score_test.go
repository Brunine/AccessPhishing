package candidate

import (
	"testing"
	"time"

	"phishforge/internal/registrar"
)

func boolPtr(b bool) *bool { return &b }

func quote(reg string, first, renew int64) registrar.Quote {
	return registrar.Quote{
		Registrar: reg, Currency: "USD",
		FirstYearCents: &first, RenewalCents: &renew, QuotedAt: time.Now(),
	}
}

func TestComputeConflictDisqualifies(t *testing.T) {
	s := Compute(ScoreInput{Available: boolPtr(true), Conflict: true, Quotes: []registrar.Quote{quote("porkbun", 100, 100)}})
	if s.Value != 0 {
		t.Fatalf("conflict should score 0, got %v", s.Value)
	}
	if !s.Conflict {
		t.Fatalf("Conflict flag not set")
	}
}

func TestComputeAvailabilityBase(t *testing.T) {
	// No quotes => cost bonus 0, base only.
	avail := Compute(ScoreInput{Available: boolPtr(true)})
	if avail.Value != 60 {
		t.Fatalf("available/no-quote: want 60, got %v", avail.Value)
	}
	unknown := Compute(ScoreInput{Available: nil})
	if unknown.Value != 40 {
		t.Fatalf("unknown/no-quote: want 40, got %v", unknown.Value)
	}
	registered := Compute(ScoreInput{Available: boolPtr(false)})
	if registered.Value != 10 {
		t.Fatalf("registered/no-quote: want 10, got %v", registered.Value)
	}
}

func TestComputeCostBonus(t *testing.T) {
	// Free 3-year cost => full +40 bonus. 3y cost = first + 2*renew.
	free := Compute(ScoreInput{Available: boolPtr(true), Quotes: []registrar.Quote{quote("porkbun", 0, 0)}})
	if free.Value != 100 {
		t.Fatalf("available + free: want 100, got %v", free.Value)
	}
	if free.CostBonus != 40 {
		t.Fatalf("free cost bonus: want 40, got %v", free.CostBonus)
	}
	// At/over the reference ($300 / 30000 cents over 3y) => no bonus.
	// 3y = 10000 + 2*10000 = 30000.
	expensive := Compute(ScoreInput{Available: boolPtr(true), Quotes: []registrar.Quote{quote("porkbun", 10000, 10000)}})
	if expensive.Value != 60 {
		t.Fatalf("available + at-reference: want 60, got %v", expensive.Value)
	}
	if expensive.CostBonus != 0 {
		t.Fatalf("at-reference cost bonus: want 0, got %v", expensive.CostBonus)
	}
}

func TestComputeCheapestAcrossRegistrars(t *testing.T) {
	s := Compute(ScoreInput{
		Available: boolPtr(true),
		Quotes: []registrar.Quote{
			quote("expensive", 5000, 5000), // 3y = 15000
			quote("cheap", 1000, 1000),     // 3y = 3000
		},
	})
	if s.MinCost3YCents == nil || *s.MinCost3YCents != 3000 {
		t.Fatalf("min cost: %+v", s.MinCost3YCents)
	}
	if s.CheapestRegistrar != "cheap" {
		t.Fatalf("cheapest registrar: %q", s.CheapestRegistrar)
	}
}

func TestComputeDeterministic(t *testing.T) {
	in := ScoreInput{Available: boolPtr(true), Quotes: []registrar.Quote{quote("porkbun", 968, 1106)}}
	a := Compute(in)
	b := Compute(in)
	if a.Value != b.Value || a.CostBonus != b.CostBonus {
		t.Fatalf("Compute not deterministic: %v vs %v", a, b)
	}
}

func TestRankOrdering(t *testing.T) {
	items := []Ranked{
		{Name: "b.com", Value: 90, Cost3Y: 5000, HasCost: true},
		{Name: "a.com", Value: 90, Cost3Y: 3000, HasCost: true}, // same value, cheaper => higher
		{Name: "c.com", Value: 100, Cost3Y: 9000, HasCost: true},
		{Name: "d.com", Value: 90, HasCost: false}, // no cost => sorts after priced ties
	}
	ranks := Rank(items)
	if ranks["c.com"] != 1 {
		t.Fatalf("highest value should rank 1, got %d", ranks["c.com"])
	}
	if ranks["a.com"] != 2 || ranks["b.com"] != 3 {
		t.Fatalf("cost tie-break wrong: a=%d b=%d", ranks["a.com"], ranks["b.com"])
	}
	if ranks["d.com"] != 4 {
		t.Fatalf("no-cost candidate should rank last among ties, got %d", ranks["d.com"])
	}
}
