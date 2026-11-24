package candidate

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"phishforge/internal/audit"
	"phishforge/internal/engagement"
	"phishforge/internal/osintclient"
	"phishforge/internal/registrar"
)

// defaultMaxCandidates bounds how many candidates one discovery run scores, to
// keep the background job fast and the per-engagement list manageable.
const defaultMaxCandidates = 50

// Suggester produces lookalike candidate names (with availability) for a seed
// domain. Implemented by *osintclient.Client.
type Suggester interface {
	Suggest(ctx context.Context, domain string) ([]osintclient.SuggestCandidate, error)
}

// NameSuggester proposes additional candidate NAMES for a seed. It is optional
// and advisory only: its output is validated, availability-checked (indirectly,
// since LLM names get no RDAP data here and score as "unknown"), and scored by
// the same deterministic pipeline as every other candidate. It is NEVER a
// source of truth for availability, price, or rank. Implemented by an LLM
// adapter (see NewLLMNamer).
type NameSuggester interface {
	SuggestNames(ctx context.Context, seed string, limit int) ([]string, error)
}

// Collector runs engagement-scoped candidate discovery: suggest -> quote ->
// score -> rank -> persist. It is transport-independent (no HTTP concerns) so
// the Asynq worker and integration tests drive the same code path.
type Collector struct {
	pool          *pgxpool.Pool
	repo          *Repository
	engagements   *engagement.Repository
	osint         Suggester
	registrars    *registrar.Set
	names         NameSuggester // optional; nil disables LLM name suggestions
	maxCandidates int
	logger        *slog.Logger
}

// CollectorConfig configures a Collector. Osint and Registrars are required;
// Names is optional.
type CollectorConfig struct {
	Pool          *pgxpool.Pool
	OSINT         Suggester
	Registrars    *registrar.Set
	Names         NameSuggester
	MaxCandidates int
	Logger        *slog.Logger
}

// NewCollector builds a Collector.
func NewCollector(cfg CollectorConfig) *Collector {
	max := cfg.MaxCandidates
	if max <= 0 {
		max = defaultMaxCandidates
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{
		pool:          cfg.Pool,
		repo:          NewRepository(),
		engagements:   engagement.NewRepository(),
		osint:         cfg.OSINT,
		registrars:    cfg.Registrars,
		names:         cfg.Names,
		maxCandidates: max,
		logger:        logger,
	}
}

// Result summarizes a discovery run.
type Result struct {
	EngagementID uuid.UUID `json:"engagement_id"`
	Seeds        []string  `json:"seeds"`
	Suggested    int       `json:"suggested"`
	Scored       int       `json:"scored"`
	Conflicts    int       `json:"conflicts"`
}

// scored is the in-memory record built before persistence.
type scored struct {
	name      string
	source    string
	fuzzer    *string
	available *bool
	score     Score
	scoreJSON []byte
	quotes    []registrar.Quote
}

// Collect discovers, prices, scores, and ranks candidates for an engagement.
//
// Scope enforcement mirrors the campaign launch gate: the engagement must be
// authorized, unexpired, and non-terminated (engagement.CheckCampaignLaunchable),
// and it must declare at least one authorized_scope entry — candidates are only
// ever derived from that scope. All network work (OSINT suggestions, registrar
// quotes) happens before a write transaction is opened; persistence is atomic.
func (c *Collector) Collect(ctx context.Context, tenantID, engagementID, requestedBy uuid.UUID) (Result, error) {
	res := Result{EngagementID: engagementID}
	if c.osint == nil {
		return res, fmt.Errorf("candidate: OSINT suggester not configured")
	}

	eng, err := c.engagements.GetByID(ctx, c.pool, tenantID, engagementID)
	if err != nil {
		return res, err // engagement.ErrNotFound or a wrapped db error
	}
	if gate := eng.CheckCampaignLaunchable(time.Now().UTC()); gate != nil {
		return res, gate // engagement.ErrEngagementNotAuthorized / Expired / Terminated
	}

	seeds := seedsFromScope(eng.AuthorizedScope)
	if len(seeds) == 0 {
		return res, ErrNoScope
	}
	res.Seeds = seeds

	// 1. Gather suggestions from the OSINT service (and, optionally, the LLM
	//    namer), preserving first-seen order and de-duplicating by name.
	suggestions := c.gather(ctx, seeds)
	res.Suggested = len(suggestions)
	if len(suggestions) == 0 {
		// Nothing to score; still a successful (empty) run.
		return res, nil
	}

	// 2. Conflict check against existing inventory (read).
	names := make([]string, 0, len(suggestions))
	for _, s := range suggestions {
		names = append(names, s.name)
	}
	conflicts, err := c.repo.ConflictingNames(ctx, c.pool, tenantID, names)
	if err != nil {
		return res, err
	}
	res.Conflicts = len(conflicts)

	// 3. Price + score each suggestion (network, no tx held).
	records := make([]scored, 0, len(suggestions))
	ranks := make([]Ranked, 0, len(suggestions))
	for _, s := range suggestions {
		var quotes []registrar.Quote
		if c.registrars != nil && c.registrars.Len() > 0 {
			var errs map[string]string
			quotes, errs = c.registrars.Quote(ctx, s.name)
			for reg, e := range errs {
				c.logger.Debug("registrar quote failed", "registrar", reg, "domain", s.name, "err", e)
			}
		}
		sc := Compute(ScoreInput{Available: s.available, Conflict: conflicts[s.name], Quotes: quotes})
		raw, err := json.Marshal(sc)
		if err != nil {
			return res, fmt.Errorf("candidate: marshal score: %w", err)
		}
		rec := scored{
			name: s.name, source: s.source, fuzzer: s.fuzzer,
			available: s.available, score: sc, scoreJSON: raw, quotes: quotes,
		}
		records = append(records, rec)

		rk := Ranked{Name: s.name, Value: sc.Value}
		if sc.MinCost3YCents != nil {
			rk.Cost3Y = *sc.MinCost3YCents
			rk.HasCost = true
		}
		ranks = append(ranks, rk)
	}
	ranking := Rank(ranks)

	// 4. Persist atomically.
	tx, err := c.pool.Begin(ctx)
	if err != nil {
		return res, fmt.Errorf("candidate: begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	for _, rec := range records {
		cand, err := c.repo.Upsert(ctx, tx, tenantID, engagementID, UpsertInput{
			Source: rec.source, Name: rec.name, Fuzzer: rec.fuzzer,
			Available: rec.available, Score: rec.scoreJSON, Status: StatusScored, CreatedBy: requestedBy,
		})
		if err != nil {
			return res, err
		}
		for _, q := range rec.quotes {
			if _, err := c.repo.UpsertQuote(ctx, tx, tenantID, cand.ID, QuoteInput{
				Registrar: q.Registrar, Currency: q.Currency,
				FirstYearCents: q.FirstYearCents, RenewalCents: q.RenewalCents,
				TransferCents: q.TransferCents, Available: q.Available,
			}); err != nil {
				return res, err
			}
		}
		if rank, ok := ranking[rec.name]; ok {
			if err := c.repo.SetRank(ctx, tx, tenantID, engagementID, rec.name, rank); err != nil {
				return res, err
			}
		}
		res.Scored++
	}

	if err := audit.Write(ctx, tx, audit.Entry{
		TenantID: tenantID, ActorID: requestedBy,
		Action: "candidate.collect", TargetType: "engagement", TargetID: engagementID.String(),
		Metadata: map[string]any{
			"seeds": seeds, "suggested": res.Suggested, "scored": res.Scored, "conflicts": res.Conflicts,
			"registrars": registrarNames(c.registrars),
		},
	}); err != nil {
		return res, fmt.Errorf("candidate: audit: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return res, fmt.Errorf("candidate: commit: %w", err)
	}
	return res, nil
}

// suggestion is a de-duplicated candidate name before pricing/scoring.
type suggestion struct {
	name      string
	source    string
	fuzzer    *string
	available *bool
}

// gather collects suggestions from the OSINT service and the optional LLM namer,
// capped at maxCandidates, de-duplicated by name in first-seen order.
func (c *Collector) gather(ctx context.Context, seeds []string) []suggestion {
	seen := map[string]bool{}
	out := make([]suggestion, 0, c.maxCandidates)

	add := func(name, source string, fuzzer *string, available *bool) bool {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" || seen[name] || len(out) >= c.maxCandidates {
			return len(out) < c.maxCandidates
		}
		seen[name] = true
		out = append(out, suggestion{name: name, source: source, fuzzer: fuzzer, available: available})
		return len(out) < c.maxCandidates
	}

	for _, seed := range seeds {
		cands, err := c.osint.Suggest(ctx, seed)
		if err != nil {
			c.logger.Warn("osint suggest failed", "seed", seed, "err", err)
			continue
		}
		for _, cand := range cands {
			f := cand.Fuzzer
			if !add(cand.Domain, "lookalike", &f, cand.Available) {
				return out
			}
		}
	}

	if c.names != nil {
		for _, seed := range seeds {
			if len(out) >= c.maxCandidates {
				break
			}
			names, err := c.names.SuggestNames(ctx, seed, 10)
			if err != nil {
				c.logger.Warn("llm name suggest failed", "seed", seed, "err", err)
				continue
			}
			for _, n := range names {
				if !validCandidateName(n) {
					continue
				}
				if !add(n, "llm", nil, nil) {
					return out
				}
			}
		}
	}
	return out
}

// seedsFromScope extracts base domains from an engagement's authorized_scope,
// de-duplicated. URL entries are reduced to their host; wildcard entries
// (*.acme.com) to the bare domain. Entries without a dot are dropped.
func seedsFromScope(scope []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, raw := range scope {
		s := strings.ToLower(strings.TrimSpace(raw))
		if s == "" {
			continue
		}
		if strings.Contains(s, "://") {
			if u, err := url.Parse(s); err == nil && u.Host != "" {
				s = u.Hostname()
			}
		}
		s = strings.TrimPrefix(s, "*.")
		s = strings.Trim(s, ".")
		if !strings.Contains(s, ".") {
			continue
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// validCandidateName is a lenient guard for LLM-proposed names: a dotted,
// lowercase host whose labels use only [a-z0-9-]. It mirrors the OSINT service's
// label validation without importing it.
func validCandidateName(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || len(name) > 253 || !strings.Contains(name, ".") {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

func registrarNames(set *registrar.Set) []string {
	if set == nil {
		return []string{}
	}
	return set.Names()
}
