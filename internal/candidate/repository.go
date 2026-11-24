package candidate

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"phishforge/internal/db"
)

// Repository provides domain_candidates / domain_price_quotes / registrar_
// providers persistence. Stateless; each method takes a db.Querier and (except
// the global registrar catalog) is scoped by tenant_id.
type Repository struct{}

// NewRepository returns a candidate repository.
func NewRepository() *Repository { return &Repository{} }

const candCols = `id, tenant_id, engagement_id, source, name, fuzzer, available,
                  score, rank, status, notes, created_by, created_at, updated_at`

func scanCandidate(row pgx.Row) (Candidate, error) {
	var (
		c  Candidate
		cb uuid.NullUUID
	)
	if err := row.Scan(
		&c.ID, &c.TenantID, &c.EngagementID, &c.Source, &c.Name, &c.Fuzzer, &c.Available,
		&c.Score, &c.Rank, &c.Status, &c.Notes, &cb, &c.CreatedAt, &c.UpdatedAt,
	); err != nil {
		return Candidate{}, err
	}
	if cb.Valid {
		id := cb.UUID
		c.CreatedBy = &id
	}
	return c, nil
}

// UpsertInput carries the fields written when a candidate is suggested/scored.
type UpsertInput struct {
	Source    string
	Name      string
	Fuzzer    *string
	Available *bool
	Score     []byte // JSON; defaults to '{}' when nil
	Status    Status
	CreatedBy uuid.UUID
}

// Upsert inserts or refreshes a candidate for (engagement, name). On conflict it
// updates the discovery-derived fields (source/fuzzer/available/score/status)
// but never clobbers an operator decision: a selected/rejected/imported row
// keeps its status. Returns the stored row.
func (r *Repository) Upsert(ctx context.Context, q db.Querier, tenantID, engagementID uuid.UUID, in UpsertInput) (Candidate, error) {
	score := in.Score
	if len(score) == 0 {
		score = []byte("{}")
	}
	var createdArg any
	if in.CreatedBy != uuid.Nil {
		createdArg = in.CreatedBy
	}
	const sql = `
INSERT INTO domain_candidates (tenant_id, engagement_id, source, name, fuzzer, available, score, status, created_by)
VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::domain_candidate_status, $9)
ON CONFLICT (engagement_id, name) DO UPDATE SET
    source = EXCLUDED.source,
    fuzzer = EXCLUDED.fuzzer,
    available = EXCLUDED.available,
    score = EXCLUDED.score,
    status = CASE
        WHEN domain_candidates.status IN ('selected','rejected','imported')
        THEN domain_candidates.status
        ELSE EXCLUDED.status
    END,
    updated_at = now()
RETURNING ` + candCols
	c, err := scanCandidate(q.QueryRow(ctx, sql,
		tenantID, engagementID, in.Source, in.Name, in.Fuzzer, in.Available, string(score), string(in.Status), createdArg))
	if err != nil {
		return Candidate{}, fmt.Errorf("candidate: upsert: %w", err)
	}
	return c, nil
}

// SetRank writes a candidate's 1-based rank (scoped by tenant + engagement).
func (r *Repository) SetRank(ctx context.Context, q db.Querier, tenantID, engagementID uuid.UUID, name string, rank int) error {
	const sql = `UPDATE domain_candidates SET rank = $4, updated_at = now()
	             WHERE tenant_id = $1 AND engagement_id = $2 AND name = $3`
	if _, err := q.Exec(ctx, sql, tenantID, engagementID, name, rank); err != nil {
		return fmt.Errorf("candidate: set rank: %w", err)
	}
	return nil
}

// ListByEngagement returns an engagement's candidates ordered by rank (nulls
// last), then by name, within a tenant.
func (r *Repository) ListByEngagement(ctx context.Context, q db.Querier, tenantID, engagementID uuid.UUID) ([]Candidate, error) {
	const sql = `SELECT ` + candCols + ` FROM domain_candidates
	             WHERE tenant_id = $1 AND engagement_id = $2
	             ORDER BY rank ASC NULLS LAST, name ASC`
	rows, err := q.Query(ctx, sql, tenantID, engagementID)
	if err != nil {
		return nil, fmt.Errorf("candidate: list: %w", err)
	}
	defer rows.Close()
	out := make([]Candidate, 0)
	for rows.Next() {
		c, err := scanCandidate(rows)
		if err != nil {
			return nil, fmt.Errorf("candidate: scan: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("candidate: iterate: %w", err)
	}
	return out, nil
}

// GetByID loads one candidate by id, scoped to tenant + engagement.
func (r *Repository) GetByID(ctx context.Context, q db.Querier, tenantID, engagementID, id uuid.UUID) (Candidate, error) {
	const sql = `SELECT ` + candCols + ` FROM domain_candidates
	             WHERE tenant_id = $1 AND engagement_id = $2 AND id = $3`
	c, err := scanCandidate(q.QueryRow(ctx, sql, tenantID, engagementID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Candidate{}, ErrNotFound
	}
	if err != nil {
		return Candidate{}, fmt.Errorf("candidate: get by id: %w", err)
	}
	return c, nil
}

// SetStatus updates a candidate's status (operator pick/reject). The caller
// validates the transition.
func (r *Repository) SetStatus(ctx context.Context, q db.Querier, tenantID, engagementID, id uuid.UUID, status Status) (Candidate, error) {
	const sql = `UPDATE domain_candidates SET status = $4::domain_candidate_status, updated_at = now()
	             WHERE tenant_id = $1 AND engagement_id = $2 AND id = $3 RETURNING ` + candCols
	c, err := scanCandidate(q.QueryRow(ctx, sql, tenantID, engagementID, id, string(status)))
	if errors.Is(err, pgx.ErrNoRows) {
		return Candidate{}, ErrNotFound
	}
	if err != nil {
		return Candidate{}, fmt.Errorf("candidate: set status: %w", err)
	}
	return c, nil
}

// ConflictingNames returns the subset of names that already exist in the
// tenant's domain inventory (domains table). Used by scoring to disqualify
// candidates that collide with domains we already own/track.
func (r *Repository) ConflictingNames(ctx context.Context, q db.Querier, tenantID uuid.UUID, names []string) (map[string]bool, error) {
	out := map[string]bool{}
	if len(names) == 0 {
		return out, nil
	}
	const sql = `SELECT name FROM domains WHERE tenant_id = $1 AND name = ANY($2)`
	rows, err := q.Query(ctx, sql, tenantID, names)
	if err != nil {
		return nil, fmt.Errorf("candidate: conflict check: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, fmt.Errorf("candidate: scan conflict: %w", err)
		}
		out[n] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("candidate: iterate conflicts: %w", err)
	}
	return out, nil
}

// --- quotes ----------------------------------------------------------------

const quoteCols = `id, candidate_id, registrar, currency, first_year_cents,
                   renewal_cents, transfer_cents, available, quoted_at, created_at`

// quoteColsPQ is quoteCols qualified with the "pq" alias for the join in
// ListQuotesByEngagement (column order must match scanQuote).
const quoteColsPQ = `pq.id, pq.candidate_id, pq.registrar, pq.currency, pq.first_year_cents,
                     pq.renewal_cents, pq.transfer_cents, pq.available, pq.quoted_at, pq.created_at`

func scanQuote(row pgx.Row) (Quote, error) {
	var qt Quote
	if err := row.Scan(
		&qt.ID, &qt.CandidateID, &qt.Registrar, &qt.Currency, &qt.FirstYearCents,
		&qt.RenewalCents, &qt.TransferCents, &qt.Available, &qt.QuotedAt, &qt.CreatedAt,
	); err != nil {
		return Quote{}, err
	}
	return qt, nil
}

// QuoteInput carries a normalized quote to persist.
type QuoteInput struct {
	Registrar      string
	Currency       string
	FirstYearCents *int64
	RenewalCents   *int64
	TransferCents  *int64
	Available      *bool
}

// UpsertQuote inserts or refreshes a candidate's quote for one registrar.
func (r *Repository) UpsertQuote(ctx context.Context, q db.Querier, tenantID, candidateID uuid.UUID, in QuoteInput) (Quote, error) {
	currency := in.Currency
	if currency == "" {
		currency = "USD"
	}
	const sql = `
INSERT INTO domain_price_quotes
    (tenant_id, candidate_id, registrar, currency, first_year_cents, renewal_cents, transfer_cents, available, quoted_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
ON CONFLICT (candidate_id, registrar) DO UPDATE SET
    currency = EXCLUDED.currency,
    first_year_cents = EXCLUDED.first_year_cents,
    renewal_cents = EXCLUDED.renewal_cents,
    transfer_cents = EXCLUDED.transfer_cents,
    available = EXCLUDED.available,
    quoted_at = now()
RETURNING ` + quoteCols
	qt, err := scanQuote(q.QueryRow(ctx, sql,
		tenantID, candidateID, in.Registrar, currency, in.FirstYearCents, in.RenewalCents, in.TransferCents, in.Available))
	if err != nil {
		return Quote{}, fmt.Errorf("candidate: upsert quote: %w", err)
	}
	return qt, nil
}

// ListQuotesByEngagement returns every quote for an engagement's candidates,
// keyed by candidate id, in a single query (no N+1). Scoped by tenant.
func (r *Repository) ListQuotesByEngagement(ctx context.Context, q db.Querier, tenantID, engagementID uuid.UUID) (map[uuid.UUID][]Quote, error) {
	const sql = `SELECT ` + quoteColsPQ + `
	             FROM domain_price_quotes pq
	             JOIN domain_candidates dc ON dc.id = pq.candidate_id
	             WHERE pq.tenant_id = $1 AND dc.engagement_id = $2
	             ORDER BY pq.registrar ASC`
	rows, err := q.Query(ctx, sql, tenantID, engagementID)
	if err != nil {
		return nil, fmt.Errorf("candidate: list quotes: %w", err)
	}
	defer rows.Close()
	out := map[uuid.UUID][]Quote{}
	for rows.Next() {
		qt, err := scanQuote(rows)
		if err != nil {
			return nil, fmt.Errorf("candidate: scan quote: %w", err)
		}
		out[qt.CandidateID] = append(out[qt.CandidateID], qt)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("candidate: iterate quotes: %w", err)
	}
	return out, nil
}

// --- registrar catalog (global) --------------------------------------------

// ListProviders returns the registrar_providers catalog, name-ordered.
func (r *Repository) ListProviders(ctx context.Context, q db.Querier) ([]Provider, error) {
	const sql = `SELECT id, name, api_kind, enabled, base_url, notes, created_at
	             FROM registrar_providers ORDER BY name ASC`
	rows, err := q.Query(ctx, sql)
	if err != nil {
		return nil, fmt.Errorf("candidate: list providers: %w", err)
	}
	defer rows.Close()
	out := make([]Provider, 0)
	for rows.Next() {
		var p Provider
		if err := rows.Scan(&p.ID, &p.Name, &p.APIKind, &p.Enabled, &p.BaseURL, &p.Notes, &p.CreatedAt); err != nil {
			return nil, fmt.Errorf("candidate: scan provider: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("candidate: iterate providers: %w", err)
	}
	return out, nil
}
