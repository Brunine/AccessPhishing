// Package report computes read-only KPI aggregates over the existing events and
// campaign_targets tables. It performs no writes and exposes no captured secret
// material — only per-state counts, rates, timelines, and per-recipient state.
package report

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"phishforge/internal/db"
)

// linearStages is the forward funnel order (matches the victim state machine).
var linearStages = []string{
	"sent", "delivered", "opened", "clicked", "creds",
	"session_hijacked", "post_exploitation",
}

// rank gives each state its position in the funnel; pending precedes sent.
var rank = map[string]int{
	"pending": 0, "sent": 1, "delivered": 2, "opened": 3, "clicked": 4,
	"creds": 5, "session_hijacked": 6, "post_exploitation": 7,
}

// Totals holds the recipient funnel for a campaign. Each linear field counts
// recipients that reached that stage OR beyond (the successful path). bounced,
// failed and scanned are reported separately and are not part of the linear
// funnel. scanned (M9b/quishing) counts recipients currently resting at the
// 'scanned' state — a QR scan with no click yet; the common scan→click flow
// lands on 'clicked', so the richer per-scan signal lives in the timeline
// (scanned event counts) and the per-recipient drilldown (scanned_at).
type Totals struct {
	Recipients       int `json:"recipients"`
	Pending          int `json:"pending"`
	Sent             int `json:"sent"`
	Delivered        int `json:"delivered"`
	Opened           int `json:"opened"`
	Scanned          int `json:"scanned"`
	Clicked          int `json:"clicked"`
	Creds            int `json:"creds"`
	SessionHijacked  int `json:"session_hijacked"`
	PostExploitation int `json:"post_exploitation"`
	Bounced          int `json:"bounced"`
	Failed           int `json:"failed"`
}

// Rates are funnel fractions of total recipients (0..1).
type Rates struct {
	Delivered       float64 `json:"delivered"`
	Opened          float64 `json:"opened"`
	Clicked         float64 `json:"clicked"`
	Creds           float64 `json:"creds"`
	SessionHijacked float64 `json:"session_hijacked"`
}

// TimelineBucket is per-time-bucket event counts by type.
type TimelineBucket struct {
	Bucket time.Time      `json:"bucket"`
	Counts map[string]int `json:"counts"`
}

// CampaignReport is the full KPI set for one campaign.
type CampaignReport struct {
	CampaignID uuid.UUID        `json:"campaign_id"`
	Name       string           `json:"name"`
	Status     string           `json:"status"`
	Bucket     string           `json:"bucket"`
	Totals     Totals           `json:"totals"`
	Rates      Rates            `json:"rates"`
	Timeline   []TimelineBucket `json:"timeline"`
}

// RecipientRow is one flat per-recipient drilldown row (for CSV export). It
// carries only state and stage timestamps — never captured credentials.
type RecipientRow struct {
	Email             string     `json:"email"`
	State             string     `json:"state"`
	SentAt            *time.Time `json:"sent_at,omitempty"`
	DeliveredAt       *time.Time `json:"delivered_at,omitempty"`
	OpenedAt          *time.Time `json:"opened_at,omitempty"`
	ScannedAt         *time.Time `json:"scanned_at,omitempty"`
	ClickedAt         *time.Time `json:"clicked_at,omitempty"`
	CredsAt           *time.Time `json:"creds_at,omitempty"`
	SessionHijackedAt *time.Time `json:"session_hijacked_at,omitempty"`
	LastEventAt       *time.Time `json:"last_event_at,omitempty"`
}

// CampaignSummary is a per-campaign rollup used in the tenant portfolio view.
type CampaignSummary struct {
	CampaignID uuid.UUID `json:"campaign_id"`
	Name       string    `json:"name"`
	Status     string    `json:"status"`
	Totals     Totals    `json:"totals"`
	Rates      Rates     `json:"rates"`
}

// TenantSummary is the portfolio rollup across all of a tenant's campaigns.
type TenantSummary struct {
	TenantID  uuid.UUID         `json:"tenant_id"`
	Campaigns []CampaignSummary `json:"campaigns"`
	Totals    Totals            `json:"totals"`
	Rates     Rates             `json:"rates"`
}

// Repository runs the aggregate queries. Stateless; each method takes a
// db.Querier and is tenant-scoped.
type Repository struct{}

// NewRepository returns a report repository.
func NewRepository() *Repository { return &Repository{} }

// normalizeBucket maps a request bucket to a safe date_trunc field.
func normalizeBucket(b string) string {
	switch b {
	case "hour":
		return "hour"
	default:
		return "day"
	}
}

// totalsFromHistogram builds the funnel from a state->count histogram.
func totalsFromHistogram(hist map[string]int) (Totals, Rates) {
	var t Totals
	for state, n := range hist {
		t.Recipients += n
		switch state {
		case "bounced":
			t.Bounced += n
		case "failed":
			t.Failed += n
		case "scanned":
			// A recipient resting at scanned (QR scan, click not yet recorded).
			// Reported separately, like bounced/failed — not a linear stage.
			t.Scanned += n
		case "pending":
			t.Pending += n
		}
	}
	// Funnel "reached stage or beyond" over the linear path only.
	for _, stage := range linearStages {
		sr := rank[stage]
		sum := 0
		for state, n := range hist {
			if r, ok := rank[state]; ok && r >= sr && r >= rank["sent"] {
				sum += n
			}
		}
		switch stage {
		case "sent":
			t.Sent = sum
		case "delivered":
			t.Delivered = sum
		case "opened":
			t.Opened = sum
		case "clicked":
			t.Clicked = sum
		case "creds":
			t.Creds = sum
		case "session_hijacked":
			t.SessionHijacked = sum
		case "post_exploitation":
			t.PostExploitation = sum
		}
	}
	return t, ratesFromTotals(t)
}

func ratesFromTotals(t Totals) Rates {
	var r Rates
	if t.Recipients == 0 {
		return r
	}
	d := float64(t.Recipients)
	r.Delivered = float64(t.Delivered) / d
	r.Opened = float64(t.Opened) / d
	r.Clicked = float64(t.Clicked) / d
	r.Creds = float64(t.Creds) / d
	r.SessionHijacked = float64(t.SessionHijacked) / d
	return r
}

// stateHistogram returns a state->recipient-count map for a campaign, counting
// snapshotted recipients (those without a target row yet are 'pending').
func (r *Repository) stateHistogram(ctx context.Context, q db.Querier, tenantID, campaignID uuid.UUID) (map[string]int, error) {
	const sql = `
SELECT COALESCE(ct.state::text, 'pending') AS state, count(*)
FROM recipients r
LEFT JOIN campaign_targets ct
       ON ct.campaign_id = r.campaign_id AND ct.contact_id = r.contact_id
WHERE r.tenant_id = $1 AND r.campaign_id = $2
GROUP BY 1`
	rows, err := q.Query(ctx, sql, tenantID, campaignID)
	if err != nil {
		return nil, fmt.Errorf("report: histogram: %w", err)
	}
	defer rows.Close()
	hist := make(map[string]int)
	for rows.Next() {
		var state string
		var n int
		if err := rows.Scan(&state, &n); err != nil {
			return nil, fmt.Errorf("report: histogram scan: %w", err)
		}
		hist[state] = n
	}
	return hist, rows.Err()
}

// timeline returns event counts bucketed by hour or day for a campaign.
func (r *Repository) timeline(ctx context.Context, q db.Querier, tenantID, campaignID uuid.UUID, bucket string) ([]TimelineBucket, error) {
	const sql = `
SELECT date_trunc($3::text, occurred_at) AS bucket, type::text, count(*)
FROM events
WHERE tenant_id = $1 AND campaign_id = $2
GROUP BY 1, 2
ORDER BY 1`
	rows, err := q.Query(ctx, sql, tenantID, campaignID, bucket)
	if err != nil {
		return nil, fmt.Errorf("report: timeline: %w", err)
	}
	defer rows.Close()

	ordered := make([]TimelineBucket, 0)
	index := make(map[time.Time]int)
	for rows.Next() {
		var ts time.Time
		var typ string
		var n int
		if err := rows.Scan(&ts, &typ, &n); err != nil {
			return nil, fmt.Errorf("report: timeline scan: %w", err)
		}
		i, ok := index[ts]
		if !ok {
			i = len(ordered)
			index[ts] = i
			ordered = append(ordered, TimelineBucket{Bucket: ts, Counts: map[string]int{}})
		}
		ordered[i].Counts[typ] = n
	}
	return ordered, rows.Err()
}

// Campaign builds the full KPI report for a campaign.
func (r *Repository) Campaign(ctx context.Context, q db.Querier, tenantID, campaignID uuid.UUID, name, status, bucket string) (CampaignReport, error) {
	bucket = normalizeBucket(bucket)
	hist, err := r.stateHistogram(ctx, q, tenantID, campaignID)
	if err != nil {
		return CampaignReport{}, err
	}
	tl, err := r.timeline(ctx, q, tenantID, campaignID, bucket)
	if err != nil {
		return CampaignReport{}, err
	}
	totals, rates := totalsFromHistogram(hist)
	return CampaignReport{
		CampaignID: campaignID,
		Name:       name,
		Status:     status,
		Bucket:     bucket,
		Totals:     totals,
		Rates:      rates,
		Timeline:   tl,
	}, nil
}

// Recipients returns the flat per-recipient drilldown rows for a campaign, in a
// single aggregate query (no N+1). Timestamps are the first occurrence of each
// stage; no captured secret material is selected.
func (r *Repository) Recipients(ctx context.Context, q db.Querier, tenantID, campaignID uuid.UUID) ([]RecipientRow, error) {
	const sql = `
SELECT c.email,
       COALESCE(ct.state::text, 'pending') AS state,
       min(e.occurred_at) FILTER (WHERE e.type = 'sent')             AS sent_at,
       min(e.occurred_at) FILTER (WHERE e.type = 'delivered')        AS delivered_at,
       min(e.occurred_at) FILTER (WHERE e.type = 'opened')           AS opened_at,
       min(e.occurred_at) FILTER (WHERE e.type = 'scanned')          AS scanned_at,
       min(e.occurred_at) FILTER (WHERE e.type = 'clicked')          AS clicked_at,
       min(e.occurred_at) FILTER (WHERE e.type = 'creds')            AS creds_at,
       min(e.occurred_at) FILTER (WHERE e.type = 'session_hijacked') AS session_hijacked_at,
       max(e.occurred_at)                                            AS last_event_at
FROM recipients r
JOIN contacts c ON c.id = r.contact_id
LEFT JOIN campaign_targets ct
       ON ct.campaign_id = r.campaign_id AND ct.contact_id = r.contact_id
LEFT JOIN events e
       ON e.campaign_id = r.campaign_id AND e.contact_id = r.contact_id
WHERE r.tenant_id = $1 AND r.campaign_id = $2
GROUP BY r.contact_id, c.email, ct.state
ORDER BY c.email`
	rows, err := q.Query(ctx, sql, tenantID, campaignID)
	if err != nil {
		return nil, fmt.Errorf("report: recipients: %w", err)
	}
	defer rows.Close()

	out := make([]RecipientRow, 0)
	for rows.Next() {
		var row RecipientRow
		if err := rows.Scan(&row.Email, &row.State, &row.SentAt, &row.DeliveredAt,
			&row.OpenedAt, &row.ScannedAt, &row.ClickedAt, &row.CredsAt, &row.SessionHijackedAt, &row.LastEventAt); err != nil {
			return nil, fmt.Errorf("report: recipients scan: %w", err)
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// PlatformTenant is one tenant's headline rollup for the cross-tenant console.
type PlatformTenant struct {
	TenantID  uuid.UUID `json:"tenant_id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	Campaigns int       `json:"campaigns"`
	Totals    Totals    `json:"totals"`
	Rates     Rates     `json:"rates"`
}

// PlatformOverview builds a per-tenant headline rollup across ALL tenants (for
// platform-admin oversight). Read-only; counts/rates only. Two aggregate
// queries (state histogram per tenant + campaign counts), merged in Go — no
// N+1 per tenant.
func (r *Repository) PlatformOverview(ctx context.Context, q db.Querier) ([]PlatformTenant, error) {
	const histSQL = `
SELECT t.id, t.name, t.slug, t.created_at,
       COALESCE(ct.state::text, 'pending') AS state, count(r.id) AS n
FROM tenants t
LEFT JOIN recipients r ON r.tenant_id = t.id
LEFT JOIN campaign_targets ct
       ON ct.campaign_id = r.campaign_id AND ct.contact_id = r.contact_id
GROUP BY t.id, t.name, t.slug, t.created_at, state
ORDER BY t.created_at DESC`
	rows, err := q.Query(ctx, histSQL)
	if err != nil {
		return nil, fmt.Errorf("report: platform histogram: %w", err)
	}
	type acc struct {
		name, slug string
		hist       map[string]int
	}
	order := make([]uuid.UUID, 0)
	byID := make(map[uuid.UUID]*acc)
	for rows.Next() {
		var (
			id         uuid.UUID
			name, slug string
			created    time.Time
			state      string
			n          int
		)
		if err := rows.Scan(&id, &name, &slug, &created, &state, &n); err != nil {
			rows.Close()
			return nil, fmt.Errorf("report: platform scan: %w", err)
		}
		a, ok := byID[id]
		if !ok {
			a = &acc{name: name, slug: slug, hist: map[string]int{}}
			byID[id] = a
			order = append(order, id)
		}
		if n > 0 {
			a.hist[state] += n
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("report: platform iterate: %w", err)
	}

	campaignCounts, err := r.campaignCountsByTenant(ctx, q)
	if err != nil {
		return nil, err
	}

	out := make([]PlatformTenant, 0, len(order))
	for _, id := range order {
		a := byID[id]
		totals, rates := totalsFromHistogram(a.hist)
		out = append(out, PlatformTenant{
			TenantID: id, Name: a.name, Slug: a.slug,
			Campaigns: campaignCounts[id], Totals: totals, Rates: rates,
		})
	}
	return out, nil
}

func (r *Repository) campaignCountsByTenant(ctx context.Context, q db.Querier) (map[uuid.UUID]int, error) {
	rows, err := q.Query(ctx, `SELECT tenant_id, count(*) FROM campaigns GROUP BY tenant_id`)
	if err != nil {
		return nil, fmt.Errorf("report: campaign counts: %w", err)
	}
	defer rows.Close()
	out := make(map[uuid.UUID]int)
	for rows.Next() {
		var id uuid.UUID
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, fmt.Errorf("report: campaign counts scan: %w", err)
		}
		out[id] = n
	}
	return out, rows.Err()
}

// TenantSummary builds the portfolio rollup across a tenant's campaigns in one
// aggregate query.
func (r *Repository) TenantSummary(ctx context.Context, q db.Querier, tenantID uuid.UUID) (TenantSummary, error) {
	const sql = `
SELECT c.id, c.name, c.status::text,
       COALESCE(ct.state::text, 'pending') AS state, count(r.id) AS n
FROM campaigns c
LEFT JOIN recipients r ON r.campaign_id = c.id
LEFT JOIN campaign_targets ct
       ON ct.campaign_id = r.campaign_id AND ct.contact_id = r.contact_id
WHERE c.tenant_id = $1
GROUP BY c.id, c.name, c.status, c.created_at, state
ORDER BY c.created_at DESC`
	rows, err := q.Query(ctx, sql, tenantID)
	if err != nil {
		return TenantSummary{}, fmt.Errorf("report: tenant summary: %w", err)
	}
	defer rows.Close()

	// Per-campaign histogram, preserving first-seen (created_at DESC) order.
	type camp struct {
		name, status string
		hist         map[string]int
	}
	order := make([]uuid.UUID, 0)
	byID := make(map[uuid.UUID]*camp)
	tenantHist := make(map[string]int)

	for rows.Next() {
		var id uuid.UUID
		var name, status, state string
		var n int
		if err := rows.Scan(&id, &name, &status, &state, &n); err != nil {
			return TenantSummary{}, fmt.Errorf("report: tenant summary scan: %w", err)
		}
		c, ok := byID[id]
		if !ok {
			c = &camp{name: name, status: status, hist: map[string]int{}}
			byID[id] = c
			order = append(order, id)
		}
		if n > 0 {
			c.hist[state] += n
			tenantHist[state] += n
		}
	}
	if err := rows.Err(); err != nil {
		return TenantSummary{}, fmt.Errorf("report: tenant summary iterate: %w", err)
	}

	out := TenantSummary{TenantID: tenantID, Campaigns: make([]CampaignSummary, 0, len(order))}
	for _, id := range order {
		c := byID[id]
		totals, rates := totalsFromHistogram(c.hist)
		out.Campaigns = append(out.Campaigns, CampaignSummary{
			CampaignID: id, Name: c.name, Status: c.status, Totals: totals, Rates: rates,
		})
	}
	out.Totals, out.Rates = totalsFromHistogram(tenantHist)
	return out, nil
}
