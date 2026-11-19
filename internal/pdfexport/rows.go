// Package pdfexport renders executive PDF reports from the report aggregation.
// The aggregation-to-row mapping is pure and separately tested; the PDF drawing
// (pdf.go) wraps it. Reports contain only states, counts, rates and timestamps
// — never captured credential/session material.
package pdfexport

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"phishforge/internal/osintresult"
	"phishforge/internal/report"
)

// Row caps per table. When exceeded, the mapper reports truncated=true and the
// PDF footer notes it.
const (
	MaxTimelineRows  = 500
	MaxRecipientRows = 1000
	MaxCampaignRows  = 500
	MaxOSINTRows     = 200
)

func fpct(v float64) string { return fmt.Sprintf("%.1f%%", v*100) }

func itoa(n int) string { return strconv.Itoa(n) }

func tsfmt(t *time.Time) string {
	if t == nil {
		return "—"
	}
	return t.UTC().Format("2006-01-02 15:04")
}

// TimelineCols are the event-type columns of the timeline table (after Bucket).
var TimelineCols = []string{"sent", "delivered", "opened", "clicked", "creds"}

// FunnelHeader / etc. expose the table headers so the PDF and tests agree.
var (
	FunnelHeader    = []string{"Stage", "Count", "% of recipients"}
	TimelineHeader  = append([]string{"Bucket (UTC)"}, TimelineCols...)
	RecipientHeader = []string{"Email", "State", "Sent", "Opened", "Clicked", "Creds", "Last event"}
	CampaignHeader  = []string{"Campaign", "Status", "Recipients", "Delivered", "Opened", "Clicked", "Creds"}
	OSINTHeader     = []string{"Domain", "Subdomains", "Lookalikes", "Available"}
)

// FunnelRows maps the funnel totals to [stage, count, pct-of-recipients] rows.
func FunnelRows(tot report.Totals) [][]string {
	base := tot.Recipients
	row := func(label string, n int) []string {
		p := 0.0
		if base > 0 {
			p = float64(n) / float64(base)
		}
		return []string{label, itoa(n), fpct(p)}
	}
	return [][]string{
		row("Sent", tot.Sent),
		row("Delivered", tot.Delivered),
		row("Opened", tot.Opened),
		row("Clicked", tot.Clicked),
		row("Submitted creds", tot.Creds),
		row("Session hijacked", tot.SessionHijacked),
	}
}

// TimelineRows maps timeline buckets to a fixed-column grid. Truncated when the
// bucket count exceeds cap.
func TimelineRows(buckets []report.TimelineBucket, cap int) ([][]string, bool) {
	truncated := false
	if len(buckets) > cap {
		buckets = buckets[:cap]
		truncated = true
	}
	out := make([][]string, 0, len(buckets))
	for _, b := range buckets {
		row := []string{b.Bucket.UTC().Format("2006-01-02 15:04")}
		for _, c := range TimelineCols {
			row = append(row, itoa(b.Counts[c]))
		}
		out = append(out, row)
	}
	return out, truncated
}

// RecipientRows maps the per-recipient drilldown to rows of states + timestamps
// only (no secret material). Truncated when the count exceeds cap.
func RecipientRows(rows []report.RecipientRow, cap int) ([][]string, bool) {
	truncated := false
	if len(rows) > cap {
		rows = rows[:cap]
		truncated = true
	}
	out := make([][]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, []string{
			r.Email, r.State,
			tsfmt(r.SentAt), tsfmt(r.OpenedAt), tsfmt(r.ClickedAt), tsfmt(r.CredsAt), tsfmt(r.LastEventAt),
		})
	}
	return out, truncated
}

// CampaignSummaryRows maps the tenant rollup's per-campaign rates to rows.
func CampaignSummaryRows(cs []report.CampaignSummary, cap int) ([][]string, bool) {
	truncated := false
	if len(cs) > cap {
		cs = cs[:cap]
		truncated = true
	}
	out := make([][]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, []string{
			c.Name, c.Status, itoa(c.Totals.Recipients),
			fpct(c.Rates.Delivered), fpct(c.Rates.Opened), fpct(c.Rates.Clicked), fpct(c.Rates.Creds),
		})
	}
	return out, truncated
}

type osintCounts struct {
	Subdomains   []json.RawMessage `json:"subdomains"`
	Lookalikes   []json.RawMessage `json:"lookalikes"`
	Availability []struct {
		Available *bool `json:"available"`
	} `json:"availability"`
}

// OSINTHighlightRows maps stored OSINT collections to counts-only rows
// (domain, #subdomains, #lookalikes, #available). No listing of the data.
func OSINTHighlightRows(results []osintresult.Result, cap int) ([][]string, bool) {
	truncated := false
	if len(results) > cap {
		results = results[:cap]
		truncated = true
	}
	out := make([][]string, 0, len(results))
	for _, r := range results {
		var c osintCounts
		_ = json.Unmarshal(r.Result, &c)
		available := 0
		for _, a := range c.Availability {
			if a.Available != nil && *a.Available {
				available++
			}
		}
		out = append(out, []string{r.Domain, itoa(len(c.Subdomains)), itoa(len(c.Lookalikes)), itoa(available)})
	}
	return out, truncated
}
