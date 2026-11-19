package pdfexport

import (
	"fmt"
	"io"
	"time"

	"github.com/go-pdf/fpdf"

	"phishforge/internal/osintresult"
	"phishforge/internal/report"
)

// Meta carries the page-furniture data (tenant name + generation time).
type Meta struct {
	TenantName  string
	GeneratedAt time.Time
}

// doc wraps an fpdf document with shared header/footer furniture. truncated is
// captured by the footer closure and set by table rendering.
type doc struct {
	pdf       *fpdf.Fpdf
	title     string
	meta      Meta
	truncated bool
}

func newDoc(title string, meta Meta) *doc {
	d := &doc{pdf: fpdf.New("P", "mm", "A4", ""), title: title, meta: meta}
	d.pdf.SetAutoPageBreak(true, 18)
	d.pdf.AliasNbPages("")
	d.pdf.SetHeaderFunc(func() {
		d.pdf.SetY(8)
		d.pdf.SetFont("Helvetica", "B", 9)
		d.pdf.SetTextColor(60, 60, 60)
		d.pdf.CellFormat(120, 5, "PhishForge — "+d.meta.TenantName, "", 0, "L", false, 0, "")
		d.pdf.CellFormat(70, 5, d.title, "", 1, "R", false, 0, "")
		d.pdf.SetDrawColor(200, 200, 200)
		d.pdf.Line(10, 15, 200, 15)
		d.pdf.Ln(6)
		d.pdf.SetTextColor(0, 0, 0)
	})
	d.pdf.SetFooterFunc(func() {
		d.pdf.SetY(-15)
		d.pdf.SetFont("Helvetica", "", 7)
		d.pdf.SetTextColor(120, 120, 120)
		d.pdf.CellFormat(95, 5, "Generated "+d.meta.GeneratedAt.UTC().Format("2006-01-02 15:04 UTC"), "", 0, "L", false, 0, "")
		note := ""
		if d.truncated {
			note = "Some tables truncated.  "
		}
		d.pdf.CellFormat(95, 5, fmt.Sprintf("%sPage %d/{nb}", note, d.pdf.PageNo()), "", 0, "R", false, 0, "")
		d.pdf.SetTextColor(0, 0, 0)
	})
	return d
}

func (d *doc) heading(text string) {
	d.pdf.Ln(2)
	d.pdf.SetFont("Helvetica", "B", 12)
	d.pdf.CellFormat(0, 7, text, "", 1, "L", false, 0, "")
	d.pdf.Ln(1)
}

func (d *doc) kv(label, value string) {
	d.pdf.SetFont("Helvetica", "", 10)
	d.pdf.CellFormat(45, 6, label, "", 0, "L", false, 0, "")
	d.pdf.SetFont("Helvetica", "B", 10)
	d.pdf.CellFormat(0, 6, value, "", 1, "L", false, 0, "")
}

// table renders a header row (shaded) followed by data rows. widths sum to the
// content width (190mm). If rows was truncated upstream, callers set d.truncated.
func (d *doc) table(headers []string, widths []float64, aligns []string, rows [][]string) {
	d.pdf.SetFont("Helvetica", "B", 8)
	d.pdf.SetFillColor(235, 237, 242)
	for i, h := range headers {
		d.pdf.CellFormat(widths[i], 6, h, "1", 0, aligns[i], true, 0, "")
	}
	d.pdf.Ln(-1)
	d.pdf.SetFont("Helvetica", "", 8)
	for _, row := range rows {
		for i := range headers {
			cell := ""
			if i < len(row) {
				cell = row[i]
			}
			d.pdf.CellFormat(widths[i], 5.5, truncateCell(cell, widths[i]), "1", 0, aligns[i], false, 0, "")
		}
		d.pdf.Ln(-1)
	}
	if len(rows) == 0 {
		d.pdf.SetFont("Helvetica", "I", 8)
		d.pdf.CellFormat(sum(widths), 5.5, "(none)", "1", 1, "L", false, 0, "")
	}
	d.pdf.Ln(3)
}

func sum(ws []float64) float64 {
	t := 0.0
	for _, w := range ws {
		t += w
	}
	return t
}

// truncateCell clamps a cell string to roughly fit its column width (8pt).
func truncateCell(s string, widthMM float64) string {
	max := int(widthMM / 1.6) // ~1.6mm per char at 8pt
	if max < 4 {
		max = 4
	}
	if len(s) > max {
		if max <= 1 {
			return s[:max]
		}
		return s[:max-1] + "…"
	}
	return s
}

// CampaignPDF renders a single-campaign report to w.
func CampaignPDF(w io.Writer, meta Meta, rep report.CampaignReport, recipients []report.RecipientRow) error {
	d := newDoc("Campaign Report", meta)
	d.pdf.AddPage()

	d.pdf.SetFont("Helvetica", "B", 15)
	d.pdf.CellFormat(0, 9, rep.Name, "", 1, "L", false, 0, "")
	d.kv("Status", rep.Status)
	d.kv("Recipients", itoa(rep.Totals.Recipients))
	d.kv("Timeline bucket", rep.Bucket)
	d.kv("Pending / Bounced / Failed", fmt.Sprintf("%d / %d / %d", rep.Totals.Pending, rep.Totals.Bounced, rep.Totals.Failed))

	d.heading("Funnel")
	d.table(FunnelHeader, []float64{80, 40, 70}, []string{"L", "R", "R"}, FunnelRows(rep.Totals))

	d.heading(fmt.Sprintf("Event timeline (by %s)", rep.Bucket))
	tl, tlTrunc := TimelineRows(rep.Timeline, MaxTimelineRows)
	d.truncated = d.truncated || tlTrunc
	d.table(TimelineHeader, []float64{50, 28, 28, 28, 28, 28}, []string{"L", "R", "R", "R", "R", "R"}, tl)

	d.heading("Per-recipient drilldown (states + timestamps only)")
	rr, rrTrunc := RecipientRows(recipients, MaxRecipientRows)
	d.truncated = d.truncated || rrTrunc
	d.table(
		RecipientHeader,
		[]float64{46, 20, 24, 24, 24, 24, 28},
		[]string{"L", "L", "L", "L", "L", "L", "L"},
		rr,
	)
	return d.pdf.Output(w)
}

// TenantPDF renders a tenant-level executive report to w.
func TenantPDF(w io.Writer, meta Meta, sum report.TenantSummary, osint []osintresult.Result) error {
	d := newDoc("Executive Summary", meta)
	d.pdf.AddPage()

	d.pdf.SetFont("Helvetica", "B", 15)
	d.pdf.CellFormat(0, 9, meta.TenantName+" — Executive Summary", "", 1, "L", false, 0, "")
	d.kv("Period", "all campaigns to "+meta.GeneratedAt.UTC().Format("2006-01-02"))
	d.kv("Campaigns", itoa(len(sum.Campaigns)))
	d.kv("Recipients", itoa(sum.Totals.Recipients))

	d.heading("Aggregate funnel")
	d.table(FunnelHeader, []float64{80, 40, 70}, []string{"L", "R", "R"}, FunnelRows(sum.Totals))

	d.heading("Per-campaign rates")
	cr, crTrunc := CampaignSummaryRows(sum.Campaigns, MaxCampaignRows)
	d.truncated = d.truncated || crTrunc
	d.table(CampaignHeader, []float64{54, 24, 28, 21, 21, 21, 21}, []string{"L", "L", "R", "R", "R", "R", "R"}, cr)

	d.heading("OSINT highlights (counts only)")
	or, orTrunc := OSINTHighlightRows(osint, MaxOSINTRows)
	d.truncated = d.truncated || orTrunc
	d.table(OSINTHeader, []float64{94, 32, 32, 32}, []string{"L", "R", "R", "R"}, or)

	return d.pdf.Output(w)
}
