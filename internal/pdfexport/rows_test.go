package pdfexport

import (
	"encoding/json"
	"testing"
	"time"

	"phishforge/internal/osintresult"
	"phishforge/internal/report"
)

func tp(s string) *time.Time {
	t, _ := time.Parse("2006-01-02 15:04", s)
	return &t
}

func eq(t *testing.T, got, want [][]string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("rows: got %d want %d\n got=%v\nwant=%v", len(got), len(want), got, want)
	}
	for i := range want {
		if len(got[i]) != len(want[i]) {
			t.Fatalf("row %d cols: got %v want %v", i, got[i], want[i])
		}
		for j := range want[i] {
			if got[i][j] != want[i][j] {
				t.Fatalf("cell [%d][%d]: got %q want %q", i, j, got[i][j], want[i][j])
			}
		}
	}
}

func TestFunnelRows(t *testing.T) {
	tot := report.Totals{Recipients: 10, Sent: 10, Delivered: 8, Opened: 6, Clicked: 4, Creds: 2, SessionHijacked: 1}
	eq(t, FunnelRows(tot), [][]string{
		{"Sent", "10", "100.0%"},
		{"Delivered", "8", "80.0%"},
		{"Opened", "6", "60.0%"},
		{"Clicked", "4", "40.0%"},
		{"Submitted creds", "2", "20.0%"},
		{"Session hijacked", "1", "10.0%"},
	})
}

func TestFunnelRowsZeroRecipients(t *testing.T) {
	// No divide-by-zero; all rates 0.0%.
	rows := FunnelRows(report.Totals{})
	if rows[0][2] != "0.0%" {
		t.Fatalf("zero recipients pct: %q", rows[0][2])
	}
}

func TestTimelineRows(t *testing.T) {
	buckets := []report.TimelineBucket{
		{Bucket: *tp("2024-01-02 03:00"), Counts: map[string]int{"sent": 3, "opened": 1}},
	}
	rows, trunc := TimelineRows(buckets, 10)
	if trunc {
		t.Fatal("unexpected truncation")
	}
	eq(t, rows, [][]string{{"2024-01-02 03:00", "3", "0", "1", "0", "0"}})
}

func TestTimelineTruncation(t *testing.T) {
	buckets := make([]report.TimelineBucket, 5)
	for i := range buckets {
		buckets[i] = report.TimelineBucket{Bucket: time.Now(), Counts: map[string]int{}}
	}
	rows, trunc := TimelineRows(buckets, 2)
	if !trunc || len(rows) != 2 {
		t.Fatalf("truncation: trunc=%v len=%d", trunc, len(rows))
	}
}

func TestRecipientRows(t *testing.T) {
	rows := []report.RecipientRow{
		{Email: "a@b.test", State: "clicked", SentAt: tp("2024-01-02 03:04"), ClickedAt: tp("2024-01-02 03:10")},
	}
	got, trunc := RecipientRows(rows, 10)
	if trunc {
		t.Fatal("unexpected truncation")
	}
	eq(t, got, [][]string{
		{"a@b.test", "clicked", "2024-01-02 03:04", "—", "2024-01-02 03:10", "—", "—"},
	})
}

func TestCampaignSummaryRows(t *testing.T) {
	cs := []report.CampaignSummary{
		{
			Name: "Q2 Drill", Status: "completed",
			Totals: report.Totals{Recipients: 50},
			Rates:  report.Rates{Delivered: 0.9, Opened: 0.5, Clicked: 0.2, Creds: 0.04},
		},
	}
	got, _ := CampaignSummaryRows(cs, 10)
	eq(t, got, [][]string{{"Q2 Drill", "completed", "50", "90.0%", "50.0%", "20.0%", "4.0%"}})
}

func TestOSINTHighlightRows(t *testing.T) {
	payload, _ := json.Marshal(map[string]any{
		"subdomains": []string{"a.example.com", "b.example.com"},
		"lookalikes": []map[string]string{{"domain": "examp1e.com", "fuzzer": "replacement"}},
		"availability": []map[string]any{
			{"available": true}, {"available": false}, {"available": nil},
		},
	})
	results := []osintresult.Result{{Domain: "example.com", Result: payload}}
	got, _ := OSINTHighlightRows(results, 10)
	eq(t, got, [][]string{{"example.com", "2", "1", "1"}})
}
