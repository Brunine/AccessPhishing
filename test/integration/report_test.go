package integration

import (
	"context"
	"encoding/csv"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"phishforge/internal/apikey"
	"phishforge/internal/events"
	"phishforge/internal/tenant"
)

// TestCampaignReport seeds a funnel of events and asserts the KPI aggregates,
// the CSV drilldown shape, and the tenant rollup (incl. cross-tenant 403).
func TestCampaignReport(t *testing.T) {
	pool := setupDB(t)
	ctx := context.Background()

	tenants := tenant.NewRepository()
	tn, err := tenants.Create(ctx, pool, "Report Co", "rep-"+short())
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	opID := createUser(t, ctx, pool, tn.ID, "op@rep.test", "operator")
	keys := apikey.NewService(pool)
	opTok, _, _ := keys.Create(ctx, tn.ID, opID, "op")

	srv, _ := newAPI(t, pool)
	defer srv.Close()

	// group + 3 contacts
	_, gb := do(t, srv.URL, http.MethodPost, "/api/v1/contact-groups", opTok, map[string]any{"name": "wave"})
	var grp struct {
		ID uuid.UUID `json:"id"`
	}
	mustJSON(t, gb, &grp)

	contactIDs := make(map[string]uuid.UUID)
	for _, e := range []string{"a@t.test", "b@t.test", "c@t.test"} {
		_, cb := do(t, srv.URL, http.MethodPost, "/api/v1/contacts", opTok,
			map[string]any{"email": e, "first_name": "X", "group_id": grp.ID})
		var c struct {
			ID uuid.UUID `json:"id"`
		}
		mustJSON(t, cb, &c)
		contactIDs[e] = c.ID
	}

	// campaign + launch (snapshots 3 recipients)
	engID := seedAuthorizedEngagement(t, ctx, pool, tn.ID, opID)
	_, cb := do(t, srv.URL, http.MethodPost, "/api/v1/campaigns", opTok, map[string]any{"name": "Report Drill", "engagement_id": engID})
	var camp struct {
		ID uuid.UUID `json:"id"`
	}
	mustJSON(t, cb, &camp)
	if code, body := do(t, srv.URL, http.MethodPost, "/api/v1/campaigns/"+camp.ID.String()+"/launch", opTok,
		map[string]any{"group_id": grp.ID}); code != http.StatusOK {
		t.Fatalf("launch: %d (%s)", code, body)
	}

	// Seed a funnel: A->clicked, B->creds, C->sent.
	er := events.NewRepository(pool)
	appendChain := func(email string, chain ...events.Type) {
		for _, et := range chain {
			if _, err := er.Append(ctx, events.NewEvent{
				TenantID: tn.ID, CampaignID: camp.ID, ContactID: contactIDs[email], Type: et,
			}); err != nil {
				t.Fatalf("append %s to %s: %v", et, email, err)
			}
		}
	}
	appendChain("a@t.test", events.TypeSent, events.TypeDelivered, events.TypeOpened, events.TypeClicked)
	appendChain("b@t.test", events.TypeSent, events.TypeDelivered, events.TypeOpened, events.TypeClicked, events.TypeCreds)
	appendChain("c@t.test", events.TypeSent)

	// --- /report ---
	code, rb := do(t, srv.URL, http.MethodGet, "/api/v1/campaigns/"+camp.ID.String()+"/report", opTok, nil)
	if code != http.StatusOK {
		t.Fatalf("report: %d (%s)", code, rb)
	}
	var rep struct {
		Totals struct {
			Recipients, Sent, Delivered, Opened, Clicked, Creds, SessionHijacked, Pending int
		} `json:"totals"`
		Rates struct {
			Clicked float64 `json:"clicked"`
		} `json:"rates"`
		Timeline []struct {
			Counts map[string]int `json:"counts"`
		} `json:"timeline"`
	}
	mustJSON(t, rb, &rep)

	got := rep.Totals
	if got.Recipients != 3 || got.Sent != 3 || got.Delivered != 2 || got.Opened != 2 ||
		got.Clicked != 2 || got.Creds != 1 || got.SessionHijacked != 0 || got.Pending != 0 {
		t.Fatalf("totals wrong: %+v", got)
	}
	if rep.Rates.Clicked < 0.66 || rep.Rates.Clicked > 0.67 {
		t.Fatalf("clicked rate: want ~0.667, got %v", rep.Rates.Clicked)
	}
	if len(rep.Timeline) == 0 || rep.Timeline[0].Counts["sent"] != 3 {
		t.Fatalf("timeline wrong: %+v", rep.Timeline)
	}

	// --- /report.csv ---
	code, csvBody := do(t, srv.URL, http.MethodGet, "/api/v1/campaigns/"+camp.ID.String()+"/report.csv", opTok, nil)
	if code != http.StatusOK {
		t.Fatalf("report.csv: %d (%s)", code, csvBody)
	}
	records, err := csv.NewReader(strings.NewReader(csvBody)).ReadAll()
	if err != nil {
		t.Fatalf("parse csv: %v", err)
	}
	if len(records) != 4 { // header + 3 rows
		t.Fatalf("csv rows: want 4, got %d (%v)", len(records), records)
	}
	if records[0][0] != "email" || records[0][1] != "state" {
		t.Fatalf("csv header: %v", records[0])
	}
	states := map[string]string{}
	for _, row := range records[1:] {
		states[row[0]] = row[1]
	}
	if states["a@t.test"] != "clicked" || states["b@t.test"] != "creds" || states["c@t.test"] != "sent" {
		t.Fatalf("csv states wrong: %v", states)
	}

	// --- /tenants/{id}/summary ---
	code, sb := do(t, srv.URL, http.MethodGet, "/api/v1/tenants/"+tn.ID.String()+"/summary", opTok, nil)
	if code != http.StatusOK {
		t.Fatalf("summary: %d (%s)", code, sb)
	}
	var sum struct {
		Campaigns []struct {
			CampaignID uuid.UUID `json:"campaign_id"`
			Totals     struct {
				Recipients, Clicked int
			} `json:"totals"`
		} `json:"campaigns"`
		Totals struct {
			Recipients, Clicked, Creds int
		} `json:"totals"`
	}
	mustJSON(t, sb, &sum)
	if sum.Totals.Recipients != 3 || sum.Totals.Clicked != 2 || sum.Totals.Creds != 1 {
		t.Fatalf("tenant totals wrong: %+v", sum.Totals)
	}
	if len(sum.Campaigns) != 1 || sum.Campaigns[0].CampaignID != camp.ID {
		t.Fatalf("tenant campaigns wrong: %+v", sum.Campaigns)
	}

	// cross-tenant summary is forbidden
	other, _ := tenants.Create(ctx, pool, "Other Co", "oth-"+short())
	if code, _ := do(t, srv.URL, http.MethodGet, "/api/v1/tenants/"+other.ID.String()+"/summary", opTok, nil); code != http.StatusForbidden {
		t.Fatalf("cross-tenant summary: want 403, got %d", code)
	}

	// audit entries for the read endpoints
	if n := count(t, ctx, pool, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='report.view'`, tn.ID); n != 1 {
		t.Fatalf("report.view audit: want 1, got %d", n)
	}
	if n := count(t, ctx, pool, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='report.export'`, tn.ID); n != 1 {
		t.Fatalf("report.export audit: want 1, got %d", n)
	}
}
