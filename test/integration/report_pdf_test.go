package integration

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"phishforge/internal/apikey"
	"phishforge/internal/events"
	"phishforge/internal/tenant"
)

// TestReportPDF renders both PDF endpoints against seeded data and asserts the
// PDF magic bytes + a non-trivial size.
func TestReportPDF(t *testing.T) {
	pool := setupDB(t)
	ctx := context.Background()

	tenants := tenant.NewRepository()
	tn, err := tenants.Create(ctx, pool, "PDF Co", "pdf-"+short())
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	opID := createUser(t, ctx, pool, tn.ID, "op@pdf.test", "operator")
	opTok, _, _ := apikey.NewService(pool).Create(ctx, tn.ID, opID, "op")

	srv, _ := newAPI(t, pool)
	defer srv.Close()

	_, gb := do(t, srv.URL, http.MethodPost, "/api/v1/contact-groups", opTok, map[string]any{"name": "wave"})
	var grp struct {
		ID uuid.UUID `json:"id"`
	}
	mustJSON(t, gb, &grp)
	ids := map[string]uuid.UUID{}
	for _, e := range []string{"a@t.test", "b@t.test"} {
		_, cb := do(t, srv.URL, http.MethodPost, "/api/v1/contacts", opTok, map[string]any{"email": e, "first_name": "X", "group_id": grp.ID})
		var c struct {
			ID uuid.UUID `json:"id"`
		}
		mustJSON(t, cb, &c)
		ids[e] = c.ID
	}
	_, cb := do(t, srv.URL, http.MethodPost, "/api/v1/campaigns", opTok, map[string]any{"name": "PDF Drill"})
	var camp struct {
		ID uuid.UUID `json:"id"`
	}
	mustJSON(t, cb, &camp)
	if code, b := do(t, srv.URL, http.MethodPost, "/api/v1/campaigns/"+camp.ID.String()+"/launch", opTok, map[string]any{"group_id": grp.ID}); code != http.StatusOK {
		t.Fatalf("launch: %d (%s)", code, b)
	}
	er := events.NewRepository(pool)
	for _, et := range []events.Type{events.TypeSent, events.TypeDelivered, events.TypeOpened, events.TypeClicked} {
		if _, err := er.Append(ctx, events.NewEvent{TenantID: tn.ID, CampaignID: camp.ID, ContactID: ids["a@t.test"], Type: et}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	assertPDF := func(label, path string) {
		code, body := do(t, srv.URL, http.MethodGet, path, opTok, nil)
		if code != http.StatusOK {
			t.Fatalf("%s: want 200, got %d (%s)", label, code, body)
		}
		if !strings.HasPrefix(body, "%PDF-") {
			t.Fatalf("%s: not a PDF (prefix %q)", label, body[:min(8, len(body))])
		}
		if len(body) < 800 {
			t.Fatalf("%s: PDF too small (%d bytes)", label, len(body))
		}
	}

	assertPDF("campaign pdf", "/api/v1/campaigns/"+camp.ID.String()+"/report.pdf")
	assertPDF("campaign pdf hourly", "/api/v1/campaigns/"+camp.ID.String()+"/report.pdf?bucket=hour")
	assertPDF("tenant pdf", "/api/v1/tenants/"+tn.ID.String()+"/summary.pdf")

	// cross-tenant summary.pdf is forbidden
	other, _ := tenants.Create(ctx, pool, "Other", "oth-"+short())
	if code, _ := do(t, srv.URL, http.MethodGet, "/api/v1/tenants/"+other.ID.String()+"/summary.pdf", opTok, nil); code != http.StatusForbidden {
		t.Fatalf("cross-tenant pdf: want 403, got %d", code)
	}

	// audited
	if n := count(t, ctx, pool, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='report.pdf'`, tn.ID); n != 2 {
		t.Fatalf("report.pdf audit: want 2, got %d", n)
	}
}
