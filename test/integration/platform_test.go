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

// seedFunnel creates a group + 2 contacts + a launched campaign for a tenant
// (driven over HTTP with tok) and drives one contact through sent->clicked.
func seedFunnel(t *testing.T, ctx context.Context, srvURL, tok string, er *events.Repository, tenantID uuid.UUID) uuid.UUID {
	t.Helper()
	_, gb := do(t, srvURL, http.MethodPost, "/api/v1/contact-groups", tok, map[string]any{"name": "wave"})
	var grp struct {
		ID uuid.UUID `json:"id"`
	}
	mustJSON(t, gb, &grp)
	var first uuid.UUID
	for i, e := range []string{"a@x.test", "b@x.test"} {
		_, cb := do(t, srvURL, http.MethodPost, "/api/v1/contacts", tok, map[string]any{"email": e, "group_id": grp.ID})
		var c struct {
			ID uuid.UUID `json:"id"`
		}
		mustJSON(t, cb, &c)
		if i == 0 {
			first = c.ID
		}
	}
	_, cb := do(t, srvURL, http.MethodPost, "/api/v1/campaigns", tok, map[string]any{"name": "Drill"})
	var camp struct {
		ID uuid.UUID `json:"id"`
	}
	mustJSON(t, cb, &camp)
	if code, b := do(t, srvURL, http.MethodPost, "/api/v1/campaigns/"+camp.ID.String()+"/launch", tok, map[string]any{"group_id": grp.ID}); code != http.StatusOK {
		t.Fatalf("launch: %d (%s)", code, b)
	}
	for _, et := range []events.Type{events.TypeSent, events.TypeDelivered, events.TypeOpened, events.TypeClicked} {
		if _, err := er.Append(ctx, events.NewEvent{TenantID: tenantID, CampaignID: camp.ID, ContactID: first, Type: et}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	return camp.ID
}

func TestPlatformConsole(t *testing.T) {
	pool := setupDB(t)
	ctx := context.Background()
	tenants := tenant.NewRepository()
	keys := apikey.NewService(pool)
	er := events.NewRepository(pool)

	tnA, _ := tenants.Create(ctx, pool, "Alpha", "alpha-"+short())
	aAdmin := createUser(t, ctx, pool, tnA.ID, "admin@a.test", "admin")
	aOp := createUser(t, ctx, pool, tnA.ID, "op@a.test", "operator")
	aAdminTok, _, _ := keys.Create(ctx, tnA.ID, aAdmin, "a-admin")
	aOpTok, _, _ := keys.Create(ctx, tnA.ID, aOp, "a-op")

	tnB, _ := tenants.Create(ctx, pool, "Bravo", "bravo-"+short())
	bAdmin := createUser(t, ctx, pool, tnB.ID, "admin@b.test", "admin")
	bAdminTok, _, _ := keys.Create(ctx, tnB.ID, bAdmin, "b-admin")

	srv, _ := newAPI(t, pool)
	defer srv.Close()

	seedFunnel(t, ctx, srv.URL, aOpTok, er, tnA.ID)
	seedFunnel(t, ctx, srv.URL, bAdminTok, er, tnB.ID)

	// Platform overview (A's admin sees ALL tenants with KPIs).
	code, body := do(t, srv.URL, http.MethodGet, "/api/v1/platform/tenants", aAdminTok, nil)
	if code != http.StatusOK {
		t.Fatalf("platform tenants: %d (%s)", code, body)
	}
	var ov struct {
		Items []struct {
			TenantID  uuid.UUID `json:"tenant_id"`
			Name      string    `json:"name"`
			Campaigns int       `json:"campaigns"`
			Totals    struct {
				Recipients, Clicked int
			} `json:"totals"`
		} `json:"items"`
	}
	mustJSON(t, body, &ov)
	byID := map[uuid.UUID]int{}
	for _, it := range ov.Items {
		byID[it.TenantID] = it.Totals.Recipients
	}
	if _, ok := byID[tnA.ID]; !ok {
		t.Fatalf("overview missing tenant A")
	}
	if _, ok := byID[tnB.ID]; !ok {
		t.Fatalf("overview missing tenant B (cross-tenant)")
	}
	for _, it := range ov.Items {
		if it.TenantID == tnA.ID {
			if it.Totals.Recipients != 2 || it.Totals.Clicked != 1 || it.Campaigns != 1 {
				t.Fatalf("tenant A KPIs wrong: %+v", it)
			}
		}
	}

	// Cross-tenant summary (A admin reads tenant B).
	if code, b := do(t, srv.URL, http.MethodGet, "/api/v1/platform/tenants/"+tnB.ID.String()+"/summary", aAdminTok, nil); code != http.StatusOK || !strings.Contains(b, "campaigns") {
		t.Fatalf("cross-tenant summary: %d (%s)", code, b)
	}

	// Operator is forbidden from the platform console.
	if code, _ := do(t, srv.URL, http.MethodGet, "/api/v1/platform/tenants", aOpTok, nil); code != http.StatusForbidden {
		t.Fatalf("operator platform: want 403, got %d", code)
	}

	// Unknown tenant -> 404.
	if code, _ := do(t, srv.URL, http.MethodGet, "/api/v1/platform/tenants/"+uuid.New().String()+"/summary", aAdminTok, nil); code != http.StatusNotFound {
		t.Fatalf("unknown tenant summary: want 404, got %d", code)
	}

	// Cross-tenant PDF.
	code, body = do(t, srv.URL, http.MethodGet, "/api/v1/platform/tenants/"+tnB.ID.String()+"/summary.pdf", aAdminTok, nil)
	if code != http.StatusOK || !strings.HasPrefix(body, "%PDF-") || len(body) < 800 {
		t.Fatalf("cross-tenant pdf: code=%d len=%d", code, len(body))
	}

	// Audited under the acting admin's tenant.
	if n := count(t, ctx, pool, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='platform.overview'`, tnA.ID); n != 1 {
		t.Fatalf("platform.overview audit: want 1, got %d", n)
	}
}
