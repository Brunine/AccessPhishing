package integration

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"phishforge/internal/apikey"
	"phishforge/internal/tenant"
)

// TestTargetManagement exercises M2: groups, contacts, suppression-aware
// import, and that listing/scoping stays within the tenant.
func TestTargetManagement(t *testing.T) {
	pool := setupDB(t)
	ctx := context.Background()

	tenants := tenant.NewRepository()
	tn, err := tenants.Create(ctx, pool, "Targets Co", "targets-"+short())
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	opID := createUser(t, ctx, pool, tn.ID, "op@targets.test", "operator")
	opTok, _, err := apikey.NewService(pool).Create(ctx, tn.ID, opID, "op")
	if err != nil {
		t.Fatalf("op key: %v", err)
	}

	srv, _ := newAPI(t, pool)
	defer srv.Close()

	// group
	code, body := do(t, srv.URL, http.MethodPost, "/api/v1/contact-groups", opTok, map[string]any{"name": "VIPs"})
	if code != http.StatusCreated {
		t.Fatalf("create group: want 201, got %d (%s)", code, body)
	}
	var grp struct {
		ID uuid.UUID `json:"id"`
	}
	mustJSON(t, body, &grp)

	// a group id from another tenant must be rejected on contact create
	other, err := tenants.Create(ctx, pool, "Other Co", "other-"+short())
	if err != nil {
		t.Fatalf("create other tenant: %v", err)
	}
	foreignGroup := createGroupRow(t, ctx, pool, other.ID, "foreign")
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/contacts", opTok, map[string]any{"email": "x@t.test", "group_id": foreignGroup}); code != http.StatusBadRequest {
		t.Fatalf("foreign group: want 400, got %d", code)
	}

	// single contact into our group
	code, body = do(t, srv.URL, http.MethodPost, "/api/v1/contacts", opTok, map[string]any{
		"email": "alice@targets.test", "first_name": "Alice", "group_id": grp.ID,
		"attributes": map[string]any{"dept": "finance"},
	})
	if code != http.StatusCreated {
		t.Fatalf("create contact: want 201, got %d (%s)", code, body)
	}

	// suppress one address, then import a batch that includes it + a duplicate
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/suppressions", opTok, map[string]any{"email": "blocked@targets.test", "reason": "opt-out"}); code != http.StatusCreated {
		t.Fatalf("add suppression: got %d", code)
	}
	code, body = do(t, srv.URL, http.MethodPost, "/api/v1/contacts/import", opTok, map[string]any{
		"group_id": grp.ID,
		"contacts": []map[string]any{
			{"email": "alice@targets.test"},   // duplicate of existing
			{"email": "bob@targets.test"},     // new
			{"email": "carol@targets.test"},   // new
			{"email": "blocked@targets.test"}, // suppressed
		},
	})
	if code != http.StatusOK {
		t.Fatalf("import: want 200, got %d (%s)", code, body)
	}
	var res struct {
		Created    int `json:"created"`
		Duplicates int `json:"duplicates"`
		Suppressed int `json:"suppressed"`
	}
	mustJSON(t, body, &res)
	if res.Created != 2 || res.Duplicates != 1 || res.Suppressed != 1 {
		t.Fatalf("import result: want created=2 dup=1 suppressed=1, got %+v", res)
	}

	// list by group should show 3 (alice, bob, carol); blocked never inserted
	code, body = do(t, srv.URL, http.MethodGet, "/api/v1/contacts?group_id="+grp.ID.String(), opTok, nil)
	if code != http.StatusOK {
		t.Fatalf("list contacts: got %d", code)
	}
	var list struct {
		Items []struct {
			Email string `json:"email"`
		} `json:"items"`
	}
	mustJSON(t, body, &list)
	if len(list.Items) != 3 {
		t.Fatalf("group contacts: want 3, got %d", len(list.Items))
	}

	// removing the suppression then re-importing lets it through
	if code, _ := do(t, srv.URL, http.MethodDelete, "/api/v1/suppressions?email=blocked@targets.test", opTok, nil); code != http.StatusNoContent {
		t.Fatalf("remove suppression: got %d", code)
	}
	code, body = do(t, srv.URL, http.MethodPost, "/api/v1/contacts/import", opTok, map[string]any{
		"contacts": []map[string]any{{"email": "blocked@targets.test"}},
	})
	mustJSON(t, body, &res)
	if code != http.StatusOK || res.Created != 1 {
		t.Fatalf("re-import after unsuppress: want 200/created=1, got %d/%+v", code, res)
	}

	// audit entries recorded for both import actions
	if n := count(t, ctx, pool, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='contact.import'`, tn.ID); n != 2 {
		t.Fatalf("contact.import audit: want 2, got %d", n)
	}
}

func createGroupRow(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID uuid.UUID, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := pool.QueryRow(ctx,
		`INSERT INTO contact_groups (tenant_id, name) VALUES ($1, $2) RETURNING id`,
		tenantID, name).Scan(&id); err != nil {
		t.Fatalf("create group row: %v", err)
	}
	return id
}
