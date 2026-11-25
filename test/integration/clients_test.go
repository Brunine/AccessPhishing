package integration

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"phishforge/internal/apikey"
	"phishforge/internal/tenant"
)

// TestClientCRUD covers the clients happy paths, duplicate-name conflict,
// partial patch (including clearing contact_email), and validation errors.
func TestClientCRUD(t *testing.T) {
	pool := setupDB(t)
	ctx := context.Background()

	tenants := tenant.NewRepository()
	tn, err := tenants.Create(ctx, pool, "Client Co", "cli-"+short())
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	opID := createUser(t, ctx, pool, tn.ID, "op@cli.test", "operator")
	keys := apikey.NewService(pool)
	opTok, _, _ := keys.Create(ctx, tn.ID, opID, "op")

	srv, _ := newAPI(t, pool)
	defer srv.Close()

	// --- create ---
	code, body := do(t, srv.URL, http.MethodPost, "/api/v1/clients", opTok, map[string]any{
		"name": "Acme Inc", "contact_email": "ciso@acme.com", "notes": "priority",
	})
	if code != http.StatusCreated {
		t.Fatalf("create client: want 201, got %d (%s)", code, body)
	}
	var cl struct {
		ID           uuid.UUID `json:"id"`
		Name         string    `json:"name"`
		ContactEmail *string   `json:"contact_email"`
		Notes        *string   `json:"notes"`
	}
	mustJSON(t, body, &cl)
	if cl.Name != "Acme Inc" || cl.ContactEmail == nil || *cl.ContactEmail != "ciso@acme.com" {
		t.Fatalf("created client: %+v", cl)
	}

	// --- get ---
	code, body = do(t, srv.URL, http.MethodGet, "/api/v1/clients/"+cl.ID.String(), opTok, nil)
	if code != http.StatusOK {
		t.Fatalf("get client: want 200, got %d (%s)", code, body)
	}

	// --- list (contains the one client) ---
	_, lb := do(t, srv.URL, http.MethodGet, "/api/v1/clients", opTok, nil)
	var list struct {
		Items []struct {
			ID uuid.UUID `json:"id"`
		} `json:"items"`
	}
	mustJSON(t, lb, &list)
	if len(list.Items) != 1 || list.Items[0].ID != cl.ID {
		t.Fatalf("list: want 1 item (%s), got %+v", cl.ID, list.Items)
	}

	// --- duplicate name -> 409 ---
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/clients", opTok, map[string]any{"name": "Acme Inc"}); code != http.StatusConflict {
		t.Fatalf("duplicate name: want 409, got %d", code)
	}

	// --- partial patch: change notes only, leave name/email intact ---
	code, body = do(t, srv.URL, http.MethodPatch, "/api/v1/clients/"+cl.ID.String(), opTok, map[string]any{"notes": "vip"})
	if code != http.StatusOK {
		t.Fatalf("patch notes: want 200, got %d (%s)", code, body)
	}
	mustJSON(t, body, &cl)
	if cl.Name != "Acme Inc" || cl.ContactEmail == nil || *cl.ContactEmail != "ciso@acme.com" || cl.Notes == nil || *cl.Notes != "vip" {
		t.Fatalf("after partial patch: %+v", cl)
	}

	// --- patch: clear contact_email with "" -> null ---
	// A cleared (nil) contact_email is omitted from the JSON (omitempty), so
	// decode into a FRESH struct — reusing cl would retain the stale pointer.
	code, body = do(t, srv.URL, http.MethodPatch, "/api/v1/clients/"+cl.ID.String(), opTok, map[string]any{"contact_email": ""})
	if code != http.StatusOK {
		t.Fatalf("clear email: want 200, got %d (%s)", code, body)
	}
	var cleared struct {
		Name         string  `json:"name"`
		ContactEmail *string `json:"contact_email"`
		Notes        *string `json:"notes"`
	}
	mustJSON(t, body, &cleared)
	if cleared.ContactEmail != nil {
		t.Fatalf("contact_email should be cleared, got %v", *cleared.ContactEmail)
	}
	if cleared.Name != "Acme Inc" || cleared.Notes == nil || *cleared.Notes != "vip" {
		t.Fatalf("clear email should not disturb other fields: %+v", cleared)
	}

	// --- validation errors (400) ---
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/clients", opTok, map[string]any{"name": ""}); code != http.StatusBadRequest {
		t.Fatalf("empty name: want 400, got %d", code)
	}
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/clients", opTok, map[string]any{"name": strings.Repeat("a", 201)}); code != http.StatusBadRequest {
		t.Fatalf("over-long name: want 400, got %d", code)
	}
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/clients", opTok, map[string]any{"name": "Bad Email Co", "contact_email": "not-an-email"}); code != http.StatusBadRequest {
		t.Fatalf("bad email: want 400, got %d", code)
	}

	// --- delete (no references) -> 204, then 404 ---
	if code, _ := do(t, srv.URL, http.MethodDelete, "/api/v1/clients/"+cl.ID.String(), opTok, nil); code != http.StatusNoContent {
		t.Fatalf("delete client: want 204, got %d", code)
	}
	if code, _ := do(t, srv.URL, http.MethodGet, "/api/v1/clients/"+cl.ID.String(), opTok, nil); code != http.StatusNotFound {
		t.Fatalf("get deleted client: want 404, got %d", code)
	}

	// --- audit counts: 1 create (only the first succeeded), 2 updates, 1 delete ---
	if n := count(t, ctx, pool, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='client.create'`, tn.ID); n != 1 {
		t.Fatalf("client.create audit: want 1, got %d", n)
	}
	if n := count(t, ctx, pool, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='client.update'`, tn.ID); n != 2 {
		t.Fatalf("client.update audit: want 2, got %d", n)
	}
	if n := count(t, ctx, pool, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='client.delete'`, tn.ID); n != 1 {
		t.Fatalf("client.delete audit: want 1, got %d", n)
	}
}

// TestClientEngagementLink covers the optional engagement.client_id binding:
// an engagement can bind a same-tenant client, the client cannot be deleted
// while referenced (409), and unbinding frees it for deletion.
func TestClientEngagementLink(t *testing.T) {
	pool := setupDB(t)
	ctx := context.Background()

	tenants := tenant.NewRepository()
	tn, _ := tenants.Create(ctx, pool, "Link Co", "lnk-"+short())
	opID := createUser(t, ctx, pool, tn.ID, "op@lnk.test", "operator")
	keys := apikey.NewService(pool)
	opTok, _, _ := keys.Create(ctx, tn.ID, opID, "op")

	srv, _ := newAPI(t, pool)
	defer srv.Close()

	// client
	_, cb := do(t, srv.URL, http.MethodPost, "/api/v1/clients", opTok, map[string]any{"name": "Globex"})
	var cl struct {
		ID uuid.UUID `json:"id"`
	}
	mustJSON(t, cb, &cl)

	// engagement bound to the client via client_id
	code, eb := do(t, srv.URL, http.MethodPost, "/api/v1/engagements", opTok, map[string]any{
		"name": "Globex Q1", "client_name": "Globex", "client_id": cl.ID,
	})
	if code != http.StatusCreated {
		t.Fatalf("create bound engagement: want 201, got %d (%s)", code, eb)
	}
	var eng struct {
		ID       uuid.UUID  `json:"id"`
		ClientID *uuid.UUID `json:"client_id"`
	}
	mustJSON(t, eb, &eng)
	if eng.ClientID == nil || *eng.ClientID != cl.ID {
		t.Fatalf("engagement client_id: want %s, got %v", cl.ID, eng.ClientID)
	}

	// binding a non-existent / cross-tenant client_id -> 400
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/engagements", opTok, map[string]any{
		"name": "Bad Bind", "client_name": "X", "client_id": uuid.New(),
	}); code != http.StatusBadRequest {
		t.Fatalf("bind unknown client_id: want 400, got %d", code)
	}

	// delete client while referenced -> 409
	if code, _ := do(t, srv.URL, http.MethodDelete, "/api/v1/clients/"+cl.ID.String(), opTok, nil); code != http.StatusConflict {
		t.Fatalf("delete referenced client: want 409, got %d", code)
	}

	// unbind the engagement (PATCH without client_id clears it), then delete succeeds
	if code, _ := do(t, srv.URL, http.MethodPatch, "/api/v1/engagements/"+eng.ID.String(), opTok, map[string]any{
		"name": "Globex Q1", "client_name": "Globex",
	}); code != http.StatusOK {
		t.Fatalf("unbind engagement: want 200, got %d", code)
	}
	if code, _ := do(t, srv.URL, http.MethodDelete, "/api/v1/clients/"+cl.ID.String(), opTok, nil); code != http.StatusNoContent {
		t.Fatalf("delete unreferenced client: want 204, got %d", code)
	}
}

// TestClientTenantIsolation covers cross-tenant scoping for every new client
// endpoint: a foreign client id is 404 on get/patch/delete, and never appears
// in another tenant's list.
func TestClientTenantIsolation(t *testing.T) {
	pool := setupDB(t)
	ctx := context.Background()

	tenants := tenant.NewRepository()
	keys := apikey.NewService(pool)

	tnA, _ := tenants.Create(ctx, pool, "A Co", "a-"+short())
	aOp := createUser(t, ctx, pool, tnA.ID, "op@a.test", "operator")
	aTok, _, _ := keys.Create(ctx, tnA.ID, aOp, "a-op")

	tnB, _ := tenants.Create(ctx, pool, "B Co", "b-"+short())
	bOp := createUser(t, ctx, pool, tnB.ID, "op@b.test", "operator")
	bTok, _, _ := keys.Create(ctx, tnB.ID, bOp, "b-op")

	srv, _ := newAPI(t, pool)
	defer srv.Close()

	// B creates a client.
	_, bb := do(t, srv.URL, http.MethodPost, "/api/v1/clients", bTok, map[string]any{"name": "B Client"})
	var bCl struct {
		ID uuid.UUID `json:"id"`
	}
	mustJSON(t, bb, &bCl)

	// A cannot GET B's client -> 404 (tenant-scoped, not 403).
	if code, _ := do(t, srv.URL, http.MethodGet, "/api/v1/clients/"+bCl.ID.String(), aTok, nil); code != http.StatusNotFound {
		t.Fatalf("A get B client: want 404, got %d", code)
	}
	// A cannot PATCH B's client -> 404.
	if code, _ := do(t, srv.URL, http.MethodPatch, "/api/v1/clients/"+bCl.ID.String(), aTok, map[string]any{"notes": "x"}); code != http.StatusNotFound {
		t.Fatalf("A patch B client: want 404, got %d", code)
	}
	// A cannot DELETE B's client -> 404.
	if code, _ := do(t, srv.URL, http.MethodDelete, "/api/v1/clients/"+bCl.ID.String(), aTok, nil); code != http.StatusNotFound {
		t.Fatalf("A delete B client: want 404, got %d", code)
	}
	// A cannot bind B's client to an A engagement -> 400 (not found in A's tenant).
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/engagements", aTok, map[string]any{
		"name": "A Eng", "client_name": "A", "client_id": bCl.ID,
	}); code != http.StatusBadRequest {
		t.Fatalf("A bind B client: want 400, got %d", code)
	}
	// A's list is empty (does not include B's).
	code, lb := do(t, srv.URL, http.MethodGet, "/api/v1/clients", aTok, nil)
	if code != http.StatusOK {
		t.Fatalf("A list: %d", code)
	}
	var list struct {
		Items []struct {
			ID uuid.UUID `json:"id"`
		} `json:"items"`
	}
	mustJSON(t, lb, &list)
	if len(list.Items) != 0 {
		t.Fatalf("A list should be empty, got %d", len(list.Items))
	}
}
