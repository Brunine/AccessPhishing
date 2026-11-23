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

// TestAPIKeyManagement covers list/create/revoke, the self-lockout guard, and
// auditing.
func TestAPIKeyManagement(t *testing.T) {
	pool := setupDB(t)
	ctx := context.Background()

	tenants := tenant.NewRepository()
	tn, err := tenants.Create(ctx, pool, "Keys Co", "keys-"+short())
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	opID := createUser(t, ctx, pool, tn.ID, "op@keys.test", "operator")
	keys := apikey.NewService(pool)
	k1, _, err := keys.Create(ctx, tn.ID, opID, "bootstrap") // the key we auth with
	if err != nil {
		t.Fatalf("bootstrap key: %v", err)
	}

	srv, _ := newAPI(t, pool)
	defer srv.Close()

	// list: one key, and no secret material leaks.
	code, body := do(t, srv.URL, http.MethodGet, "/api/v1/api-keys", k1, nil)
	if code != http.StatusOK {
		t.Fatalf("list: %d (%s)", code, body)
	}
	if strings.Contains(strings.ToLower(body), "hash") || strings.Contains(body, "pf_") {
		t.Fatalf("list leaked secret material: %s", body)
	}
	var list struct {
		Items []struct {
			ID   uuid.UUID `json:"id"`
			Name string    `json:"name"`
		} `json:"items"`
	}
	mustJSON(t, body, &list)
	if len(list.Items) != 1 {
		t.Fatalf("list: want 1 key, got %d", len(list.Items))
	}

	// create a second key -> plaintext token returned once.
	code, body = do(t, srv.URL, http.MethodPost, "/api/v1/api-keys", k1, map[string]any{"name": "ci"})
	if code != http.StatusCreated {
		t.Fatalf("create: %d (%s)", code, body)
	}
	var created struct {
		ID    uuid.UUID `json:"id"`
		Token string    `json:"token"`
	}
	mustJSON(t, body, &created)
	if !strings.HasPrefix(created.Token, "pf_") {
		t.Fatalf("create: token not returned: %s", body)
	}
	// the new key actually works.
	if code, _ := do(t, srv.URL, http.MethodGet, "/api/v1/api-keys", created.Token, nil); code != http.StatusOK {
		t.Fatalf("new key auth: want 200, got %d", code)
	}

	// revoke the second key (not the current one) -> 200.
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/api-keys/"+created.ID.String()+"/revoke", k1, nil); code != http.StatusOK {
		t.Fatalf("revoke k2: want 200, got %d", code)
	}
	// revoked key no longer authenticates.
	if code, _ := do(t, srv.URL, http.MethodGet, "/api/v1/api-keys", created.Token, nil); code != http.StatusUnauthorized {
		t.Fatalf("revoked key auth: want 401, got %d", code)
	}

	// self-lockout: k1 is now the last active operator key; revoking it (current) is refused.
	var k1ID uuid.UUID
	for _, it := range list.Items {
		k1ID = it.ID // bootstrap is the only one in the earlier list
	}
	if code, b := do(t, srv.URL, http.MethodPost, "/api/v1/api-keys/"+k1ID.String()+"/revoke", k1, nil); code != http.StatusConflict {
		t.Fatalf("self-lockout: want 409, got %d (%s)", code, b)
	}
	// k1 still works after the refused revoke.
	if code, _ := do(t, srv.URL, http.MethodGet, "/api/v1/api-keys", k1, nil); code != http.StatusOK {
		t.Fatalf("k1 after refused revoke: want 200, got %d", code)
	}

	// create a third key; now revoking the current key is allowed (another active operator key remains).
	_, body = do(t, srv.URL, http.MethodPost, "/api/v1/api-keys", k1, map[string]any{"name": "backup"})
	var k3 struct {
		Token string `json:"token"`
	}
	mustJSON(t, body, &k3)
	if code, b := do(t, srv.URL, http.MethodPost, "/api/v1/api-keys/"+k1ID.String()+"/revoke", k1, nil); code != http.StatusOK {
		t.Fatalf("revoke current (not last): want 200, got %d (%s)", code, b)
	}
	// k1 now revoked.
	if code, _ := do(t, srv.URL, http.MethodGet, "/api/v1/api-keys", k1, nil); code != http.StatusUnauthorized {
		t.Fatalf("k1 after revoke: want 401, got %d", code)
	}
	// k3 still works.
	if code, _ := do(t, srv.URL, http.MethodGet, "/api/v1/api-keys", k3.Token, nil); code != http.StatusOK {
		t.Fatalf("k3 auth: want 200, got %d", code)
	}

	// revoking an unknown key -> 404.
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/api-keys/"+uuid.New().String()+"/revoke", k3.Token, nil); code != http.StatusNotFound {
		t.Fatalf("revoke unknown: want 404, got %d", code)
	}

	// audit: 3 creates (bootstrap + ci + backup), 2 revokes (k2 + k1).
	if n := count(t, ctx, pool, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='apikey.create'`, tn.ID); n != 3 {
		t.Fatalf("apikey.create audit: want 3, got %d", n)
	}
	if n := count(t, ctx, pool, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='apikey.revoke'`, tn.ID); n != 2 {
		t.Fatalf("apikey.revoke audit: want 2, got %d", n)
	}
}
