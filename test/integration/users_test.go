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

// TestUserManagement covers list/create/deactivate, RBAC (admin for mutations),
// the last-active-admin guard, deactivation disabling auth, and auditing.
func TestUserManagement(t *testing.T) {
	pool := setupDB(t)
	ctx := context.Background()

	tenants := tenant.NewRepository()
	tn, err := tenants.Create(ctx, pool, "Users Co", "users-"+short())
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	adminID := createUser(t, ctx, pool, tn.ID, "admin@u.test", "admin")
	opID := createUser(t, ctx, pool, tn.ID, "op@u.test", "operator")
	keys := apikey.NewService(pool)
	adminTok, _, _ := keys.Create(ctx, tn.ID, adminID, "admin")
	opTok, _, _ := keys.Create(ctx, tn.ID, opID, "op")

	srv, _ := newAPI(t, pool)
	defer srv.Close()

	// list (operator) — two users, no secret material.
	code, body := do(t, srv.URL, http.MethodGet, "/api/v1/users", opTok, nil)
	if code != http.StatusOK {
		t.Fatalf("list: %d (%s)", code, body)
	}
	if strings.Contains(strings.ToLower(body), "password") || strings.Contains(strings.ToLower(body), "hash") {
		t.Fatalf("list leaked secret material: %s", body)
	}
	var list struct {
		Items []struct {
			ID uuid.UUID `json:"id"`
		} `json:"items"`
	}
	mustJSON(t, body, &list)
	if len(list.Items) != 2 {
		t.Fatalf("list: want 2 users, got %d", len(list.Items))
	}

	// create requires admin.
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/users", opTok, map[string]any{"email": "x@u.test", "role": "operator"}); code != http.StatusForbidden {
		t.Fatalf("operator create: want 403, got %d", code)
	}

	// create (admin) a new operator user -> 201 active.
	code, body = do(t, srv.URL, http.MethodPost, "/api/v1/users", adminTok, map[string]any{"email": "new@u.test", "role": "operator"})
	if code != http.StatusCreated {
		t.Fatalf("create: %d (%s)", code, body)
	}
	var newUser struct {
		ID     uuid.UUID `json:"id"`
		Active bool      `json:"active"`
		Role   string    `json:"role"`
	}
	mustJSON(t, body, &newUser)
	if !newUser.Active || newUser.Role != "operator" {
		t.Fatalf("new user: %+v", newUser)
	}
	// a key for the new user authenticates while active.
	newTok, _, _ := keys.Create(ctx, tn.ID, newUser.ID, "nk")
	if code, _ := do(t, srv.URL, http.MethodGet, "/api/v1/users", newTok, nil); code != http.StatusOK {
		t.Fatalf("new user key auth: want 200, got %d", code)
	}

	// duplicate email -> 409; invalid role -> 400.
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/users", adminTok, map[string]any{"email": "new@u.test", "role": "viewer"}); code != http.StatusConflict {
		t.Fatalf("dup email: want 409, got %d", code)
	}
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/users", adminTok, map[string]any{"email": "z@u.test", "role": "superuser"}); code != http.StatusBadRequest {
		t.Fatalf("bad role: want 400, got %d", code)
	}

	// deactivate requires admin.
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/users/"+newUser.ID.String()+"/deactivate", opTok, nil); code != http.StatusForbidden {
		t.Fatalf("operator deactivate: want 403, got %d", code)
	}

	// deactivate the new user (admin) -> 200; its key then fails auth.
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/users/"+newUser.ID.String()+"/deactivate", adminTok, nil); code != http.StatusOK {
		t.Fatalf("deactivate: want 200, got %d", code)
	}
	if code, _ := do(t, srv.URL, http.MethodGet, "/api/v1/users", newTok, nil); code != http.StatusUnauthorized {
		t.Fatalf("deactivated user key: want 401, got %d", code)
	}
	// already inactive -> 409.
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/users/"+newUser.ID.String()+"/deactivate", adminTok, nil); code != http.StatusConflict {
		t.Fatalf("re-deactivate: want 409, got %d", code)
	}

	// last-admin guard: adminID is the only active admin -> 409.
	if code, b := do(t, srv.URL, http.MethodPost, "/api/v1/users/"+adminID.String()+"/deactivate", adminTok, nil); code != http.StatusConflict {
		t.Fatalf("last admin: want 409, got %d (%s)", code, b)
	}
	// adminTok still works after the refused deactivate.
	if code, _ := do(t, srv.URL, http.MethodGet, "/api/v1/users", adminTok, nil); code != http.StatusOK {
		t.Fatalf("admin after refused deactivate: want 200, got %d", code)
	}

	// create a second admin, then deactivating it is allowed (adminID remains).
	_, body = do(t, srv.URL, http.MethodPost, "/api/v1/users", adminTok, map[string]any{"email": "admin2@u.test", "role": "admin"})
	var admin2 struct {
		ID uuid.UUID `json:"id"`
	}
	mustJSON(t, body, &admin2)
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/users/"+admin2.ID.String()+"/deactivate", adminTok, nil); code != http.StatusOK {
		t.Fatalf("deactivate admin2 (another admin remains): want 200, got %d", code)
	}

	// unknown user -> 404.
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/users/"+uuid.New().String()+"/deactivate", adminTok, nil); code != http.StatusNotFound {
		t.Fatalf("deactivate unknown: want 404, got %d", code)
	}

	// audit: 2 creates (new + admin2), 2 deactivates (new + admin2).
	if n := count(t, ctx, pool, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='user.create'`, tn.ID); n != 2 {
		t.Fatalf("user.create audit: want 2, got %d", n)
	}
	if n := count(t, ctx, pool, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='user.deactivate'`, tn.ID); n != 2 {
		t.Fatalf("user.deactivate audit: want 2, got %d", n)
	}
}
