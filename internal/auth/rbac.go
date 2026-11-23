// Package auth defines roles, the request principal, and RBAC middleware.
//
// M1 scope: principal resolution is pluggable via an Identifier so the HTTP
// stack can enforce roles today; real token/session verification arrives with
// the auth module. Enforcement (RequireRole) and the principal contract are
// stable and do not change when the Identifier is replaced.
package auth

import (
	"context"
	"net/http"

	"github.com/google/uuid"

	"phishforge/internal/httpx"
)

// Role is a tenant-scoped RBAC role.
type Role string

const (
	RoleAdmin    Role = "admin"
	RoleOperator Role = "operator"
	RoleViewer   Role = "viewer"
)

// Valid reports whether r is a recognized role.
func (r Role) Valid() bool {
	switch r {
	case RoleAdmin, RoleOperator, RoleViewer:
		return true
	default:
		return false
	}
}

// rank orders roles for hierarchical ("at least") checks.
func (r Role) rank() int {
	switch r {
	case RoleAdmin:
		return 3
	case RoleOperator:
		return 2
	case RoleViewer:
		return 1
	default:
		return 0
	}
}

// AtLeast reports whether r meets or exceeds the required minimum role.
func (r Role) AtLeast(min Role) bool { return r.rank() >= min.rank() }

// Principal is the authenticated actor bound to a request.
type Principal struct {
	UserID   uuid.UUID
	TenantID uuid.UUID
	Email    string
	Role     Role
	KeyID    uuid.UUID // the API key this request authenticated with (if any)
}

type ctxKey int

const principalKey ctxKey = iota

// WithPrincipal returns a context carrying p.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey, p)
}

// FromContext extracts the principal bound to ctx, if any.
func FromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey).(Principal)
	return p, ok
}

// Identifier resolves the authenticated principal for a request. Returning an
// error rejects the request as unauthorized.
type Identifier func(r *http.Request) (Principal, error)

// Authenticate resolves the principal via id and stores it in the request
// context. Requests that fail resolution or carry an invalid role are rejected.
func Authenticate(id Identifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, err := id(r)
			if err != nil {
				httpx.Problem(w, r, http.StatusUnauthorized, "unauthorized", err.Error())
				return
			}
			if !p.Role.Valid() || p.TenantID == uuid.Nil || p.UserID == uuid.Nil {
				httpx.Problem(w, r, http.StatusUnauthorized, "unauthorized", "invalid principal")
				return
			}
			next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
		})
	}
}

// RequireRole enforces that the request principal satisfies a minimum role.
// It must run after Authenticate.
func RequireRole(min Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := FromContext(r.Context())
			if !ok {
				httpx.Problem(w, r, http.StatusUnauthorized, "unauthorized", "no principal in context")
				return
			}
			if !p.Role.AtLeast(min) {
				httpx.Problem(w, r, http.StatusForbidden, "forbidden", "insufficient role")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
