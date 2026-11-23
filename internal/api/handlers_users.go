package api

import (
	"errors"
	"net/http"
	"strings"

	"phishforge/internal/audit"
	"phishforge/internal/auth"
	"phishforge/internal/httpx"
	"phishforge/internal/user"
)

// listUsers returns the tenant's operator users (operator).
func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	items, err := s.users.List(r.Context(), s.pool, p.TenantID)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "list users")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": items})
}

// createUser adds an active, key-based user to the tenant (admin). It mirrors
// the seed tool: email + role, no password; access is granted later by minting
// an API key for the user.
func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if !decode(w, r, &b) {
		return
	}
	email := strings.TrimSpace(b.Email)
	if email == "" || !strings.Contains(email, "@") {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "a valid email is required")
		return
	}
	if !user.ValidRole(b.Role) {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "role must be one of admin, operator, viewer")
		return
	}
	p, _ := auth.FromContext(r.Context())

	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "begin transaction")
		return
	}
	defer tx.Rollback(r.Context())

	u, err := s.users.Create(r.Context(), tx, p.TenantID, email, b.Role)
	if err != nil {
		if isUniqueViolation(err) {
			httpx.Problem(w, r, http.StatusConflict, "conflict", "a user with this email already exists")
			return
		}
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "create user")
		return
	}
	if err := audit.Write(r.Context(), tx, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: "user.create", TargetType: "user", TargetID: u.ID.String(),
		Metadata: map[string]any{"email": u.Email, "role": u.Role},
	}); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "commit")
		return
	}
	httpx.JSON(w, http.StatusCreated, u)
}

// deactivateUser deactivates a tenant user (admin). It refuses to deactivate
// the last active admin (409), the self-lockout analog.
func (s *Server) deactivateUser(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}

	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "begin transaction")
		return
	}
	defer tx.Rollback(r.Context())

	target, err := s.users.GetByID(r.Context(), tx, p.TenantID, id)
	if errors.Is(err, user.ErrNotFound) {
		httpx.Problem(w, r, http.StatusNotFound, "not found", "user not found")
		return
	}
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "load user")
		return
	}
	if !target.Active {
		httpx.Problem(w, r, http.StatusConflict, "conflict", "user is already inactive")
		return
	}
	if target.Role == "admin" {
		others, err := s.users.CountActiveAdmins(r.Context(), tx, p.TenantID, id)
		if err != nil {
			httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "count admins")
			return
		}
		if others == 0 {
			httpx.Problem(w, r, http.StatusConflict, "conflict", "cannot deactivate the tenant's last active admin")
			return
		}
	}

	u, err := s.users.Deactivate(r.Context(), tx, p.TenantID, id)
	if errors.Is(err, user.ErrNotFound) {
		httpx.Problem(w, r, http.StatusConflict, "conflict", "user is already inactive")
		return
	}
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "deactivate user")
		return
	}
	if err := audit.Write(r.Context(), tx, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: "user.deactivate", TargetType: "user", TargetID: id.String(),
		Metadata: map[string]any{"email": u.Email, "role": u.Role},
	}); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "commit")
		return
	}
	httpx.JSON(w, http.StatusOK, u)
}
