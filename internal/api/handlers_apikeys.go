package api

import (
	"errors"
	"net/http"
	"strings"

	"phishforge/internal/apikey"
	"phishforge/internal/auth"
	"phishforge/internal/httpx"
)

// listAPIKeys returns the tenant's API keys (never the secret).
func (s *Server) listAPIKeys(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	items, err := s.keys.List(r.Context(), p.TenantID)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "list api keys")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": items})
}

// createAPIKey mints a key for the calling operator and returns the plaintext
// token exactly once. The create is audited by the service.
func (s *Server) createAPIKey(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &b) {
		return
	}
	if strings.TrimSpace(b.Name) == "" {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "name is required")
		return
	}
	p, _ := auth.FromContext(r.Context())

	token, key, err := s.keys.Create(r.Context(), p.TenantID, p.UserID, b.Name)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "create api key")
		return
	}
	// The token is returned once here and never stored in plaintext.
	httpx.JSON(w, http.StatusCreated, map[string]any{
		"id":         key.ID,
		"name":       key.Name,
		"created_at": key.CreatedAt,
		"token":      token,
	})
}

// revokeAPIKey revokes a tenant key. Revoking the key the request authenticated
// with is refused when it is the last active operator-capable key (self-lockout
// guard).
func (s *Server) revokeAPIKey(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	isCurrent := id == p.KeyID

	err := s.keys.RevokeOperatorKey(r.Context(), p.TenantID, p.UserID, id, isCurrent)
	if errors.Is(err, apikey.ErrLastOperatorKey) {
		httpx.Problem(w, r, http.StatusConflict, "conflict",
			"cannot revoke the key you are using — it is the tenant's last active operator key")
		return
	}
	if errors.Is(err, apikey.ErrInvalidKey) {
		httpx.Problem(w, r, http.StatusNotFound, "not found", "api key not found or already revoked")
		return
	}
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "revoke api key")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"id": id, "status": "revoked"})
}
