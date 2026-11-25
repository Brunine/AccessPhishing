package api

import (
	"errors"
	"net/http"

	"phishforge/internal/audit"
	"phishforge/internal/auth"
	"phishforge/internal/client"
	"phishforge/internal/httpx"
)

// clientCreateBody is the POST /clients request body. name is required;
// contact_email and notes are optional.
type clientCreateBody struct {
	Name         string  `json:"name"`
	ContactEmail *string `json:"contact_email"`
	Notes        *string `json:"notes"`
}

// clientPatchBody is the PATCH /clients/{id} request body. Every field is
// optional: a field that is absent is left unchanged. Sending contact_email as
// "" (or whitespace) clears it to NULL.
type clientPatchBody struct {
	Name         *string `json:"name"`
	ContactEmail *string `json:"contact_email"`
	Notes        *string `json:"notes"`
}

func (s *Server) createClient(w http.ResponseWriter, r *http.Request) {
	var b clientCreateBody
	if !decode(w, r, &b) {
		return
	}
	in := client.Input{Name: b.Name, ContactEmail: b.ContactEmail, Notes: b.Notes}.Normalize()
	if err := in.Validate(); err != nil {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", err.Error())
		return
	}
	p, _ := auth.FromContext(r.Context())

	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "begin transaction")
		return
	}
	defer tx.Rollback(r.Context())

	c, err := s.clients.Create(r.Context(), tx, p.TenantID, in)
	if err != nil {
		if isUniqueViolation(err) {
			httpx.Problem(w, r, http.StatusConflict, "conflict", "client name already exists for this tenant")
			return
		}
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "create client")
		return
	}
	if err := audit.Write(r.Context(), tx, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: "client.create", TargetType: "client", TargetID: c.ID.String(),
		Metadata: map[string]any{"name": c.Name},
	}); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "commit")
		return
	}
	httpx.JSON(w, http.StatusCreated, c)
}

func (s *Server) listClients(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	limit, offset := parsePage(r)
	items, err := s.clients.List(r.Context(), s.pool, p.TenantID, limit, offset)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "list clients")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": items, "limit": limit, "offset": offset})
}

func (s *Server) getClient(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	c, err := s.clients.GetByID(r.Context(), s.pool, p.TenantID, id)
	if errors.Is(err, client.ErrNotFound) {
		httpx.Problem(w, r, http.StatusNotFound, "not found", "client not found")
		return
	}
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "get client")
		return
	}
	httpx.JSON(w, http.StatusOK, c)
}

func (s *Server) patchClient(w http.ResponseWriter, r *http.Request) {
	var b clientPatchBody
	if !decode(w, r, &b) {
		return
	}
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

	cur, err := s.clients.GetByID(r.Context(), tx, p.TenantID, id)
	if errors.Is(err, client.ErrNotFound) {
		httpx.Problem(w, r, http.StatusNotFound, "not found", "client not found")
		return
	}
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "load client")
		return
	}

	// Merge provided fields over the current row (partial update), then
	// normalize + validate the result.
	in := client.Input{Name: cur.Name, ContactEmail: cur.ContactEmail, Notes: cur.Notes}
	if b.Name != nil {
		in.Name = *b.Name
	}
	if b.ContactEmail != nil {
		in.ContactEmail = b.ContactEmail
	}
	if b.Notes != nil {
		in.Notes = b.Notes
	}
	in = in.Normalize()
	if err := in.Validate(); err != nil {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", err.Error())
		return
	}

	c, err := s.clients.Update(r.Context(), tx, p.TenantID, id, in)
	if err != nil {
		if isUniqueViolation(err) {
			httpx.Problem(w, r, http.StatusConflict, "conflict", "client name already exists for this tenant")
			return
		}
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "update client")
		return
	}
	if err := audit.Write(r.Context(), tx, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: "client.update", TargetType: "client", TargetID: id.String(),
	}); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "commit")
		return
	}
	httpx.JSON(w, http.StatusOK, c)
}

func (s *Server) deleteClient(w http.ResponseWriter, r *http.Request) {
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

	cur, err := s.clients.GetByID(r.Context(), tx, p.TenantID, id)
	if errors.Is(err, client.ErrNotFound) {
		httpx.Problem(w, r, http.StatusNotFound, "not found", "client not found")
		return
	}
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "load client")
		return
	}

	n, err := s.clients.CountEngagements(r.Context(), tx, p.TenantID, id)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "count engagements")
		return
	}
	if n > 0 {
		httpx.Problem(w, r, http.StatusConflict, "conflict",
			"client is referenced by one or more engagements; unbind or delete them first")
		return
	}

	if err := s.clients.Delete(r.Context(), tx, p.TenantID, id); err != nil {
		if errors.Is(err, client.ErrNotFound) {
			httpx.Problem(w, r, http.StatusNotFound, "not found", "client not found")
			return
		}
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "delete client")
		return
	}
	if err := audit.Write(r.Context(), tx, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: "client.delete", TargetType: "client", TargetID: id.String(),
		Metadata: map[string]any{"name": cur.Name},
	}); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "commit")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
