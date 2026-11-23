package api

import (
	"errors"
	"net/http"

	"github.com/google/uuid"

	"phishforge/internal/audit"
	"phishforge/internal/auth"
	"phishforge/internal/contact"
	"phishforge/internal/group"
	"phishforge/internal/httpx"
	"phishforge/internal/suppression"
)

// --- contacts -------------------------------------------------------------

type contactBody struct {
	Email      string         `json:"email"`
	FirstName  string         `json:"first_name"`
	LastName   string         `json:"last_name"`
	Phone      string         `json:"phone"`
	PhoneE164  string         `json:"phone_e164"`
	GroupID    *uuid.UUID     `json:"group_id"`
	Attributes map[string]any `json:"attributes"`
}

func (b contactBody) toInput() contact.Input {
	return contact.Input{
		Email:      b.Email,
		FirstName:  b.FirstName,
		LastName:   b.LastName,
		Phone:      b.Phone,
		PhoneE164:  b.PhoneE164,
		GroupID:    b.GroupID,
		Attributes: b.Attributes,
	}
}

// groupBelongsToTenant verifies a referenced group is owned by the tenant.
func (s *Server) groupOK(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID, groupID *uuid.UUID) bool {
	if groupID == nil {
		return true
	}
	if _, err := s.groups.GetByID(r.Context(), s.pool, tenantID, *groupID); err != nil {
		if errors.Is(err, group.ErrNotFound) {
			httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "group_id not found in tenant")
			return false
		}
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "verify group")
		return false
	}
	return true
}

func (s *Server) createContact(w http.ResponseWriter, r *http.Request) {
	var b contactBody
	if !decode(w, r, &b) {
		return
	}
	if b.Email == "" {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "email is required")
		return
	}
	if b.PhoneE164 != "" && !contact.ValidE164(b.PhoneE164) {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "phone_e164 must be E.164, e.g. +15551234567")
		return
	}
	p, _ := auth.FromContext(r.Context())
	if !s.groupOK(w, r, p.TenantID, b.GroupID) {
		return
	}

	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "begin transaction")
		return
	}
	defer tx.Rollback(r.Context())

	c, err := s.contacts.Create(r.Context(), tx, p.TenantID, b.toInput())
	if err != nil {
		if isUniqueViolation(err) {
			httpx.Problem(w, r, http.StatusConflict, "conflict", "email already exists in tenant")
			return
		}
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "create contact")
		return
	}
	if err := audit.Write(r.Context(), tx, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: "contact.create", TargetType: "contact", TargetID: c.ID.String(),
		Metadata: map[string]any{"email": c.Email},
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

func (s *Server) listContacts(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	limit, offset := parsePage(r)

	var groupID *uuid.UUID
	if v := r.URL.Query().Get("group_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "invalid group_id")
			return
		}
		groupID = &id
	}

	items, err := s.contacts.List(r.Context(), s.pool, p.TenantID, groupID, limit, offset)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "list contacts")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": items, "limit": limit, "offset": offset})
}

func (s *Server) getContact(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	c, err := s.contacts.GetByID(r.Context(), s.pool, p.TenantID, id)
	if errors.Is(err, contact.ErrNotFound) {
		httpx.Problem(w, r, http.StatusNotFound, "not found", "contact not found")
		return
	}
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "get contact")
		return
	}
	httpx.JSON(w, http.StatusOK, c)
}

func (s *Server) updateContact(w http.ResponseWriter, r *http.Request) {
	var b contactBody
	if !decode(w, r, &b) {
		return
	}
	if b.Email == "" {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "email is required")
		return
	}
	if b.PhoneE164 != "" && !contact.ValidE164(b.PhoneE164) {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "phone_e164 must be E.164, e.g. +15551234567")
		return
	}
	p, _ := auth.FromContext(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	if !s.groupOK(w, r, p.TenantID, b.GroupID) {
		return
	}

	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "begin transaction")
		return
	}
	defer tx.Rollback(r.Context())

	c, err := s.contacts.Update(r.Context(), tx, p.TenantID, id, b.toInput())
	if errors.Is(err, contact.ErrNotFound) {
		httpx.Problem(w, r, http.StatusNotFound, "not found", "contact not found")
		return
	}
	if err != nil {
		if isUniqueViolation(err) {
			httpx.Problem(w, r, http.StatusConflict, "conflict", "email already exists in tenant")
			return
		}
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "update contact")
		return
	}
	if err := audit.Write(r.Context(), tx, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: "contact.update", TargetType: "contact", TargetID: c.ID.String(),
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

func (s *Server) deleteContact(w http.ResponseWriter, r *http.Request) {
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

	if err := s.contacts.Delete(r.Context(), tx, p.TenantID, id); err != nil {
		if errors.Is(err, contact.ErrNotFound) {
			httpx.Problem(w, r, http.StatusNotFound, "not found", "contact not found")
			return
		}
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "delete contact")
		return
	}
	if err := audit.Write(r.Context(), tx, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: "contact.delete", TargetType: "contact", TargetID: id.String(),
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

func (s *Server) importContacts(w http.ResponseWriter, r *http.Request) {
	var b struct {
		GroupID  *uuid.UUID    `json:"group_id"`
		Contacts []contactBody `json:"contacts"`
	}
	if !decode(w, r, &b) {
		return
	}
	if len(b.Contacts) == 0 {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "contacts must be non-empty")
		return
	}
	p, _ := auth.FromContext(r.Context())
	if !s.groupOK(w, r, p.TenantID, b.GroupID) {
		return
	}

	items := make([]contact.Input, 0, len(b.Contacts))
	for _, cb := range b.Contacts {
		if cb.Email == "" {
			httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "every contact requires an email")
			return
		}
		in := cb.toInput()
		if b.GroupID != nil {
			in.GroupID = b.GroupID // top-level group applies to all
		}
		// Import is lenient on phone: an invalid/absent E.164 is dropped (left
		// null) rather than failing the whole batch. SMS campaigns validate
		// presence at launch.
		if in.PhoneE164 != "" && !contact.ValidE164(in.PhoneE164) {
			in.PhoneE164 = ""
		}
		items = append(items, in)
	}

	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "begin transaction")
		return
	}
	defer tx.Rollback(r.Context())

	res, err := s.contacts.BulkImport(r.Context(), tx, p.TenantID, items)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "import contacts")
		return
	}
	if err := audit.Write(r.Context(), tx, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: "contact.import", TargetType: "tenant", TargetID: p.TenantID.String(),
		Metadata: map[string]any{"created": res.Created, "duplicates": res.Duplicates, "suppressed": res.Suppressed},
	}); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "commit")
		return
	}
	httpx.JSON(w, http.StatusOK, res)
}

// --- contact groups -------------------------------------------------------

func (s *Server) createGroup(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &b) {
		return
	}
	if b.Name == "" {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "name is required")
		return
	}
	p, _ := auth.FromContext(r.Context())

	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "begin transaction")
		return
	}
	defer tx.Rollback(r.Context())

	g, err := s.groups.Create(r.Context(), tx, p.TenantID, b.Name)
	if err != nil {
		if isUniqueViolation(err) {
			httpx.Problem(w, r, http.StatusConflict, "conflict", "group name already exists")
			return
		}
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "create group")
		return
	}
	if err := audit.Write(r.Context(), tx, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: "group.create", TargetType: "contact_group", TargetID: g.ID.String(),
		Metadata: map[string]any{"name": g.Name},
	}); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "commit")
		return
	}
	httpx.JSON(w, http.StatusCreated, g)
}

func (s *Server) listGroups(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	limit, offset := parsePage(r)
	items, err := s.groups.List(r.Context(), s.pool, p.TenantID, limit, offset)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "list groups")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": items, "limit": limit, "offset": offset})
}

func (s *Server) getGroup(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	g, err := s.groups.GetByID(r.Context(), s.pool, p.TenantID, id)
	if errors.Is(err, group.ErrNotFound) {
		httpx.Problem(w, r, http.StatusNotFound, "not found", "group not found")
		return
	}
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "get group")
		return
	}
	httpx.JSON(w, http.StatusOK, g)
}

func (s *Server) deleteGroup(w http.ResponseWriter, r *http.Request) {
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

	if err := s.groups.Delete(r.Context(), tx, p.TenantID, id); err != nil {
		if errors.Is(err, group.ErrNotFound) {
			httpx.Problem(w, r, http.StatusNotFound, "not found", "group not found")
			return
		}
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "delete group")
		return
	}
	if err := audit.Write(r.Context(), tx, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: "group.delete", TargetType: "contact_group", TargetID: id.String(),
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

// --- suppressions ---------------------------------------------------------

func (s *Server) addSuppression(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Email  string `json:"email"`
		Reason string `json:"reason"`
	}
	if !decode(w, r, &b) {
		return
	}
	if b.Email == "" {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "email is required")
		return
	}
	p, _ := auth.FromContext(r.Context())

	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "begin transaction")
		return
	}
	defer tx.Rollback(r.Context())

	e, err := s.suppressions.Add(r.Context(), tx, p.TenantID, b.Email, b.Reason)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "add suppression")
		return
	}
	if err := audit.Write(r.Context(), tx, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: "suppression.add", TargetType: "suppression", TargetID: e.ID.String(),
		Metadata: map[string]any{"email": e.Email},
	}); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "commit")
		return
	}
	httpx.JSON(w, http.StatusCreated, e)
}

func (s *Server) listSuppressions(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	limit, offset := parsePage(r)
	items, err := s.suppressions.List(r.Context(), s.pool, p.TenantID, limit, offset)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "list suppressions")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": items, "limit": limit, "offset": offset})
}

func (s *Server) deleteSuppression(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	if email == "" {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "email query param is required")
		return
	}
	p, _ := auth.FromContext(r.Context())

	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "begin transaction")
		return
	}
	defer tx.Rollback(r.Context())

	if err := s.suppressions.Remove(r.Context(), tx, p.TenantID, email); err != nil {
		if errors.Is(err, suppression.ErrNotFound) {
			httpx.Problem(w, r, http.StatusNotFound, "not found", "suppression not found")
			return
		}
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "remove suppression")
		return
	}
	if err := audit.Write(r.Context(), tx, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: "suppression.remove", TargetType: "suppression", TargetID: email,
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
