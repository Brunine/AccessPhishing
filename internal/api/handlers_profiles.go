package api

import (
	"errors"
	"net/http"
	"strings"

	"phishforge/internal/audit"
	"phishforge/internal/auth"
	"phishforge/internal/httpx"
	"phishforge/internal/profiles"
)

// --- M10b application profiles (operator, tenant-scoped, audited) ----------

// createProfile stores a new profile revision from a JSON envelope
// {"spec_yaml": "<yaml>"}. The YAML is validated against every VALIDATION.md
// rule; a new version N+1 is stored for the declared metadata.name.
func (s *Server) createProfile(w http.ResponseWriter, r *http.Request) {
	var b struct {
		SpecYAML string `json:"spec_yaml"`
	}
	if !decode(w, r, &b) {
		return
	}
	s.storeNewProfile(w, r, []byte(b.SpecYAML))
}

// importProfile stores a new profile revision from a raw YAML request body
// (text/yaml). Identical semantics to createProfile, ergonomic for CLI imports.
func (s *Server) importProfile(w http.ResponseWriter, r *http.Request) {
	raw, err := readBodyCapped(w, r, profiles.MaxSpecBytes)
	if err != nil {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "read body")
		return
	}
	s.storeNewProfile(w, r, raw)
}

// storeNewProfile validates raw YAML, canonicalizes + checksums it, and inserts
// a new version. All profile input is untrusted; nothing is stored until it
// passes validation.
func (s *Server) storeNewProfile(w http.ResponseWriter, r *http.Request, raw []byte) {
	if strings.TrimSpace(string(raw)) == "" {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "empty profile document")
		return
	}
	spec, result := profiles.ValidateBytes(raw)
	if result.HasErrors() {
		writeProfileViolations(w, result)
		return
	}
	name := profiles.Name(spec)
	canonical, err := profiles.Canonicalize(spec)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "canonicalize profile")
		return
	}
	checksum := profiles.Checksum(canonical)

	p, _ := auth.FromContext(r.Context())
	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "begin transaction")
		return
	}
	defer tx.Rollback(r.Context())

	prof, err := s.appProfiles.Create(r.Context(), tx, p.TenantID, p.UserID, name, canonical, checksum)
	if err != nil {
		if isUniqueViolation(err) {
			httpx.Problem(w, r, http.StatusConflict, "conflict", "profile name+version already exists")
			return
		}
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "create profile")
		return
	}
	if err := audit.Write(r.Context(), tx, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: "appprofile.import", TargetType: "app_profile", TargetID: prof.ID.String(),
		Metadata: map[string]any{"name": prof.Name, "version": prof.Version, "checksum": prof.Checksum},
	}); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "commit")
		return
	}
	httpx.JSON(w, http.StatusCreated, prof)
}

func (s *Server) listProfiles(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	limit, offset := parsePage(r)
	items, err := s.appProfiles.List(r.Context(), s.pool, p.TenantID, limit, offset)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "list profiles")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": items, "limit": limit, "offset": offset})
}

func (s *Server) getProfile(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	prof, err := s.appProfiles.GetByID(r.Context(), s.pool, p.TenantID, id)
	if errors.Is(err, profiles.ErrNotFound) {
		httpx.Problem(w, r, http.StatusNotFound, "not found", "profile not found")
		return
	}
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "get profile")
		return
	}
	httpx.JSON(w, http.StatusOK, prof)
}

// updateProfile replaces a profile row's spec in place (same version) from a
// JSON envelope {"spec_yaml": "<yaml>"}. The YAML is re-validated.
func (s *Server) updateProfile(w http.ResponseWriter, r *http.Request) {
	var b struct {
		SpecYAML string `json:"spec_yaml"`
	}
	if !decode(w, r, &b) {
		return
	}
	p, _ := auth.FromContext(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	spec, result := profiles.ValidateBytes([]byte(b.SpecYAML))
	if result.HasErrors() {
		writeProfileViolations(w, result)
		return
	}
	canonical, err := profiles.Canonicalize(spec)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "canonicalize profile")
		return
	}
	checksum := profiles.Checksum(canonical)

	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "begin transaction")
		return
	}
	defer tx.Rollback(r.Context())

	prof, err := s.appProfiles.Update(r.Context(), tx, p.TenantID, id, canonical, checksum)
	if errors.Is(err, profiles.ErrNotFound) {
		httpx.Problem(w, r, http.StatusNotFound, "not found", "profile not found")
		return
	}
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "update profile")
		return
	}
	if err := audit.Write(r.Context(), tx, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: "appprofile.update", TargetType: "app_profile", TargetID: prof.ID.String(),
		Metadata: map[string]any{"name": prof.Name, "version": prof.Version, "checksum": prof.Checksum},
	}); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "commit")
		return
	}
	httpx.JSON(w, http.StatusOK, prof)
}

func (s *Server) deleteProfile(w http.ResponseWriter, r *http.Request) {
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

	if err := s.appProfiles.Delete(r.Context(), tx, p.TenantID, id); err != nil {
		if errors.Is(err, profiles.ErrNotFound) {
			httpx.Problem(w, r, http.StatusNotFound, "not found", "profile not found")
			return
		}
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "delete profile")
		return
	}
	if err := audit.Write(r.Context(), tx, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: "appprofile.delete", TargetType: "app_profile", TargetID: id.String(),
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

// writeProfileViolations returns a 400 problem+json-style body carrying the
// exact VALIDATION.md rule IDs so clients see every failed rule in one pass.
func writeProfileViolations(w http.ResponseWriter, result profiles.Result) {
	httpx.JSON(w, http.StatusBadRequest, map[string]any{
		"type":       "about:blank",
		"title":      "invalid profile",
		"status":     http.StatusBadRequest,
		"detail":     "profile failed validation",
		"violations": result.Violations,
	})
}
