package api

import (
	"errors"
	"net/http"
	"strings"

	"phishforge/internal/audit"
	"phishforge/internal/auth"
	"phishforge/internal/httpx"
	"phishforge/internal/prompttpl"
)

type promptTemplateBody struct {
	Name         string               `json:"name"`
	Kind         string               `json:"kind"`
	SystemPrompt string               `json:"system_prompt"`
	UserTemplate string               `json:"user_template"`
	Variables    []prompttpl.Variable `json:"variables"`
	IsDefault    bool                 `json:"is_default"`
}

func (b promptTemplateBody) toInput() prompttpl.Input {
	kind := b.Kind
	if kind == "" {
		kind = "email"
	}
	return prompttpl.Input{
		Name: b.Name, Kind: kind, SystemPrompt: b.SystemPrompt,
		UserTemplate: b.UserTemplate, Variables: b.Variables, IsDefault: b.IsDefault,
	}
}

// validatePromptInput runs name + strict template validation, writing a 400 on
// failure. Returns false when a response was already written.
func (s *Server) validatePromptInput(w http.ResponseWriter, r *http.Request, in prompttpl.Input) bool {
	if strings.TrimSpace(in.Name) == "" {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "name is required")
		return false
	}
	if err := prompttpl.Validate(in.Kind, in.UserTemplate, in.Variables); err != nil {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", err.Error())
		return false
	}
	return true
}

func (s *Server) createPromptTemplate(w http.ResponseWriter, r *http.Request) {
	var b promptTemplateBody
	if !decode(w, r, &b) {
		return
	}
	in := b.toInput()
	if !s.validatePromptInput(w, r, in) {
		return
	}
	p, _ := auth.FromContext(r.Context())

	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "begin transaction")
		return
	}
	defer tx.Rollback(r.Context())

	t, err := s.prompttpls.Create(r.Context(), tx, p.TenantID, in)
	if err != nil {
		if isUniqueViolation(err) {
			httpx.Problem(w, r, http.StatusConflict, "conflict", "prompt template name already exists")
			return
		}
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "create prompt template")
		return
	}
	if err := audit.Write(r.Context(), tx, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: "prompttpl.create", TargetType: "prompt_template", TargetID: t.ID.String(),
		Metadata: map[string]any{"name": t.Name, "kind": t.Kind},
	}); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "commit")
		return
	}
	httpx.JSON(w, http.StatusCreated, t)
}

func (s *Server) listPromptTemplates(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	limit, offset := parsePage(r)
	items, err := s.prompttpls.List(r.Context(), s.pool, p.TenantID, limit, offset)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "list prompt templates")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": items, "limit": limit, "offset": offset})
}

func (s *Server) getPromptTemplate(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	t, err := s.prompttpls.GetByID(r.Context(), s.pool, p.TenantID, id)
	if errors.Is(err, prompttpl.ErrNotFound) {
		httpx.Problem(w, r, http.StatusNotFound, "not found", "prompt template not found")
		return
	}
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "get prompt template")
		return
	}
	httpx.JSON(w, http.StatusOK, t)
}

func (s *Server) updatePromptTemplate(w http.ResponseWriter, r *http.Request) {
	var b promptTemplateBody
	if !decode(w, r, &b) {
		return
	}
	in := b.toInput()
	if !s.validatePromptInput(w, r, in) {
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

	t, err := s.prompttpls.Update(r.Context(), tx, p.TenantID, id, in)
	if errors.Is(err, prompttpl.ErrNotFound) {
		httpx.Problem(w, r, http.StatusNotFound, "not found", "prompt template not found")
		return
	}
	if err != nil {
		if isUniqueViolation(err) {
			httpx.Problem(w, r, http.StatusConflict, "conflict", "prompt template name already exists")
			return
		}
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "update prompt template")
		return
	}
	if err := audit.Write(r.Context(), tx, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: "prompttpl.update", TargetType: "prompt_template", TargetID: t.ID.String(),
	}); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "commit")
		return
	}
	httpx.JSON(w, http.StatusOK, t)
}

func (s *Server) deletePromptTemplate(w http.ResponseWriter, r *http.Request) {
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

	if err := s.prompttpls.Delete(r.Context(), tx, p.TenantID, id); err != nil {
		if errors.Is(err, prompttpl.ErrNotFound) {
			httpx.Problem(w, r, http.StatusNotFound, "not found", "prompt template not found")
			return
		}
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "delete prompt template")
		return
	}
	if err := audit.Write(r.Context(), tx, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: "prompttpl.delete", TargetType: "prompt_template", TargetID: id.String(),
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

// renderPromptTemplate is a dry-run: it renders the template against a sample
// context (declared examples overlaid with any supplied values) and returns the
// text WITHOUT calling the LLM.
func (s *Server) renderPromptTemplate(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Variables map[string]string `json:"variables"`
	}
	if r.ContentLength > 0 && !decode(w, r, &b) {
		return
	}
	p, _ := auth.FromContext(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	t, err := s.prompttpls.GetByID(r.Context(), s.pool, p.TenantID, id)
	if errors.Is(err, prompttpl.ErrNotFound) {
		httpx.Problem(w, r, http.StatusNotFound, "not found", "prompt template not found")
		return
	}
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "get prompt template")
		return
	}

	ctx := prompttpl.SampleContext(t.Variables, b.Variables)
	rendered, err := prompttpl.Render(t.UserTemplate, ctx)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "render template")
		return
	}
	prompt, err := prompttpl.BuildPrompt(t.SystemPrompt, t.UserTemplate, ctx)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "build prompt")
		return
	}
	if err := audit.Write(r.Context(), s.pool, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: "prompttpl.render", TargetType: "prompt_template", TargetID: id.String(),
	}); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{
		"kind":          t.Kind,
		"system_prompt": t.SystemPrompt,
		"rendered_user": rendered,
		"prompt":        prompt,
		"context":       ctx,
	})
}
