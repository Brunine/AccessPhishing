package api

import (
	"errors"
	"net/http"

	"github.com/google/uuid"

	"phishforge/internal/approval"
	"phishforge/internal/audit"
	"phishforge/internal/auth"
	"phishforge/internal/campaign"
	"phishforge/internal/httpx"
	"phishforge/internal/sendingprofile"
	tmpl "phishforge/internal/template"
)

// --- templates (operator) -------------------------------------------------

type templateBody struct {
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	Subject string `json:"subject"`
	Body    string `json:"body"`
}

func (b templateBody) toInput() tmpl.Input {
	kind := b.Kind
	if kind == "" {
		kind = "email"
	}
	return tmpl.Input{Kind: kind, Name: b.Name, Subject: b.Subject, Body: b.Body}
}

func (s *Server) createTemplate(w http.ResponseWriter, r *http.Request) {
	var b templateBody
	if !decode(w, r, &b) {
		return
	}
	in := b.toInput()
	if in.Name == "" || in.Body == "" {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "name and body are required")
		return
	}
	if !tmpl.ValidKind(in.Kind) {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "invalid template kind")
		return
	}
	// SMS hard cap: a single message is ~160 chars (one segment); beyond one
	// segment is allowed (the console warns), but 1600 chars (~10 segments) is
	// the maximum we accept.
	if in.Kind == "sms" && len(in.Body) > 1600 {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "sms template body exceeds 1600 characters")
		return
	}
	p, _ := auth.FromContext(r.Context())

	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "begin transaction")
		return
	}
	defer tx.Rollback(r.Context())

	t, err := s.templates.Create(r.Context(), tx, p.TenantID, p.UserID, in)
	if err != nil {
		if isUniqueViolation(err) {
			httpx.Problem(w, r, http.StatusConflict, "conflict", "template name already exists for this kind")
			return
		}
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "create template")
		return
	}
	if err := audit.Write(r.Context(), tx, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: "template.create", TargetType: "template", TargetID: t.ID.String(),
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

func (s *Server) listTemplates(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	limit, offset := parsePage(r)
	items, err := s.templates.List(r.Context(), s.pool, p.TenantID, limit, offset)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "list templates")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": items, "limit": limit, "offset": offset})
}

func (s *Server) getTemplate(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	t, err := s.templates.GetByID(r.Context(), s.pool, p.TenantID, id)
	if errors.Is(err, tmpl.ErrNotFound) {
		httpx.Problem(w, r, http.StatusNotFound, "not found", "template not found")
		return
	}
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "get template")
		return
	}
	httpx.JSON(w, http.StatusOK, t)
}

func (s *Server) updateTemplate(w http.ResponseWriter, r *http.Request) {
	var b templateBody
	if !decode(w, r, &b) {
		return
	}
	in := b.toInput()
	if in.Name == "" || in.Body == "" {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "name and body are required")
		return
	}
	if !tmpl.ValidKind(in.Kind) {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "invalid template kind")
		return
	}
	// SMS hard cap: a single message is ~160 chars (one segment); beyond one
	// segment is allowed (the console warns), but 1600 chars (~10 segments) is
	// the maximum we accept.
	if in.Kind == "sms" && len(in.Body) > 1600 {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "sms template body exceeds 1600 characters")
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

	t, err := s.templates.Update(r.Context(), tx, p.TenantID, id, in)
	if errors.Is(err, tmpl.ErrNotFound) {
		httpx.Problem(w, r, http.StatusNotFound, "not found", "template not found")
		return
	}
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "update template")
		return
	}
	if err := audit.Write(r.Context(), tx, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: "template.update", TargetType: "template", TargetID: t.ID.String(),
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

func (s *Server) deleteTemplate(w http.ResponseWriter, r *http.Request) {
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

	if err := s.templates.Delete(r.Context(), tx, p.TenantID, id); err != nil {
		if errors.Is(err, tmpl.ErrNotFound) {
			httpx.Problem(w, r, http.StatusNotFound, "not found", "template not found")
			return
		}
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "delete template")
		return
	}
	if err := audit.Write(r.Context(), tx, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: "template.delete", TargetType: "template", TargetID: id.String(),
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

// --- sending profiles (operator) ------------------------------------------

func (s *Server) createSendingProfile(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Name        string `json:"name"`
		Channel     string `json:"channel"`
		SMTPHost    string `json:"smtp_host"`
		SMTPPort    int    `json:"smtp_port"`
		SMTPUser    string `json:"smtp_user"`
		SMTPPass    string `json:"smtp_pass"`
		Secret      string `json:"secret"` // API client secret / SMS auth token
		APITenantID string `json:"api_tenant_id"`
		APIClientID string `json:"api_client_id"` // Graph/Gmail client id or Twilio Account SID
		SMSProvider string `json:"sms_provider"`
		SMSSenderID string `json:"sms_sender_id"`
		FromAddress string `json:"from_address"`
		FromName    string `json:"from_name"`
		TLSMode     string `json:"tls_mode"`
	}
	if !decode(w, r, &b) {
		return
	}
	if b.Channel == "" {
		b.Channel = "smtp"
	}
	if !sendingprofile.ValidChannel(b.Channel) {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "channel must be one of smtp, graph, gmail, sms")
		return
	}
	if b.Name == "" {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "name is required")
		return
	}

	// The per-channel secret and its validation differ by channel.
	secret := b.SMTPPass
	switch b.Channel {
	case "smtp":
		if b.SMTPHost == "" || b.SMTPPort == 0 {
			httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "smtp_host and smtp_port are required for the smtp channel")
			return
		}
		if b.FromAddress == "" {
			httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "from_address is required")
			return
		}
		if b.TLSMode == "" {
			b.TLSMode = "starttls"
		}
		if !sendingprofile.ValidTLSMode(b.TLSMode) {
			httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "invalid tls_mode")
			return
		}
	case "sms":
		// SMS uses provider + sender_id; credentials are the account SID
		// (api_client_id, non-secret) + auth token (secret). from_address/smtp
		// are unused.
		if !sendingprofile.ValidSMSProvider(b.SMSProvider) {
			httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "sms_provider must be one of: twilio")
			return
		}
		secret = b.Secret
		b.SMTPHost, b.SMTPPort, b.SMTPUser = "", 0, ""
		b.TLSMode = "none"
	default: // graph, gmail
		if b.FromAddress == "" {
			httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "from_address is required")
			return
		}
		secret = b.Secret
		b.SMTPHost, b.SMTPPort, b.SMTPUser = "", 0, ""
		b.TLSMode = "none"
	}
	p, _ := auth.FromContext(r.Context())

	if s.cipher == nil {
		httpx.Problem(w, r, http.StatusServiceUnavailable, "unavailable", "encryption key not configured (ARTIFACT_ENC_KEY)")
		return
	}
	encrypted := ""
	if secret != "" {
		ct, err := s.cipher.Encrypt(p.TenantID, []byte(secret))
		if err != nil {
			httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "encrypt secret")
			return
		}
		encrypted = ct
	}

	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "begin transaction")
		return
	}
	defer tx.Rollback(r.Context())

	prof, err := s.profiles.Create(r.Context(), tx, p.TenantID, sendingprofile.Input{
		Name: b.Name, Channel: b.Channel, SMTPHost: b.SMTPHost, SMTPPort: b.SMTPPort, SMTPUser: b.SMTPUser,
		PassEncrypted: encrypted, APITenantID: b.APITenantID, APIClientID: b.APIClientID,
		SMSProvider: b.SMSProvider, SMSSenderID: b.SMSSenderID,
		FromAddress: b.FromAddress, FromName: b.FromName, TLSMode: b.TLSMode,
	})
	if err != nil {
		if isUniqueViolation(err) {
			httpx.Problem(w, r, http.StatusConflict, "conflict", "sending profile name already exists")
			return
		}
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "create sending profile")
		return
	}
	if err := audit.Write(r.Context(), tx, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: "sending_profile.create", TargetType: "sending_profile", TargetID: prof.ID.String(),
		Metadata: map[string]any{"name": prof.Name, "channel": prof.Channel, "host": prof.SMTPHost},
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

func (s *Server) listSendingProfiles(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	limit, offset := parsePage(r)
	items, err := s.profiles.List(r.Context(), s.pool, p.TenantID, limit, offset)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "list sending profiles")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": items, "limit": limit, "offset": offset})
}

func (s *Server) getSendingProfile(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	prof, err := s.profiles.GetByID(r.Context(), s.pool, p.TenantID, id)
	if errors.Is(err, sendingprofile.ErrNotFound) {
		httpx.Problem(w, r, http.StatusNotFound, "not found", "sending profile not found")
		return
	}
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "get sending profile")
		return
	}
	httpx.JSON(w, http.StatusOK, prof)
}

func (s *Server) deleteSendingProfile(w http.ResponseWriter, r *http.Request) {
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

	if err := s.profiles.Delete(r.Context(), tx, p.TenantID, id); err != nil {
		if errors.Is(err, sendingprofile.ErrNotFound) {
			httpx.Problem(w, r, http.StatusNotFound, "not found", "sending profile not found")
			return
		}
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "delete sending profile")
		return
	}
	if err := audit.Write(r.Context(), tx, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: "sending_profile.delete", TargetType: "sending_profile", TargetID: id.String(),
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

// --- approvals (operator requests; admin decides) -------------------------

func (s *Server) requestApproval(w http.ResponseWriter, r *http.Request) {
	var b struct {
		SubjectType string    `json:"subject_type"`
		SubjectID   uuid.UUID `json:"subject_id"`
	}
	if !decode(w, r, &b) {
		return
	}
	if b.SubjectType == "" || b.SubjectID == uuid.Nil {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "subject_type and subject_id are required")
		return
	}
	p, _ := auth.FromContext(r.Context())

	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "begin transaction")
		return
	}
	defer tx.Rollback(r.Context())

	a, err := s.approvals.Request(r.Context(), tx, p.TenantID, p.UserID, b.SubjectType, b.SubjectID)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "request approval")
		return
	}
	if err := audit.Write(r.Context(), tx, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: "approval.request", TargetType: b.SubjectType, TargetID: b.SubjectID.String(),
		Metadata: map[string]any{"approval_id": a.ID.String()},
	}); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "commit")
		return
	}
	httpx.JSON(w, http.StatusCreated, a)
}

func (s *Server) listApprovals(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	limit, offset := parsePage(r)
	items, err := s.approvals.List(r.Context(), s.pool, p.TenantID, limit, offset)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "list approvals")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": items, "limit": limit, "offset": offset})
}

func (s *Server) approveApproval(w http.ResponseWriter, r *http.Request) { s.decide(w, r, "approved") }
func (s *Server) rejectApproval(w http.ResponseWriter, r *http.Request)  { s.decide(w, r, "rejected") }

func (s *Server) decide(w http.ResponseWriter, r *http.Request, status string) {
	var b struct {
		Notes string `json:"notes"`
	}
	// Notes are optional; tolerate an empty body.
	if r.ContentLength > 0 && !decode(w, r, &b) {
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

	a, err := s.approvals.Decide(r.Context(), tx, p.TenantID, id, p.UserID, status, b.Notes)
	if errors.Is(err, approval.ErrNotFound) {
		httpx.Problem(w, r, http.StatusNotFound, "not found", "approval not found")
		return
	}
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "decide approval")
		return
	}
	if err := audit.Write(r.Context(), tx, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: "approval." + status, TargetType: "approval", TargetID: id.String(),
	}); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "commit")
		return
	}
	httpx.JSON(w, http.StatusOK, a)
}

// --- send (operator): enqueue delivery ------------------------------------

func (s *Server) sendCampaign(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}

	camp, err := s.campaigns.GetByID(r.Context(), s.pool, p.TenantID, id)
	if errors.Is(err, campaign.ErrNotFound) {
		httpx.Problem(w, r, http.StatusNotFound, "not found", "campaign not found")
		return
	}
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "load campaign")
		return
	}
	if camp.Status != "scheduled" {
		httpx.Problem(w, r, http.StatusConflict, "conflict", "campaign must be 'scheduled' to send")
		return
	}
	// Engagement authorization gate: re-check at send time — the engagement may
	// have expired or been terminated (emergency stop) since launch.
	if !s.checkEngagementGate(w, r, s.pool, p.TenantID, camp) {
		return
	}
	if camp.TemplateID == nil {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "campaign has no template assigned")
		return
	}
	if camp.SendingProfileID == nil {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "campaign has no sending profile assigned")
		return
	}

	approved, err := s.approvals.IsApproved(r.Context(), s.pool, p.TenantID, "template", *camp.TemplateID)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "check approval")
		return
	}
	if !approved {
		httpx.Problem(w, r, http.StatusForbidden, "forbidden", "template is not approved")
		return
	}

	if s.enqueuer == nil {
		httpx.Problem(w, r, http.StatusServiceUnavailable, "unavailable", "task queue not configured")
		return
	}
	if err := s.enqueuer.EnqueueCampaignSend(r.Context(), p.TenantID, id); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "enqueue send")
		return
	}

	// Audit the enqueue (best-effort, non-transactional with the queue).
	if err := audit.Write(r.Context(), s.pool, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: "campaign.send.enqueue", TargetType: "campaign", TargetID: id.String(),
	}); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}
	httpx.JSON(w, http.StatusAccepted, map[string]any{"campaign_id": id, "status": "queued"})
}
