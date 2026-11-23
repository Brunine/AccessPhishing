package api

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"phishforge/internal/audit"
	"phishforge/internal/auth"
	"phishforge/internal/campaign"
	"phishforge/internal/contact"
	"phishforge/internal/db"
	"phishforge/internal/events"
	"phishforge/internal/httpx"
	"phishforge/internal/recipient"
)

// maxSnapshot caps how many contacts a single launch resolves.
const maxSnapshot = 100000

// transparentGIF is a 1x1 transparent GIF used by the open-tracking pixel.
var transparentGIF, _ = base64.StdEncoding.DecodeString(
	"R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")

// --- launch (operator) ----------------------------------------------------

func (s *Server) launchCampaign(w http.ResponseWriter, r *http.Request) {
	var b struct {
		GroupID          *uuid.UUID  `json:"group_id"`
		ContactIDs       []uuid.UUID `json:"contact_ids"`
		LandingURL       *string     `json:"landing_url"`
		TemplateID       *uuid.UUID  `json:"template_id"`
		SendingProfileID *uuid.UUID  `json:"sending_profile_id"`
	}
	if !decode(w, r, &b) {
		return
	}
	if b.GroupID == nil && len(b.ContactIDs) == 0 {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "provide group_id or contact_ids")
		return
	}
	p, _ := auth.FromContext(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}

	// Validate referenced template / sending profile belong to the tenant.
	if b.TemplateID != nil {
		if _, err := s.templates.GetByID(r.Context(), s.pool, p.TenantID, *b.TemplateID); err != nil {
			httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "template_id not found in tenant")
			return
		}
	}
	profileChannel := ""
	if b.SendingProfileID != nil {
		prof, err := s.profiles.GetByID(r.Context(), s.pool, p.TenantID, *b.SendingProfileID)
		if err != nil {
			httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "sending_profile_id not found in tenant")
			return
		}
		profileChannel = prof.Channel
	}

	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "begin transaction")
		return
	}
	defer tx.Rollback(r.Context())

	camp, err := s.campaigns.GetByID(r.Context(), tx, p.TenantID, id)
	if errors.Is(err, campaign.ErrNotFound) {
		httpx.Problem(w, r, http.StatusNotFound, "not found", "campaign not found")
		return
	}
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "load campaign")
		return
	}
	if camp.Status != "draft" {
		httpx.Problem(w, r, http.StatusConflict, "conflict", "campaign is not in draft (already launched)")
		return
	}

	// Resolve the selected contacts within the tenant, skipping suppressed
	// addresses (the do-not-contact list is honored at launch).
	targets, err := s.resolveTargets(r, tx, p.TenantID, b.GroupID, b.ContactIDs)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "resolve recipients")
		return
	}
	if len(targets) == 0 {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "no eligible recipients (empty selection or all suppressed)")
		return
	}

	// An SMS campaign requires every recipient to have a phone number — this is
	// a launch-time validation (clear count), not a silent per-recipient skip.
	if profileChannel == "sms" {
		ids := make([]uuid.UUID, len(targets))
		for i, t := range targets {
			ids[i] = t.ContactID
		}
		var missing int
		if err := tx.QueryRow(r.Context(),
			`SELECT count(*) FROM contacts WHERE tenant_id = $1 AND id = ANY($2) AND (phone_e164 IS NULL OR phone_e164 = '')`,
			p.TenantID, ids).Scan(&missing); err != nil {
			httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "check recipient phones")
			return
		}
		if missing > 0 {
			httpx.Problem(w, r, http.StatusBadRequest, "invalid request",
				fmt.Sprintf("%d selected recipient(s) have no phone number (required for an SMS campaign)", missing))
			return
		}
	}

	created, err := s.recipients.Snapshot(r.Context(), tx, p.TenantID, id, targets)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "snapshot recipients")
		return
	}
	if err := s.campaigns.MarkScheduled(r.Context(), tx, p.TenantID, id, b.LandingURL, b.TemplateID, b.SendingProfileID); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "schedule campaign")
		return
	}
	if err := audit.Write(r.Context(), tx, audit.Entry{
		TenantID: p.TenantID, ActorID: p.UserID, ActorEmail: p.Email,
		Action: "campaign.launch", TargetType: "campaign", TargetID: id.String(),
		Metadata: map[string]any{"recipients": created},
	}); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "commit")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{
		"campaign_id": id,
		"status":      "scheduled",
		"recipients":  created,
	})
}

// resolveTargets gathers the deduped, non-suppressed contacts to snapshot.
func (s *Server) resolveTargets(r *http.Request, tx db.Querier, tenantID uuid.UUID, groupID *uuid.UUID, contactIDs []uuid.UUID) ([]recipient.Target, error) {
	chosen := make(map[uuid.UUID]contact.Contact)

	if groupID != nil {
		list, err := s.contacts.List(r.Context(), tx, tenantID, groupID, maxSnapshot, 0)
		if err != nil {
			return nil, err
		}
		for _, c := range list {
			chosen[c.ID] = c
		}
	}
	for _, cid := range contactIDs {
		c, err := s.contacts.GetByID(r.Context(), tx, tenantID, cid)
		if errors.Is(err, contact.ErrNotFound) {
			continue // silently skip unknown ids
		}
		if err != nil {
			return nil, err
		}
		chosen[c.ID] = c
	}

	targets := make([]recipient.Target, 0, len(chosen))
	for _, c := range chosen {
		suppressed, err := s.suppressions.IsSuppressed(r.Context(), tx, tenantID, c.Email)
		if err != nil {
			return nil, err
		}
		if suppressed {
			continue
		}
		targets = append(targets, recipient.Target{ContactID: c.ID, GroupID: c.GroupID})
	}
	return targets, nil
}

// --- links (operator) -----------------------------------------------------

func (s *Server) campaignLinks(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	if _, err := s.campaigns.GetByID(r.Context(), s.pool, p.TenantID, id); err != nil {
		if errors.Is(err, campaign.ErrNotFound) {
			httpx.Problem(w, r, http.StatusNotFound, "not found", "campaign not found")
			return
		}
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "load campaign")
		return
	}

	recs, err := s.recipients.ListByCampaign(r.Context(), s.pool, p.TenantID, id)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "list recipients")
		return
	}
	items := make([]map[string]any, 0, len(recs))
	for _, rec := range recs {
		items = append(items, map[string]any{
			"recipient_id": rec.ID,
			"contact_id":   rec.ContactID,
			"token":        rec.Token,
			"click_url":    s.baseURL + "/t/" + rec.Token,
			"pixel_url":    s.baseURL + "/px/" + rec.Token,
		})
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": items})
}

// --- public tracking (token-authenticated, no middleware auth) -------------

func (s *Server) trackClick(w http.ResponseWriter, r *http.Request) {
	rec, err := s.recipients.GetByToken(r.Context(), s.pool, chi.URLParam(r, "token"))
	if err != nil {
		// Unknown token: neutral page, no state change, no information leak.
		s.neutralPage(w)
		return
	}

	s.recordTracking(r, rec, events.TypeClicked)

	landing, engineID, err := s.campaigns.LandingRedirectByID(r.Context(), s.pool, rec.CampaignID)
	if err == nil && landing != nil && *landing != "" {
		target := *landing
		if engineID != nil {
			// Engine-bound campaign: carry the victim token through so the
			// proxy can attribute captured creds/session events. Plain
			// (non-engine) landings never receive the token.
			target = appendQueryParam(target, "_pft", rec.Token)
		}
		http.Redirect(w, r, target, http.StatusFound)
		return
	}
	s.neutralPage(w)
}

// appendQueryParam appends key=value to a URL, preserving existing params.
func appendQueryParam(rawURL, key, value string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String()
}

func (s *Server) trackOpen(w http.ResponseWriter, r *http.Request) {
	// Always return the pixel, whether or not the token resolves, so the
	// response never reveals token validity.
	if rec, err := s.recipients.GetByToken(r.Context(), s.pool, chi.URLParam(r, "token")); err == nil {
		s.recordTracking(r, rec, events.TypeOpened)
	}
	w.Header().Set("Content-Type", "image/gif")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(transparentGIF)
}

// recordTracking appends an observed tracking event. It is best-effort: an
// out-of-order signal (e.g. an open after a click) is a no-op on state and is
// not surfaced to the public caller.
func (s *Server) recordTracking(r *http.Request, rec recipient.Recipient, t events.Type) {
	_, _ = s.events.Append(r.Context(), events.NewEvent{
		TenantID:   rec.TenantID,
		CampaignID: rec.CampaignID,
		ContactID:  rec.ContactID,
		Type:       t,
		Metadata: map[string]any{
			"ip": clientIP(r),
			"ua": r.UserAgent(),
		},
	})
}

func (s *Server) notFoundPage(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte("<!doctype html><title>Not found</title><h1>404 — Not found</h1>"))
}

func (s *Server) neutralPage(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("<!doctype html><title>Thanks</title><p>Thank you.</p>"))
}
