package api

import (
	"encoding/base64"
	"errors"
	"net/http"

	"phishforge/internal/auth"
	"phishforge/internal/campaign"
	"phishforge/internal/httpx"
	"phishforge/internal/qr"
)

// campaignQRCodes returns a per-recipient QR artifact for a campaign: each
// recipient's /t/{token} tracking URL encoded as a PNG QR code, base64'd inline.
//
// The codes are generated on the fly from recipient.ListByCampaign — no table,
// no blob storage. A QR campaign is launched like any other; the operator uses
// these codes manually (print them, embed them in a payload PDF, etc.). The
// scan itself is tracked via the normal /t/{token} route (see trackClick): on a
// qr-channel campaign the first hit records a scanned event before the click.
//
// Read-but-audited (qrcode.view), mirroring the report-export endpoints. PDF/zip
// assembly is intentionally out of scope.
func (s *Server) campaignQRCodes(w http.ResponseWriter, r *http.Request) {
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

	recs, err := s.recipients.ListByCampaign(r.Context(), s.pool, p.TenantID, id)
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "list recipients")
		return
	}

	items := make([]map[string]any, 0, len(recs))
	for _, rec := range recs {
		clickURL := s.baseURL + "/t/" + rec.Token
		png, err := qr.PNG(clickURL, s.qrSize, s.qrECLevel)
		if err != nil {
			httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "render qr code")
			return
		}
		b64 := base64.StdEncoding.EncodeToString(png)
		items = append(items, map[string]any{
			"recipient_id":  rec.ID,
			"contact_id":    rec.ContactID,
			"token":         rec.Token,
			"click_url":     clickURL,
			"qr_png_base64": b64,
			"data_uri":      "data:image/png;base64," + b64,
		})
	}

	if err := s.auditView(r, "qrcode.view", "campaign", id.String()); err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "audit write")
		return
	}

	httpx.JSON(w, http.StatusOK, map[string]any{
		"campaign_id": id,
		"channel":     camp.Channel,
		"size":        s.qrSize,
		"ec_level":    s.qrECLevel,
		"items":       items,
	})
}
