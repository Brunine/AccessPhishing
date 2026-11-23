package delivery

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"phishforge/internal/sendingprofile"
)

// SMSConfig holds process-wide defaults for the SMS channel. Provider
// credentials come from the sending profile, not from env — only the base URL
// (for testing against a mock) and timeout are process-level.
type SMSConfig struct {
	BaseURL string // e.g. https://api.twilio.com
	Timeout time.Duration
}

// UseSMS sets the SMS channel configuration on the sender.
func (s *Sender) UseSMS(cfg SMSConfig) { s.sms = cfg }

// smsSender delivers a plain-text message via the Twilio Messages API using
// HTTP basic auth (Account SID + Auth Token). The "subject" argument of the
// channelSender interface is ignored for SMS; the body is sent as-is.
type smsSender struct {
	http       *http.Client
	baseURL    string
	accountSID string
	authToken  string
	from       string
}

func newSMSSender(p sendingprofile.Profile, cfg SMSConfig, secret string) *smsSender {
	base := strings.TrimRight(cfg.BaseURL, "/")
	if base == "" {
		base = "https://api.twilio.com"
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &smsSender{
		http:       &http.Client{Timeout: timeout},
		baseURL:    base,
		accountSID: orElse(p.APIClientID, ""), // Twilio Account SID (non-secret)
		authToken:  secret,                    // Twilio Auth Token (AES-GCM sealed at rest)
		from:       orElse(p.SMSSenderID, ""),
	}
}

func (s *smsSender) Send(ctx context.Context, to, _subject, body string) error {
	if s.accountSID == "" || s.authToken == "" {
		return fmt.Errorf("sms: missing Twilio account SID / auth token on the profile")
	}
	form := url.Values{"To": {to}, "Body": {body}}
	if s.from != "" {
		form.Set("From", s.from)
	}
	endpoint := fmt.Sprintf("%s/2010-04-01/Accounts/%s/Messages.json", s.baseURL, url.PathEscape(s.accountSID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("sms: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(s.accountSID, s.authToken)

	resp, err := s.http.Do(req)
	if err != nil {
		return fmt.Errorf("sms: request failed: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("sms: twilio %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return nil
}
