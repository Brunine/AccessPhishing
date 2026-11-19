package delivery

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"phishforge/internal/sendingprofile"
)

// GmailConfig holds process-wide defaults for the Gmail channel (OAuth2
// refresh-token flow). A profile may override the client id and provide its own
// refresh token (the encrypted secret); empty values fall back to these.
type GmailConfig struct {
	TokenURL     string // default https://oauth2.googleapis.com/token
	BaseURL      string // default https://gmail.googleapis.com
	ClientID     string
	ClientSecret string
	RefreshToken string
}

// UseGmail sets the Gmail channel configuration on the sender.
func (s *Sender) UseGmail(cfg GmailConfig) { s.gmail = cfg }

// gmailSender delivers mail via the Gmail API using an OAuth2 refresh token to
// mint short-lived access tokens (cached until shortly before expiry). Safe for
// concurrent use.
type gmailSender struct {
	http         *http.Client
	tokenURL     string
	baseURL      string
	clientID     string
	clientSecret string
	refreshToken string
	fromAddr     string
	fromName     string

	mu       sync.Mutex
	token    string
	tokenExp time.Time
}

func newGmailSender(p sendingprofile.Profile, cfg GmailConfig, secret string) *gmailSender {
	tokenURL := strings.TrimRight(cfg.TokenURL, "/")
	if tokenURL == "" {
		tokenURL = "https://oauth2.googleapis.com/token"
	}
	base := strings.TrimRight(cfg.BaseURL, "/")
	if base == "" {
		base = "https://gmail.googleapis.com"
	}
	fromName := ""
	if p.FromName != nil {
		fromName = *p.FromName
	}
	return &gmailSender{
		http:         &http.Client{Timeout: 30 * time.Second},
		tokenURL:     tokenURL,
		baseURL:      base,
		clientID:     orElse(p.APIClientID, cfg.ClientID),
		clientSecret: cfg.ClientSecret,
		refreshToken: orElseStr(secret, cfg.RefreshToken),
		fromAddr:     p.FromAddress,
		fromName:     fromName,
	}
}

func (g *gmailSender) token_(ctx context.Context) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.token != "" && time.Now().Before(g.tokenExp) {
		return g.token, nil
	}
	if g.clientID == "" || g.clientSecret == "" || g.refreshToken == "" {
		return "", fmt.Errorf("gmail: missing client id/secret/refresh token (set GMAIL_* or the profile's api fields + secret)")
	}

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {g.clientID},
		"client_secret": {g.clientSecret},
		"refresh_token": {g.refreshToken},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("gmail: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := g.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("gmail: token request failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("gmail: token endpoint %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", fmt.Errorf("gmail: decode token: %w", err)
	}
	if tok.AccessToken == "" {
		return "", fmt.Errorf("gmail: empty access_token")
	}
	ttl := time.Duration(tok.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = 3600 * time.Second
	}
	g.token = tok.AccessToken
	g.tokenExp = time.Now().Add(ttl - 60*time.Second)
	return g.token, nil
}

func (g *gmailSender) Send(ctx context.Context, to, subject, htmlBody string) error {
	for attempt := 0; attempt < 2; attempt++ {
		retryAfter, err := g.sendOnce(ctx, to, subject, htmlBody)
		if err == nil {
			return nil
		}
		if retryAfter <= 0 || attempt == 1 {
			return err
		}
		if retryAfter > 60*time.Second {
			retryAfter = 60 * time.Second
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(retryAfter):
		}
	}
	return fmt.Errorf("gmail: send exhausted retries")
}

func (g *gmailSender) sendOnce(ctx context.Context, to, subject, htmlBody string) (time.Duration, error) {
	tok, err := g.token_(ctx)
	if err != nil {
		return 0, err
	}

	raw := rfc2822HTML(g.fromAddr, g.fromName, to, subject, htmlBody)
	encoded := base64.URLEncoding.EncodeToString([]byte(raw))
	payload, err := json.Marshal(map[string]string{"raw": encoded})
	if err != nil {
		return 0, fmt.Errorf("gmail: marshal message: %w", err)
	}

	endpoint := g.baseURL + "/gmail/v1/users/me/messages/send"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(payload)))
	if err != nil {
		return 0, fmt.Errorf("gmail: build send request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")

	resp, err := g.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("gmail: send request failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode == http.StatusTooManyRequests {
		return parseRetryAfter(resp.Header.Get("Retry-After")), fmt.Errorf("gmail: 429 rate limited")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, fmt.Errorf("gmail: messages.send %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return 0, nil
}
