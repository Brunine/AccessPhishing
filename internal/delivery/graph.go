package delivery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"phishforge/internal/sendingprofile"
)

// graphSender delivers mail via the Microsoft Graph sendMail API using the
// OAuth2 client-credentials flow. The access token is cached in memory until
// shortly before expiry. Safe for concurrent use.
type graphSender struct {
	http     *http.Client
	loginURL string
	graphURL string
	tenantID string
	clientID string
	secret   string
	sender   string // mailbox: /users/{sender}/sendMail
	fromName string

	mu       sync.Mutex
	token    string
	tokenExp time.Time
}

func newGraphSender(p sendingprofile.Profile, cfg GraphConfig, secret string) *graphSender {
	login := strings.TrimRight(cfg.LoginBaseURL, "/")
	if login == "" {
		login = "https://login.microsoftonline.com"
	}
	graph := strings.TrimRight(cfg.GraphBaseURL, "/")
	if graph == "" {
		graph = "https://graph.microsoft.com"
	}
	fromName := ""
	if p.FromName != nil {
		fromName = *p.FromName
	}
	return &graphSender{
		http:     &http.Client{Timeout: 30 * time.Second},
		loginURL: login,
		graphURL: graph,
		tenantID: orElse(p.APITenantID, cfg.TenantID),
		clientID: orElse(p.APIClientID, cfg.ClientID),
		secret:   orElseStr(secret, cfg.ClientSecret),
		sender:   p.FromAddress,
		fromName: fromName,
	}
}

func orElseStr(v, fallback string) string {
	if v != "" {
		return v
	}
	return fallback
}

func (g *graphSender) token_(ctx context.Context) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.token != "" && time.Now().Before(g.tokenExp) {
		return g.token, nil
	}
	if g.tenantID == "" || g.clientID == "" || g.secret == "" {
		return "", fmt.Errorf("graph: missing tenant/client/secret (set GRAPH_* or the profile's api fields)")
	}

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {g.clientID},
		"client_secret": {g.secret},
		"scope":         {g.graphURL + "/.default"},
	}
	endpoint := fmt.Sprintf("%s/%s/oauth2/v2.0/token", g.loginURL, g.tenantID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("graph: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := g.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("graph: token request failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("graph: token endpoint %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", fmt.Errorf("graph: decode token: %w", err)
	}
	if tok.AccessToken == "" {
		return "", fmt.Errorf("graph: empty access_token")
	}
	ttl := time.Duration(tok.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = 3600 * time.Second
	}
	g.token = tok.AccessToken
	g.tokenExp = time.Now().Add(ttl - 60*time.Second) // refresh a minute early
	return g.token, nil
}

// graphMessage is the sendMail request body.
type graphMessage struct {
	Message struct {
		Subject string `json:"subject"`
		Body    struct {
			ContentType string `json:"contentType"`
			Content     string `json:"content"`
		} `json:"body"`
		ToRecipients []graphRecipient `json:"toRecipients"`
		From         *graphRecipient  `json:"from,omitempty"`
	} `json:"message"`
	SaveToSentItems bool `json:"saveToSentItems"`
}

type graphRecipient struct {
	EmailAddress struct {
		Address string `json:"address"`
		Name    string `json:"name,omitempty"`
	} `json:"emailAddress"`
}

func (g *graphSender) Send(ctx context.Context, to, subject, htmlBody string) error {
	// One retry on 429, honoring Retry-After (bounded).
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
	return fmt.Errorf("graph: send exhausted retries")
}

// sendOnce returns (retryAfter, err); retryAfter > 0 signals a 429 to retry.
func (g *graphSender) sendOnce(ctx context.Context, to, subject, htmlBody string) (time.Duration, error) {
	tok, err := g.token_(ctx)
	if err != nil {
		return 0, err
	}

	var msg graphMessage
	msg.Message.Subject = subject
	msg.Message.Body.ContentType = "HTML"
	msg.Message.Body.Content = htmlBody
	var rcpt graphRecipient
	rcpt.EmailAddress.Address = to
	msg.Message.ToRecipients = []graphRecipient{rcpt}
	if g.sender != "" {
		from := &graphRecipient{}
		from.EmailAddress.Address = g.sender
		from.EmailAddress.Name = g.fromName
		msg.Message.From = from
	}
	msg.SaveToSentItems = false

	payload, err := json.Marshal(msg)
	if err != nil {
		return 0, fmt.Errorf("graph: marshal message: %w", err)
	}
	endpoint := fmt.Sprintf("%s/v1.0/users/%s/sendMail", g.graphURL, url.PathEscape(g.sender))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(payload)))
	if err != nil {
		return 0, fmt.Errorf("graph: build send request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")

	resp, err := g.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("graph: send request failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode == http.StatusTooManyRequests {
		return parseRetryAfter(resp.Header.Get("Retry-After")), fmt.Errorf("graph: 429 rate limited")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, fmt.Errorf("graph: sendMail %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return 0, nil
}

func parseRetryAfter(h string) time.Duration {
	if h == "" {
		return 5 * time.Second
	}
	if secs, err := strconv.Atoi(strings.TrimSpace(h)); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(h); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 5 * time.Second
}
