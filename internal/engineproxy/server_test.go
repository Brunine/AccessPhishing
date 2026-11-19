package engineproxy

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"phishforge/internal/engineconfig"
)

func testConfig(listenAddr, upstreamHost string, upstreamPort int, upstreamScheme string) engineconfig.Config {
	return engineconfig.Config{
		Kind:     "proxy",
		Listener: &engineconfig.Listener{ListenAddr: listenAddr},
		Upstream: &engineconfig.Upstream{Scheme: upstreamScheme, Host: upstreamHost, Port: upstreamPort},
	}
}

func TestProxyForwardsToUpstream(t *testing.T) {
	// Upstream echoes the Host header it received.
	var gotHost, gotPath string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		gotPath = r.URL.Path
		w.WriteHeader(200)
		_, _ = w.Write([]byte("upstream-body"))
	}))
	defer up.Close()

	hostPort := up.URL[len("http://"):]
	host, port := splitHostPort(t, hostPort)

	srv, err := New(testConfig("127.0.0.1:0", host, port, "http"), slog.Default(), nil)
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	ln, err := listenFree()
	if err != nil {
		t.Fatalf("listenFree: %v", err)
	}
	addr := ln.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ctx, ln) }()

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + addr + "/some/path")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	buf := make([]byte, 13)
	_, _ = io.ReadFull(resp.Body, buf)
	if string(buf) != "upstream-body" {
		t.Fatalf("body = %q", buf)
	}
	if gotPath != "/some/path" {
		t.Fatalf("upstream path = %q", gotPath)
	}
	if gotHost != hostPort {
		t.Fatalf("upstream Host = %q, want %q", gotHost, hostPort)
	}

	if err := srv.Stop(context.Background()); err != nil {
		t.Fatalf("stop: %v", err)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("serve error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not return after Stop")
	}
}

func TestHealthPathServedLocally(t *testing.T) {
	srv, err := New(testConfig("127.0.0.1:0", "invalid.invalid", 80, "http"), slog.Default(), nil)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	// We do not Start (upstream unreachable); call the handler directly.
	h := srv.handler(srv.newReverseProxy(mustURL(t, "http://invalid.invalid:80")))
	req := httptest.NewRequest("GET", HealthPath, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("health status = %d", rec.Code)
	}
	if got := rec.Body.String(); got != `{"status":"ok"}` {
		t.Fatalf("health body = %q", got)
	}
}

func TestNewRejectsMissingSections(t *testing.T) {
	if _, err := New(engineconfig.Config{Kind: "proxy"}, slog.Default(), nil); err == nil {
		t.Fatal("want error for missing listener")
	}
	cfg := engineconfig.Config{Kind: "proxy", Listener: &engineconfig.Listener{ListenAddr: "127.0.0.1:80"}}
	if _, err := New(cfg, slog.Default(), nil); err == nil {
		t.Fatal("want error for missing upstream")
	}
}
