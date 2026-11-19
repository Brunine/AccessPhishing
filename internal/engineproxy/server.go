// Package engineproxy implements the traffic-handling engine binary's core:
// it binds the configured listener (optionally TLS) and reverse-proxies all
// traffic to the configured upstream. The orchestrator supervises this
// process and hands it a materialized engine config file; this package owns
// only traffic handling. Batch A: proxying + health. Event capture/reporting
// arrives in batch B.
package engineproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"phishforge/internal/engineconfig"
)

// HealthPath is served locally by the proxy and never forwarded upstream.
// Operators (and the orchestrator's future readiness check) probe it.
const HealthPath = "/engineproxy-health"

// Server is the running proxy instance for one engine config.
type Server struct {
	cfg         engineconfig.Config
	logger      *slog.Logger
	httpSrv     *http.Server
	interceptor *Interceptor
}

// New builds a Server from a validated config. Parse (not just Validate)
// must have produced cfg so defaults are applied.
func New(cfg engineconfig.Config, logger *slog.Logger, ic *Interceptor) (*Server, error) {
	if cfg.Listener == nil || cfg.Listener.ListenAddr == "" {
		return nil, errors.New("engineproxy: config has no listener section")
	}
	if cfg.Upstream == nil {
		return nil, errors.New("engineproxy: config has no upstream section")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{cfg: cfg, logger: logger, interceptor: ic}, nil
}

// upstreamURL resolves the configured upstream into a base URL.
func (s *Server) upstreamURL() (*url.URL, error) {
	u := &url.URL{
		Scheme: s.cfg.Upstream.Scheme,
		Host:   net.JoinHostPort(strings.Trim(s.cfg.Upstream.Host, "[]"), fmt.Sprint(s.cfg.Upstream.Port)),
	}
	return u.Parse("")
}

// newReverseProxy builds the httputil.ReverseProxy for the upstream. Host is
// rewritten to the upstream so vhost-based backends resolve correctly.
func (s *Server) newReverseProxy(target *url.URL) *httputil.ReverseProxy {
	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = target.Host
		},
		// Long-lived upstream connections; upstream is typically a large
		// SaaS origin with HTTP/2.
		Transport: s.newTransport(),
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			s.logger.Error("proxy error", "method", r.Method, "path", r.URL.Path, "err", err)
			w.WriteHeader(http.StatusBadGateway)
		},
		ModifyResponse: func(resp *http.Response) error {
			s.interceptor.InspectResponse(resp)
			return nil
		},
	}
	return rp
}

// newTransport returns the upstream transport. TLS verification is on by
// default; the upstream is the legitimate origin.
func (s *Server) newTransport() http.RoundTripper {
	t := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   20,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	return t
}

func (s *Server) handler(rp *httputil.ReverseProxy) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(HealthPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	// Root catch-all proxies; /engineproxy-health never reaches it because
	// ServeMux serves the longest registered pattern first.
	mux.Handle("/", rp)

	// Wrap the whole mux with the capture middleware (nil-safe: a nil
	// interceptor returns next unchanged).
	var h http.Handler = mux
	h = s.interceptor.RequestMiddleware(h)
	return h
}

// Start binds the configured listener and serves until Stop.
func (s *Server) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Listener.ListenAddr)
	if err != nil {
		return fmt.Errorf("engineproxy: listen %s: %w", s.cfg.Listener.ListenAddr, err)
	}
	return s.Serve(ctx, ln)
}

// Serve serves on the provided listener (bound listener, host:port fixed by
// the caller) until Stop or ctx cancellation. TLS is enabled when the config
// carries certificate/key paths.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	target, err := s.upstreamURL()
	if err != nil {
		_ = ln.Close()
		return fmt.Errorf("engineproxy: upstream url: %w", err)
	}
	rp := s.newReverseProxy(target)

	s.httpSrv = &http.Server{
		Handler:           s.handler(rp),
		ReadHeaderTimeout: 10 * time.Second,
		// Long-lived proxy connections; no blanket WriteTimeout.
		IdleTimeout: 120 * time.Second,
	}

	if s.cfg.Listener.TLS != nil {
		cert, err := tls.LoadX509KeyPair(s.cfg.Listener.TLS.CertFile, s.cfg.Listener.TLS.KeyFile)
		if err != nil {
			_ = ln.Close()
			return fmt.Errorf("engineproxy: load tls material: %w", err)
		}
		s.httpSrv.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		ln = tls.NewListener(ln, s.httpSrv.TLSConfig)
	}

	s.logger.Info("engineproxy listening",
		"addr", ln.Addr().String(), "upstream", target.String(), "tls", s.cfg.Listener.TLS != nil)

	go func() {
		<-ctx.Done()
		_ = s.Stop(context.Background())
	}()

	err = s.httpSrv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Stop gracefully drains active connections then returns.
func (s *Server) Stop(ctx context.Context) error {
	if s.httpSrv == nil {
		return nil
	}
	sctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	err := s.httpSrv.Shutdown(sctx)
	s.httpSrv = nil
	return err
}
