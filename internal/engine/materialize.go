package engine

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"phishforge/internal/engineconfig"
)

// Materialize writes the effective (defaults-applied) config as a YAML file
// under dir, named <id>.yaml, and returns its path. The engine process
// receives this path as its -config argument (appended by the caller at
// spawn time). Files are 0600 and the dir 0700 since configs may reference
// TLS key material.
func Materialize(dir, id string, cfg engineconfig.Config) (string, error) {
	if dir == "" {
		return "", fmt.Errorf("engine: materialize: data dir not configured")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("engine: materialize: mkdir: %w", err)
	}
	b, err := yaml.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("engine: materialize: marshal: %w", err)
	}
	path := filepath.Join(dir, id+".yaml")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return "", fmt.Errorf("engine: materialize: write: %w", err)
	}
	return path, nil
}

// Runtime describes the resolved network endpoints of an engine, for the
// dashboard and campaign-link resolution.
type Runtime struct {
	ListenAddr string `json:"listen_addr,omitempty"`
	TLSEnabled bool   `json:"tls_enabled"`
	Scheme     string `json:"scheme,omitempty"`
	Host       string `json:"host,omitempty"`
	Port       int    `json:"port,omitempty"`
}

// RuntimeOf extracts the network endpoints from a validated config.
func RuntimeOf(cfg engineconfig.Config) Runtime {
	var rt Runtime
	if cfg.Listener != nil {
		rt.ListenAddr = cfg.Listener.ListenAddr
		rt.TLSEnabled = cfg.Listener.TLS != nil
	}
	if cfg.Upstream != nil {
		rt.Scheme = cfg.Upstream.Scheme
		rt.Host = cfg.Upstream.Host
		rt.Port = cfg.Upstream.Port
	}
	return rt
}

// PublicURL returns the externally reachable URL of the engine's listener,
// or "" when no listener is configured. hostOverride replaces the bind host
// (0.0.0.0 / :: are not routable; the operator supplies the public hostname).
func PublicURL(cfg engineconfig.Config, hostOverride string) string {
	if cfg.Listener == nil || cfg.Listener.ListenAddr == "" {
		return ""
	}
	scheme := "http"
	if cfg.Listener.TLS != nil {
		scheme = "https"
	}
	_, port, err := net.SplitHostPort(cfg.Listener.ListenAddr)
	if err != nil {
		return ""
	}
	host := hostOverride
	if host == "" {
		host, _, _ = net.SplitHostPort(cfg.Listener.ListenAddr)
		if host == "0.0.0.0" || host == "::" || host == "" {
			host = "localhost"
		}
	}
	return fmt.Sprintf("%s://%s:%s", scheme, host, port)
}