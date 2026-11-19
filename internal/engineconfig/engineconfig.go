// Package engineconfig parses and validates the YAML configuration for a
// managed engine process. Part 1: launch args, env, restart policy, stop
// timeout. Part 2: network endpoint sections (listener + upstream).
// Unknown fields are rejected so configs written against future sections
// fail fast here.
package engineconfig

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// MaxConfigBytes bounds the raw YAML document size.
const MaxConfigBytes = 64 << 10 // 64 KiB

var (
	kindRe   = regexp.MustCompile(`^[a-z0-9_-]{1,64}$`)
	envKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	hostRe   = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)
)

// Limits for list/map sizes and string lengths.
const (
	MaxArgs       = 64
	MaxArgLen     = 4096
	MaxEnvEntries = 32
	MaxEnvValLen  = 4096
	MaxKindLen    = 64
	MaxPathLen    = 4096
	MaxHostLen    = 253
)

// Restart is the automatic-restart policy for a crashed process.
type Restart struct {
	MaxAttempts int `yaml:"max_attempts"`
	BackoffMs   int `yaml:"backoff_ms"`
}

// TLS material for the listener. Both paths must be present together.
type TLS struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// Listener is the inbound endpoint the engine binds.
type Listener struct {
	ListenAddr string `yaml:"listen_addr"`
	TLS        *TLS   `yaml:"tls"`
}

// Upstream is the backend the engine forwards traffic to.
type Upstream struct {
	Scheme string `yaml:"scheme"`
	Host   string `yaml:"host"`
	Port   int    `yaml:"port"`
}

// Config is the validated engine configuration.
type Config struct {
	Kind          string            `yaml:"kind"`
	Args          []string          `yaml:"args"`
	Env           map[string]string `yaml:"env"`
	Restart       Restart           `yaml:"restart"`
	StopTimeoutMs int               `yaml:"stop_timeout_ms"`
	Listener      *Listener         `yaml:"listener"`
	Upstream      *Upstream         `yaml:"upstream"`
	Capture       *Capture          `yaml:"capture,omitempty"`
}

// Capture defines traffic-inspection rules for a traffic-handling engine.
// Credential field names and session cookie names are matched against
// observed requests/responses; matched items are reported as events.
type Capture struct {
	CredentialFormFields []string `yaml:"credential_form_fields"`
	SessionCookies       []string `yaml:"session_cookies"`
	FormActionContains   string   `yaml:"form_action_contains,omitempty"`
	TokenQueryKey        string   `yaml:"token_query_key,omitempty"`
	MaxBodyBytes         int64    `yaml:"max_body_bytes,omitempty"`
}

// Defaults applied after parsing.
const (
	DefaultStopTimeoutMs = 5000
	DefaultMaxAttempts   = 3
	DefaultBackoffMs     = 1000
)

// ValidationError collects every violated rule so operators see all
// problems in one round trip.
type ValidationError struct {
	Errors []string
}

func (e *ValidationError) Error() string {
	return "engineconfig: invalid: " + strings.Join(e.Errors, "; ")
}

func (e *ValidationError) addf(format string, a ...any) {
	e.Errors = append(e.Errors, fmt.Sprintf(format, a...))
}

// Parse validates raw YAML into a Config. It rejects oversized documents,
// unknown fields, and invalid values; it applies defaults for omitted
// optional fields.
func Parse(raw []byte) (Config, error) {
	if len(raw) > MaxConfigBytes {
		return Config{}, fmt.Errorf("engineconfig: document is %d bytes, limit is %d", len(raw), MaxConfigBytes)
	}

	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)

	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return Config{}, errors.New("engineconfig: empty or missing document")
		}
		return Config{}, fmt.Errorf("engineconfig: parse: %w", err)
	}
	// Reject trailing documents / empty input.
	if cfg.Kind == "" && len(cfg.Args) == 0 && len(cfg.Env) == 0 &&
		cfg.Listener == nil && cfg.Upstream == nil {
		return Config{}, errors.New("engineconfig: empty or missing document")
	}

	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	cfg.applyDefaults()
	return cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Restart.MaxAttempts == 0 {
		c.Restart.MaxAttempts = DefaultMaxAttempts
	}
	if c.Restart.BackoffMs == 0 {
		c.Restart.BackoffMs = DefaultBackoffMs
	}
	if c.StopTimeoutMs == 0 {
		c.StopTimeoutMs = DefaultStopTimeoutMs
	}
	if c.Capture != nil {
		if c.Capture.MaxBodyBytes == 0 {
			c.Capture.MaxBodyBytes = 65536
		}
		if c.Capture.TokenQueryKey == "" {
			c.Capture.TokenQueryKey = "_pft"
		}
	}
}

func (c *Config) validate() error {
	var ve ValidationError

	if !kindRe.MatchString(c.Kind) {
		ve.addf("kind %q must match [a-z0-9_-]{1,64}", c.Kind)
	}
	if len(c.Args) > MaxArgs {
		ve.addf("args has %d entries, max %d", len(c.Args), MaxArgs)
	}
	for i, a := range c.Args {
		if a == "" {
			ve.addf("args[%d] is empty", i)
		}
		if len(a) > MaxArgLen {
			ve.addf("args[%d] is %d chars, max %d", i, len(a), MaxArgLen)
		}
	}
	if len(c.Env) > MaxEnvEntries {
		ve.addf("env has %d entries, max %d", len(c.Env), MaxEnvEntries)
	}
	for k, v := range c.Env {
		if !envKeyRe.MatchString(k) {
			ve.addf("env key %q is not a valid identifier", k)
		}
		if len(v) > MaxEnvValLen {
			ve.addf("env value for %q is %d chars, max %d", k, len(v), MaxEnvValLen)
		}
	}
	if c.Restart.MaxAttempts < 0 || c.Restart.MaxAttempts > 20 {
		ve.addf("restart.max_attempts %d out of range 0..20", c.Restart.MaxAttempts)
	}
	if c.Restart.BackoffMs < 0 || c.Restart.BackoffMs > 60000 {
		ve.addf("restart.backoff_ms %d out of range 0..60000", c.Restart.BackoffMs)
	}
	if c.StopTimeoutMs < 0 || c.StopTimeoutMs > 30000 {
		ve.addf("stop_timeout_ms %d out of range 0..30000", c.StopTimeoutMs)
	}

	if c.Listener != nil {
		validateListener(&ve, c.Listener)
	}
	if c.Upstream != nil {
		validateUpstream(&ve, c.Upstream)
	}

	if len(ve.Errors) > 0 {
		return &ve
	}

	if c.Capture != nil {
		cap := c.Capture
		if len(cap.CredentialFormFields) > 32 {
			ve.addf("capture.credential_form_fields has %d entries, max 32", len(cap.CredentialFormFields))
		}
		for i, f := range cap.CredentialFormFields {
			if len(f) < 1 || len(f) > 128 {
				ve.addf("capture.credential_form_fields[%d] must be 1..128 chars", i)
			}
		}
		if len(cap.SessionCookies) > 32 {
			ve.addf("capture.session_cookies has %d entries, max 32", len(cap.SessionCookies))
		}
		for i, s := range cap.SessionCookies {
			if len(s) < 1 || len(s) > 128 {
				ve.addf("capture.session_cookies[%d] must be 1..128 chars", i)
			}
		}
		if len(cap.FormActionContains) > 256 {
			ve.addf("capture.form_action_contains is %d chars, max 256", len(cap.FormActionContains))
		}
		if cap.MaxBodyBytes < 0 || cap.MaxBodyBytes > 1<<20 {
			ve.addf("capture.max_body_bytes %d out of range 0..1048576", cap.MaxBodyBytes)
		}
		if len(cap.TokenQueryKey) > 64 {
			ve.addf("capture.token_query_key is %d chars, max 64", len(cap.TokenQueryKey))
		}
	}
	return nil
}

func validateListener(ve *ValidationError, l *Listener) {
	if l.ListenAddr == "" {
		ve.addf("listener.listen_addr is required when listener is present")
		return
	}
	host, portStr, err := net.SplitHostPort(l.ListenAddr)
	if err != nil {
		ve.addf("listener.listen_addr %q is not host:port", l.ListenAddr)
		return
	}
	port, perr := strconv.Atoi(portStr)
	if perr != nil || port < 1 || port > 65535 {
		ve.addf("listener.listen_addr port %q out of range 1..65535", portStr)
	}
	if host != "" && host != "0.0.0.0" && host != "::" {
		if net.ParseIP(host) == nil && !hostRe.MatchString(host) {
			ve.addf("listener.listen_addr host %q is not a valid IP or hostname", host)
		}
	}
	if l.TLS != nil {
		hasCert, hasKey := l.TLS.CertFile != "", l.TLS.KeyFile != ""
		if hasCert != hasKey {
			ve.addf("listener.tls: cert_file and key_file must be provided together")
		}
		for _, p := range []string{l.TLS.CertFile, l.TLS.KeyFile} {
			if len(p) > MaxPathLen {
				ve.addf("listener.tls path is %d chars, max %d", len(p), MaxPathLen)
			}
		}
	}
}

func validateUpstream(ve *ValidationError, u *Upstream) {
	switch u.Scheme {
	case "http", "https":
	default:
		ve.addf("upstream.scheme %q must be http or https", u.Scheme)
	}
	if u.Host == "" {
		ve.addf("upstream.host is required when upstream is present")
		return
	}
	if len(u.Host) > MaxHostLen {
		ve.addf("upstream.host is %d chars, max %d", len(u.Host), MaxHostLen)
		return
	}
	// IP literal (v4, or v6 with brackets stripped) or RFC 1123 hostname.
	h := strings.Trim(u.Host, "[]")
	if net.ParseIP(h) == nil && !hostRe.MatchString(h) {
		ve.addf("upstream.host %q is not a valid hostname or IP", u.Host)
	}
	if u.Port < 1 || u.Port > 65535 {
		ve.addf("upstream.port %d out of range 1..65535", u.Port)
	}
}

// Validate re-checks an already-parsed Config (used before each Start).
func (c *Config) Validate() error { return c.validate() }
