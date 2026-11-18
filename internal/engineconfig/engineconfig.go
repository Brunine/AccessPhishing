// Package engineconfig parses and validates the YAML configuration for a
// managed engine process. Part 1 is structural only: launch args, env,
// restart policy, and stop timeout. Unknown fields are rejected so that
// configs written against future (part 2+) sections fail fast here.
package engineconfig

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// MaxConfigBytes bounds the raw YAML document size.
const MaxConfigBytes = 64 << 10 // 64 KiB

var (
	kindRe  = regexp.MustCompile(`^[a-z0-9_-]{1,64}$`)
	envKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// Limits for list/map sizes and string lengths.
const (
	MaxArgs        = 64
	MaxArgLen      = 4096
	MaxEnvEntries  = 32
	MaxEnvValLen   = 4096
	MaxKindLen     = 64
)

// Restart is the automatic-restart policy for a crashed process.
type Restart struct {
	MaxAttempts int `yaml:"max_attempts"`
	BackoffMs   int `yaml:"backoff_ms"`
}

// Config is the validated, launch-oriented engine configuration.
type Config struct {
	Kind          string            `yaml:"kind"`
	Args          []string          `yaml:"args"`
	Env           map[string]string `yaml:"env"`
	Restart       Restart           `yaml:"restart"`
	StopTimeoutMs int               `yaml:"stop_timeout_ms"`
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

func (e *ValidationError) add(msg string) {
	e.Errors = append(e.Errors, msg)
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
		return Config{}, fmt.Errorf("engineconfig: parse: %w", err)
	}
	// Reject trailing documents / empty input.
	if cfg.Kind == "" && len(cfg.Args) == 0 && len(cfg.Env) == 0 {
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
}

func (c *Config) validate() error {
	var ve ValidationError

	if c.Kind == "" {
		ve.add("kind: empty or missing")
	} else if !kindRe.MatchString(c.Kind) {
		ve.add(fmt.Sprintf("kind %q must match [a-z0-9_-]{1,64}", c.Kind))
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

	if len(ve.Errors) > 0 {
		return &ve
	}
	return nil
}

// Validate re-checks an already-parsed Config (used before each Start).
func (c *Config) Validate() error { return c.validate() }

// StopTimeout returns the graceful-stop deadline.
func (c *Config) StopTimeout() (ms int) { return c.StopTimeoutMs }