package engineconfig

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		raw     string
		wantErr string // substring; empty means success
		check   func(t *testing.T, c Config)
	}{
		{
			name: "minimal valid",
			raw:  "kind: proxy\n",
			check: func(t *testing.T, c Config) {
				if c.Kind != "proxy" {
					t.Fatalf("kind = %q", c.Kind)
				}
				if c.StopTimeoutMs != DefaultStopTimeoutMs {
					t.Fatalf("stop default not applied: %d", c.StopTimeoutMs)
				}
				if c.Restart.MaxAttempts != DefaultMaxAttempts || c.Restart.BackoffMs != DefaultBackoffMs {
					t.Fatalf("restart defaults not applied: %+v", c.Restart)
				}
			},
		},
		{
			name: "full valid",
			raw: `kind: proxy
args: ["-config", "/etc/e.yaml"]
env:
  GOMAXPROCS: "4"
restart:
  max_attempts: 5
  backoff_ms: 250
stop_timeout_ms: 3000
`,
			check: func(t *testing.T, c Config) {
				if len(c.Args) != 2 || c.Args[1] != "/etc/e.yaml" {
					t.Fatalf("args = %v", c.Args)
				}
				if c.Env["GOMAXPROCS"] != "4" {
					t.Fatalf("env = %v", c.Env)
				}
				if c.Restart.MaxAttempts != 5 || c.Restart.BackoffMs != 250 || c.StopTimeoutMs != 3000 {
					t.Fatalf("fields not parsed: %+v %d", c.Restart, c.StopTimeoutMs)
				}
			},
		},
		{name: "unknown field rejected", raw: "kind: proxy\nnot_a_field: 1\n", wantErr: "field not_a_field not found"},
		{name: "missing kind", raw: "args: [x]\n", wantErr: `kind "" must match`},
		{name: "empty document", raw: "", wantErr: "empty or missing"},
		{name: "bad kind charset", raw: "kind: \"Bad Kind!\"\n", wantErr: "kind"},
		{name: "kind too long", raw: "kind: " + strings.Repeat("a", 65) + "\n", wantErr: "kind"},
		{name: "too many args", raw: "kind: p\nargs:\n" + strings.Repeat("  - a\n", MaxArgs+1), wantErr: "args has"},
		{name: "empty arg", raw: "kind: p\nargs: [\"\"]\n", wantErr: "args[0] is empty"},
		{name: "bad env key", raw: "kind: p\nenv:\n  \"9bad\": v\n", wantErr: "not a valid identifier"},
		{name: "too many env", raw: "kind: p\nenv:\n" + func() string {
			var b strings.Builder
			for i := 0; i < MaxEnvEntries+1; i++ {
				b.WriteString("  K" + strings.Repeat("x", i) + ": v\n")
			}
			return b.String()
		}(), wantErr: "env has"},
		{name: "negative restart", raw: "kind: p\nrestart:\n  max_attempts: -1\n", wantErr: "max_attempts"},
		{name: "stop timeout out of range", raw: "kind: p\nstop_timeout_ms: 99999\n", wantErr: "stop_timeout_ms"},
		{name: "not yaml", raw: "\t\t[[[\n", wantErr: "parse"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := Parse([]byte(tt.raw))
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("want error containing %q, got nil (cfg %+v)", tt.wantErr, cfg)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, cfg)
			}
		})
	}
}

func TestParseTooLarge(t *testing.T) {
	t.Parallel()
	raw := "kind: proxy\n# " + strings.Repeat("x", MaxConfigBytes)
	if _, err := Parse([]byte(raw)); err == nil || !strings.Contains(err.Error(), "limit is") {
		t.Fatalf("want size-limit error, got %v", err)
	}
}
