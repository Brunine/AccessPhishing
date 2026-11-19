package engineconfig

import (
	"strings"
	"testing"
)

// TestParsePart2 covers the listener + upstream sections added in part 2,
// including that part-1 tests' rejection of these fields no longer applies.
func TestParsePart2(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		raw     string
		wantErr string
		check   func(t *testing.T, c Config)
	}{
		{
			name: "full part 2 config",
			raw: `kind: proxy
listener:
  listen_addr: "0.0.0.0:443"
  tls:
    cert_file: /etc/engines/cert.pem
    key_file: /etc/engines/key.pem
upstream:
  scheme: https
  host: login.example.com
  port: 443
`,
			check: func(t *testing.T, c Config) {
				if c.Listener == nil || c.Listener.ListenAddr != "0.0.0.0:443" {
					t.Fatalf("listener = %+v", c.Listener)
				}
				if c.Listener.TLS == nil || c.Listener.TLS.CertFile == "" || c.Listener.TLS.KeyFile == "" {
					t.Fatalf("tls = %+v", c.Listener.TLS)
				}
				if c.Upstream == nil || c.Upstream.Scheme != "https" || c.Upstream.Host != "login.example.com" || c.Upstream.Port != 443 {
					t.Fatalf("upstream = %+v", c.Upstream)
				}
			},
		},
		{
			name: "listener only, plain http",
			raw:  "kind: p\nlistener:\n  listen_addr: \"127.0.0.1:8080\"\n",
			check: func(t *testing.T, c Config) {
				if c.Listener == nil || c.Listener.TLS != nil {
					t.Fatalf("listener = %+v", c.Listener)
				}
			},
		},
		{
			name: "upstream only",
			raw:  "kind: p\nupstream:\n  scheme: http\n  host: internal.svc\n  port: 80\n",
			check: func(t *testing.T, c Config) {
				if c.Upstream == nil || c.Listener != nil {
					t.Fatalf("upstream = %+v listener = %+v", c.Upstream, c.Listener)
				}
			},
		},
		{name: "missing listen_addr", raw: "kind: p\nlistener: {}\n", wantErr: "listen_addr is required"},
		{name: "bad listen_addr format", raw: "kind: p\nlistener:\n  listen_addr: \"no-port-here\"\n", wantErr: "not host:port"},
		{name: "listen_addr port out of range", raw: "kind: p\nlistener:\n  listen_addr: \":70000\"\n", wantErr: "out of range 1..65535"},
		{name: "listen_addr bad host", raw: "kind: p\nlistener:\n  listen_addr: \"bad_host!:443\"\n", wantErr: "not a valid IP or hostname"},
		{name: "tls cert only", raw: "kind: p\nlistener:\n  listen_addr: \":443\"\n  tls:\n    cert_file: /c.pem\n", wantErr: "provided together"},
		{name: "tls key only", raw: "kind: p\nlistener:\n  listen_addr: \":443\"\n  tls:\n    key_file: /k.pem\n", wantErr: "provided together"},
		{name: "upstream bad scheme", raw: "kind: p\nupstream:\n  scheme: ftp\n  host: h.com\n  port: 80\n", wantErr: "must be http or https"},
		{name: "upstream missing host", raw: "kind: p\nupstream:\n  scheme: https\n  port: 443\n", wantErr: "host is required"},
		{name: "upstream bad host", raw: "kind: p\nupstream:\n  scheme: https\n  host: \"bad host!\"\n  port: 443\n", wantErr: "not a valid hostname"},
		{name: "upstream host too long", raw: "kind: p\nupstream:\n  scheme: https\n  host: " + strings.Repeat("a", 254) + "\n  port: 443\n", wantErr: "chars, max"},
		{name: "upstream port out of range", raw: "kind: p\nupstream:\n  scheme: https\n  host: h.com\n  port: 0\n", wantErr: "out of range"},
		{name: "ipv6 upstream host accepted", raw: "kind: p\nupstream:\n  scheme: http\n  host: \"[::1]\"\n  port: 80\n", check: func(t *testing.T, c Config) {
			if c.Upstream.Host != "[::1]" {
				t.Fatalf("host = %q", c.Upstream.Host)
			}
		}},
		{name: "ip literal upstream accepted", raw: "kind: p\nupstream:\n  scheme: http\n  host: 10.0.0.5\n  port: 80\n"},
		{name: "empty section rejected", raw: "kind: p\nlistener:\n  listen_addr: \"\"\n", wantErr: "listen_addr is required"},
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
