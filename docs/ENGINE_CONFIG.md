# Engine Config Schema (M5 part 1)

An engine is a supervised child process. This document defines the YAML
config stored in `engines.config` and validated by `internal/engineconfig`.
Part 1 is structural only: the schema describes **how to launch and
supervise a process** — arguments, environment, restart policy, stop
behavior. It contains no traffic/proxy semantics; those arrive in part 2
as additional validated sections.

## Format

```yaml
kind: proxy            # required, [a-z0-9_-]{1,64}; labels the engine type
args:                  # optional, 0..64 entries, each 1..4096 chars
  - "-config"
  - "/etc/engines/proxy.yaml"
env:                   # optional, 0..32 entries
  GOMAXPROCS: "4"
restart:               # optional section
  max_attempts: 3      # 0..20, default 3 (0 = no restarts)
  backoff_ms: 1000     # 10..60000, default 1000
stop_timeout_ms: 5000  # 100..30000, default 5000 (graceful-stop deadline)

# ---- Part 2: network sections (all optional at the schema level; the
# ---- engine kind decides which are required at start time) ----
listener:              # where the engine binds for inbound traffic
  listen_addr: "0.0.0.0:443"
  tls:                 # optional; omit for plain HTTP
    cert_file: /etc/engines/cert.pem
    key_file: /etc/engines/key.pem
upstream:              # the backend the engine forwards to
  scheme: https        # http | https
  host: login.example.com
  port: 443            # 1..65535
```

## Validation rules

1. **Size limit**: the raw YAML document must be ≤ 65536 bytes.
2. **Strict parsing**: unknown fields are rejected (`KnownFields(true)`).
3. `kind` must match `^[a-z0-9_-]{1,64}$`.
4. `args`: max 64 entries; each non-empty, ≤ 4096 chars.
5. `env`: max 32 entries; keys match `^[A-Za-z_][A-Za-z0-9_]*$`, values
   ≤ 4096 chars.
6. `restart.max_attempts` clamped to 0..20; `backoff_ms` clamped to
   10..60000. Missing values get defaults.
7. `stop_timeout_ms` clamped to 100..30000 (default 5000).

## Future sections (part 2+, not valid yet)

Sections describing listener addresses, upstream targets, and TLS
material will be added to this schema and validator in the next
increment. Passing configs containing such sections today fails with
"unknown field" — intentionally.