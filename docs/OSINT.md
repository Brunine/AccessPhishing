# OSINT microservice (M7)

A small, standalone FastAPI service in `services/osint-py`. It is isolated from
the Go core: it has its own process, port, and auth, and the orchestrator will
call it over HTTP later (see *Go integration* below). It performs no credential
or traffic handling — only domain reconnaissance and lookups.

## Run

```bash
# Local (binds loopback by default when you pass --host 127.0.0.1)
cd services/osint-py
python -m venv .venv && . .venv/Scripts/activate      # or .venv/bin/activate
pip install -e .[dev]
uvicorn app.main:app --host 127.0.0.1 --port 8099

# Tests (no network — all HTTP is mocked with respx)
pytest

# Docker, via the compose "osint" profile (published only on 127.0.0.1)
docker compose -f deploy/docker-compose.yml --profile osint up --build osint
```

### Dependency locking

`pyproject.toml` is the source of truth. Generate a lock (committed) with:

```bash
uv pip compile pyproject.toml -o requirements.lock
uv pip compile --extra dev pyproject.toml -o requirements-dev.lock
# or: pip-compile --output-file=requirements.lock pyproject.toml
```

## Environment variables

| Var | Default | Meaning |
| --- | --- | --- |
| `OSINT_TOKEN` | *(empty)* | When set, every endpoint (except `/health`) requires header `X-OSINT-TOKEN: <value>`. Empty ⇒ open (intended for loopback binding). |
| `OSINT_MAX_CANDIDATES` | `500` | Hard cap on lookalike candidates returned by `/domains/generate`. |
| `VT_API_KEY` | *(empty)* | VirusTotal v3 key. Empty ⇒ `/domains/reputation` returns `status: "no_key"` per domain. |
| `VT_CACHE_TTL` | `3600` | Seconds to cache VT results in-memory. |
| `RDAP_TIMEOUT` | `10` | Per-request timeout (s) for RDAP lookups. |
| `OSINT_HTTP_TIMEOUT` | `15` | Timeout (s) for crt.sh / VT requests. |
| `OSINT_HTTP_RETRIES` | `2` | Retries for the crt.sh fallback. |
| `OSINT_AVAILABILITY_CONCURRENCY` | `10` | Max concurrent RDAP lookups (semaphore). |
| `CRTSH_BASE` / `RDAP_BASE` / `VT_BASE` | public hosts | Overridable endpoints (used by tests). |

## Endpoints

All request/response bodies are validated pydantic models. Invalid input ⇒ `422`.

### `POST /recon/subdomains`
Body: `{ "domain": "example.com" }`

Uses `subfinder` when it is on `PATH` (`shutil.which`), otherwise falls back to
a crt.sh JSON query (timeout + retries). Hostnames are lowercased, wildcard
prefixes stripped, de-duplicated, and filtered to the queried domain.

```json
{ "domain": "example.com", "source": "crtsh", "count": 3,
  "subdomains": ["example.com", "mail.example.com", "www.example.com"] }
```

### `POST /domains/generate`
Body: `{ "domain": "example.com", "modes": ["addition","hyphenation","tld-swap","bitsquatting","omission","repetition","replacement"] }`

Native dnstwist-style generation (no subprocess, no network). The **leftmost
label** is fuzzed and the remainder is kept as the suffix (a deliberate
simplification over a full public-suffix split); `tld-swap` replaces the suffix
with common TLDs. Output is deterministic (mode order, then a fixed order within
each mode) and capped at `OSINT_MAX_CANDIDATES`.

```json
{ "domain": "example.com", "count": 240, "truncated": false,
  "candidates": [ { "domain": "examplea.com", "fuzzer": "addition" } ] }
```

### `POST /domains/availability`
Body: `{ "domains": ["a.com", "b.net"] }`

RDAP lookup per domain (`https://rdap.org/domain/{d}`), concurrency-limited
(semaphore 10). `404 ⇒ available=true` (unregistered), `200 ⇒ available=false`
(registered), anything else ⇒ `available=null` with the status code. Connection
errors ⇒ `available=null` with an `error` string.

### `POST /domains/reputation`
Body: `{ "domains": ["a.com"] }`

VirusTotal v3 `/domains/{d}` when `VT_API_KEY` is set; results cached in-memory
for `VT_CACHE_TTL`. Without a key, each domain returns `{"status":"no_key"}`.
With a key: `{"status":"ok","malicious":N,"suspicious":N,"harmless":N,"undetected":N,"cached":bool}`.

## Structure

```
app/
  main.py              # FastAPI factory + lifespan (shared httpx.AsyncClient)
  config.py            # immutable Settings from env
  deps.py              # settings / client / cache / require_token
  models.py            # pydantic request/response models
  cache.py             # thread-safe TTL cache (the only mutable state)
  logging_setup.py     # stdlib JSON logging
  routers/recon.py     # /recon/subdomains
  routers/domains.py   # /domains/{generate,availability,reputation}
  services/            # twist (generation), subdomains, rdap, virustotal
tests/                 # pytest + respx (crt.sh / RDAP / VT mocked, no network)
```

## Go integration (later)

The Go orchestrator (`cmd/api`) will call this service server-to-server over
HTTP — not the browser. Expected shape when wired:

- An `OSINT_URL` (e.g. `http://osint:8099`) and `OSINT_TOKEN` in the API config.
- A thin `internal/osint` client (Generate/Availability/Reputation/Subdomains)
  mirroring these payloads, used by an operator-gated, audited set of
  `/api/v1/osint/*` endpoints.
- Results feed domain selection for a campaign (pick a lookalike → check
  availability → check reputation) and asset discovery.

That wiring is intentionally **not** part of M7; this service stands alone and
is exercised only by its own tests for now.
