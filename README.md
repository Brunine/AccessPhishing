# PhishForge

A self-hosted phishing-**simulation** platform for authorized security teams.
It runs multi-tenant awareness engagements: manage targets, draft and approve
message templates, deliver over SMTP / Microsoft Graph / Gmail, track opens and
clicks, and report funnel KPIs — with tenant-scoped RBAC, an approval gate on
every send, and a full audit trail.

> **Authorized use only.** PhishForge is intended for simulated phishing against
> organizations that have given you written authorization (e.g. your own
> organization, or a customer under a signed engagement). You are responsible
> for operating it lawfully and within scope. See
> [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the platform's own security
> model and operator requirements.

## What it is

- **Multi-tenant**: every record is scoped to a tenant; queries are
  tenant-scoped from the authenticated principal, never a query parameter.
- **RBAC**: `admin` / `operator` / `viewer`, enforced per route. In this
  internal deployment `admin` is platform-level (cross-tenant oversight).
- **Approval-gated sending**: templates (and LLM-generated drafts) must be
  approved before a campaign can send; the API refuses otherwise.
- **Audited**: every mutating operator action writes an append-only
  `audit_log` entry.
- **Secrets encrypted at rest**: SMTP/API credentials are sealed with per-tenant
  AES-256-GCM (`ARTIFACT_ENC_KEY`); plaintext is returned once at creation and
  never again.
  **AiTM engine support**: supervised reverse-proxy engine subprocesses with a capture-only event boundary (see below).

## Architecture (sketch)

```
            ┌────────────┐   X-API-Key    ┌──────────────┐
  operator ─┤ web console ├───────────────┤   Go API     ├──── PostgreSQL 16
 (browser)  │ React/Vite  │   /api/v1/*    │  (cmd/api)   ├──── Redis (Asynq)
            └────────────┘                 └───┬───┬──────┘
                                               │   │
                   ┌───────────────────────────┘   └──────────────┐
                   │ Asynq task                                    │ HTTP
            ┌──────┴───────┐                                ┌──────┴───────┐
            │ worker       │  SMTP / Graph / Gmail           │ OSINT service│
            │ (cmd/worker) ├──────────────────► providers    │ (FastAPI,    │
            │ delivery +   │                                 │  Python)     │
            │ bounce IMAP  │                                 └──────────────┘
            └──────────────┘
            engine subprocesses (cmd/engineproxy) are supervised by the API and
            POST captured events back over a per-run bearer token.
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for components, data flow, the
data model, and the engine/capture boundary.

## Quickstart (local dev)

Prerequisites: Go 1.26.0, Docker, Node 20+, and the
[`golang-migrate`](https://github.com/golang-migrate/migrate) CLI.

```sh
# 1. Config: copy the sample and set the required values.
cp .env.example .env
#   - set DATABASE_URL (the compose default works as-is)
#   - set ARTIFACT_ENC_KEY: openssl rand -hex 32

# 2. Start Postgres + Redis (deploy/docker-compose.yml).
make dev-up

# 3. Apply migrations.
make migrate

# 4. Mint a tenant + admin user + API key (prints a pf_... token once).
make seed
#   or: go run ./cmd/devtools/seed -tenant "Acme" -email you@acme.test -role admin

# 5. Run the API and the delivery/bounce worker (separate shells).
go run ./cmd/api
go run ./cmd/worker

# 6. Run the web console and sign in with the seeded key.
cd web && npm install && npm run dev   # http://localhost:5173 (proxies /api/v1 -> :8080)
```

Paste the `pf_<keyID>.<secret>` token from step 4 into the console's key screen.
The OSINT microservice is optional and run separately — see
[`services/osint-py/README.md`](services/osint-py/README.md) and
[`docs/OSINT.md`](docs/OSINT.md).

## Features by module

| Module | Status | Summary |
| --- | --- | --- |
| M1 Orchestrator core | ✅ | chi HTTP API, Postgres schema, RBAC, API-key auth, append-only events state machine, audit log |
| M2 Target management | ✅ | contacts, groups, suppression-aware bulk import, tenant isolation |
| M3 Delivery engine | ✅ | templates + approval gate, Asynq worker, SMTP / Microsoft Graph / Gmail channels, NDR bounce ingest (IMAP poller) |
| M4 Launch & tracking | ✅ | recipient snapshot with unguessable path tokens, public `/t` click + `/px` open tracking, victim state machine |
| M6 LLM service | ✅ | Ollama client, generate→draft→approve→promote pipeline, strict prompt-template library |
| M7 OSINT | ◐ | Python FastAPI service (subdomains, lookalike generation, RDAP, VirusTotal) wired into the Go orchestrator (`/osint/*`); amass TODO |
| M8 Dashboard & reporting | ✅ | KPI aggregation, dashboard charts, CSV + executive PDF export, platform-admin cross-tenant console |
| Ops | ✅ | operator-managed API keys and users (with last-admin / last-operator-key self-lockout guards) |

Modules M5 (AiTM proxy integration), M9 (additional delivery channels) 
and M10 (engine proxy extensions: rewrite rules, per-target configs, 
TLS automation) are on the roadmap; see CLAUDE.md.

## Configuration

The Go API/worker read configuration from the environment (see
[`internal/config/config.go`](internal/config/config.go)). `DATABASE_URL` is the
only hard requirement to boot; optional integrations degrade gracefully
(endpoints return `503` when their config is absent).

| Variable | Default | Required | Purpose |
| --- | --- | --- | --- |
| `DATABASE_URL` | — | **yes** | PostgreSQL DSN |
| `API_ADDR` | `:8080` | no | API listen address |
| `REDIS_ADDR` | `localhost:6379` | no | Redis for the Asynq queue |
| `BASE_URL` | `http://localhost:8080` | no | public base for tracking links/pixels |
| `ARTIFACT_ENC_KEY` | — | for delivery | 32-byte hex AES key; empty disables sending-profile creation (`503`) |
| `SEND_CONCURRENCY` | `10` | no | worker send concurrency |
| `APP_ENV` | `dev` | no | environment label |
| `LLM_BASE_URL` | — | for LLM | Ollama host; empty disables `/llm/generate` (`503`) |
| `LLM_MODEL` | `llama3.1:8b` | no | Ollama model |
| `LLM_TIMEOUT` | `120s` | no | per-generate timeout (seconds or Go duration) |
| `ENGINE_BINARY_PATH` | — | for engines | engine binary; empty disables engine start/stop (`503`) |
| `ENGINE_MAX_RESTARTS` | `3` | no | engine restart attempts |
| `ENGINE_BACKOFF` | `1s` | no | engine restart backoff |
| `ENGINE_DATA_DIR` | `data/engines` | no | engine working directory |
| `LOGIN_BASE_URL` | `https://login.microsoftonline.com` | no | Microsoft OAuth2 host |
| `GRAPH_BASE_URL` | `https://graph.microsoft.com` | no | Microsoft Graph host |
| `GRAPH_TENANT_ID` / `GRAPH_CLIENT_ID` / `GRAPH_CLIENT_SECRET` | — | for Graph | Graph app credentials (profiles may override) |
| `GOOGLE_TOKEN_URL` | `https://oauth2.googleapis.com/token` | no | Google OAuth2 token endpoint |
| `GMAIL_BASE_URL` | `https://gmail.googleapis.com` | no | Gmail API host |
| `GMAIL_CLIENT_ID` / `GMAIL_CLIENT_SECRET` / `GMAIL_REFRESH_TOKEN` | — | for Gmail | Gmail OAuth2 credentials (profiles may override the refresh token) |
| `OSINT_BASE_URL` | — | for OSINT | OSINT microservice URL; empty disables `/osint/*` (`503`) |
| `OSINT_API_KEY` | — | no | sent as `X-OSINT-TOKEN` to the OSINT service |
| `OSINT_TIMEOUT` | `30s` | no | OSINT request timeout |
| `IMAP_HOST` | — | for bounces | bounce mailbox host; empty disables polling |
| `IMAP_PORT` | `993` | no | bounce mailbox port |
| `IMAP_USERNAME` / `IMAP_PASSWORD` | — | for bounces | bounce mailbox credentials |
| `IMAP_MAILBOX` | `INBOX` | no | bounce mailbox folder |
| `IMAP_USE_TLS` | `true` | no | IMAPS vs plaintext |

The Python OSINT service has its own environment, documented in
[`docs/OSINT.md`](docs/OSINT.md).

## Adversary-in-the-Middle engine (M5)

Beyond email delivery, the platform supervises **engine subprocesses** —
including a built-in reverse-proxy engine (`cmd/engineproxy`) used for
adversary-in-the-middle (AiTM) simulations:

- **Lifecycle management**: engines are registered with a validated YAML
  config and started/stopped from the console; the orchestrator supervises
  the process (graceful stop, restart policy, bounded log capture).
- **Per-run isolation**: each engine run receives a unique bearer token,
  stored only as a SHA-256 hash; the plaintext lives solely in the engine
  process environment.
- **Capture-only boundary**: the platform records *that* an event occurred —
  credential submission (form field names) and session issuance (cookie
  names) — never the submitted values or tokens themselves. This is a
  deliberate security property: the platform can demonstrate
  credential-harvesting and MFA-bypass impact without storing material an
  attacker would want.

A campaign can bind to an engine; when the campaign launches, the engine
serves the engagement's landing flow and reports events back into the same
funnel (…→ clicked → creds → session_hijacked) as email campaigns.

## Delivery channels

| Channel | Status | Funnel coverage |
| --- | --- | --- |
| Email (SMTP, Microsoft Graph, Gmail) | ✅ | sent → delivered → opened → clicked → creds → session |
| SMS (smishing) | planned (M9) | sent → clicked → creds → session |
| QR codes (quishing) | planned (M9) | token issued → clicked → creds → session |
| Teams / Slack / WhatsApp | planned (M9) | sent → clicked → creds → session |
| MFA-fatigue simulation | planned (M9, own-org tenants only) | prompt → approved/denied |
| Voice (vishing) | out of scope | — |

See the roadmap in [`CLAUDE.md`](CLAUDE.md) for the delivery-channel and
engine-extension plan.

## Development

```sh
go build ./... && go vet ./...        # compile + vet
gofmt -l .                            # must be empty

go test ./internal/...                # unit tests (no DB)

# Integration tests spin up a throwaway database per run from the migrations.
# TEST_DATABASE_URL points at a MAINTENANCE database (it CREATEs/DROPs its own
# phishforge_test_* databases).
TEST_DATABASE_URL=postgres://phishforge:devpass@localhost:5432/postgres?sslmode=disable \
  go test ./...

cd web && npm run build               # type-check (tsc) + Vite production build
cd services/osint-py && pytest        # OSINT service tests (respx, no network)
```

**CI** ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs on pushes to
`main` and PRs, with three jobs: **unit** (build / vet / `go test ./internal/...`),
**integration** (Postgres service container + migrations + `go test
./test/integration/`), and **gofmt** (`gofmt -l .` must be empty).

### Project layout

```
cmd/
  api/            HTTP API service
  worker/         Asynq consumer: delivery + bounce polling
  engineproxy/    engine subprocess entrypoint
  devtools/seed/  mint tenant + user + API key
internal/         API handlers, auth/RBAC, repositories, delivery, llm,
                  osintclient, report, pdfexport, engine, bounce, crypto, …
migrations/       golang-migrate SQL (0001…0013)
services/osint-py/ FastAPI OSINT microservice (Python)
web/              React + TypeScript + Vite + Tailwind operator console
docs/             API_SPEC/openapi.yaml, ARCHITECTURE.md, THREAT_MODEL.md, …
deploy/           docker-compose.yml (dev stack + optional profiles)
test/integration/ end-to-end tests against a throwaway DB
```

API contract: [`docs/API_SPEC/openapi.yaml`](docs/API_SPEC/openapi.yaml).

## License

Proprietary and confidential. Copyright © 2026 Access Security. All rights
reserved. This is an internal commercial product for internal use only; no
redistribution or derivative works are permitted without written permission.
See the [`LICENSE`](LICENSE) notice for the full terms. This README does not
grant any license.
