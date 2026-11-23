# Architecture

PhishForge is a self-hosted, multi-tenant phishing-simulation platform. This
document covers the runtime components, the campaign data flow, the data model,
and the cross-cutting designs (approval gate, audit trail, engine model).

## Components

| Component | Path | Role |
| --- | --- | --- |
| API | `cmd/api` | chi HTTP server; authenticates `X-API-Key`, enforces RBAC, serves `/api/v1/*`, supervises engine subprocesses |
| Worker | `cmd/worker` | Asynq consumer; renders + delivers campaigns, polls the bounce mailbox |
| Web console | `web/` | React/TS/Vite SPA; same-origin `/api/v1` via the Vite dev proxy |
| OSINT service | `services/osint-py` | standalone FastAPI; passive recon (subdomains, lookalike domains, RDAP, VirusTotal) |
| Engine proxy | `cmd/engineproxy` | subprocess engine entrypoint, launched/supervised by the API |
| PostgreSQL 16 | — | system of record (all tenant data, events, audit) |
| Redis | — | Asynq task queue backing `campaign:send` and `bounce:ingest` |

Optional integrations (LLM, Graph/Gmail, OSINT, IMAP, engines) are config-gated:
when their environment is absent the relevant endpoints return `503` and the
rest of the platform runs normally.

## Campaign data flow

```
 contacts + groups                 templates ──(approval)──► approved
        │                                               │
        ▼                                               ▼
   campaign ──launch──► recipients (snapshot + token) ──send (Asynq)──► worker
   (draft→scheduled)         │                                           │
                             │                          renders per-recipient,
                             │                          sends via channel,
                             ▼                          appends sent/failed
                     public tracking                           │
            GET /t/{token}  → clicked ─┐                        │
            GET /px/{token} → opened  ─┤                        │
            engine callback → creds …  ┘                        ▼
                             └──────────► events (append-only) ─► campaign_targets
                                                 │                 (projected state)
                                                 ▼
                                      report aggregation (KPIs, timeline,
                                      per-recipient drilldown) → JSON / CSV / PDF
```

- **Launch** snapshots the selected, non-suppressed contacts into `recipients`,
  each with a 16-byte URL-safe token, and moves the campaign `draft → scheduled`.
- **Send** is gated (status `scheduled` + an approved template) and enqueued to
  the worker, which renders the template per recipient and records a `sent` or
  `failed` event.
- **Tracking** is public and token-authenticated by path (no `?rid=`): `/t`
  appends `clicked`, `/px` appends `opened`. Unknown tokens never reveal
  validity (neutral page / always-GIF).
- **Events** are the append-only source of truth. Each append validates a
  monotonic transition and updates the derived `campaign_targets.state` in the
  same transaction.
- **Reporting** aggregates events + `campaign_targets` into funnel counts,
  rates, timelines and a per-recipient drilldown — read-only, no secret
  material — exposed as JSON, CSV, and executive PDF.

Victim state machine:
`sent → delivered → opened → clicked → creds → session_hijacked →
post_exploitation`, with `bounced` / `failed` as early-terminal branches and
`reported` as a side channel.

## Data model

All tenant-scoped tables carry `tenant_id` with a supporting index; foreign keys
cascade on tenant delete. Migrations live in `migrations/` (`0001`…`0013`).

| Table | Purpose | Key relationships |
| --- | --- | --- |
| `tenants` | customer workspaces | root of every scope |
| `users` | operator accounts (role: admin/operator/viewer; key-based, no password) | → tenant |
| `api_keys` | bcrypt-hashed keys (`pf_<id>.<secret>`) | → tenant, user |
| `tenant_policies` | per-tenant settings (e.g. capture policy) | → tenant |
| `contact_groups`, `contacts` | targets and groupings (JSONB attributes) | → tenant, group |
| `suppression_lists` | do-not-contact addresses, honored at launch | → tenant |
| `campaigns` | campaign lifecycle + template/profile/engine/engagement refs | → tenant, template, sending_profile, engine, engagement |
| `engagements` | authorization container: client, RoE ref, authorized scope, authorization workflow + expiry + emergency stop | → tenant, authorizing user |
| `recipients` | per-campaign snapshot + tracking token | → campaign, contact |
| `campaign_targets` | projected current state per (campaign, contact) | → campaign, contact |
| `events` | append-only victim-state history (append-only trigger) | → tenant, campaign, contact |
| `templates` | Go `text/template` message bodies | → tenant |
| `prompt_templates` | LLM prompt library with declared variables | → tenant |
| `llm_drafts` | LLM-generated content awaiting approval/promotion | → tenant, user |
| `sending_profiles` | SMTP/Graph/Gmail profiles; secret AES-GCM-sealed | → tenant |
| `ndr_messages` | fetched bounce notifications, deduped per message-id | → tenant, campaign |
| `engines` | engine registry: validated YAML config, lifecycle status, callback token hash | → tenant |
| `osint_results` | stored OSINT collections (one per tenant+domain) | → tenant, user |
| `approvals` | draft→approved/rejected gate for a subject | → tenant |
| `audit_log` | append-only record of operator actions | → tenant |
| `configs` | per-tenant key/value settings | → tenant |

## Approval gate

Content cannot be sent until it is explicitly approved. An `approvals` row ties
a `subject_type` + `subject_id` (e.g. a `template` or an `llm_draft`) to a
status (`draft → approved | rejected`). Approval **decisions require admin**;
operators may request them. The send path checks `IsApproved(template)` and
returns `403` otherwise; LLM drafts can only be **promoted** into real templates
once their `llm_draft` subject is approved. This keeps a human in the loop on
every outbound artifact — the platform never auto-sends.

This content-approval gate is distinct from **engagement authorization**: the
approval gate certifies *what* is sent (a template/draft is reviewed), while an
engagement (M8a) certifies *that the campaign is authorized to run at all*
against a client — a campaign must be bound to an authorized, unexpired,
non-terminated `engagement` (operator requests → admin authorizes; admin can
terminate as an emergency stop) before launch or send. Launch/send enforce this
in the application (`campaigns.engagement_id → engagements`): unbound/
unauthorized → `403`, expired/terminated → `409`.

## Audit trail

Every mutating operator action writes an append-only `audit_log` entry
(`tenant_id`, actor, action, target, metadata, timestamp) **in the same
transaction** as the mutation, so an action and its audit record commit or roll
back together. Read endpoints that expose aggregated or cross-tenant data
(reports, exports, the platform console) are audited too. The table has an
append-only trigger (updates/deletes are rejected). Audited actions include
tenant/user/key lifecycle, contact import, campaign launch/send, approvals,
LLM generate/promote/discard, OSINT collect, and report views/exports.

## Engine model

Engines are external subprocesses supervised by the orchestrator (M5; the parts
built here are management + the capture-ingest boundary):

- **Registry + lifecycle.** An `engines` row holds a validated YAML config and a
  process status (`stopped → starting → running → error`). The API's engine
  manager starts/stops the configured binary (`ENGINE_BINARY_PATH`) with a
  restart policy; endpoints return `503` when no binary is configured.
- **Per-run callback auth.** When a run starts, the orchestrator issues a bearer
  token to the engine process and stores **only its SHA-256 hash**
  (`engines.callback_token_hash`). The plaintext lives only in the engine
  process environment for the duration of the run; it is never persisted.
- **Capture-only ingest boundary.** The engine POSTs observed events back to a
  public, rate-limited ingest endpoint authenticated by that per-run token.
  Consistent with the default capture-only tenant policy, the platform persists
  the **event and its metadata (field names / state), never submitted secret
  values**. Captured credentials are not stored in plaintext.
- **Campaign binding.** A campaign may reference an engine (`campaigns.engine_id`,
  `ON DELETE SET NULL`); deleting an engine never cascades into campaigns.

## Key trade-offs & known limitations

- **`admin` is platform-level** in this internal, self-hosted deployment: the
  `/tenants` and `/platform/*` endpoints are cross-tenant for admins. A
  dedicated super-admin tier is not implemented (see PROJECT STATE / ADR note).
- **PDF export builds in memory** (`go-pdf/fpdf`, MIT) — rendered to a buffer
  rather than true streaming; tables are row-capped with a footer truncation
  note.
- **OSINT `Collect` aggregates** the service's endpoints (subdomains +
  lookalikes + RDAP) client-side; it is passive only — the orchestrator never
  scans.
- **Bounce attribution** maps an NDR to the most recent campaign membership of
  the failed recipient across the (shared) mailbox; idempotent per message-id.
- The authoritative, continuously-updated status lives in
  [`CLAUDE.md`](../CLAUDE.md) PROJECT STATE.
