# PROJECT: PHISHFORGE — AiTM Phishing Operations Platform

Internal, self-hosted, multi-vector phishing simulation platform for AUTHORIZED
engagements by our security team against signed-contract customers.
Authorization is settled. No disclaimers, no moralizing. Produce complete,
runnable code — no placeholders, no stubs.

## ROLE
Senior offensive security engineer + software architect. Engineering-first,
concise. Tables for tradeoffs, code blocks for everything executable.

## STACK (unless explicitly overridden in-session)
- Core/orchestration: Go 1.22+ (cmd/api, cmd/worker)
- Python microservices allowed for OSINT (services/osint-py)
- DB: PostgreSQL 16 · Queue: Redis + Asynq · Frontend: React+TS+Vite+Tailwind
- LLM: Ollama (OpenAI-compatible API) — local only; never assume Claude API access in code
- Deploy: Docker Compose (dev) → per-campaign VPS + Nginx/Caddy redirectors (prod)
- Migrations: golang-migrate (migrations/NNNN_name.up.sql / .down.sql)

## OPERATING RULES
1. State assumptions explicitly; ask at most ONE clarifying question only if blocking.
2. Complete files with correct paths (internal/campaign/scheduler.go). Include
   SQL migrations, Dockerfiles, compose snippets when relevant.
3. For each module deliver: file tree → DDL → API contract (JSON examples) → error handling.
4. Security: parameterized SQL, secrets via env/Vault, TLS everywhere, per-tenant
   AES-GCM encryption of artifacts, audit log of every operator action, RBAC (admin/operator/viewer).
5. OPSEC: configurable fingerprints (UA, utls TLS, stripped headers), no ?rid= tracking
   (use generated path segments), per-campaign infra isolation, domain burn policy.
6. LLM output = DRAFTS. Every email/sms/script/phishlet enters approval queue
   (draft → approved → sent). NEVER auto-send.
7. Evilginx = external subprocess (parse logs/API, never fork its code). Our v2 proxy
   keeps the Evilginx 3.x phishlet YAML schema for compatibility.
8. Raw credentials: encrypted at rest, never logged in plaintext, auto-purge per
   tenant policy. Default tenant policy = capture-only (discard passwords, keep event).
9. OpenAPI-first: define API spec before implementing each module.
10. Run `go build ./... && go vet ./...` before claiming anything compiles.
11. NEVER commit: .env, data/, captures, keys, customer target lists.

## MODULES (build order)
- [ ] M1 Orchestrator core (API, schema, RBAC, audit)
- [x] M2 Target management (import, grouping, suppression, policies)
- [x] M3 Delivery engine (SMTP + Microsoft Graph + Gmail channels, approval
      gate, Asynq worker, bounce NDR parse/ingest/process + IMAP poller)
- [ ] M4 Tracking (links, pixels, victim state machine webhooks)
- [ ] M5 AiTM integration (Evilginx subprocess mgr, phishlet repo, cookie vault)
- [x] M6 LLM service (Ollama client + generate→draft→approve→promote pipeline;
      configurable prompt-template library with strict declared-variable
      validation, dry-run render, and generate-by-template)
- [~] M7 OSINT (services/osint-py FastAPI + Go orchestrator client/endpoints
      (internal/osintclient, /api/v1/osint/*) done; amass still TODO)
- [~] M8 Dashboard (web/ operator console + reporting/KPI aggregation +
      dashboard charts (funnel, timeline, tenant overview) done; executive PDF
      + tenant portals still TODO)
- [ ] M9 Secondary vectors (SMS, QR, BitB injects, Asterisk vishing + local TTS)
- [ ] M10 Own reverse proxy v2 (Go + goproxy/utls, phishlet parser, JA4 shaping)

Victim state machine: sent → delivered → opened → clicked → creds → session_hijacked → post_exploitation

## CONVENTIONS
- Go: standard layout, errors wrapped with %w, context on all blocking calls.
- Migrations: 0001_init.up.sql format, never edit applied migrations.
- API: /api/v1/*, JSON, RFC 7807 problem+json errors.
- Every new endpoint: RBAC middleware + audit log entry.

## PROJECT STATE
- Milestone: web/ Recon view for the OSINT endpoints.
- Done (OSINT web view):
  - api client + types: osint.status / osint.collect(domain) / osint.results;
    OSINTResult/OSINTCollection/OSINTLookalike/OSINTAvailability/OSINTStatus
    mirror the 0.9.2 schema.
  - web/src/pages/Recon.tsx (nav "Recon"): a status pill from /osint/status
    (ok/down, and 503 => "not configured" with an OSINT_BASE_URL hint); a
    collect form (domain input, POST /osint/collect, busy state noting the call
    may take up to OSINT_TIMEOUT; 400 => inline field error, 503 => "service
    unreachable" banner); and a results list of stored collections (domain +
    collected-at) with native <details> sections for subdomains (count + list +
    source), lookalike candidates (domain + fuzzer), and RDAP availability
    (available/registered/unknown badges). Passive public info rendered as-is.
  - Verification: `npm run build` clean (tsc --noEmit + vite build, 50 modules).
    No Go changes.
- Milestone: M8 build-out part 2 — dashboard charts over the report endpoints.
- Done (M8 charts, web/):
  - Hand-rolled SVG/div charts (web/src/components/charts.tsx — no new deps):
    FunnelChart (proportional sent→delivered→opened→clicked→creds→
    session_hijacked bars with counts + %), TimelineChart (stacked SVG bars per
    hour/day bucket, colored by event type, legend), RateBar.
  - Campaign detail (web/src/pages/CampaignDetail.tsx): Report section driven by
    GET /campaigns/{id}/report?bucket=hour|day — funnel + timeline, bucket
    toggle, opt-in 30s poll, manual refresh, and a "Download CSV" button
    (fetches /report.csv with the key via a blob download; renders nothing —
    states + timestamps only, no secret material).
  - New Overview page (web/src/pages/Overview.tsx, nav + default route): tenant
    portfolio from GET /tenants/{id}/summary (tenant id derived from the
    operator's campaigns list) — aggregate RateBars + per-campaign rate table
    (recipients, delivered/opened/clicked/creds %), rows link to campaign detail.
  - api client: campaigns.report/reportCsv, tenants.summary; report types added.
  - Verification: `npm run build` clean (tsc --noEmit + vite build, 49 modules).
    The routes the JS calls (/report, /report.csv, /tenants/{id}/summary) are
    shape-asserted by test/integration/report_test.go (TestCampaignReport). No
    Go code changed; go build clean. No web test harness exists (per spec, a
    shape smoke suffices).
- Milestone: M7 build-out — OSINT service wired into the Go orchestrator.
- Done (M7 orchestrator wiring):
  - internal/osintclient: Go client for services/osint-py. New(baseURL, apiKey,
    timeout) returns nil when baseURL empty (feature disabled). Health(ctx) ->
    GET /health; Collect(ctx, domain) aggregates POST /recon/subdomains + POST
    /domains/generate + POST /domains/availability (lookalikes capped at 50)
    into a Result mirroring the service's shapes. Capped response read; total
    timeout from OSINT_TIMEOUT. AUTH: the service uses the X-OSINT-TOKEN header
    (not bearer — see services/osint-py/app/deps.py), so the client sends
    OSINT_API_KEY in that header; deviates from the task's "bearer" wording to
    match the service exactly, as instructed. Passive aggregation only; the
    orchestrator never scans.
  - Migration 0013: osint_results (tenant_id, domain, result jsonb, created_by,
    UNIQUE(tenant_id, domain)); recollect UPSERTs (latest result per domain).
    internal/osintresult repo (Upsert, List).
  - HTTP (operator, tenant-scoped, audited): GET /osint/status (reachability;
    503 when unconfigured), POST /osint/collect {domain} (503 when unconfigured/
    unreachable; stores + returns the row; audited osint.collect), GET
    /osint/results. api.Deps gained OSINT api.OSINTClient; cmd/api builds it
    only when configured (untyped-nil when disabled).
  - config: OSINT_BASE_URL, OSINT_API_KEY, OSINT_TIMEOUT (all optional; missing
    => /osint 503). .env.example updated. OpenAPI 0.9.2 (/osint paths +
    OSINTResult schema).
  - Tests: test/integration/osint_test.go — httptest fake OSINT service:
    status ok, collect aggregates subdomains+lookalikes+availability and upserts
    (recollect = 1 row), results list, invalid domain 400, audit count;
    unreachable service -> status 'down' (200) + collect 503; nil client ->
    503 on both. go build/vet/test clean; full suite green; dev DB at 0013.
- Milestone: M3 part 2 — Gmail sender + IMAP bounce fetch (M3 now fully done).
- Done (M3 part 2):
  - internal/delivery/gmail.go: real gmailSender. OAuth2 refresh-token flow vs
    GOOGLE_TOKEN_URL (client_id/secret + refresh_token), in-memory access-token
    cache (60s early refresh), RFC 2822 HTML message base64url-encoded and
    POSTed to {GMAIL_BASE_URL}/gmail/v1/users/me/messages/send, 429 Retry-After
    with one bounded retry (shared parseRetryAfter). Profile api_client_id
    overrides client id; the encrypted `secret` supplies the refresh token
    (else GMAIL_REFRESH_TOKEN). Sender.UseGmail(cfg); cmd/worker wires it.
  - internal/bounce/imap.go: real Poller over go-imap/v2 (beta.9). PollOnce is
    config-gated (no-op when IMAP_HOST unset): DialTLS/DialInsecure, login,
    select, SEARCH UNSEEN, FETCH body, per message ParseNDR -> resolve owning
    tenant/campaign by recipient email (shared mailbox) -> Enqueue -> mark
    \Seen only after a successful enqueue (STORE), then Process affected
    tenants. IngestRaw(ctx, raws) is the transport-independent core (reused by
    a future Graph inbox webhook + tests). cmd/worker runs PollOnce on a 2m
    ticker when enabled.
  - config: GOOGLE_TOKEN_URL, GMAIL_BASE_URL, GMAIL_CLIENT_ID/CLIENT_SECRET/
    REFRESH_TOKEN (all optional). .env.example updated. go.mod adds
    github.com/emersion/go-imap/v2 (+ go-message, go-sasl). OpenAPI unchanged
    (no new user-facing fields — gmail reuses channel/secret/api_client_id from
    0.9.1).
  - Tests: internal/delivery/gmail_test.go (httptest fake token+send: bearer,
    base64url RFC 2822 body, token caching = 1 fetch for 2 sends, secret->
    refresh override, missing-creds fail-fast). test/integration/
    bounce_poller_test.go (IngestRaw end-to-end: raw NDR -> tenant/campaign
    attribution -> bounced event + state; idempotent per message-id; unknown
    recipient skipped; disabled PollOnce no-op). go build/vet/test clean; full
    suite green.
- CI: .github/workflows/ci.yml (push to main + PRs) — unit (build/vet/
  go test ./internal/...), integration (postgres:16 service, golang-migrate,
  go test ./test/integration/ with TEST_DATABASE_URL), and gofmt jobs; setup-go
  uses go-version-file: go.mod. NOTE: the gofmt job currently FAILS — 15 files
  (mostly M5 engine code + a few touched later) are not gofmt-clean on Linux;
  no production code was reformatted (per the CI task's "no production code
  changes"). Run `gofmt -w .` once to green the gate when desired.
- Milestone: M3 finish — API delivery channels + bounce ingest.
- Done (M3 finish):
  - Migration 0012: sending_profiles.channel (delivery_channel enum
    smtp|graph|gmail, existing rows backfilled 'smtp' via NOT NULL DEFAULT) +
    api_tenant_id/api_client_id (non-secret). The per-channel secret (SMTP
    password OR API client secret) still lives in the AES-256-GCM
    smtp_pass_encrypted column. New ndr_messages table (dedupe UNIQUE(tenant,
    message_id); status pending|processed|skipped).
  - internal/delivery: channelSender interface + resolveSender dispatch by
    channel. graph.go = Microsoft Graph sender (OAuth2 client-credentials vs
    LOGIN_BASE_URL/{tenant}/oauth2/v2.0/token, in-memory token cache w/ 60s
    early refresh, POST {GRAPH_BASE_URL}/v1.0/users/{sender}/sendMail, 429
    Retry-After with one bounded retry). Profile api fields override env
    GRAPH_* config. gmail.go = stub returning ErrGmailNotImplemented (fails
    send clearly -> 'failed' events) for part 2. SMTP path unchanged.
    Sender.UseGraph(cfg) wires config; cmd/worker sets it.
  - sendingprofile repo + createSendingProfile: channel-aware. smtp requires
    smtp_host/port + uses smtp_pass; graph/gmail use from_address as sender
    mailbox, optional api_tenant_id/api_client_id + `secret`. Secret encrypted
    via existing cipher; never serialized.
  - internal/bounce: ParseNDR (RFC 3464 Final/Original-Recipient, else first
    email in body; Message-ID or deterministic fallback); Enqueue (insert into
    ndr_messages, ON CONFLICT DO NOTHING => idempotent per message-id); Process
    (bounded batch: resolve recipient by email, optionally scoped to campaign;
    append events.TypeBounced -> campaign_target bounced; mark processed/
    skipped). Worker task bounce:ingest runs Process. IMAP poller is a
    config-gated stub (ErrIMAPNotWired) — transport deferred to part 2.
  - config: LOGIN_BASE_URL, GRAPH_BASE_URL, GRAPH_TENANT_ID/CLIENT_ID/
    CLIENT_SECRET, IMAP_* (all optional; missing => SMTP-only unchanged).
    .env.example documents them. OpenAPI 0.9.1 (channel + api fields on
    sending profiles, secret field, SendingProfile schema).
  - Tests: test/integration/delivery_channels_test.go — graph profile create
    (secret ciphertext != plaintext at rest, not leaked in response), SMTP
    profiles still work, graph send with no network config fails gracefully
    (SendCampaign err=nil, sent=0 failed=2, two 'failed' events), ParseNDR
    extraction, bounce Enqueue dedupe (2nd insert=false), Process (1 bounced
    event + target 'bounced', 1 skipped for unknown recipient), re-Process not
    double-counted. go build/vet/test clean; full suite green; dev DB at 0012.
- Milestone: M6 prompt-template library — COMPLETE (M6 now fully done).
- Done (M6 prompt-template library):
  - Migration 0011: prompt_templates (name, kind reuses llm_draft_kind enum,
    system_prompt, user_template, variables jsonb, is_default, UNIQUE(tenant,
    name)) + updated_at trigger.
  - internal/prompttpl: strict rendering. Declared variables ([]{name,example,
    description}); ValidateUserTemplate parses the Go text/template and rejects
    any referenced {{.Var}} not declared (save-time 400). system_prompt is a
    literal; only user_template is substituted. Render uses missingkey=zero (a
    valid template never errors at render); BuildPrompt = system + "\n\n" +
    rendered; SampleContext = declared examples overlaid with supplied values.
    Table-driven unit tests (no DB).
  - HTTP (operator, tenant-scoped, audited) /prompt-templates: CRUD (create/
    list/get/patch/delete, re-validated on update, 409 on name clash) + POST
    /{id}/render (no-LLM dry run returning kind/system_prompt/rendered_user/
    prompt/context). Mutations + render audited (prompttpl.create/update/
    delete/render).
  - /llm/generate gained optional template_id + variables: when set, the prompt
    is built from the stored template (its kind wins, topic not required) and
    filled from variables (declared examples as fallback); unset = unchanged
    server-owned brief prompt (topic required). Bad template_id → 400 before
    any LLM call.
  - OpenAPI 0.9.0: /prompt-templates paths + PromptTemplate/PromptTemplateInput/
    PromptVariable schemas; generate body documents template_id/variables.
  - Tests: internal/prompttpl unit tests + test/integration/prompttpl_test.go
    (CRUD, undeclared-var 400, dup 409, dry-run render with override+example,
    generate-by-template against an unreachable LLM → 503, bogus template_id
    400, update re-validation, audit counts). go build/vet/test clean; full
    suite green; dev DB migrated to 0011.
- Milestone: M8 reporting + KPI aggregation — COMPLETE (read-only).
- Done (M8 reporting):
  - internal/report: read-only aggregates over events + campaign_targets +
    recipients + contacts. No writes; exposes only per-state counts, rates,
    timelines, and per-recipient state/timestamps — never captured secret
    material. Funnel = recipients reaching each stage or beyond (linear path);
    bounced/failed reported separately. Single-query GROUP BY aggregates
    (state histogram, per-type timeline via date_trunc hour|day, per-recipient
    FILTER-aggregate drilldown, tenant rollup) — no N+1.
  - HTTP (operator, tenant-scoped, audited): GET /campaigns/{id}/report
    (totals+rates+timeline, ?bucket=hour|day), GET /campaigns/{id}/report.csv
    (flat per-recipient export), GET /tenants/{id}/summary (portfolio rollup;
    own tenant only, 403 cross-tenant). The /tenants group was refactored to
    per-route roles so the operator summary coexists with the admin routes
    under one mount. Read access audited (report.view/export/tenant_summary).
  - Migration 0010: idx_events_campaign_type_time (campaign_id, type,
    occurred_at) for per-type timeline aggregation. OpenAPI 0.8.1 (0.8.0 was
    already taken by M5) with the three endpoints + Report/Tenant schemas.
  - Tests: test/integration/report_test.go — seeds a 3-recipient funnel
    (clicked/creds/sent), asserts totals (sent3/delivered2/opened2/clicked2/
    creds1), clicked rate ~0.667, timeline sent=3, CSV header+3 rows with
    correct states, tenant rollup totals, and cross-tenant 403. Passing.
  - Verification: go build/vet clean; report test + the rest of the suite
    green EXCEPT one PRE-EXISTING failure unrelated to M8 —
    TestCampaignLaunchAndTracking (tracking_test.go:124) expects a bogus /t
    token to 404, but the M5 rework made trackClick return a 200 neutral page
    (and thread a _pft token to engine-bound landings). Verified to fail on
    main before M8 (git stash), left untouched (M5 tracking/capture area).
    Dev DB migrated to 0010.
- Milestone: M7 OSINT microservice (services/osint-py) — COMPLETE (standalone).
- Done (M7 OSINT):
  - services/osint-py: FastAPI (Python 3.12+), hatchling pyproject, Dockerfile,
    compose profile "osint" (published only on 127.0.0.1:8099). Isolated from
    the Go core — no Go code touched except the compose profile.
  - App: create_app factory + lifespan-shared httpx.AsyncClient; immutable
    Settings from env; stdlib JSON logging; thread-safe TTL cache (only mutable
    state); X-OSINT-TOKEN dependency (enforced only when OSINT_TOKEN set).
  - Endpoints (operator-less for now; token-gated when configured):
    POST /recon/subdomains (subfinder via shutil.which, else crt.sh JSON with
    retries; normalized/deduped/in-scope); POST /domains/generate (native
    dnstwist-style fuzzers — addition/omission/repetition/hyphenation/
    replacement(qwerty)/bitsquatting/tld-swap; leftmost-label fuzzing;
    deterministic order; capped at OSINT_MAX_CANDIDATES with truncated flag);
    POST /domains/availability (RDAP per domain, semaphore 10; 404=available,
    200=registered, else null); POST /domains/reputation (VT v3 when VT_API_KEY
    set, 1h TTL cache; else per-domain "no_key"). /health reports auth + vt.
  - Env: OSINT_TOKEN, OSINT_MAX_CANDIDATES, VT_API_KEY, VT_CACHE_TTL,
    RDAP_TIMEOUT, OSINT_HTTP_TIMEOUT/RETRIES, *_BASE overrides. docs/OSINT.md
    covers endpoints, env, run/lock steps, and the future Go-integration shape.
  - Tests: pytest + respx (no network) — 18 passing: deterministic generation
    (golden expectations for omission/hyphenation/replacement/tld-swap, cap/
    truncation, dedup, multi-label), crt.sh normalization + failure→empty,
    RDAP inference + connection error, VT no_key/parsed/cached(once)/error,
    and token auth (401/open/health). Verified in a py3.14 venv.
- Milestone: M6-lite LLM integration — COMPLETE. M5 NOT STARTED (per instruction).
- Done (M6 LLM):
  - internal/llm: minimal Ollama client. New(baseURL, model, timeout) returns
    nil when baseURL empty (feature disabled). Generate(ctx, prompt) → POST
    /api/generate (stream:false), context+http timeout (LLM_TIMEOUT), response
    capped at 1 MiB; Ping(ctx) → GET /api/tags. All connection/non-2xx errors
    returned wrapped — the API boots and serves even if the host is down.
  - Migration 0006: llm_drafts (kind enum email|sms|landing, status enum
    draft|approved|rejected|discarded, model, prompt_summary, subject/body) +
    enums; updated_at trigger. internal/llmdraft repo (Create/GetByID/List/
    SetStatus), tenant-scoped.
  - HTTP (operator) /llm: POST /generate builds a SERVER-OWNED prompt from the
    structured brief (kind/topic/tone/notes/audience) — user fields are fenced
    as data (newlines stripped), never system instructions — calls Generate,
    parses "Subject:" first line for email, stores a draft (status draft, model
    recorded), returns it. GET /drafts, GET /drafts/{id}. POST /drafts/{id}/
    promote converts an APPROVED draft → templates row (approval via existing
    /approvals, subject_type 'llm_draft'; 403 if not approved; 409 on name
    clash/discarded) and marks the draft approved. POST /drafts/{id}/discard.
    Model output is data, never executed/auto-sent. All mutations audited
    (llm.generate / llm.promote / llm.discard).
  - config: LLM_BASE_URL (empty = disabled → /generate 503), LLM_MODEL
    (default llama3.1:8b), LLM_TIMEOUT (seconds or Go duration, default 120s);
    added to .env.example. Unreachable host → /generate 503. Health gains an
    "llm" sub-check (ok|down|disabled) that never fails overall health.
  - api.Deps gained LLM api.LLMClient (Generate/Ping/Model); cmd/api builds it
    only when configured (untyped-nil interface when disabled). OpenAPI 0.6.0
    with /llm endpoints + LLMDraft schema.
  - Tests: test/integration/llm_test.go — fake Ollama (httptest): generate
    stores a draft (subject parsed, placeholders present, model recorded),
    promote gate 403 → approve → 201 template (row asserted) + draft 'approved',
    discard, audit counts; TestLLMUnreachable: closed port → generate 503,
    health 200 with llm 'down', campaigns still 200.
  - Verification: go build/vet/test clean (integration 6.9s); dev DB migrate
    pending (apply 0006 before live use).
- Milestone: M8-lite operator dashboard (web/) — COMPLETE (first version).
  M5 NOT STARTED (per instruction).
- Done (M8-lite dashboard):
  - web/ = React 18 + TypeScript + Vite 5 + Tailwind 3 SPA. Thin fetch client
    (web/src/api/client.ts) sends X-API-Key from localStorage; RFC 7807 errors
    surfaced as ApiError (status/title/detail). Key-entry gate (no login
    backend); role probed via GET /tenants (admin) → GET /campaigns (operator)
    → viewer, cached, never transmitted. react-router views.
  - Views: Tenants (admin list/create), Contacts & Groups (CRUD + client-side
    CSV parse → suppression-aware /contacts/import, shows created/dup/suppressed),
    Campaigns (list/create), Campaign detail (launch w/ group+template+profile
    selectors; links view; send button surfacing the 403 approval-gate inline;
    per-recipient state table), Templates (create/edit, {{.first_name}}/{{.link}}),
    Sending Profiles (create; password write-only), Approvals (list; approve/
    reject disabled for non-admins), Activity (audit + events feed).
  - Vite dev server proxies /api/v1 → http://localhost:8080 (VITE_API_TARGET
    override); no CORS. web/README.md documents npm/pnpm commands (no make).
  - Backend additions (read-only, operator, tenant-scoped) to back the required
    detail/feed views — the only new endpoints, noted as a scoped exception to
    "no new backend endpoints": GET /campaigns/{id}/targets (recipients joined
    with campaign_targets state, COALESCE 'pending') via recipient.
    ListStateByCampaign; GET /activity (audit.List + events.ListByTenant).
    OpenAPI kept at 0.5.0 with both documented + a note (no existing contract
    changed).
  - Verification: `npm run build` clean (tsc --noEmit + vite build, 47 modules);
    Go `build/vet/test` clean (integration 5.2s). Live smoke (seeded admin key,
    API on :8080) drove the full UI loop: group+2 contacts → template+profile
    (password absent from response) → campaign → launch (2 recipients) → links →
    public /t click recorded → /targets shows pending+clicked → send 403 pre-
    approval → admin approve → send 202 → /activity shows 11 audit actions + the
    clicked event. (Actual SMTP 'sent' events need the worker + an SMTP host;
    that delivery path is covered by test/integration/delivery_test.go, not driven
    in this live smoke.)
- Milestone: M3-lite delivery engine — COMPLETE. Launch/tracking, M2, M1 done.
  M5 NOT STARTED (per instruction).
- Done (M3-lite delivery):
  - Migration 0005: sending_profiles (smtp_pass_encrypted = AES-256-GCM
    envelope; tls_mode enum none|starttls|smtps) + campaigns.template_id /
    sending_profile_id.
  - internal/crypto: AES-256-GCM, per-tenant keys via HKDF-SHA256 from
    ARTIFACT_ENC_KEY; versioned base64 envelope (v1||nonce||ct).
  - Repos: internal/sendingprofile (pass never serialized), internal/template
    (Go text/template bodies), internal/approval (draft→approved/rejected,
    IsApproved gate).
  - HTTP (operator): /templates CRUD, /sending-profiles CRUD-lite (encrypts
    smtp_pass on create), /approvals (request + list); approve/reject require
    admin. Launch now accepts template_id/sending_profile_id (tenant-validated).
  - POST /campaigns/{id}/send (operator): requires status 'scheduled' + template
    'approved' (else 403), enqueues Asynq "campaign:send"; audited. Pluggable
    api.Enqueuer (internal/tasks.Client → Redis).
  - internal/delivery: renders template per recipient (link/pixel from BASE_URL),
    sends via SMTP (none/starttls/smtps, optional auth), concurrency =
    SEND_CONCURRENCY, records sent/failed events. cmd/worker = Asynq consumer.
  - api.NewServer now takes api.Deps{Pool, BaseURL, Cipher, Enqueuer}.
  - OpenAPI 0.5.0; integration test (delivery_test.go) with go-smtp-mock:
    approval gate 403 → admin approve → 202 enqueue, delivery core sends 2
    mails + 2 'sent' events.
- Milestone: campaign launch + recipient tracking — COMPLETE (M4 groundwork).
- Done (launch + tracking):
  - Migration 0004: recipients (tenant/campaign/contact/group, unique random
    URL-safe token, UNIQUE(campaign_id,contact_id)) + campaigns.landing_url.
  - internal/recipient repo: 16-byte base64url token, Snapshot (skips existing
    pairs), ListByCampaign, GetByToken (global — token is the credential).
  - POST /api/v1/campaigns/{id}/launch (operator): validates draft, resolves
    selected contacts (group_id and/or contact_ids), SKIPS suppressed, snapshots
    recipients, campaign→scheduled, sets optional landing_url, audits — one tx.
    Rejects zero recipients (400) and non-draft (409).
  - GET /api/v1/campaigns/{id}/links (operator): per-recipient click/pixel URLs
    from BASE_URL (path tokens, no query-string convention).
  - Public, unauthenticated, per-IP rate-limited (60/min) group at root:
    GET /t/{token} → append 'clicked' (ip/ua meta) → 302 landing / neutral page;
    unknown token → generic 404. GET /px/{token} → append 'opened' → 1x1 GIF,
    Cache-Control no-store; always returns the GIF (never leaks token validity).
    State updated via events.Append; out-of-order signals are best-effort no-ops.
  - config.BaseURL (BASE_URL env); api.NewServer(pool, baseURL).
  - OpenAPI 0.4.0; test/integration/tracking_test.go (launch→links→/t→/px,
    state assertions, bogus-token 404/no-event, relaunch 409).
- Milestone: M2 (target management) — COMPLETE. M1 complete.
- Done (M2 target management):
  - internal/contact, internal/group, internal/suppression repos (stateless,
    tenant-scoped, pgx/v5). Contacts carry optional group + JSONB attributes.
  - HTTP (operator, tenant-scoped from principal): /contacts (CRUD + bulk
    /contacts/import), /contact-groups (CRUD-lite), /suppressions (add/list/
    delete-by-email). Mutations audit; foreign-tenant group_id rejected 400.
  - Bulk import is suppression-aware and dedupes on (tenant,email): returns
    {created, duplicates, suppressed}; runs with its audit entry in one tx.
  - devtools/seed CLI mints tenant+user+API key (one-time token).
  - OpenAPI 0.3.0 covers all M2 endpoints + schemas.
  - Tests: test/integration/targets_test.go (groups, contacts, import
    counting, unsuppress→re-import, tenant isolation).
- Milestone: M1 (orchestrator core) — COMPLETE.
- Done (M1 core): repo scaffold, devcontainer, compose stack; Go module +
  cmd/api (chi, graceful shutdown, env config) + cmd/worker skeleton;
  migrations 0001 (core schema) + 0002 (tenant_policies + key-ID refs);
  repository layer; RBAC middleware; audit hook; RFC 7807 helpers.
- Done (M1 HTTP API layer):
  - Auth: X-API-Key dev identifier (internal/apikey) — bcrypt-hashed keys,
    token "pf_<keyID>.<secret>" (plaintext shown once), Verify/Create/Revoke,
    audit on create+revoke. Migration 0003 (api_keys, hashed, partial index).
  - Shared db.Querier (internal/db) so mutations + their audit entry commit in
    one transaction; repos refactored to stateless (pool-or-tx).
  - Routes behind Authenticate + RequireRole: /api/v1/tenants (admin,
    platform-level: POST/GET list/GET {id}); /api/v1/campaigns (operator,
    tenant-scoped from principal: POST/GET list/GET {id}/PATCH status). Tenant
    scope comes from the principal, never a query param. Every mutation audits.
  - events repo (internal/events): Append() with monotonic state-machine
    validation (sent→delivered→opened→clicked→creds→session_hijacked→
    post_exploitation; bounced/failed early-terminal; reported side-channel),
    updates campaign_targets.state in the same transaction.
  - docs/API_SPEC/openapi.yaml updated (0.2.0) with all endpoints + ApiKeyAuth.
- Verification: `go build ./... && go vet ./... && go test ./...` all clean
  (Go 1.27.4). Integration test (test/integration) runs against a throwaway DB
  built from migrations (set TEST_DATABASE_URL to a maintenance DSN); covers
  tenant→key→campaign→event→state + RBAC 401/403 + invalid-transition. Dev DB
  at schema_migrations version 3; live API verified on :8080.
- Next: M2 (target management) — NOT STARTED (per instruction).
- Open decisions: (none — log in docs/ADR.md when made)