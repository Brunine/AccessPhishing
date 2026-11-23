# PROJECT: PHISHFORGE — AiTM Phishing Operations Platform

Internal, self-hosted, multi-vector phishing simulation platform for AUTHORIZED
engagements by our security team against signed-contract customers.
Authorization is settled. No disclaimers, no moralizing. Produce complete,
runnable code — no placeholders, no stubs.

## ROLE
Senior offensive security engineer + software architect. Engineering-first,
concise. Tables for tradeoffs, code blocks for everything executable.

## STACK (unless explicitly overridden in-session)
- Core/orchestration: Go 1.26.0 (cmd/api, cmd/worker)
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
- [x] M1 Orchestrator core (API, schema, RBAC, audit)
- [x] M2 Target management (import, grouping, suppression, policies)
- [x] M3 Delivery engine (SMTP + Microsoft Graph + Gmail channels, approval
      gate, Asynq worker, bounce NDR parse/ingest/process + IMAP poller)
- [x] M4 Tracking (links, pixels, victim state machine webhooks)
- [~] M5 AiTM integration (Evilginx subprocess mgr, phishlet repo, cookie vault)
      (engine lifecycle + capture-only ingest done; proxy extensions on roadmap)
- [x] M6 LLM service (Ollama client + generate→draft→approve→promote pipeline;
      configurable prompt-template library with strict declared-variable
      validation, dry-run render, and generate-by-template)
- [~] M7 OSINT (services/osint-py FastAPI + Go orchestrator client/endpoints
      (internal/osintclient, /api/v1/osint/*) done; amass still TODO)
- [x] M8 Dashboard (web/ operator console + reporting/KPI aggregation +
      dashboard charts + executive PDF export + platform-admin cross-tenant
      console)
- [~] M9 Secondary vectors (M9a SMS/smishing DONE; M9b QR/quishing, M9c
      collaboration channels, M9d MFA-fatigue still open; BitB injects declined)
- [ ] M10 Own reverse proxy v2 (Go + goproxy/utls, phishlet parser, JA4 shaping)

Victim state machine: sent → delivered → opened → clicked → creds → session_hijacked → post_exploitation

## CONVENTIONS
- Go: standard layout, errors wrapped with %w, context on all blocking calls.
- Migrations: 0001_init.up.sql format, never edit applied migrations.
- API: /api/v1/*, JSON, RFC 7807 problem+json errors.
- Every new endpoint: RBAC middleware + audit log entry.

## PROJECT STATE
- Milestone: M8a — engagements as the authorization container for campaigns.
  COMPLETE. Scope chosen: a full engagement lifecycle (operator requests ->
  admin authorizes) with an emergency-stop (terminate), plus a server-side gate
  that blocks launch/send unless the campaign is bound to an authorized,
  unexpired, non-terminated engagement.
- BEHAVIOR CHANGE (intentional, documented): a campaign can no longer be
  launched or sent without a bound, authorized, unexpired engagement. Launch/
  send return 403 when unbound/unauthorized, 409 when expired/terminated.
  Campaigns created before migration 0015 have engagement_id NULL and must be
  bound (POST/PATCH /campaigns with engagement_id) before they can run — this
  required seeding engagements in the existing launch/send integration tests
  (listed below).
- Done (M8a engagements):
  - Migration 0015 (NOT 0014 — SMS took 0014): engagement_status enum
    (draft|pending_authorization|authorized|active|expired|terminated),
    engagements table (tenant-scoped, UNIQUE(tenant,name), authorized_scope
    jsonb, authorized_at/by, starts_at/expires_at, notes, set_updated_at
    trigger), campaigns.engagement_id UUID FK ON DELETE SET NULL + index.
    .down.sql drops the column/index, table, and enum cleanly. 'active' and
    'expired' are DERIVED (never stored); stored values are draft/pending/
    authorized/terminated.
  - internal/engagement: domain (Status, IsActive(now), IsExpired, Effective
    label, CheckCampaignLaunchable -> ErrEngagementNotAuthorized/Expired/
    Terminated sentinels, Can{RequestAuthorization,Authorize,Terminate,Edit}
    guards, ValidateScope for URL/wildcard-domain entries) + stateless
    tenant-scoped repo (Create/GetByID/List/Update/RequestAuthorization/
    Authorize/Terminate). Unit tests (no DB) cover transitions, IsActive/
    Effective incl. expiry boundary, launchable sentinels, scope validation.
  - HTTP (tenant-scoped, audited) /engagements: GET list, POST create, GET
    {id}, PATCH {id} (draft/pending/authorized editable; terminated -> 409),
    POST {id}/request-authorization (operator; draft|pending -> pending),
    POST {id}/authorize (ADMIN only; pending -> authorized, sets authorized_
    at/by), POST {id}/terminate (ADMIN only; any non-terminal -> terminated).
    Per-route roles so admin actions coexist with operator CRUD under one mount
    (self-authorization impossible — operator cannot reach authorize/terminate).
    Lifecycle transitions audited with {from,to} status
    (engagement.create/update/request_authorization/authorize/terminate).
  - Campaign binding: campaigns Create gained engagement_id; POST /campaigns
    and PATCH /campaigns/{id} accept an optional engagement_id (same-tenant or
    400; rebinding allowed only while draft, else 409). GetByID/ListByTenant
    LEFT JOIN engagements to return engagement_id + a derived engagement_status
    label (no N+1). Launch gate order: engagement -> SMS phone -> snapshot
    (refuse unauthorized before touching recipient data). Send re-checks the
    gate (engagement may expire/terminate between launch and send).
  - OpenAPI 0.10.0: /engagements paths + Engagement/EngagementInput/
    EngagementStatus schemas; engagement_id on campaign create + PATCH;
    engagement_id/engagement_status on Campaign; launch/send 403/409 documented.
    (Also fixed 3 PRE-EXISTING malformed-YAML lines that made the whole spec
    unparseable — listApprovals missing brace, engine-events {accepted,
    results[]} placeholder, PromptVariable unquoted [A-Za-z_] description.)
  - web/: new "Engagements" nav page (create form name/client/scope-lines/
    expires-at/RoE; table with effective-status pill, authorized/expires dates;
    per-row Request-auth [operator] / Authorize + Terminate [admin-gated]
    buttons with inline 403/409 banners). Campaign create form + launch form
    gained an engagement selector; campaign detail header + config card show
    the engagement status pill. npm run build clean (54 modules).
  - Tests: internal/engagement unit tests; test/integration/engagements_test.go
    (full lifecycle create->request->authorize->bind->launch->send 202;
    operator authorize 403; authorize-from-draft 409; launch w/o engagement 403
    + detail, pending 403, expired 409, terminated 409; rebind-after-launch
    409; terminal no-reauth/no-edit 409; audit counts; tenant isolation 400/404/
    empty-list). UPDATED existing launch/send suites to seed+bind an authorized
    engagement: tracking_test, delivery_test, delivery_channels_test, sms_test
    (both the missing-phone-400 and happy campaigns), report_test,
    report_pdf_test, bounce_poller_test, platform_test (seedFunnel). Added a
    seedAuthorizedEngagement helper to flow_test.go.
  - Verification: go build/vet/test clean; full integration suite green
    (incl. the 8 updated suites + new engagements_test); gofmt-clean (touched
    files); web build clean; OpenAPI parses as valid YAML 0.10.0.
- Milestone: M9a — SMS delivery (smishing) as a new sending-profile channel.
  COMPLETE. Extends the existing email channel pattern (channelSender +
  resolveSender dispatch); the email path was not refactored. M9b quishing,
  M9c collaboration channels, M9d MFA-fatigue still open.
- Done (M9a SMS):
  - Migration 0014: 'sms' added to delivery_channel enum (ADD VALUE IF NOT
    EXISTS, in its own tx); sending_profiles gain sms_provider + sms_sender_id;
    contacts gain nullable phone_e164 TEXT with a CHECK (^\+[1-9][0-9]{7,14}$).
    No new tables. .down.sql drops the two profile columns + phone_e164 (the
    enum value cannot be dropped — noted).
  - internal/delivery/sms.go: Twilio Messages API sender. newSMSSender reuses
    the profile's api_client_id as the Account SID and the AES-GCM `secret`
    (smtp_pass_encrypted column) as the auth token; sms_sender_id = From.
    Send POSTs form-encoded To/Body/From to {TWILIO_BASE_URL}/2010-04-01/
    Accounts/{SID}/Messages.json with HTTP basic auth, capped (1MiB) response,
    non-2xx => wrapped error (=> 'failed' event, never panic). Fails fast when
    SID/token empty. channel.go resolveSender: case "sms". No open pixel.
  - delivery.go SendCampaign: isSMS branch — subject template parsed only when
    !isSMS; per recipient, phone from contacts.phone_e164 (empty => 'failed'
    event meta{error:"recipient has no phone number"}), body rendered from the
    template, chSender.Send(ctx, phone, "", body). Email path unchanged. Funnel
    starts at 'sent' and advances only via the existing /t/{token} click.
  - sendingprofile repo: ValidChannel += sms; ValidSMSProvider (twilio);
    SMSProvider/SMSSenderID on Profile + Input; cols/scan/Create updated.
  - contact repo: Contact.PhoneE164 + Input.PhoneE164; ValidE164 (regexp);
    cols/scan/Create/Update/BulkImport updated. BulkImport drops an invalid/
    absent E.164 (lenient, no batch fail).
  - HTTP: createSendingProfile switch(channel) — sms requires ValidSMSProvider
    + sms_sender_id, secret=auth token, from_address not required, smtp fields
    cleared/tls none. Template create/update: kind=sms body >1600 chars => 400.
    Contacts create/update: invalid phone_e164 => 400; import lenient.
    Launch: when the bound profile is sms, a count query refuses the launch
    (400 with the missing count) if any selected recipient lacks a phone;
    suppression honored as before.
  - config: TWILIO_BASE_URL (default https://api.twilio.com), TWILIO_TIMEOUT
    (default 15s); only base URL/timeout from env, credentials per-profile.
    .env.example documents them. cmd/worker wires sender.UseSMS(cfg). Empty
    integration => profile creation works, send fails per-recipient.
  - web/: SendingProfiles form has a channel selector (SMTP|SMS); the SMS
    variant shows provider + sender id + Account SID + write-only auth token and
    hides the SMTP fields; table shows a Channel column. Templates editor hides
    subject for kind=sms and shows a char/segment length hint (warn >160, error
    >1600). Contacts form + CSV import + table carry phone_e164. Campaign launch
    profile selector shows [channel].
  - OpenAPI 0.9.7: channel 'sms' + sms_provider/sms_sender_id on sending
    profiles (required relaxed to [name]; per-channel notes), phone_e164 on
    Contact/ContactInput, sms body <=1600 note on TemplateInput.
  - Tests: internal/delivery/sms_test.go (httptest fake Twilio — basic auth,
    To/From/Body/path, 4xx => error, missing-creds fail-fast, timeout);
    internal/contact/repository_test.go (ValidE164 valid/invalid);
    test/integration/sms_test.go (create sms profile [auth token ciphertext at
    rest, not leaked] => sms template + length-guard 400 => invalid-E.164 400 =>
    missing-phone launch 400 => happy launch => approval gate 403->202 =>
    SendCampaign over mocked Twilio: sent=1 failed=0, provider To/From/SID/body
    asserted, 1 'sent' + 0 'opened' => /t click => 1 'clicked' + still 0
    'opened'). go build/vet/test clean; full suite green; web build clean (53
    modules); touched Go files gofmt-clean (LF). Dev DB migrated to 0014 (v14).
- Milestone: docs pass — COMPLETE (documentation only; no code changes).
- Done (docs pass):
  - README.md (root, new): what-it-is + authorized-use-only note, architecture
    sketch (ASCII), docker/migrate/seed/run quickstart (commands copied from the
    Makefile + .env.example, not invented), M1–M8 feature table, full env-var
    table generated from internal/config.go (DATABASE_URL required; optionals
    degrade to 503), dev/test/CI section, project layout.
  - docs/ARCHITECTURE.md (was an empty stub): components, campaign data flow
    diagram (campaign→delivery→tracking events→report), data-model table of the
    real tables + relationships, approval-gate + audit-trail design, the engine
    model (supervised subprocess, per-run bearer stored SHA-256-hash-only,
    capture-only ingest = metadata persisted / secret values never), trade-offs.
  - docs/THREAT_MODEL.md (was an empty stub): the platform's own security model —
    assets, trust boundaries (browser→API, engine→orchestrator, worker→
    providers, OSINT), implemented mitigations (tenant scoping, bcrypt/
    constant-time key compare, hash-only engine tokens, AES-GCM secrets,
    capture-only, approval gate, append-only audit, self-lockout guards),
    residual risks/operational requirements, and in-tool abuse prevention
    (suppression + approval). No evasion/circumvention content.
  - LICENSE: FLAGGED — no LICENSE file exists at repo root; README's License
    section says so and does not invent one (all rights reserved by default
    until one is added).
  - Verification: docs-only diff (README.md + the two docs); go build/vet/test
    green before and after; no Go files touched so the gofmt gate is unaffected.
- Milestone: M8 multi-tenant portals — platform-admin cross-tenant console
  (M8 now fully done). Scope chosen by the user: a cross-tenant oversight
  console (not a viewer customer portal / not tenant switching).
- Decision: in this internal, self-hosted deployment the `admin` role is
  platform-level — consistent with the existing admin-gated, cross-tenant
  /tenants list/get. The new /platform/* endpoints extend that to read-only
  cross-tenant KPI oversight. (A dedicated super-admin tier wasn't added; log in
  docs/ADR.md if that's ever wanted.)
- Done (platform console):
  - internal/report.PlatformOverview: per-tenant headline rollup across ALL
    tenants (two aggregate queries — state histogram per tenant + campaign
    counts — merged in Go; reuses totalsFromHistogram; no N+1).
  - HTTP (admin, audited) /platform: GET /tenants (all tenants + KPIs), GET
    /tenants/{id}/summary (ANY tenant — cross-tenant, unlike the own-tenant
    /tenants/{id}/summary), GET /tenants/{id}/summary.pdf (ANY tenant, reuses
    pdfexport.TenantPDF). 404 unknown tenant; 403 for non-admin. Audited
    platform.overview / platform.tenant_summary[.pdf].
  - web/ (admin-only nav "Platform"): Platform.tsx (all-tenants table —
    campaigns/recipients/clicked%/creds%, rows link in) + PlatformTenant.tsx
    (aggregate RateBars + per-campaign table + Download executive summary PDF).
    Routes admin-gated (redirect to /overview otherwise).
  - OpenAPI 0.9.6 (/platform paths + PlatformTenant schema). Tests:
    test/integration/platform_test.go (two seeded tenants; A's admin sees both
    with correct KPIs; cross-tenant summary + PDF %PDF; operator 403; unknown
    404; audit). go build/vet/test clean; web build clean (53 modules);
    gofmt-clean.
- Milestone: operator user management.
- Done (user management):
  - internal/user: tenant-scoped repo. Create mirrors the seed tool
    (INSERT users(tenant_id,email,role::user_role); active, no password —
    key-based). List, GetByID, Deactivate (status 'active'->'inactive', which
    disables the user's keys via apikey.Verify's status check), CountActiveAdmins,
    ValidRole. User JSON exposes active (derived from status), never a password.
  - HTTP /users (tenant-scoped, audited): GET list (operator), POST create
    (admin; 409 dup email, 400 bad role/email), POST /{id}/deactivate (admin;
    404 unknown, 409 already-inactive, 409 last-active-admin guard). Guard +
    update + audit run in one tx. Routes use per-route roles (list operator,
    mutations admin), like the /tenants group. No new migration.
  - web/ Settings: a Users section (table email/role/status/created; admin-only
    create form with role select + deactivate behind confirm, inline 409/403)
    alongside the existing API-keys section.
  - OpenAPI 0.9.5 (/users endpoints + User schema). Tests:
    internal/user/repository_test.go (ValidRole, no DB); test/integration/
    users_test.go (list no-secret, operator create/deactivate 403, admin create
    201 + dup 409 + bad role 400, deactivate disables the user's key -> 401,
    already-inactive 409, last-admin 409 then key still works, deactivate admin
    when another remains 200, unknown 404, audit create=2/deactivate=2).
    go build/vet/test clean; web build clean (51 modules); gofmt-clean.
- Milestone: operator API key management.
- Done (API key management):
  - internal/apikey: added Record + List (never returns secret/hash), KeyID on
    Identity (from the parsed token), and RevokeOperatorKey with the self-
    lockout guard. Rule: revoking the key the request authenticated with is
    refused (ErrLastOperatorKey) when no OTHER active operator-capable
    (role admin/operator) key would remain for the tenant; check + revoke run
    in one tx. Plain Revoke retained for seed/tests.
  - auth.Principal gained KeyID; server identifier populates it from the key.
  - HTTP (operator, tenant-scoped, audited) /api-keys: GET list, POST create
    (returns the pf_... token exactly once; audited apikey.create by the
    service), POST /{id}/revoke (self-lockout => 409, unknown/already-revoked
    => 404; audited apikey.revoke). No new migration (api_keys columns already
    exist since 0003).
  - web/ Settings page (nav "Settings"): create form; a one-time token box with
    a Copy button (dismissable); key table (name/created/last-used/status) with
    Revoke behind window.confirm and inline 409 handling.
  - OpenAPI 0.9.4 (/api-keys endpoints + APIKey schema).
  - Tests: internal/apikey/apikey_test.go (parseToken valid/invalid forms, no
    DB); test/integration/apikeys_test.go (list has no secret, create token
    once + works, revoke non-current, self-lockout 409 on last operator key +
    key still works, revoke current when another remains, revoked key -> 401,
    unknown -> 404, audit counts create=3/revoke=2). npm run build clean (51
    modules); go build/vet/test clean; full suite green; gofmt-clean.
    (Docker Desktop had stopped over the gap; restarted postgres/redis to run
    the integration suite.)
- Milestone: web/ PDF download buttons.
- Done (web PDF downloads):
  - client: generalized the CSV blob-download helper to downloadFile (reads the
    Content-Disposition filename when present, else a fallback; sends the API
    key). Added campaigns.reportPdf(id, bucket) and tenants.summaryPdf(id).
  - Campaign detail Report section: "Download PDF" button (uses the current
    bucket selector) with a loading state, beside the existing CSV button.
  - Overview page: "Download executive summary" button (tenant id derived from
    the campaigns list) with a loading state + error banner.
  - Downloads use the authenticated blob fetch (not window.open), so the
    X-API-Key header is sent. npm run build clean (50 modules). No Go changes.
- Milestone: M8 build-out part 3 — executive PDF export.
- Dependency choice: github.com/go-pdf/fpdf v0.9.0 — pure Go (no CGO, no
  browser, no network at render), MIT-licensed (NOT MPL/AGPL; safe to vendor).
  Chosen over chromedp/headless and over AGPL libs (e.g. unidoc).
- Done (M8 PDF export):
  - internal/pdfexport: pure row-mappers (FunnelRows, TimelineRows,
    RecipientRows, CampaignSummaryRows, OSINTHighlightRows) with per-table caps
    (truncated flag) — unit-tested against fixed structs; and pdf.go which
    renders via fpdf with a page header (PhishForge — <tenant>), footer
    (generated timestamp + Page x/{nb} + a truncation note when any table was
    capped), auto page-break pagination, and shaded tables.
  - HTTP (operator, tenant-scoped, audited): GET /campaigns/{id}/report.pdf
    (?bucket=hour|day — funnel + timeline table + per-recipient drilldown,
    states+timestamps only) and GET /tenants/{id}/summary.pdf (own tenant only,
    403 else — aggregate funnel + per-campaign rates + OSINT highlights counts).
    Both REUSE the same report.Repository functions as the JSON/CSV handlers
    (report.Campaign / Recipients / TenantSummary) so numbers can't diverge.
    Content-Type application/pdf; Content-Disposition filename from campaign/
    tenant name + date. Rendered to a buffer (fpdf builds in memory) so render
    errors return cleanly before headers are sent.
  - OpenAPI 0.9.3 (both .pdf endpoints). Audited report.pdf /
    report.tenant_summary.pdf.
  - Tests: internal/pdfexport/rows_test.go (cell-value assertions for every
    mapper incl. truncation + zero-recipient guard); test/integration/
    report_pdf_test.go (renders both endpoints + hourly bucket, asserts %PDF-
    magic + >800 bytes, cross-tenant 403, audit count). go build/vet/test clean;
    full suite green; gofmt-clean.
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