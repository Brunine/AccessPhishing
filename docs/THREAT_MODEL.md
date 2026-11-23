# Threat model

This is the **platform's own** security model — the defender's view of
PhishForge as a system to be operated safely. It describes what the tool
protects, where its trust boundaries are, the mitigations already implemented,
and the residual risks an operator must own. It is not a guide to conducting
engagements and contains no evasion or circumvention content.

PhishForge is designed for **authorized** simulations only (your own
organization, or a customer under a signed engagement). Authorization is an
operational precondition the platform cannot itself verify; see Residual risks.

## Assets

| Asset | Where | Sensitivity |
| --- | --- | --- |
| Captured event metadata | `events` (append-only) | tenant-confidential: who clicked/opened and when; **not** submitted secret values |
| Tenant data | contacts, campaigns, templates, OSINT results | PII (target emails) + engagement data |
| API keys | `api_keys` (bcrypt hash only) | authenticate operators to the API |
| Sending credentials | `sending_profiles` (AES-256-GCM sealed) | SMTP passwords / OAuth secrets |
| Engine callback tokens | `engines.callback_token_hash` (SHA-256 hash only) | authorize an engine run's event ingest |
| Audit log | `audit_log` (append-only) | tamper-evident record of operator actions |

The **database is the crown jewels**: it holds all of the above. Protect it
accordingly (see Residual risks).

## Trust boundaries

| Boundary | Authn | Notes |
| --- | --- | --- |
| Browser → API | `X-API-Key` (`pf_<id>.<secret>`) | key maps to a tenant + role; every query is tenant-scoped from the principal, never from client input |
| Engine → orchestrator | per-run bearer token (hash-only at rest) | public, rate-limited ingest endpoint; plaintext token only in the engine process env for the run |
| Worker → mail providers | SMTP auth / Graph + Gmail OAuth2 | credentials decrypted in-process at send time only |
| OSINT service → (and from) API | `X-OSINT-TOKEN` | the Go API calls the Python service; the service binds loopback by default and gates on a token when set |
| Public tracking (`/t`, `/px`) | path token = the credential | unauthenticated by design; never reveals token validity |

## Mitigations implemented

- **Tenant isolation**: repositories are tenant-scoped; the authenticated
  principal supplies the tenant id — it is never taken from a query parameter.
  Cross-tenant reads exist only on admin-gated `/platform/*` endpoints (admin is
  platform-level in this internal deployment) and are audited.
- **RBAC**: `admin` / `operator` / `viewer` enforced per route; approval
  decisions and user/tenant administration require admin.
- **API-key hygiene**: only a bcrypt hash is stored; the plaintext token is
  returned exactly once at creation and never again; verification compares the
  secret against the hash (bcrypt is constant-time) and rejects revoked keys or
  inactive users uniformly.
- **Secrets encrypted at rest**: sending-profile secrets are sealed with
  per-tenant AES-256-GCM keys derived from `ARTIFACT_ENC_KEY` (HKDF-SHA256);
  the secret is never serialized back out of the API.
- **Engine tokens hash-only**: the per-run callback bearer is stored as a
  SHA-256 hash; the plaintext exists only in the engine process for the run.
- **Capture-only boundary**: consistent with the default capture-only tenant
  policy, event ingest persists the event and its metadata (field names /
  state), **never submitted secret values**; captured credentials are not
  logged or stored in plaintext.
- **Approval gate**: every outbound artifact (template, LLM draft → template)
  must be approved before a campaign can send; the platform never auto-sends.
- **Full audit log**: append-only (DB trigger rejects update/delete); every
  mutating action and sensitive read is recorded with actor + target, committed
  in the same transaction as the action.
- **Self-lockout guards**: the API refuses to revoke a tenant's last active
  operator key, or to deactivate its last active admin.
- **No tracking identifiers in URLs**: tracking uses unguessable path segments,
  not `?rid=`-style parameters, and responses don't leak token validity.
- **Parameterized SQL** throughout (pgx); no string-built queries.

## Residual risks & operational requirements

- **Authorization is the operator's responsibility.** The platform cannot verify
  that an engagement is authorized or in scope. Operate it only against
  organizations that have authorized you in writing.
- **Secret material is intentionally unrecoverable.** API tokens and engine
  callback tokens are hash-only; sending secrets are write-only. Lost tokens
  must be re-created, not recovered.
- **Engine subprocesses run with the orchestrator's privileges.** Only register
  engines whose binary (`ENGINE_BINARY_PATH`) and config you trust; the config
  is structurally validated but the process inherits host privileges.
- **The database is the crown jewels.** Compromise exposes all tenant data and
  encrypted secrets. Restrict network access, enable TLS, back up regularly, and
  rotate `ARTIFACT_ENC_KEY` and provider credentials on a schedule and after any
  suspected exposure. Keep `.env`, `data/`, captures, keys, and customer target
  lists out of version control (enforced by `.gitignore`).
- **Public endpoints are exposed by design.** `/t`, `/px`, and the engine ingest
  endpoint are unauthenticated-by-token and rate-limited; front them with a
  redirector/CDN per the deployment model and monitor for abuse.
- **Tenant data minimization.** Prefer the capture-only default policy; purge
  per tenant policy. Avoid storing more PII than an engagement needs.

## Abuse prevention within the tool

- **Suppression lists**: per-tenant do-not-contact addresses are honored at
  launch, so suppressed recipients are never snapshotted or sent to.
- **Approval workflow**: the human-in-the-loop gate prevents un-reviewed or
  auto-generated content from being sent.
- **Audit + RBAC**: every operator action is attributable and role-gated, so
  misuse is both constrained and recorded.
