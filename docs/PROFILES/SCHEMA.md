# Application Profile Schema v1

> **Status:** M10b Phase 2 — DESIGN ONLY. This document defines the contract; no
> parser, migration, or handler exists yet (Phase 3). The AiTM reverse proxy
> (M5, NOT STARTED) is the primary runtime consumer; the template/LLM layer
> (M6) consumes the `phishing_facet` section only.

An **application profile** describes how to phish and proxy one target web
application: the shape of its login flow, the markers that signal a successful
upstream authentication, and the lookalike-clone configuration. One profile ==
one application login surface (e.g. "Outlook Web App logon").

Profiles are **file-first** (versionable, reviewable, shareable YAML) but are
stored as **tenant-owned DB rows** for scoping, authorization, and audit — the
same split the domain inventory (M8b) uses. See [the ADR](../ADR.md) for the
rationale.

---

## 1. Design principles

These are binding on the parser (Phase 3) and on this schema:

1. **Fail closed.** A profile that omits `auth.method`, or carries an unknown
   `auth.method` value, is *unusable* — never guessed. The proxy refuses to
   serve a campaign bound to an invalid or unsupported profile. (Mirrors
   `engineconfig.Parse`, which rejects unknown fields and invalid values rather
   than defaulting.)
2. **Capture is an explicit allowlist.** The proxy *never* dumps arbitrary
   request bodies into `creds` events. Only fields marked `capture: true` are
   added to the credential allowlist, and — per the existing capture-only
   boundary — only their **names** (never their values) ever reach the events
   table. See §5.
3. **Secrets never live in a profile.** A profile describes the *shape* of
   authentication and session material, not its values. `session.token_locations`
   say *where* a token lives and *that* it is sensitive — never a token, cookie
   value, password, or client secret. Real secrets (SMTP/API) stay in the
   AES-GCM `*_encrypted` columns they already occupy. See §6.
4. **Extensibility is namespaced.** Unknown keys under a reserved `x-` namespace
   are allowed and ignored by v1 (forward-compat for shareable files). Unknown
   keys *anywhere else* are a validation error (`SCHEMA-UNKNOWN-KEY`). This is a
   deliberate, documented deviation from `engineconfig`'s blanket
   unknown-field rejection — see §7.
5. **Versioned.** `version` is a required integer. v1 parsers reject any
   `version` they do not implement (`SCHEMA-VERSION-UNSUPPORTED`) rather than
   best-effort parsing a future shape.

---

## 2. Top-level structure

```yaml
version: 1                      # REQUIRED int. Forward-compat gate.

metadata:                       # REQUIRED
  name: owa-login               # unique per tenant; [a-z0-9][a-z0-9_-]{0,63}
  vendor: Microsoft
  product: Outlook Web App
  notes: >-                     # optional, <= 2 KiB
    Exchange on-prem / OWA form logon.

auth:                           # REQUIRED — how the proxy recognizes/forges auth
  login_path: /owa/auth/logon.aspx
  method: form                  # form | oauth2_code | saml_post | ntlm | basic
  fields:                       # REQUIRED when method=form
    - selector: input[name=username]
      upstream_field: username
      capture: true
    - selector: input[name=password]
      upstream_field: password
      capture: true
  oauth2: {}                    # RESERVED — see §4.2 (open question)
  saml:   {}                    # RESERVED — see §4.2 (open question)

session:                        # REQUIRED — upstream-success detection + token shape
  success_indicators:
    - type: cookie_set          # cookie_set | url_redirect | status_code | body_regex
      name: X-OWA-CANARY
  token_locations:
    - in: cookie                # cookie | header | body | query
      name: X-OWA-CANARY
      sensitive: true
  refresh_endpoints:            # optional; paths intercepted for replay
    - /owa/sessiondata.ashx

mfa:                            # REQUIRED (mode may be `none`)
  mode: none                    # none | totp_field | push_intercept | custom
  totp: {}                      # populated when mode=totp_field

phishing_facet:                 # REQUIRED — consumed by clone/LLM, never the proxy
  login_page_url: https://outlook.office.com/owa/auth/logon.aspx
  clone_strategy: mirror        # mirror | template | llm_assisted
  asset_policy: proxy           # proxy | inline | strip
  detectable_hooks: []          # known client-side defenses to watch for

proxy:                          # optional — runtime tuning (compiled to M5 Capture)
  token_query_key: _pft
  form_action_contains: logon.aspx
  max_body_bytes: 65536

x-notes: anything               # reserved extension namespace, ignored by v1
```

---

## 3. Section reference

### 3.1 `metadata` (required)

| Key | Type | Req | Rule |
|---|---|---|---|
| `name` | string | yes | Unique per tenant. `^[a-z0-9][a-z0-9_-]{0,63}$`. Mirrors the clone stored as a DB row's `name` (like `prompt_templates.name`). |
| `vendor` | string | no | <= 128 chars, display only. |
| `product` | string | no | <= 128 chars, display only. |
| `notes` | string | no | <= 2048 chars. |

### 3.2 `auth` (required)

| Key | Type | Req | Rule |
|---|---|---|---|
| `login_path` | string | yes | Absolute request path, `^/` , <= 2048 chars. No scheme/host (SSRF-safe: a path, not a URL). |
| `method` | enum | yes | One of `form`, `oauth2_code`, `saml_post`, `ntlm`, `basic`. Unknown → fail closed. **v1 fully implements `form` only** (see §4). |
| `fields[]` | list | when `method=form` | The login form fields. See below. |
| `oauth2` | map | when `method=oauth2_code` | **Reserved** (§4.2). |
| `saml` | map | when `method=saml_post` | **Reserved** (§4.2). |

**`auth.fields[]` entry** (form method):

| Key | Type | Req | Rule |
|---|---|---|---|
| `selector` | string | yes | How the field is identified in the **clone** page. One of three forms: a bare name/id token `^[A-Za-z_][\w-]{0,63}$`, a `name=` / `id=` qualifier, or a constrained CSS selector (see `SELECTOR-SYNTAX` in VALIDATION.md). |
| `upstream_field` | string | yes | The field **name** as it appears in the upstream POST body. This is the key matched against observed requests. `^[A-Za-z_][\w.\[\]-]{0,127}$`. |
| `capture` | bool | no (default `false`) | When `true`, `upstream_field` joins the credential allowlist. Only captured fields produce `creds` metadata. See §5. |

### 3.3 `session` (required)

Markers the proxy uses to detect a *successful upstream login* and to locate
session material for capture/refresh/replay.

**`success_indicators[]`:**

| Key | Type | Req | Rule |
|---|---|---|---|
| `type` | enum | yes | `cookie_set` \| `url_redirect` \| `status_code` \| `body_regex`. |
| `name` | string | for `cookie_set` | Cookie name set by upstream on success. |
| `location` | string | for `url_redirect` | Path/URL substring the upstream redirects to on success. |
| `code` | int | for `status_code` | HTTP status (100–599). |
| `pattern` | string | for `body_regex` | RE2 regex, <= 512 chars, applied to a bounded response body. |

**`token_locations[]`:** where session material lives (shape, not value).

| Key | Type | Req | Rule |
|---|---|---|---|
| `in` | enum | yes | `cookie` \| `header` \| `body` \| `query`. |
| `name` | string | yes | The cookie/header/param name. <= 128 chars. |
| `sensitive` | bool | no (default `true`) | Hint that this token is session-bearing. Does **not** carry a value. |

| Key | Type | Req | Rule |
|---|---|---|---|
| `refresh_endpoints[]` | list[string] | no | Absolute paths (`^/`) intercepted to keep a hijacked session warm. <= 16 entries. |

### 3.4 `mfa` (required; `mode: none` is valid)

| Key | Type | Req | Rule |
|---|---|---|---|
| `mode` | enum | yes | `none` \| `totp_field` \| `push_intercept` \| `custom`. Unknown → fail closed. |
| `totp` | map | when `mode=totp_field` | `{ selector, upstream_field }` — same shape as an `auth.fields` entry; the OTP field is captured into the **same** `creds` mechanism (§5). |

`push_intercept` and `custom` are **reserved** in v1 (recognized, but
proxy-unsupported — `MFA-MODE-UNSUPPORTED`, error). Flagged as an open question
(§8) — real-time push relay is not the form-capture model.

### 3.5 `phishing_facet` (required — clone/LLM only, never the proxy)

| Key | Type | Req | Rule |
|---|---|---|---|
| `login_page_url` | string (URL) | yes | The real login page to clone. Full `https://` URL (this *is* a URL, unlike `auth.login_path`). |
| `clone_strategy` | enum | yes | `mirror` (fetch+rewrite live), `template` (hand-authored, reuse the `template` library), `llm_assisted` (seed an `llm_draft` of kind `landing`). |
| `asset_policy` | enum | yes | `proxy` \| `inline` \| `strip` — how static assets resolve in the clone. |
| `detectable_hooks[]` | list[string] | no | Known client-side defenses present on the page (e.g. `fido2`, `js-challenge`). Advisory; surfaced to the operator, not enforced. <= 32 entries. |

### 3.6 `proxy` (optional — runtime tuning)

Compiled directly into the M5 engine `Capture` config
([engineconfig.Capture](../../internal/engineconfig/engineconfig.go)). Present so
a profile is a complete proxy contract.

| Key | Type | Req | Rule | Maps to |
|---|---|---|---|---|
| `token_query_key` | string | no (default `_pft`) | <= 64 chars. The victim-token query param stripped before forwarding. | `Capture.TokenQueryKey` |
| `form_action_contains` | string | no | <= 256 chars. Only inspect POSTs whose path contains this. | `Capture.FormActionContains` |
| `max_body_bytes` | int | no (default `65536`) | 0–1048576 (1 MiB). Request-body inspection cap. | `Capture.MaxBodyBytes` |

---

## 4. Auth methods: what v1 implements

### 4.1 `form` — fully implemented

The form method is the complete, supported v1 contract and the only one the M5
proxy will serve at first. It is a direct generalization of today's
`engineconfig.Capture`:

- every `auth.fields[*].upstream_field` with `capture: true` →
  `Capture.CredentialFormFields`
- `session.token_locations[*]` with `in: cookie` →
  `Capture.SessionCookies`
- `proxy.*` → the matching `Capture.*` knobs

### 4.2 `oauth2_code`, `saml_post`, `ntlm`, `basic` — reserved

These enum values are **recognized** (so a typo still fails closed rather than
masquerading as a supported method), but v1 does **not** implement their
interception. A profile declaring one is parse-valid but **proxy-unsupported**
(`AUTH-METHOD-UNSUPPORTED`, error for runtime use). They exist in the enum for
forward-compat, exactly as `engagement_status` carries `active`/`expired` ahead
of their stored use.

> **OPEN QUESTION (for you to rule on — see §8):** the AiTM interception model
> for OAuth2 authorization-code flow and SAML POST is materially different from
> form capture (the proxy must sit in the redirect/token-exchange chain and lift
> the `code`/`SAMLResponse` artifact, not a POST field). Rather than invent that
> sub-schema silently, v1 leaves `auth.oauth2` / `auth.saml` as reserved empty
> maps and defers their shape to M5 design input.

---

## 5. Capture → `creds` event mapping (grounded, not guessed)

This is the load-bearing contract. It is pinned to how creds metadata is written
*today*, in
[internal/api/handlers_engine_events.go](../../internal/api/handlers_engine_events.go)
(`sanitizeEnginePayload`) and
[internal/engineproxy/capture.go](../../internal/engineproxy/capture.go)
(`RequestMiddleware`):

1. The proxy builds a credential allowlist from the profile — the set of
   `auth.fields[*].upstream_field` where `capture: true` (plus `mfa.totp.upstream_field`
   when `mfa.mode=totp_field`). This is exactly `Capture.CredentialFormFields`.
2. On a matching POST, the proxy parses the (bounded) body and keeps only fields
   **whose name is in the allowlist**. A `creds` capture event carries
   `payload.fields = { name: value, ... }` for matched names only.
3. The orchestrator's `sanitizeEnginePayload` reduces that to
   **names only** before `events.Append`: the stored `creds` event metadata is

   ```json
   { "fields": ["password", "username"], "source": "engine" }
   ```

   The **values are discarded** at ingest — they are never written to the
   `events` table. (The proxy may additionally be run under a tenant's
   capture-only policy, which discards values even earlier.)
4. Session material maps the same way: `session.token_locations` with
   `in: cookie` → `Capture.SessionCookies`; a hijack produces a
   `session_hijacked` event whose metadata is
   `{ "cookies": ["X-OWA-CANARY"], "host": "...", "source": "engine" }` —
   again **names and a non-secret host only**, never cookie values.

**Consequence for schema design:** a profile can only ever cause a field's
*name* to be recorded. There is no profile key that can cause a raw value to be
stored, by construction. This is why `capture: true` is safe to express
declaratively.

---

## 6. Secrets & sensitive values — hard rule

A profile MUST NOT contain:

- passwords, OTP seeds, API client secrets, bearer tokens, cookie **values**,
  or any live session material;
- real victim or operator credentials of any kind.

`session.token_locations[*].sensitive: true` is a **shape** marker — it declares
"a sensitive token lives in this named location" so the proxy treats it
carefully. It carries no value. The validator rejects any `token_locations`
entry that includes a `value`/`secret`/`token` key (`SECRETS-NO-VALUES`, error).

Real secrets continue to live where they already do: AES-GCM-encrypted
`*_encrypted` columns (`sending_profiles.smtp_pass_encrypted`, etc.), never in a
profile row's YAML.

---

## 7. Extensibility: the `x-` namespace

- Keys prefixed `x-` at **any** level are accepted and **ignored** by the v1
  parser. Use them for annotations a future schema version may formalize.
- Any other unrecognized key is a hard error (`SCHEMA-UNKNOWN-KEY`).

This is a deliberate deviation from `engineconfig`, which rejects *all* unknown
fields. Justification: an app profile is a **shareable, long-lived artifact**
that may be authored against a newer schema and read by an older parser; a
reserved ignore-namespace lets teams annotate without forking the schema, while
core-key strictness preserves fail-closed behavior for anything that actually
drives the proxy.

---

## 8. Storage model — intended `migrations/0021` shape (DO NOT BUILD YET)

Columns only; pseudo-SQL. Mirrors the domain inventory (M8b, `0017`) so
engagement binding and the admin-authorization gate are reused, not reinvented.
A profile is a tenant-owned row whose YAML body is the source of truth; the
lifecycle (`verified`→`active`) means "validated and cleared for use".

```sql
-- app_profile_status: verified/active mirror the domain lifecycle; stored path
-- is draft -> verified -> active, with suspended/retired as off-ramps.
CREATE TYPE app_profile_status AS ENUM (
    'draft', 'verified', 'active', 'suspended', 'retired'
);

CREATE TABLE app_profiles (
    id          UUID PK,
    tenant_id   UUID NOT NULL REFERENCES tenants ON DELETE CASCADE,
    name        TEXT NOT NULL,              -- metadata.name
    vendor      TEXT,
    product     TEXT,
    version     INT  NOT NULL,              -- schema version from the YAML
    status      app_profile_status NOT NULL DEFAULT 'draft',
    spec        JSONB NOT NULL,             -- the parsed, validated profile
    spec_yaml   TEXT  NOT NULL,             -- the exact source (reviewable diff)
    checksum    TEXT  NOT NULL,             -- sha256 of spec_yaml (audit/dedupe)
    verified_at TIMESTAMPTZ,
    created_by  UUID NOT NULL REFERENCES users ON DELETE RESTRICT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),  -- set_updated_at trigger
    UNIQUE (tenant_id, name)
);

-- Engagement binding + admin authorization gate, independent of verification —
-- the same two-independent-checks invariant as domain_assignments (0017).
CREATE TABLE app_profile_assignments (
    id            UUID PK,
    tenant_id     UUID NOT NULL REFERENCES tenants ON DELETE CASCADE,
    profile_id    UUID NOT NULL REFERENCES app_profiles ON DELETE CASCADE,
    engagement_id UUID NOT NULL REFERENCES engagements ON DELETE CASCADE,
    status        TEXT NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending','authorized','revoked')),
    authorized_by UUID REFERENCES users ON DELETE SET NULL,  -- admin only
    authorized_at TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (profile_id, engagement_id)
);
```

**Invariant (reiterated from domains):** *verification* (the YAML parses and
passes `VALIDATION.md`) and *authorization* (an admin flips an assignment to
`authorized`) are enforced **independently**. A profile may be `verified` but
bound to no authorized engagement, and vice versa.

---

## 9. What M5 does with this (contract summary)

- At request time, the proxy loads the **active, authorized** profile bound to
  the campaign's engagement, compiles it to an `engineconfig.Capture`, and
  serves. No re-launch is required to pick up a profile edit (see the ADR's
  recommendation); profile changes are **audited**.
- The proxy only ever records field/cookie **names** (§5). A profile cannot
  widen that boundary.
- An invalid, unsupported-method, or unauthorized profile → the proxy refuses
  the campaign (fail closed).

See [VALIDATION.md](./VALIDATION.md) for the numbered rule set and
[examples/owa.yaml](./examples/owa.yaml) for a complete profile.
