# Architecture Decision Records

This file logs significant architecture decisions. Format per record:
**Status · Context · Decision · Consequences**. Append new records; never
rewrite a superseded one — mark it `Superseded by ADR-NNNN` instead.

---

## ADR-0001 — Application profiles are file-defined, DB-backed, explicit-capture (M10b)

**Status:** Accepted — 2026-11-24. Design-only (M10b Phase 2); implementation
(Phase 3) and the consuming proxy (M5) are NOT STARTED.

### Context

M5's AiTM reverse proxy needs a per-application description of *how* to phish and
proxy a target login surface: form shape, SSO/MFA flow, session markers, and
clone configuration. Today a single engine carries an ad-hoc
[`engineconfig.Capture`](../internal/engineconfig/engineconfig.go) block
(`credential_form_fields`, `session_cookies`, `token_query_key`, …). That is
enough for one hand-tuned engine but does not scale to a reviewed, shareable,
per-tenant library of application targets, and it predates engagements/domain
inventory, so it has no authorization story.

We need a contract that (a) M5 can consume at request time, (b) the M6 LLM/clone
layer can consume for lookalike generation, (c) is reviewable and shareable, and
(d) inherits the tenant-scoping + admin-authorization guarantees the rest of the
platform already enforces.

### Decision

1. **File-based YAML schema, versioned.** Profiles are authored as YAML
   (`docs/PROFILES/SCHEMA.md`, v1). YAML is versionable in git, reviewable as a
   diff, and shareable between operators/engagements. A required integer
   `version` field gates forward compatibility: a v1 parser rejects versions it
   does not implement rather than best-effort parsing a future shape — the same
   fail-closed stance `engineconfig` takes on unknown fields.

2. **Backed by a tenant-owned DB row.** Each profile is stored as a row
   (`app_profiles`, proposed migration `0021`) with `UNIQUE (tenant_id, name)`,
   `created_by`, an `updated_at` trigger, the parsed `spec` (JSONB), the exact
   `spec_yaml` source, and a checksum. This gives tenant scoping, audit, and a
   `verified → active` lifecycle. Engagement binding + an **admin**
   authorization gate live in a separate `app_profile_assignments` table — the
   same independent-checks design as `domain_assignments` (M8b/`0017`):
   *verification* (the YAML validates) and *authorization* (an admin clears an
   assignment) are enforced independently.

3. **Capture is an explicit allowlist.** Only fields marked `capture: true`
   enter the credential set. This is not a stylistic choice — it is enforced by
   the existing capture-only boundary: the proxy keeps only allowlisted field
   names, and the orchestrator's `sanitizeEnginePayload` strips every value and
   records **names only** in the `creds`/`session_hijacked` event metadata. A
   profile, by construction, can cause a field *name* to be recorded and nothing
   more; there is no key that stores a raw value.

4. **Profiles never carry secrets.** `session.token_locations` describe *where*
   a token lives and *that* it is sensitive — never a value. Real secrets stay
   in the AES-GCM `*_encrypted` columns. The validator rejects value-bearing
   keys (`SECRETS-NO-VALUES`).

5. **Namespaced extensibility.** Unknown `x-` keys are ignored; any other
   unknown key is an error. A reserved ignore-namespace lets a long-lived,
   shareable artifact be annotated against a newer schema without breaking older
   parsers, while core keys stay strict.

### What M5 will do with this contract

- At request time the proxy loads the campaign engagement's **active,
  authorized** profile, compiles it to an `engineconfig.Capture`, and serves.
  An invalid, unsupported-method, or unauthorized profile → the campaign is
  refused (fail closed).
- **Recommendation (for ruling):** profile edits take effect **without a
  campaign re-launch** — the proxy reads the current active profile per request,
  and every profile change is written to the audit log. Rationale: an operator
  fixing a selector mid-engagement should not have to tear down and re-launch a
  live campaign; the authorization gate (admin-approved assignment) already
  bounds *which* profile applies, so re-reading its body is safe. The
  alternative — snapshotting the profile at launch — is more reproducible but
  freezes bugs into a running campaign. We recommend read-current + audit, and
  flag it for confirmation.

### Consequences

- **+** One reviewed, tenant-scoped, authorized library of application targets;
  M5 and M6 share one contract; capture stays provably name-only.
- **+** Reuses the domains lifecycle/authorization pattern — no new auth model.
- **−** Two representations of the target (`spec_yaml` + `spec` JSONB) must be
  kept in sync (checksum guards this).
- **−** v1 implements the `form` method only; `oauth2_code`/`saml_post`/`ntlm`/
  `basic` are reserved-but-unsupported (see open question below), so SSO targets
  wait on a later version.

### Open questions (deferred — not decided here)

1. **OAuth2 code-flow / SAML POST interception model.** The AiTM mechanics for
   authorization-code and SAML flows differ fundamentally from form capture (the
   proxy must sit in the redirect/token-exchange chain and lift the
   `code`/`SAMLResponse` artifact). v1 reserves `auth.oauth2`/`auth.saml` as
   empty maps and defers their shape to M5 design input rather than inventing it.
2. **MFA `push_intercept` / `custom`.** Real-time push (number-matching) relay
   is not the form-capture model; v1 recognizes but does not implement these.
3. **Profile-change propagation.** Read-current + audit (recommended) vs.
   snapshot-at-launch — see the recommendation above.
