# Application Profile — Validation Rules (v1)

Numbered, machine-checkable rules the Phase 3 parser MUST enforce. Each rule has
a stable ID and a severity:

- **error** — the profile is rejected / unusable (fail closed). The proxy will
  not serve a campaign bound to it.
- **warn** — accepted, but surfaced to the operator for review.

The validator SHOULD collect **all** violations in one pass and return them
together (as `engineconfig.ValidationError` does today), not stop at the first.

Field references below use the paths from [SCHEMA.md](./SCHEMA.md). Every rule
references a field that exists in the schema.

---

## Document & schema

| ID | Severity | Rule |
|---|---|---|
| `SCHEMA-VERSION-REQUIRED` | error | `version` is present and is an integer. |
| `SCHEMA-VERSION-UNSUPPORTED` | error | `version == 1`. A v1 parser rejects any other version rather than best-effort parsing. |
| `SCHEMA-SIZE-LIMIT` | error | Raw YAML document <= 64 KiB (mirrors `engineconfig.MaxConfigBytes`). |
| `SCHEMA-UNKNOWN-KEY` | error | No unrecognized key except under the `x-` namespace (SCHEMA.md §7). |
| `SCHEMA-SECTIONS-REQUIRED` | error | `metadata`, `auth`, `session`, `mfa`, `phishing_facet` are all present. |

## metadata

| ID | Severity | Rule |
|---|---|---|
| `META-NAME-REQUIRED` | error | `metadata.name` is present. |
| `META-NAME-SYNTAX` | error | `metadata.name` matches `^[a-z0-9][a-z0-9_-]{0,63}$`. |
| `META-NAME-UNIQUE` | error | `metadata.name` is unique within the tenant (DB `UNIQUE (tenant_id, name)`). |
| `META-NOTES-SIZE` | warn | `metadata.notes` <= 2048 chars (truncation risk otherwise). |

## auth

| ID | Severity | Rule |
|---|---|---|
| `AUTH-METHOD-REQUIRED` | error | `auth.method` is present. **Omission is NOT guessed** (SCHEMA.md §1.1). |
| `AUTH-METHOD-KNOWN` | error | `auth.method` ∈ {`form`,`oauth2_code`,`saml_post`,`ntlm`,`basic`}. Unknown → fail closed. |
| `AUTH-METHOD-UNSUPPORTED` | error | For **runtime use**, `auth.method == form` in v1. The other recognized values are reserved and proxy-unsupported (SCHEMA.md §4.2). |
| `AUTH-LOGINPATH-REQUIRED` | error | `auth.login_path` present, starts with `/`, <= 2048 chars, contains no scheme/host (it is a path, not a URL — SSRF-safe). |
| `AUTH-FORM-FIELDS-REQUIRED` | error | When `method=form`, `auth.fields` is a non-empty list. |
| `AUTH-FIELD-SELECTOR-REQUIRED` | error | Each `auth.fields[*].selector` is present and non-empty. |
| `AUTH-FIELD-UPSTREAM-REQUIRED` | error | Each `auth.fields[*].upstream_field` is present. |
| `AUTH-FIELD-UPSTREAM-SYNTAX` | error | `upstream_field` matches `^[A-Za-z_][\w.\[\]-]{0,127}$` (form-field name grammar). |
| `AUTH-FIELD-UPSTREAM-UNIQUE` | error | `upstream_field` values are unique across `auth.fields` (and vs `mfa.totp.upstream_field`). Duplicates make capture ambiguous. |
| `AUTH-CAPTURE-ATLEAST-ONE` | warn | At least one `auth.fields[*].capture == true` (a form profile that captures nothing is almost certainly a mistake). |
| `AUTH-FIELDS-COUNT` | error | `auth.fields` has <= 32 entries (mirrors `Capture.CredentialFormFields` cap). |

### Selector syntax (`SELECTOR-SYNTAX`, error)

`auth.fields[*].selector` and `mfa.totp.selector` must be one of:

1. a bare token — `^[A-Za-z_][\w-]{0,63}$` (treated as name/id), or
2. a qualifier — `name=<token>` or `id=<token>`, or
3. a constrained CSS selector — `^(input|select|textarea)(\[[a-zA-Z0-9_-]+=[^\]]{1,64}\])?$`.

No descendant combinators, no `*`, no scripting — keeps the clone-time matcher
bounded and injection-free.

## session

| ID | Severity | Rule |
|---|---|---|
| `SESSION-SUCCESS-REQUIRED` | error | `session.success_indicators` is a non-empty list. |
| `SESSION-SUCCESS-TYPE` | error | Each `type` ∈ {`cookie_set`,`url_redirect`,`status_code`,`body_regex`}. |
| `SESSION-SUCCESS-FIELDS` | error | Type-specific field present: `cookie_set`→`name`; `url_redirect`→`location`; `status_code`→`code` (100–599); `body_regex`→`pattern` (valid RE2, <= 512 chars). |
| `SESSION-TOKENS-REQUIRED` | error | `session.token_locations` is a non-empty list. |
| `SESSION-TOKEN-IN` | error | Each `token_locations[*].in` ∈ {`cookie`,`header`,`body`,`query`} and `name` is present (<= 128 chars). |
| `SESSION-INDICATOR-INTERSECT` | error | Every `success_indicators` entry of type `cookie_set` has its `name` also appear as a `token_locations` entry with `in: cookie`. A success cookie the proxy can't locate is unusable for hijack. |
| `SESSION-COOKIES-COUNT` | error | `token_locations` entries with `in: cookie` number <= 32 (mirrors `Capture.SessionCookies` cap). |
| `SESSION-REFRESH-PATHS` | error | Each `refresh_endpoints[*]` starts with `/`, <= 16 entries. |

## mfa

| ID | Severity | Rule |
|---|---|---|
| `MFA-MODE-REQUIRED` | error | `mfa.mode` is present. |
| `MFA-MODE-KNOWN` | error | `mfa.mode` ∈ {`none`,`totp_field`,`push_intercept`,`custom`}. Unknown → fail closed. |
| `MFA-MODE-UNSUPPORTED` | error | For runtime use, `mfa.mode` ∈ {`none`,`totp_field`} in v1. `push_intercept`/`custom` are reserved (SCHEMA.md §3.4, open question §8). |
| `MFA-TOTP-REQUIRED` | error | When `mode=totp_field`, `mfa.totp.selector` and `mfa.totp.upstream_field` are present and satisfy `SELECTOR-SYNTAX` / `AUTH-FIELD-UPSTREAM-SYNTAX`. |
| `MFA-TOTP-CONSISTENCY` | error | When `mode != totp_field`, `mfa.totp` is absent or empty. A TOTP field without the matching mode is a contradiction. |
| `MFA-TOTP-CAPTURED` | warn | When `mode=totp_field`, the TOTP `upstream_field` is treated as captured (joins the credential allowlist); surfaced so the operator knows the OTP enters the `creds` event names. |

## phishing_facet

| ID | Severity | Rule |
|---|---|---|
| `FACET-REQUIRED` | error | `phishing_facet.login_page_url`, `clone_strategy`, `asset_policy` all present. |
| `FACET-URL-SYNTAX` | error | `login_page_url` is an absolute `http(s)://` URL (<= 2048 chars). |
| `FACET-CLONE-STRATEGY` | error | `clone_strategy` ∈ {`mirror`,`template`,`llm_assisted`}. |
| `FACET-ASSET-POLICY` | error | `asset_policy` ∈ {`proxy`,`inline`,`strip`}. |
| `FACET-HOOKS-COUNT` | warn | `detectable_hooks` <= 32 entries. |

## proxy (optional)

| ID | Severity | Rule |
|---|---|---|
| `PROXY-TOKENKEY-SIZE` | error | `proxy.token_query_key` <= 64 chars (mirrors `Capture.TokenQueryKey`). |
| `PROXY-FORMACTION-SIZE` | error | `proxy.form_action_contains` <= 256 chars. |
| `PROXY-MAXBODY-RANGE` | error | `proxy.max_body_bytes` ∈ [0, 1048576] (mirrors `Capture.MaxBodyBytes`). |

## Secrets (hard rules)

| ID | Severity | Rule |
|---|---|---|
| `SECRETS-NO-VALUES` | error | No `token_locations` / `fields` entry carries a `value`, `secret`, or `token` key. Profiles describe shape, never values (SCHEMA.md §6). |
| `SECRETS-NO-CREDS` | error | No profile value looks like an embedded credential (e.g. a `password:`/`client_secret:` key anywhere outside the `x-` namespace). |

---

## Cross-check summary (the non-obvious ones)

- **Capture allowlist is explicit:** only `capture: true` fields (+ a
  `totp_field` TOTP) ever enter `creds`. `AUTH-CAPTURE-ATLEAST-ONE` /
  `MFA-TOTP-CAPTURED` make the harvested set visible at save time.
- **Success ↔ token intersection:** `SESSION-INDICATOR-INTERSECT` guarantees
  every "login succeeded" cookie is also locatable for hijack — no dead
  indicators.
- **Fail closed everywhere:** `AUTH-METHOD-REQUIRED`, `AUTH-METHOD-KNOWN`,
  `MFA-MODE-KNOWN`, `SCHEMA-VERSION-UNSUPPORTED`, `SCHEMA-UNKNOWN-KEY` all
  reject rather than guess.
