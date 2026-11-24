-- 0019_domain_candidates.up.sql — M8d: engagement-scoped domain discovery,
-- registrar price comparison, and deterministic candidate ranking.
--
-- The operator drives discovery for an authorized engagement; a background job
-- suggests lookalike candidates (via the OSINT service), fetches comparable
-- registrar price quotes, scores each candidate deterministically, and ranks
-- them. The operator then PICKS a candidate, purchases it EXTERNALLY, and
-- imports it through the existing manual /domains flow. There is NO automated
-- purchasing here and nothing in this milestone ever registers a domain.
--
-- Three new objects:
--   registrar_providers  — a global registry of the registrars we can quote
--                          from, and how (public API, authed API, or a manual
--                          price list). Seeded with porkbun/namecheap/cloudflare.
--   domain_candidates    — tenant+engagement-scoped suggested names with a
--                          deterministic score (jsonb) and a derived rank.
--   domain_price_quotes  — normalized price quotes per candidate per registrar.

BEGIN;

CREATE TYPE domain_candidate_status AS ENUM (
    'suggested', 'scored', 'selected', 'rejected', 'imported'
);

-- Global catalog of registrars we can obtain comparable quotes from. Not
-- tenant-scoped: registrar pricing is universal. api_kind maps a row to the Go
-- adapter that implements it (see internal/registrar).
CREATE TABLE registrar_providers (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name       TEXT NOT NULL UNIQUE,
    api_kind   TEXT NOT NULL CHECK (api_kind IN ('porkbun', 'namecheap', 'cloudflare', 'manual')),
    enabled    BOOLEAN NOT NULL DEFAULT true,
    base_url   TEXT,
    notes      TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO registrar_providers (name, api_kind, enabled, base_url, notes) VALUES
  ('porkbun',    'porkbun',    true,  'https://api.porkbun.com',
   'Public pricing API (no auth): POST /api/json/v3/pricing/get returns per-TLD register/renew/transfer prices.'),
  ('namecheap',  'namecheap',  false, 'https://api.namecheap.com',
   'namecheap.users.getPricing (XML). Requires ApiUser/ApiKey/UserName/ClientIp and an API IP allowlist; disabled until configured.'),
  ('cloudflare', 'cloudflare', false, '',
   'Cloudflare Registrar sells at wholesale/at-cost and exposes no public price-list API. Point CLOUDFLARE_PRICING_URL at an exported price table (per-TLD JSON) to enable.');

-- A suggested candidate domain for an engagement. score carries the full
-- deterministic breakdown (availability, conflict, cost); rank is 1-based,
-- lower is better, assigned by the collector after scoring.
CREATE TABLE domain_candidates (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    engagement_id UUID NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    source        TEXT NOT NULL DEFAULT 'lookalike',
    name          TEXT NOT NULL,
    fuzzer        TEXT,
    available     BOOLEAN,
    score         JSONB NOT NULL DEFAULT '{}'::jsonb,
    rank          INTEGER,
    status        domain_candidate_status NOT NULL DEFAULT 'suggested',
    notes         TEXT,
    created_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (engagement_id, name)
);

CREATE INDEX idx_domain_candidates_tenant_id ON domain_candidates (tenant_id);
CREATE INDEX idx_domain_candidates_engagement ON domain_candidates (engagement_id);

CREATE TRIGGER trg_domain_candidates_updated_at
    BEFORE UPDATE ON domain_candidates
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- A normalized registrar price quote for a candidate. Prices are stored in
-- integer minor units (cents) in the quote currency; NULL means the registrar
-- did not price that TLD. quoted_at is when the upstream quote was observed.
CREATE TABLE domain_price_quotes (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    candidate_id     UUID NOT NULL REFERENCES domain_candidates(id) ON DELETE CASCADE,
    registrar        TEXT NOT NULL,
    currency         TEXT NOT NULL DEFAULT 'USD',
    first_year_cents BIGINT,
    renewal_cents    BIGINT,
    transfer_cents   BIGINT,
    available        BOOLEAN,
    quoted_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (candidate_id, registrar)
);

CREATE INDEX idx_domain_price_quotes_candidate ON domain_price_quotes (candidate_id);
CREATE INDEX idx_domain_price_quotes_tenant_id ON domain_price_quotes (tenant_id);

COMMIT;
