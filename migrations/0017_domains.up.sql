-- 0017_domains.up.sql — M8b + M8c: centralized domain inventory with manual
-- import, TXT-based ownership verification, and DNS/TLS diagnostics.
--
-- Operators purchase domains externally (no registrar API / no automated
-- purchasing in this milestone) and import them here. Ownership verification
-- (a _phishforge.<domain> TXT record) and engagement authorization are two
-- INDEPENDENT checks: a domain may be verified but authorized for no
-- engagement, and vice versa.
--
-- domain_status enum carries forward-compat values ('candidate',
-- 'pending_purchase') for M8d; manual import lands in 'pending_verification'.
-- 'authorized'/'expired' are reserved/derived labels — the stored path a
-- domain follows in this milestone is pending_verification -> verified ->
-- active (via explicit activation). A background job to roll rows to 'expired'
-- from expires_at is out of scope here (derive-and-note, never auto-mutate).

BEGIN;

CREATE TYPE domain_status AS ENUM (
    'candidate', 'pending_purchase', 'pending_verification',
    'verified', 'authorized', 'active', 'suspended', 'expired', 'retired'
);

CREATE TABLE domains (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    registrar     TEXT,
    status        domain_status NOT NULL DEFAULT 'candidate',
    registered_at TIMESTAMPTZ,
    expires_at    TIMESTAMPTZ,
    dns_provider  TEXT,
    nameservers   TEXT[] NOT NULL DEFAULT '{}',
    tls_status    TEXT CHECK (tls_status IS NULL OR tls_status IN ('none', 'pending', 'valid', 'expiring', 'invalid')),
    notes         TEXT,
    created_by    UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE INDEX idx_domains_tenant_id ON domains (tenant_id);

CREATE TRIGGER trg_domains_updated_at
    BEFORE UPDATE ON domains
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- A domain attached to an engagement. Attach (operator) and authorize (admin)
-- are separate steps so the two checks stay independent: an operator may bind a
-- verified domain to an engagement, but only an admin flips the assignment to
-- 'authorized'. Deleting the engagement cascades the assignment away.
CREATE TABLE domain_assignments (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    domain_id     UUID NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    engagement_id UUID NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    status        TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'authorized', 'revoked')),
    authorized_by UUID REFERENCES users(id) ON DELETE SET NULL,
    authorized_at TIMESTAMPTZ,
    notes         TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (domain_id, engagement_id)
);

CREATE INDEX idx_domain_assignments_tenant_id ON domain_assignments (tenant_id);
CREATE INDEX idx_domain_assignments_domain_id ON domain_assignments (domain_id);

CREATE TRIGGER trg_domain_assignments_updated_at
    BEFORE UPDATE ON domain_assignments
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- A single ownership-verification challenge. hostname is always
-- _phishforge.<domain>; the operator publishes a TXT record with expected_value
-- and the API checks it. token is opaque (crypto/rand hex) and globally unique.
CREATE TABLE domain_verifications (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    domain_id      UUID NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    method         TEXT NOT NULL DEFAULT 'txt',
    hostname       TEXT NOT NULL,
    expected_value TEXT NOT NULL,
    token          TEXT NOT NULL UNIQUE,
    status         TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'verified', 'failed', 'expired')),
    verified_at    TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_domain_verifications_tenant_id ON domain_verifications (tenant_id);
CREATE INDEX idx_domain_verifications_domain_status ON domain_verifications (domain_id, status);

COMMIT;
