-- 0002_tenant_policy.up.sql — per-tenant data-retention policy and key-ID refs.
-- NO key material is stored here: only external KMS/Vault key identifiers.
-- Default policy is capture-only (passwords discarded) per project policy.

BEGIN;

CREATE TYPE capture_mode AS ENUM ('capture_only', 'full');
CREATE TYPE key_purpose  AS ENUM ('artifact', 'credential', 'session');

-- ---------------------------------------------------------------------------
-- tenant_policies  (one row per tenant)
-- ---------------------------------------------------------------------------

CREATE TABLE tenant_policies (
    tenant_id                 UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    capture                   capture_mode NOT NULL DEFAULT 'capture_only',
    store_passwords           BOOLEAN NOT NULL DEFAULT false,
    credential_retention_days INTEGER NOT NULL DEFAULT 7   CHECK (credential_retention_days >= 0),
    session_retention_days    INTEGER NOT NULL DEFAULT 3   CHECK (session_retention_days >= 0),
    event_retention_days      INTEGER NOT NULL DEFAULT 365 CHECK (event_retention_days >= 0),
    artifact_retention_days   INTEGER NOT NULL DEFAULT 30  CHECK (artifact_retention_days >= 0),
    auto_purge                BOOLEAN NOT NULL DEFAULT true,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- capture-only tenants must not retain passwords
    CONSTRAINT chk_capture_only_no_passwords
        CHECK (capture = 'full' OR store_passwords = false)
);

CREATE TRIGGER trg_tenant_policies_updated_at
    BEFORE UPDATE ON tenant_policies
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------------
-- tenant_encryption_keys  (references only — key material lives in Vault/KMS)
-- ---------------------------------------------------------------------------

CREATE TABLE tenant_encryption_keys (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    purpose    key_purpose NOT NULL DEFAULT 'artifact',
    key_id     TEXT NOT NULL,   -- external KMS/Vault key reference, never key bytes
    active     BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, purpose, key_id)
);

CREATE INDEX idx_tenant_keys_tenant_id ON tenant_encryption_keys (tenant_id);
-- at most one active key per (tenant, purpose)
CREATE UNIQUE INDEX uq_tenant_keys_active
    ON tenant_encryption_keys (tenant_id, purpose)
    WHERE active;

-- ---------------------------------------------------------------------------
-- Auto-provision a default policy row whenever a tenant is created.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION create_default_tenant_policy() RETURNS trigger AS $$
BEGIN
    INSERT INTO tenant_policies (tenant_id)
    VALUES (NEW.id)
    ON CONFLICT (tenant_id) DO NOTHING;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_tenant_default_policy
    AFTER INSERT ON tenants
    FOR EACH ROW EXECUTE FUNCTION create_default_tenant_policy();

-- Backfill policies for any tenants created before this migration.
INSERT INTO tenant_policies (tenant_id)
SELECT id FROM tenants
ON CONFLICT (tenant_id) DO NOTHING;

COMMIT;
