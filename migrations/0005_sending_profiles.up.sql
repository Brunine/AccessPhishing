-- 0005_sending_profiles.up.sql — SMTP sending profiles + campaign send config.
-- smtp_pass_encrypted holds an AES-256-GCM envelope (per-tenant key); never
-- plaintext.

BEGIN;

CREATE TYPE tls_mode AS ENUM ('none', 'starttls', 'smtps');

CREATE TABLE sending_profiles (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name                TEXT NOT NULL,
    smtp_host           TEXT NOT NULL,
    smtp_port           INTEGER NOT NULL,
    smtp_user           TEXT,
    smtp_pass_encrypted TEXT,            -- AES-256-GCM envelope; never plaintext
    from_address        TEXT NOT NULL,
    from_name           TEXT,
    tls_mode            tls_mode NOT NULL DEFAULT 'starttls',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE INDEX idx_sending_profiles_tenant_id ON sending_profiles (tenant_id);

CREATE TRIGGER trg_sending_profiles_updated_at
    BEFORE UPDATE ON sending_profiles
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- A campaign references the template to send and the profile to send it from.
ALTER TABLE campaigns ADD COLUMN template_id UUID REFERENCES templates(id) ON DELETE SET NULL;
ALTER TABLE campaigns ADD COLUMN sending_profile_id UUID REFERENCES sending_profiles(id) ON DELETE SET NULL;

COMMIT;
