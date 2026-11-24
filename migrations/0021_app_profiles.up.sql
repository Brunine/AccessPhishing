-- 0021_app_profiles.up.sql — M10b Phase 3: application profiles (runtime
-- contract for the M5 AiTM proxy) + launch-time checksum stamping.
--
-- A profile describes how to phish/proxy one target login surface (see
-- docs/PROFILES/SCHEMA.md). It is a tenant-owned row whose validated spec is the
-- source of truth. Imports are versioned: UNIQUE(tenant_id, name, version) lets
-- multiple revisions of a named profile coexist, and a new import stores the
-- next version N+1 rather than overwriting history.
--
-- Additive only; no backfill. Numbering continues from 0021 (0020 is quishing).

BEGIN;

CREATE TABLE app_profiles (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    version    INT  NOT NULL,
    spec       JSONB NOT NULL,          -- canonical JSON of the validated profile
    checksum   TEXT  NOT NULL,          -- sha256 hex of the canonical spec
    created_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name, version)
);

CREATE INDEX idx_app_profiles_tenant_id ON app_profiles (tenant_id);
CREATE INDEX idx_app_profiles_tenant_name ON app_profiles (tenant_id, name);

CREATE TRIGGER trg_app_profiles_updated_at
    BEFORE UPDATE ON app_profiles
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Launch-time binding + forensic stamp on the campaign. A campaign is bound to
-- the profile it was launched against (app_profile_id); profile_checksum /
-- profile_version are the resolved profile's checksum + revision FROZEN at
-- launch. A later profile import (new version) never rewrites these — in-flight
-- campaigns keep their launch-time checksum. ON DELETE SET NULL so deleting a
-- profile never cascades into campaign history (the frozen checksum survives).
ALTER TABLE campaigns
    ADD COLUMN app_profile_id   UUID REFERENCES app_profiles(id) ON DELETE SET NULL,
    ADD COLUMN profile_checksum TEXT,
    ADD COLUMN profile_version  INT;

COMMIT;
