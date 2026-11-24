-- 0021_app_profiles.down.sql — revert M10b Phase 3 app profiles.

BEGIN;

ALTER TABLE campaigns
    DROP COLUMN IF EXISTS profile_version,
    DROP COLUMN IF EXISTS profile_checksum,
    DROP COLUMN IF EXISTS app_profile_id;

DROP TABLE IF EXISTS app_profiles;

COMMIT;
