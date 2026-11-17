-- 0005_sending_profiles.down.sql — reverse of 0005_sending_profiles.up.sql

BEGIN;

ALTER TABLE campaigns DROP COLUMN IF EXISTS sending_profile_id;
ALTER TABLE campaigns DROP COLUMN IF EXISTS template_id;

DROP TABLE IF EXISTS sending_profiles;
DROP TYPE IF EXISTS tls_mode;

COMMIT;
