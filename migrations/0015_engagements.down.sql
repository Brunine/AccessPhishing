-- 0015_engagements.down.sql

BEGIN;

DROP INDEX IF EXISTS idx_campaigns_engagement_id;
ALTER TABLE campaigns DROP COLUMN IF EXISTS engagement_id;

DROP TABLE IF EXISTS engagements;
DROP TYPE IF EXISTS engagement_status;

COMMIT;
