BEGIN;
DROP INDEX IF EXISTS idx_campaigns_engine_id;
ALTER TABLE campaigns DROP COLUMN IF EXISTS engine_id;
COMMIT;