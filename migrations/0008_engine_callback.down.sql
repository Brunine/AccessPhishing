-- 0008_engine_callback.down.sql
BEGIN;
ALTER TABLE engines DROP COLUMN IF EXISTS callback_token_hash;
COMMIT;