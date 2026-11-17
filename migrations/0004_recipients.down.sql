-- 0004_recipients.down.sql — reverse of 0004_recipients.up.sql

BEGIN;

DROP TABLE IF EXISTS recipients;
ALTER TABLE campaigns DROP COLUMN IF EXISTS landing_url;

COMMIT;
