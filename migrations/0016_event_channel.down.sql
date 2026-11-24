-- 0016_event_channel.down.sql

BEGIN;

DROP INDEX IF EXISTS idx_events_channel;
ALTER TABLE events DROP COLUMN IF EXISTS channel;
DROP TYPE IF EXISTS event_channel;

COMMIT;
