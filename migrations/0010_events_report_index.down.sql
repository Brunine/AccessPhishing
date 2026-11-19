-- 0010_events_report_index.down.sql

BEGIN;

DROP INDEX IF EXISTS idx_events_campaign_type_time;

COMMIT;
