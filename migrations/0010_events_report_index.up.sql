-- 0010_events_report_index.up.sql — M8 reporting
-- Supports per-type timeline aggregation (GROUP BY type over a campaign's
-- events ordered by time). Existing indexes cover (tenant_id, campaign_id,
-- occurred_at) and (campaign_id, contact_id, occurred_at) but not type.

BEGIN;

CREATE INDEX IF NOT EXISTS idx_events_campaign_type_time
    ON events (campaign_id, type, occurred_at);

COMMIT;
