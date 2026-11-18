-- 0008_campaign_engine.up.sql — M5 part 2b: bind a campaign to an engine.
-- Deleting the engine clears the reference; it never cascades into campaigns.

BEGIN;

ALTER TABLE campaigns
    ADD COLUMN engine_id UUID REFERENCES engines(id) ON DELETE SET NULL;

CREATE INDEX idx_campaigns_engine_id ON campaigns (engine_id);

COMMIT;