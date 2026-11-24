-- 0016_event_channel.up.sql — Event taxonomy v2 (mechanism only).
--
-- Adds a channel dimension to events so SMS/QR/auth/system events can be
-- appended in future milestones (M9a/M9b) without disturbing the email funnel.
-- This migration is purely additive: existing rows and the append-only trigger
-- are untouched; the NOT NULL DEFAULT 'email' backfills every existing row, so
-- email behavior is byte-identical. event_type is deliberately NOT altered —
-- per-channel event-type values arrive with the M9 migrations that need them.

BEGIN;

CREATE TYPE event_channel AS ENUM ('email', 'sms', 'qr', 'auth', 'system');

ALTER TABLE events
    ADD COLUMN channel event_channel NOT NULL DEFAULT 'email';

-- Supports future per-channel filtering/aggregation. A composite
-- (tenant_id, channel) index is intentionally omitted: current report queries
-- filter/group by type (email-only today), so a plain channel index is enough
-- until a channel-scoped query pattern actually exists.
CREATE INDEX idx_events_channel ON events (channel);

COMMIT;
