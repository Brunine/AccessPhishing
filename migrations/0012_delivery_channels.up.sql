-- 0012_delivery_channels.up.sql — M3 finish: API delivery channels + bounces.
-- Adds a channel to sending_profiles (existing rows backfill to 'smtp' via the
-- NOT NULL DEFAULT) and non-secret API credential columns. The per-channel
-- secret (SMTP password or API client secret) continues to live in the
-- AES-256-GCM encrypted smtp_pass_encrypted column. Also adds ndr_messages for
-- idempotent bounce (NDR) ingestion.

BEGIN;

CREATE TYPE delivery_channel AS ENUM ('smtp', 'graph', 'gmail');

ALTER TABLE sending_profiles
    ADD COLUMN channel       delivery_channel NOT NULL DEFAULT 'smtp',
    ADD COLUMN api_tenant_id TEXT,   -- e.g. Graph tenant id (non-secret)
    ADD COLUMN api_client_id TEXT;   -- e.g. Graph/Gmail client id (non-secret)

-- Fetched bounce notifications, deduped per (tenant, message_id). A row is
-- processed once: 'pending' -> 'processed' (matched) or 'skipped' (no match).
CREATE TABLE ndr_messages (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    message_id      TEXT NOT NULL,
    recipient_email TEXT NOT NULL,
    campaign_id     UUID REFERENCES campaigns(id) ON DELETE SET NULL,
    raw             TEXT,
    status          TEXT NOT NULL DEFAULT 'pending',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    processed_at    TIMESTAMPTZ,
    UNIQUE (tenant_id, message_id)
);

CREATE INDEX idx_ndr_messages_tenant_status ON ndr_messages (tenant_id, status);

COMMIT;
