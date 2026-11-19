-- 0012_delivery_channels.down.sql

BEGIN;

DROP TABLE IF EXISTS ndr_messages;

ALTER TABLE sending_profiles
    DROP COLUMN IF EXISTS api_client_id,
    DROP COLUMN IF EXISTS api_tenant_id,
    DROP COLUMN IF EXISTS channel;

DROP TYPE IF EXISTS delivery_channel;

COMMIT;
