-- 0014_sms_channel.down.sql
-- Note: Postgres cannot drop a value from an enum, so 'sms' remains in
-- delivery_channel; the down migration only removes the added columns.

BEGIN;

ALTER TABLE contacts DROP COLUMN IF EXISTS phone_e164;

ALTER TABLE sending_profiles
    DROP COLUMN IF EXISTS sms_sender_id,
    DROP COLUMN IF EXISTS sms_provider;

COMMIT;
