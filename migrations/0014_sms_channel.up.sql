-- 0014_sms_channel.up.sql — M9a: SMS (smishing) delivery channel.
-- Extends the existing delivery_channel enum + sending_profiles rather than
-- adding new tables. For the 'sms' channel the per-channel secret column
-- (smtp_pass_encrypted) carries the provider auth token (AES-GCM sealed), and
-- api_client_id carries the non-secret account id (e.g. Twilio Account SID),
-- reusing the shapes added in 0012. sms_provider + sms_sender_id are new.
-- Contacts gain an E.164 phone used for SMS recipients.

BEGIN;

-- PG 16 allows ADD VALUE inside a transaction (the value just can't be USED
-- until commit; this migration does not use it).
ALTER TYPE delivery_channel ADD VALUE IF NOT EXISTS 'sms';

ALTER TABLE sending_profiles
    ADD COLUMN sms_provider  TEXT,   -- slug: 'twilio'
    ADD COLUMN sms_sender_id TEXT;   -- alphanumeric sender / short code / number

ALTER TABLE contacts
    ADD COLUMN phone_e164 TEXT
        CONSTRAINT contacts_phone_e164_chk
        CHECK (phone_e164 IS NULL OR phone_e164 ~ '^\+[1-9][0-9]{7,14}$');

COMMIT;
