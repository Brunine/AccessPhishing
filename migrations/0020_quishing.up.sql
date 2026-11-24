-- 0020_quishing.up.sql — M9b: QR / quishing delivery vector.
--
-- Adds a 'scanned' victim-state-machine step that slots in BEFORE 'clicked'
-- (scanned -> clicked -> creds -> ...), and a per-campaign channel so the
-- tracking handler can tell a QR campaign apart from an email/SMS one. A QR
-- campaign encodes each recipient's /t/{token} tracking URL into a QR image
-- (generated on the fly — no new table, no blob storage).
--
-- Purely additive: existing campaigns backfill to channel 'email' via the NOT
-- NULL DEFAULT, so the email funnel and every existing campaign are unchanged.
-- 'scanned' is added to both enums but is NOT used anywhere in this migration,
-- which keeps the whole thing valid inside one transaction on PG 16 (a new enum
-- value just cannot be *used* until commit).

BEGIN;

-- Victim-state-machine event type + projected target state. BEFORE 'clicked'
-- keeps the enum's logical order aligned with the funnel; the Go rank maps are
-- the real source of truth, so physical enum order is cosmetic.
ALTER TYPE event_type   ADD VALUE IF NOT EXISTS 'scanned' BEFORE 'clicked';
ALTER TYPE target_state ADD VALUE IF NOT EXISTS 'scanned' BEFORE 'clicked';

-- Per-campaign vector. Reuses the event_channel enum (email|sms|qr|auth|system
-- from 0016) — 'qr' already exists, so no enum change is needed here. Existing
-- rows backfill to 'email' (identical behavior); only QR campaigns are set 'qr'.
ALTER TABLE campaigns
    ADD COLUMN channel event_channel NOT NULL DEFAULT 'email';

COMMIT;
