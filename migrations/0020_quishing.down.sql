-- 0020_quishing.down.sql
--
-- Drops the per-campaign channel column. The 'scanned' value added to the
-- event_type and target_state enums is INTENTIONALLY left in place: PostgreSQL
-- does not support ALTER TYPE ... DROP VALUE, and rebuilding both enum types
-- (dropping/recreating them while every dependent column is cast away and back)
-- would be far more destructive than the forward migration. Removing the column
-- is sufficient to disable the QR vector; a leftover unused enum value is inert.
-- This mirrors the 0014/0016 down migrations, which likewise leave added enum
-- values behind.

BEGIN;

ALTER TABLE campaigns DROP COLUMN IF EXISTS channel;

COMMIT;
