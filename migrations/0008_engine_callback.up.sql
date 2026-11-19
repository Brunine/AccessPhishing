-- 0008_engine_callback.up.sql — M5 part 3c: per-engine ingest credential.
-- The token itself is generated at engine start, injected into the child
-- process env, and NEVER stored; only its SHA-256 hash lives here.

BEGIN;

ALTER TABLE engines ADD COLUMN callback_token_hash TEXT;
-- A running engine must have a token; NULL while stopped is fine.

COMMIT;