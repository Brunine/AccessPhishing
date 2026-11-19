-- 0009_engine_callback.up.sql — M5 batch C: per-engine callback auth.
-- Stores only a SHA-256 hex hash of the per-run bearer token the engine
-- uses to POST captured events back to the orchestrator. The plaintext
-- token exists only in the engine process env for the duration of a run.

BEGIN;

ALTER TABLE engines ADD COLUMN callback_token_hash TEXT;

COMMIT;