-- 0018_engine_health.down.sql — drop the engine health snapshot table.
-- The trigger is dropped implicitly with the table.

BEGIN;

DROP TABLE IF EXISTS engine_health;

COMMIT;
