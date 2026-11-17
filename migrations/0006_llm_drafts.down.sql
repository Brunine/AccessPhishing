-- 0006_llm_drafts.down.sql

BEGIN;

DROP TABLE IF EXISTS llm_drafts;
DROP TYPE IF EXISTS llm_draft_status;
DROP TYPE IF EXISTS llm_draft_kind;

COMMIT;
