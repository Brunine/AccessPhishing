-- 0001_init.down.sql — reverse of 0001_init.up.sql

BEGIN;

DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS approvals;
DROP TABLE IF EXISTS configs;
DROP TABLE IF EXISTS templates;
DROP TABLE IF EXISTS events;
DROP TABLE IF EXISTS campaign_targets;
DROP TABLE IF EXISTS suppression_lists;
DROP TABLE IF EXISTS contacts;
DROP TABLE IF EXISTS contact_groups;
DROP TABLE IF EXISTS campaigns;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS tenants;

DROP TYPE IF EXISTS template_kind;
DROP TYPE IF EXISTS approval_status;
DROP TYPE IF EXISTS target_state;
DROP TYPE IF EXISTS event_type;
DROP TYPE IF EXISTS campaign_status;
DROP TYPE IF EXISTS user_role;

DROP FUNCTION IF EXISTS forbid_mutation();
DROP FUNCTION IF EXISTS set_updated_at();

COMMIT;
