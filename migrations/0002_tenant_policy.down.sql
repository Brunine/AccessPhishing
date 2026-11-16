-- 0002_tenant_policy.down.sql — reverse of 0002_tenant_policy.up.sql

BEGIN;

DROP TRIGGER IF EXISTS trg_tenant_default_policy ON tenants;
DROP FUNCTION IF EXISTS create_default_tenant_policy();

DROP TABLE IF EXISTS tenant_encryption_keys;
DROP TABLE IF EXISTS tenant_policies;

DROP TYPE IF EXISTS key_purpose;
DROP TYPE IF EXISTS capture_mode;

COMMIT;
