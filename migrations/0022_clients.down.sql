-- 0022_clients.down.sql — reverse of 0022_clients.up.sql, in dependency order:
-- drop the engagement -> client link before the clients table it references.

BEGIN;

DROP INDEX IF EXISTS idx_engagements_client_id;
ALTER TABLE engagements DROP COLUMN IF EXISTS client_id;

DROP TRIGGER IF EXISTS trg_clients_updated_at ON clients;
DROP INDEX IF EXISTS idx_clients_tenant_id;
DROP TABLE IF EXISTS clients;

COMMIT;
