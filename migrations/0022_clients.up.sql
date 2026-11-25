-- 0022_clients.up.sql — M8a Phase 1: clients as a first-class tenant resource.
--
-- Until now a "client" was a denormalized free-text client_name on each
-- engagement (see 0015). This introduces a real clients table so engagements
-- can reference a shared, deduplicated client record. The link is strictly
-- additive and nullable: the existing engagements.client_name column is left in
-- place and untouched, and pre-existing engagements keep working with a NULL
-- client_id. Binding an engagement to a client is optional this phase.
--
-- engagements.client_id uses the default ON DELETE NO ACTION (not RESTRICT):
-- the application refuses to delete a client while any engagement references it
-- (409), and NO ACTION backs that at the DB level while still allowing a
-- tenant-wide ON DELETE CASCADE to remove clients and engagements together.

BEGIN;

CREATE TABLE clients (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    contact_email TEXT,
    notes         TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE INDEX idx_clients_tenant_id ON clients (tenant_id);

CREATE TRIGGER trg_clients_updated_at
    BEFORE UPDATE ON clients
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Optional, nullable link from an engagement to a client.
ALTER TABLE engagements
    ADD COLUMN client_id UUID REFERENCES clients(id);

CREATE INDEX idx_engagements_client_id ON engagements (client_id);

COMMIT;
