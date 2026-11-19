-- 0013_osint_results.up.sql — M7: store OSINT collection results.
-- One row per (tenant, domain); a re-collect UPSERTs (keeps the latest result
-- and refreshes created_at/created_by). Passive public-info aggregation only.

BEGIN;

CREATE TABLE osint_results (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    domain     TEXT NOT NULL,
    result     JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, domain)
);

CREATE INDEX idx_osint_results_tenant_id ON osint_results (tenant_id);

COMMIT;
