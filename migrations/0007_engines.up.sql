-- 0007_engines.up.sql — M5 part 1: engine registry + lifecycle state.
-- Stores a validated YAML config per engine and the process lifecycle
-- status. Part 1 covers management only; no traffic handling here.

BEGIN;

CREATE TYPE engine_status AS ENUM
    ('stopped', 'starting', 'running', 'error', 'stopped_failed');

CREATE TABLE engines (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    config      TEXT NOT NULL,
    status      engine_status NOT NULL DEFAULT 'stopped',
    last_error  TEXT,
    started_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE INDEX idx_engines_tenant_id ON engines (tenant_id);

CREATE TRIGGER trg_engines_updated_at
    BEFORE UPDATE ON engines
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

COMMIT;