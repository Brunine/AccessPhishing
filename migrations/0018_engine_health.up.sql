-- 0018_engine_health.up.sql — M10a: engine runtime health snapshots.
--
-- One row per engine, upserted from two processes that never share memory:
--   * cmd/api   — on each start/stop lifecycle transition (sets status,
--                 adapter_kind, detail, last_transition_at). The in-process
--                 subprocess supervisor (internal/engine.Manager) lives here.
--   * cmd/worker — the periodic health poller tick (sets status, detail,
--                 last_poll_at). It has no access to the API's in-memory
--                 supervisor, so this durable row is the only surface it can
--                 write to.
-- GET /engines/{id}/health reads this snapshot and overlays the API's live
-- adapter health when the process is tracked in that instance.
--
-- status/adapter_kind are plain TEXT (not enums) on purpose: the adapter-level
-- vocabulary (unknown|starting|running|stopped|failed) and the set of adapter
-- kinds both grow in M10 as real external drivers land, and a free-text column
-- avoids an enum-ALTER migration per driver. The engines table keeps its own
-- authoritative engine_status enum; this table is a derived health view.

BEGIN;

CREATE TABLE engine_health (
    engine_id          UUID PRIMARY KEY REFERENCES engines(id) ON DELETE CASCADE,
    tenant_id          UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    adapter_kind       TEXT NOT NULL DEFAULT 'builtin',
    status             TEXT NOT NULL DEFAULT 'unknown',
    detail             TEXT NOT NULL DEFAULT '',
    last_transition_at TIMESTAMPTZ,
    last_poll_at       TIMESTAMPTZ,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_engine_health_tenant_id ON engine_health (tenant_id);

CREATE TRIGGER trg_engine_health_updated_at
    BEFORE UPDATE ON engine_health
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

COMMIT;
