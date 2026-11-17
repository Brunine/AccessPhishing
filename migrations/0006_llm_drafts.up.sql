-- 0006_llm_drafts.up.sql — M6 LLM integration
-- Stores LLM-generated message drafts. A draft is a plain content record; it is
-- promoted to a real template only after passing the existing approval gate
-- (approvals.subject_type = 'llm_draft'). Model output is data, never executed.

BEGIN;

CREATE TYPE llm_draft_kind AS ENUM ('email', 'sms', 'landing');

CREATE TYPE llm_draft_status AS ENUM ('draft', 'approved', 'rejected', 'discarded');

CREATE TABLE llm_drafts (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    created_by     UUID REFERENCES users(id) ON DELETE SET NULL,
    kind           llm_draft_kind NOT NULL,
    name           TEXT NOT NULL,
    subject        TEXT,
    body           TEXT NOT NULL,
    model          TEXT NOT NULL,
    prompt_summary TEXT NOT NULL DEFAULT '',
    status         llm_draft_status NOT NULL DEFAULT 'draft',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_llm_drafts_tenant_id ON llm_drafts (tenant_id);
CREATE INDEX idx_llm_drafts_tenant_status ON llm_drafts (tenant_id, status);

CREATE TRIGGER trg_llm_drafts_updated_at
    BEFORE UPDATE ON llm_drafts
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

COMMIT;
