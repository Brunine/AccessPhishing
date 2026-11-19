-- 0011_prompt_templates.up.sql — M6 prompt-template library
-- Operator-authored prompt templates for the LLM draft pipeline. Reuses the
-- llm_draft_kind enum (email|sms|landing). variables declares the substitution
-- variables; the user_template may only reference declared ones (enforced in
-- the app at save time).

BEGIN;

CREATE TABLE prompt_templates (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    kind          llm_draft_kind NOT NULL,
    system_prompt TEXT NOT NULL DEFAULT '',
    user_template TEXT NOT NULL,
    variables     JSONB NOT NULL DEFAULT '[]'::jsonb,
    is_default    BOOLEAN NOT NULL DEFAULT false,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE INDEX idx_prompt_templates_tenant_id ON prompt_templates (tenant_id);

CREATE TRIGGER trg_prompt_templates_updated_at
    BEFORE UPDATE ON prompt_templates
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

COMMIT;
