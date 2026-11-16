-- 0003_api_keys.up.sql — API keys backing the X-API-Key dev identifier.
-- Only a bcrypt hash of the secret is stored; plaintext tokens are shown once
-- at creation and never persisted.

BEGIN;

CREATE TABLE api_keys (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    key_hash     TEXT NOT NULL,            -- bcrypt hash of the secret; never plaintext
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_api_keys_tenant_id ON api_keys (tenant_id);
CREATE INDEX idx_api_keys_user_id ON api_keys (user_id);
-- fast path for verifying live keys
CREATE INDEX idx_api_keys_active ON api_keys (id) WHERE revoked_at IS NULL;

COMMIT;
