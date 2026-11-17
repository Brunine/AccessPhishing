-- 0004_recipients.up.sql — campaign recipient snapshot + tracking tokens.
-- Recipients are frozen at launch; the public token (not the contact id) is
-- what appears in tracking URLs.

BEGIN;

ALTER TABLE campaigns ADD COLUMN landing_url TEXT;

CREATE TABLE recipients (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    campaign_id UUID NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    contact_id  UUID NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    group_id    UUID REFERENCES contact_groups(id) ON DELETE SET NULL,
    token       TEXT NOT NULL UNIQUE,         -- random URL-safe public handle
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (campaign_id, contact_id)
);

CREATE INDEX idx_recipients_tenant_id ON recipients (tenant_id);
CREATE INDEX idx_recipients_campaign_id ON recipients (campaign_id);
-- token already has a unique index from the UNIQUE constraint above.

COMMIT;
