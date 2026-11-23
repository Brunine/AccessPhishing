-- 0015_engagements.up.sql — M8a: engagements as the authorization container
-- for campaigns.
--
-- An engagement represents an authorized testing engagement against a client:
-- it carries the client name, a Rules-of-Engagement reference, an authorized
-- URL scope, an authorization workflow (operator requests -> admin authorizes),
-- an expiry, and an emergency-stop (terminate) control. Every campaign must be
-- bound to an authorized, unexpired, non-terminated engagement before it can be
-- launched or sent (enforced in the application, not by a DB constraint, so
-- pre-existing draft campaigns are not retroactively invalidated at rest).
--
-- 'active' and 'expired' are part of the enum for forward compatibility, but
-- activity and expiry are DERIVED at the point of use (from status +
-- expires_at), never stored — this avoids clock-state drift. A background job
-- to roll authorized rows to 'expired' may arrive later.

BEGIN;

CREATE TYPE engagement_status AS ENUM (
    'draft', 'pending_authorization', 'authorized', 'active', 'expired', 'terminated'
);

CREATE TABLE engagements (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name             TEXT NOT NULL,
    client_name      TEXT NOT NULL,
    status           engagement_status NOT NULL DEFAULT 'draft',
    roe_reference    TEXT,
    authorized_scope JSONB NOT NULL DEFAULT '[]'::jsonb,
    authorized_at    TIMESTAMPTZ,
    authorized_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    starts_at        TIMESTAMPTZ,
    expires_at       TIMESTAMPTZ,
    notes            TEXT,
    created_by       UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE INDEX idx_engagements_tenant_id ON engagements (tenant_id);

CREATE TRIGGER trg_engagements_updated_at
    BEFORE UPDATE ON engagements
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Bind a campaign to its authorizing engagement. Deleting the engagement
-- clears the reference (it never cascades into campaigns); the application
-- then refuses launch/send until a new engagement is bound.
ALTER TABLE campaigns
    ADD COLUMN engagement_id UUID REFERENCES engagements(id) ON DELETE SET NULL;

CREATE INDEX idx_campaigns_engagement_id ON campaigns (engagement_id);

COMMIT;
