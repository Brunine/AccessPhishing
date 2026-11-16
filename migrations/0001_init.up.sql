-- 0001_init.up.sql — PhishForge core schema (M1)
-- Multi-tenant orchestrator: tenants, users, campaigns, contacts, groups,
-- suppression, append-only events, templates, configs, approvals, audit.
-- Every tenant-scoped table carries tenant_id UUID with a supporting index.

BEGIN;

-- ---------------------------------------------------------------------------
-- Shared helper functions
-- ---------------------------------------------------------------------------

-- Maintain updated_at on row modification.
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Enforce append-only semantics (reject UPDATE/DELETE).
CREATE OR REPLACE FUNCTION forbid_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'table %.% is append-only', TG_TABLE_SCHEMA, TG_TABLE_NAME
        USING ERRCODE = 'restrict_violation';
END;
$$ LANGUAGE plpgsql;

-- ---------------------------------------------------------------------------
-- Enums
-- ---------------------------------------------------------------------------

CREATE TYPE user_role AS ENUM ('admin', 'operator', 'viewer');

CREATE TYPE campaign_status AS ENUM (
    'draft', 'scheduled', 'running', 'paused', 'completed', 'archived'
);

-- Victim state machine events (append-only history):
-- sent -> delivered -> opened -> clicked -> creds -> session_hijacked -> post_exploitation
CREATE TYPE event_type AS ENUM (
    'sent', 'delivered', 'opened', 'clicked', 'creds',
    'session_hijacked', 'post_exploitation', 'bounced', 'failed', 'reported'
);

-- Current per-target state (cache of latest event; 'pending' precedes 'sent').
CREATE TYPE target_state AS ENUM (
    'pending', 'sent', 'delivered', 'opened', 'clicked', 'creds',
    'session_hijacked', 'post_exploitation', 'bounced', 'failed'
);

-- Approval workflow: draft -> approved -> sent (or rejected).
CREATE TYPE approval_status AS ENUM ('draft', 'approved', 'rejected', 'sent');

CREATE TYPE template_kind AS ENUM (
    'email', 'sms', 'landing', 'phishlet', 'script', 'voice'
);

-- ---------------------------------------------------------------------------
-- tenants
-- ---------------------------------------------------------------------------

CREATE TABLE tenants (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name       TEXT NOT NULL,
    slug       TEXT NOT NULL UNIQUE,
    status     TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TRIGGER trg_tenants_updated_at
    BEFORE UPDATE ON tenants
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------------
-- users
-- ---------------------------------------------------------------------------

CREATE TABLE users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email         TEXT NOT NULL,
    role          user_role NOT NULL DEFAULT 'viewer',
    password_hash TEXT,
    status        TEXT NOT NULL DEFAULT 'active',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_users_tenant_id ON users (tenant_id);
CREATE UNIQUE INDEX uq_users_tenant_email ON users (tenant_id, lower(email));

CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------------
-- campaigns
-- ---------------------------------------------------------------------------

CREATE TABLE campaigns (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    status     campaign_status NOT NULL DEFAULT 'draft',
    created_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_campaigns_tenant_id ON campaigns (tenant_id);
CREATE INDEX idx_campaigns_tenant_status ON campaigns (tenant_id, status);

CREATE TRIGGER trg_campaigns_updated_at
    BEFORE UPDATE ON campaigns
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------------
-- contact_groups
-- ---------------------------------------------------------------------------

CREATE TABLE contact_groups (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE INDEX idx_contact_groups_tenant_id ON contact_groups (tenant_id);

-- ---------------------------------------------------------------------------
-- contacts
-- ---------------------------------------------------------------------------

CREATE TABLE contacts (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    group_id   UUID REFERENCES contact_groups(id) ON DELETE SET NULL,
    email      TEXT NOT NULL,
    first_name TEXT,
    last_name  TEXT,
    phone      TEXT,
    attributes JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, email)
);

CREATE INDEX idx_contacts_tenant_id ON contacts (tenant_id);
CREATE INDEX idx_contacts_tenant_group ON contacts (tenant_id, group_id);

CREATE TRIGGER trg_contacts_updated_at
    BEFORE UPDATE ON contacts
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------------
-- suppression_lists  (do-not-contact per tenant)
-- ---------------------------------------------------------------------------

CREATE TABLE suppression_lists (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email      TEXT NOT NULL,
    reason     TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, email)
);

CREATE INDEX idx_suppression_tenant_id ON suppression_lists (tenant_id);

-- ---------------------------------------------------------------------------
-- campaign_targets  (join + current-state cache; events remain source of truth)
-- ---------------------------------------------------------------------------

CREATE TABLE campaign_targets (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    campaign_id   UUID NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    contact_id    UUID NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    state         target_state NOT NULL DEFAULT 'pending',
    last_event_at TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (campaign_id, contact_id)
);

CREATE INDEX idx_targets_tenant_id ON campaign_targets (tenant_id);
CREATE INDEX idx_targets_campaign ON campaign_targets (campaign_id, state);

CREATE TRIGGER trg_targets_updated_at
    BEFORE UPDATE ON campaign_targets
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------------
-- events  (append-only victim state machine history)
-- ---------------------------------------------------------------------------

CREATE TABLE events (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    campaign_id UUID NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    contact_id  UUID REFERENCES contacts(id) ON DELETE SET NULL,
    type        event_type NOT NULL,
    metadata    JSONB NOT NULL DEFAULT '{}'::jsonb,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_events_tenant_id ON events (tenant_id);
CREATE INDEX idx_events_campaign_id ON events (campaign_id);
CREATE INDEX idx_events_contact_id ON events (contact_id);
CREATE INDEX idx_events_occurred_at ON events (occurred_at);
CREATE INDEX idx_events_tenant_campaign_time ON events (tenant_id, campaign_id, occurred_at);
CREATE INDEX idx_events_campaign_contact_time ON events (campaign_id, contact_id, occurred_at);

CREATE TRIGGER trg_events_append_only
    BEFORE UPDATE OR DELETE ON events
    FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

-- ---------------------------------------------------------------------------
-- templates
-- ---------------------------------------------------------------------------

CREATE TABLE templates (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    kind       template_kind NOT NULL,
    name       TEXT NOT NULL,
    subject    TEXT,
    body       TEXT NOT NULL,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, kind, name)
);

CREATE INDEX idx_templates_tenant_id ON templates (tenant_id);

CREATE TRIGGER trg_templates_updated_at
    BEFORE UPDATE ON templates
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------------
-- configs  (per-tenant key/value settings)
-- ---------------------------------------------------------------------------

CREATE TABLE configs (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    key        TEXT NOT NULL,
    value      JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, key)
);

CREATE INDEX idx_configs_tenant_id ON configs (tenant_id);

CREATE TRIGGER trg_configs_updated_at
    BEFORE UPDATE ON configs
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------------
-- approvals  (draft -> approved -> sent / rejected)
-- ---------------------------------------------------------------------------

CREATE TABLE approvals (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    subject_type TEXT NOT NULL,
    subject_id   UUID NOT NULL,
    status       approval_status NOT NULL DEFAULT 'draft',
    requested_by UUID REFERENCES users(id) ON DELETE SET NULL,
    decided_by   UUID REFERENCES users(id) ON DELETE SET NULL,
    decided_at   TIMESTAMPTZ,
    notes        TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_approvals_tenant_id ON approvals (tenant_id);
CREATE INDEX idx_approvals_subject ON approvals (tenant_id, subject_type, subject_id);

CREATE TRIGGER trg_approvals_updated_at
    BEFORE UPDATE ON approvals
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------------
-- audit_log  (append-only record of operator actions)
-- ---------------------------------------------------------------------------

CREATE TABLE audit_log (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    actor_id    UUID,            -- no FK: audit survives user deletion
    actor_email TEXT,
    action      TEXT NOT NULL,
    target_type TEXT,
    target_id   TEXT,
    metadata    JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_tenant_id ON audit_log (tenant_id);
CREATE INDEX idx_audit_tenant_time ON audit_log (tenant_id, created_at);

CREATE TRIGGER trg_audit_append_only
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

COMMIT;
