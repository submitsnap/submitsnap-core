-- Organization events are only useful if they name the organization, and the most important
-- field in any audit trail is who did it. Both are optional: a self-service event has no
-- separate actor, and an account-level event belongs to no organization.
ALTER TABLE auth_events
    ADD COLUMN actor_user_id UUID REFERENCES users (id) ON DELETE SET NULL,
    ADD COLUMN organization_id UUID REFERENCES organizations (id) ON DELETE SET NULL;

CREATE INDEX auth_events_organization_created_idx ON auth_events (organization_id, created_at DESC);
