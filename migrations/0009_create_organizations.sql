CREATE TYPE organization_role AS ENUM ('owner', 'admin', 'member');

CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT organizations_name_length_check CHECK (char_length(name) BETWEEN 1 AND 120)
);

-- An account may belong to many organizations, and an organization may have many accounts, so
-- the relationship is its own table rather than a column on `users`. The primary key's leading
-- column answers "who is in this organization".
CREATE TABLE organization_members (
    organization_id UUID NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role organization_role NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (organization_id, user_id)
);

-- Every request that resolves the caller's access starts from the account, so this direction
-- needs its own index.
CREATE INDEX organization_members_user_idx ON organization_members (user_id);

CREATE TRIGGER organizations_set_updated_at
    BEFORE UPDATE ON organizations
    FOR EACH ROW
    EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER organization_members_set_updated_at
    BEFORE UPDATE ON organization_members
    FOR EACH ROW
    EXECUTE FUNCTION set_updated_at();

-- `auth_events` records authorization changes as well as authentication, so organization
-- membership belongs in the same trail.
ALTER TYPE auth_event_type ADD VALUE IF NOT EXISTS 'organization_created';
ALTER TYPE auth_event_type ADD VALUE IF NOT EXISTS 'organization_deleted';
ALTER TYPE auth_event_type ADD VALUE IF NOT EXISTS 'organization_member_added';
ALTER TYPE auth_event_type ADD VALUE IF NOT EXISTS 'organization_member_role_changed';
ALTER TYPE auth_event_type ADD VALUE IF NOT EXISTS 'organization_member_removed';
