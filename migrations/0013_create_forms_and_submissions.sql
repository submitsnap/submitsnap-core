CREATE TYPE form_status AS ENUM ('draft', 'published', 'closed');
CREATE TYPE submission_status AS ENUM ('unread', 'read', 'spam', 'archived');

CREATE TABLE forms (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    status form_status NOT NULL DEFAULT 'draft',
    -- The handle the public endpoint uses. Separate from `id` on purpose: it can be rotated
    -- without touching the primary key, and it is the only identifier a stranger ever sees.
    public_id TEXT NOT NULL,
    -- Presentation and fields, validated by the application before it is stored.
    schema JSONB NOT NULL,
    -- Bumped whenever `schema` changes, and stamped on every submission, so answers written
    -- against an older field set stay interpretable.
    schema_version INTEGER NOT NULL DEFAULT 1,
    notify_emails TEXT[] NOT NULL DEFAULT '{}',
    success_message TEXT,
    redirect_url TEXT,
    -- A field in the payload that must stay empty. Cheap and effective.
    honeypot_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    published_at TIMESTAMPTZ,
    closed_at TIMESTAMPTZ,
    CONSTRAINT forms_name_length_check CHECK (char_length(name) BETWEEN 1 AND 120),
    CONSTRAINT forms_public_id_format_check CHECK (public_id ~ '^[A-Za-z0-9_-]{16,64}$'),
    CONSTRAINT forms_notify_emails_count_check CHECK (cardinality(notify_emails) <= 20),
    CONSTRAINT forms_schema_object_check CHECK (jsonb_typeof(schema) = 'object')
);

CREATE UNIQUE INDEX forms_public_id_key ON forms (public_id);
CREATE INDEX forms_organization_created_idx
    ON forms (organization_id, created_at DESC, id DESC);

CREATE TRIGGER forms_set_updated_at
    BEFORE UPDATE ON forms
    FOR EACH ROW
    EXECUTE FUNCTION set_updated_at();

CREATE TABLE submissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Denormalized so every submission query is scoped the same way, and so one composite
    -- index can serve both the per-form listing and the organization-wide inbox.
    organization_id UUID NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    form_id UUID NOT NULL REFERENCES forms (id) ON DELETE CASCADE,
    schema_version INTEGER NOT NULL,
    data JSONB NOT NULL,
    status submission_status NOT NULL DEFAULT 'unread',
    ip_address INET,
    user_agent TEXT,
    referer TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT submissions_data_object_check CHECK (jsonb_typeof(data) = 'object')
);

CREATE INDEX submissions_org_form_created_idx
    ON submissions (organization_id, form_id, created_at DESC, id DESC);

-- Filtering by an arbitrary field. `jsonb_path_ops` is the smaller, faster operator class for
-- containment, which is the only JSON question this API asks.
CREATE INDEX submissions_data_gin_idx ON submissions USING GIN (data jsonb_path_ops);

CREATE INDEX submissions_status_idx
    ON submissions (organization_id, form_id, status, created_at DESC);

-- Public submissions are deliberately not audited: they are business data, already durable,
-- and an audit row per submission would double the hot path's write cost for no security value.
ALTER TYPE auth_event_type ADD VALUE IF NOT EXISTS 'form_created';
ALTER TYPE auth_event_type ADD VALUE IF NOT EXISTS 'form_updated';
ALTER TYPE auth_event_type ADD VALUE IF NOT EXISTS 'form_published';
ALTER TYPE auth_event_type ADD VALUE IF NOT EXISTS 'form_closed';
ALTER TYPE auth_event_type ADD VALUE IF NOT EXISTS 'form_deleted';
ALTER TYPE auth_event_type ADD VALUE IF NOT EXISTS 'form_public_id_rotated';
