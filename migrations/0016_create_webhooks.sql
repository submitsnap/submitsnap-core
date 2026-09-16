CREATE TYPE webhook_delivery_status AS ENUM ('pending', 'delivered', 'failed');

CREATE TABLE webhook_endpoints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    -- NULL means "every form in the organization"; a specific form narrows it. One nullable
    -- column instead of a join table, because that is the whole of the requirement.
    form_id UUID REFERENCES forms (id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    -- Signs every payload, so a receiver can prove the request came from here. Stored as given
    -- because the signature has to be reproducible; it is returned once on creation and never
    -- listed again.
    secret TEXT NOT NULL,
    description TEXT,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT webhook_endpoints_url_check CHECK (url ~ '^https?://'),
    CONSTRAINT webhook_endpoints_secret_length_check CHECK (char_length(secret) >= 16)
);

CREATE INDEX webhook_endpoints_organization_idx ON webhook_endpoints (organization_id);

CREATE TRIGGER webhook_endpoints_set_updated_at
    BEFORE UPDATE ON webhook_endpoints
    FOR EACH ROW
    EXECUTE FUNCTION set_updated_at();

CREATE TABLE webhook_deliveries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    endpoint_id UUID NOT NULL REFERENCES webhook_endpoints (id) ON DELETE CASCADE,
    submission_id UUID REFERENCES submissions (id) ON DELETE SET NULL,
    -- Kept on the row so a redelivery needs no other lookup, and so the delivery log shows
    -- exactly what was sent.
    payload JSONB NOT NULL,
    status webhook_delivery_status NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    response_status INTEGER,
    last_error TEXT,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delivered_at TIMESTAMPTZ
);

CREATE INDEX webhook_deliveries_pending_idx ON webhook_deliveries (next_attempt_at)
    WHERE status = 'pending';
CREATE INDEX webhook_deliveries_organization_created_idx
    ON webhook_deliveries (organization_id, created_at DESC);

ALTER TYPE auth_event_type ADD VALUE IF NOT EXISTS 'webhook_endpoint_created';
ALTER TYPE auth_event_type ADD VALUE IF NOT EXISTS 'webhook_endpoint_updated';
ALTER TYPE auth_event_type ADD VALUE IF NOT EXISTS 'webhook_endpoint_deleted';
