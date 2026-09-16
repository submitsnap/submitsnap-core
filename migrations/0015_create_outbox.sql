CREATE TYPE outbox_kind AS ENUM ('submission_received');

-- The durable record of work that must happen after a submission is accepted. Written in the
-- same statement as the submission, so a notification can never be lost between the two, and
-- never has to be resent because the first attempt failed.
CREATE TABLE outbox_events (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    kind outbox_kind NOT NULL,
    payload JSONB NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    -- Backoff lives here: a failed dispatch is retried once this passes.
    available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    dispatched_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Partial index, so the dispatcher's scan stays proportional to the backlog rather than to the
-- table, which only ever grows.
CREATE INDEX outbox_events_pending_idx ON outbox_events (available_at)
    WHERE dispatched_at IS NULL;
