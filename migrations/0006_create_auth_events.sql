CREATE TYPE auth_event_type AS ENUM (
    'account_created',
    'login_succeeded',
    'login_failed',
    'account_locked',
    'logout',
    'token_refreshed',
    'token_reuse_detected',
    'email_verification_sent',
    'email_verified',
    'password_reset_requested',
    'password_reset_completed',
    'password_changed'
);

-- Append-only security audit trail. `user_id` is nullable and uses SET NULL so the audit
-- record survives account deletion; `email` is intentionally denormalized and is personal
-- data that must be covered by the deployment's retention policy.
CREATE TABLE auth_events (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id UUID REFERENCES users (id) ON DELETE SET NULL,
    email TEXT,
    event_type auth_event_type NOT NULL,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX auth_events_user_created_idx ON auth_events (user_id, created_at DESC);
CREATE INDEX auth_events_email_created_idx ON auth_events (lower(email), created_at DESC);
CREATE INDEX auth_events_type_created_idx ON auth_events (event_type, created_at DESC);
