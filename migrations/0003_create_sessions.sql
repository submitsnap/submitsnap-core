-- A session is one login on one device. It groups the refresh tokens issued through
-- rotation so that detecting reuse of a rotated token can revoke the whole family.
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    user_agent TEXT,
    ip_address INET,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    CONSTRAINT sessions_expires_after_created CHECK (expires_at > created_at)
);

CREATE INDEX sessions_active_user_idx ON sessions (user_id) WHERE revoked_at IS NULL;
CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);

-- Only the SHA-256 hash of a refresh token is persisted. `used_at` marks a token that has
-- already been exchanged; seeing one again means the token was replayed.
CREATE TABLE session_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    replaced_by UUID REFERENCES session_tokens (id) ON DELETE SET NULL,
    CONSTRAINT session_tokens_token_hash_key UNIQUE (token_hash),
    CONSTRAINT session_tokens_expires_after_created CHECK (expires_at > created_at)
);

CREATE INDEX session_tokens_session_id_idx ON session_tokens (session_id);
CREATE INDEX session_tokens_expires_at_idx ON session_tokens (expires_at);
