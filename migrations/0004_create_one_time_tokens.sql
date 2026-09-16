CREATE TYPE one_time_token_purpose AS ENUM ('email_verification', 'password_reset');

-- Single-use tokens for email verification and password reset. Only the SHA-256 hash is
-- stored; consumption is a conditional update guarded by `consumed_at IS NULL`.
CREATE TABLE one_time_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    purpose one_time_token_purpose NOT NULL,
    token_hash BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    CONSTRAINT one_time_tokens_token_hash_key UNIQUE (token_hash),
    CONSTRAINT one_time_tokens_expires_after_created CHECK (expires_at > created_at)
);

CREATE INDEX one_time_tokens_user_purpose_idx ON one_time_tokens (user_id, purpose);
CREATE INDEX one_time_tokens_expires_at_idx ON one_time_tokens (expires_at);
