CREATE TYPE user_status AS ENUM ('pending', 'active', 'disabled');

ALTER TABLE users
    ADD COLUMN status user_status NOT NULL DEFAULT 'active',
    ADD COLUMN email_verified_at TIMESTAMPTZ,
    ADD COLUMN last_login_at TIMESTAMPTZ,
    ADD COLUMN failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN locked_until TIMESTAMPTZ,
    ADD COLUMN password_changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- Accounts created before email verification existed cannot complete a verification
-- challenge, so treat them as already verified to avoid locking out existing deployments.
UPDATE users
SET email_verified_at = created_at
WHERE email_verified_at IS NULL;

ALTER TABLE users
    ADD CONSTRAINT users_email_length_check CHECK (char_length(email) BETWEEN 3 AND 320),
    ADD CONSTRAINT users_password_hash_present_check CHECK (char_length(password_hash) > 0),
    ADD CONSTRAINT users_failed_login_attempts_check CHECK (failed_login_attempts >= 0);

CREATE INDEX users_status_idx ON users (status);
CREATE INDEX users_created_at_idx ON users (created_at DESC);

CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER users_set_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION set_updated_at();
