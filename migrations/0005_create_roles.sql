CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT roles_name_key UNIQUE (name),
    CONSTRAINT roles_name_format_check CHECK (name ~ '^[a-z][a-z0-9_]{1,31}$')
);

CREATE TABLE user_roles (
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, role_id)
);

CREATE INDEX user_roles_role_id_idx ON user_roles (role_id);

INSERT INTO roles (name, description)
VALUES
    ('user', 'Default role for registered accounts'),
    ('admin', 'Full administrative access')
ON CONFLICT (name) DO NOTHING;
