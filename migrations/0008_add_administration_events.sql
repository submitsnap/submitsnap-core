-- Audit events raised by the administrator endpoints.
ALTER TYPE auth_event_type ADD VALUE IF NOT EXISTS 'role_granted';
ALTER TYPE auth_event_type ADD VALUE IF NOT EXISTS 'role_revoked';
ALTER TYPE auth_event_type ADD VALUE IF NOT EXISTS 'account_unlocked';
ALTER TYPE auth_event_type ADD VALUE IF NOT EXISTS 'sessions_revoked';
ALTER TYPE auth_event_type ADD VALUE IF NOT EXISTS 'account_deleted';
