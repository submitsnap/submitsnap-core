-- Supports the administrator endpoint that disables or re-enables an account.
ALTER TYPE auth_event_type ADD VALUE IF NOT EXISTS 'account_status_changed';
