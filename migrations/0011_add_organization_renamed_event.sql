-- Renaming is an administrative change worth recording alongside the other organization events.
ALTER TYPE auth_event_type ADD VALUE IF NOT EXISTS 'organization_renamed';
