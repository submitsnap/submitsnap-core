-- Inbox actions worth recording. Public submissions deliberately are not: they are business
-- data, already durable, and an audit row each would double the hot path's write cost.
ALTER TYPE auth_event_type ADD VALUE IF NOT EXISTS 'submission_status_changed';
ALTER TYPE auth_event_type ADD VALUE IF NOT EXISTS 'submission_deleted';
