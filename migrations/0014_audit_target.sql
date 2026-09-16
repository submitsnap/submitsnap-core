-- Which resource an event concerns. A form lifecycle event that does not name the form is not
-- much of an audit record, and the same will be true for submissions and webhooks.
--
-- Deliberately no foreign key: the trail has to outlive the things it describes, and the target
-- may be any of several tables.
ALTER TABLE auth_events ADD COLUMN target_id UUID;

CREATE INDEX auth_events_target_created_idx ON auth_events (target_id, created_at DESC);
