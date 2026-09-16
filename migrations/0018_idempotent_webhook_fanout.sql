-- Makes the outbox fan-out idempotent.
--
-- Dispatch is at-least-once: if any step after the fan-out fails, the event is retried and the
-- fan-out runs again. Without this, a receiver would be sent the same submission twice and, if
-- it writes to a CRM, would create a duplicate record — the failure mode with real cost.
--
-- Nulls are distinct in a Postgres unique index, which is what we want: `submission_id` is
-- nullable (it is set to NULL when the submission is deleted), and those rows need not conflict.
CREATE UNIQUE INDEX webhook_deliveries_endpoint_submission_key
    ON webhook_deliveries (endpoint_id, submission_id);
