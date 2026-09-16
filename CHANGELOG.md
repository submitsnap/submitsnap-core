# Changelog

All notable changes to SubmitSnap Core are documented in this file.

This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and intends to use [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Initial Axum, PostgreSQL, Redis, authentication, observability, email-worker, and self-hosting foundation.
- Repository community, security, licensing, and trademark documentation.
- Identity schema: account status, email verification, login lockout state, password-change tracking, and an `updated_at` trigger.
- Session and refresh-token tables with per-token rotation history.
- Single-use tokens for email verification and password recovery.
- Roles and role grants, seeded with `user` and `admin`.
- Append-only `auth_events` audit trail covering the authentication lifecycle.
- Email verification, password reset, and password change endpoints.
- Session management endpoints: refresh, logout, and sign-out-everywhere.
- Role-based authorization, demonstrated by an administrator-only account listing.
- OpenAPI 3 document and Swagger UI served from `/docs`, with bearer and cookie security schemes.
- Configuration for token lifetimes, lockout policy, an optional password pepper, CORS origins, HTTP body and timeout limits, and the application base URL used in emails.
- `Makefile` wrapping the local workflow: service lifecycle, migration and reset targets, running the API and worker, and the lint and test gates.
- `PATCH /admin/users/{id}/status` so an administrator can disable or re-enable an account; disabling revokes its sessions.
- `SMTP_TLS_MODE` selecting STARTTLS, implicit TLS, or plaintext for the SMTP connection.
- `check_email` binary and `make check-email`, which send one message so SMTP settings can be validated without going through registration.
- Startup validation that rejects placeholder `JWT_SECRET` values and incomplete SMTP configuration, plus warnings for settings that are unsafe on a non-loopback address.
- Retry with backoff when handing a message to the email queue, so a transient broker failure does not lose a verification link.
- `LOG_FORMAT` selecting human-readable coloured logs (the default) or JSON for a log collector, with request-level tracing enabled for the readable format.
- Startup banner showing the bound address, the database and email queue status, the Swagger UI and OpenAPI URLs, and a summary of the active settings, with credentials redacted from connection strings.
- Email queue reachability is checked at startup and reported, instead of surfacing at the first sign-up.
- `GET /admin/users/{id}` returning one account with its failed-attempt count, lock, and last sign-in.
- `PUT /admin/users/{id}/roles` replacing an account's role set, auditing each grant and revocation.
- `POST /admin/users/{id}/unlock` clearing a lockout, and `DELETE /admin/users/{id}/sessions` signing an account out without changing its status.
- `DELETE /admin/users/{id}` removing an account, requiring the caller to repeat its address.
- `GET /admin/audit-events`, a paginated and filterable view of the audit trail that was previously written but unreadable.
- Filters on `GET /admin/users` for email search, status, and role.
- `grant_admin` binary and `make grant-admin` for creating the first administrator, which the API alone cannot do.
- Audit event types for role changes, unlocks, session revocations, and deletions.
- Organizations, with membership and the `owner` / `admin` / `member` roles. An account may belong to many, and is provisioned none automatically.
- `POST /organizations`, `GET /organizations`, `GET`/`PATCH`/`DELETE /organizations/{id}`, member listing, invitation by email, role changes, and removal.
- Read-only `GET /admin/organizations` and `/admin/organizations/{id}` for instance administrators.
- `access(...)` resolution returning the caller's organization role, with `require_manager` and `require_owner` guards, so authorization cannot be skipped by accident.
- `auth_events.actor_user_id` and `auth_events.organization_id`, so an administrative action records who did it and to which tenant.
- Audit event types for organization creation, renaming, deletion, and membership changes, plus the `organization_id` filter on the audit trail.
- Forms, owned by an organization: definition validation, draft/published/closed lifecycle, per-form submission counting, and a rotatable public handle.
- `POST`/`GET /organizations/{organization_id}/forms`, `GET`/`PATCH`/`DELETE .../{form_id}`, plus `publish`, `close`, and `public-id` actions.
- Public `GET`/`POST /f/{public_id}` outside the API prefix, with permissive CORS, a per-form rate limit, honeypot filing, and a payload validator that reports every problem at once.
- `auth_events.target_id`, so a form lifecycle event names the form it concerns.
- `SUBMISSION_RATE_LIMIT_PER_MINUTE`, `SUBMISSION_PER_FORM_RATE_LIMIT_PER_MINUTE`, and an optional `S3_BUCKET`.
- An outbox dispatcher, run by `--bin worker`, that turns an accepted submission into a notification email and its webhook deliveries. Its loop is separate from the email loop, so a queue that is down does not stop webhooks and a slow receiver does not stop mail.
- Notifications are written in the same statement as the submission, so one cannot exist without the other. Claiming is a lease, so several workers can run at once, and a failure is retried with a widening delay rather than dropped.
- Webhook endpoints per organization, optionally narrowed to one form, with `GET`/`POST /organizations/{org}/webhook-endpoints` and `GET`/`PATCH`/`DELETE .../{endpoint_id}`.
- HMAC-SHA256 delivery signed over `<timestamp>.<body>`, sent as `X-SubmitSnap-Signature` and `X-SubmitSnap-Timestamp`, with the delivery id in `X-SubmitSnap-Delivery`.
- A delivery log at `GET /organizations/{org}/webhook-deliveries` and `POST .../{delivery_id}/redeliver`. Retries widen from 10s to 2h and stop after 6 attempts.
- `WEBHOOK_TIMEOUT_SECONDS`, `WEBHOOK_ALLOW_PRIVATE_TARGETS`, and `REDIS_KEY_PREFIX`.
- Submission inbox: paginated listing across an organization or within one form, filtered by status, time, or the value of any answer field.
- `GET`/`PATCH`/`DELETE /organizations/{organization_id}/submissions/{id}` for reading, marking, and removing a submission.
- Streamed `CSV` and `JSON` export that pages by keyset, so a large form never has to fit in memory, and keeps columns for fields the definition has since dropped.
- `outbox_events`, written by the *same statement* as the submission, so work that must follow can never be lost between the two and costs no extra round trip.
- `webhook_endpoints` and `webhook_deliveries`, with a signature that keeps the payload verifiable by the receiver.
- Optional file uploads to any S3-compatible storage, configured by `S3_BUCKET`, `S3_REGION`, `S3_ENDPOINT`, `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY`, and `S3_FORCE_PATH_STYLE`.
- `POST /f/{public_id}/files/{field_key}` and `GET /organizations/{org}/submissions/{id}/files/{field_key}`, both streamed.
- Uploads are streamed *through* the service rather than handed to the client as presigned URLs. A presigned URL never shows the server the bytes, so `max_bytes` and a field's `accept` list would only validate what the client claimed.
- The declared media type is checked against the field's allowlist, and the leading bytes are checked against the declaration, so a file that contradicts its own `Content-Type` is refused.
- Downloads are served as an attachment with `X-Content-Type-Options: nosniff`, so an uploaded HTML or SVG file cannot execute against this API's origin.
- `file_uploads`, a ledger of what has been written but not yet claimed. A submission reference is matched against it, which distinguishes a key this server issued from one somebody made up, and an upload cannot be claimed twice.
- A fourth worker loop deletes uploads that no submission claimed after `UPLOAD_TTL_HOURS`, so attaching a file and closing the tab does not leave it in the bucket forever. Deleting a submission hands its files back to the same path.
- `UPLOAD_MAX_BYTES`, a ceiling no form can raise, and `UPLOAD_TTL_HOURS`.
- MinIO in `compose.yaml`, with the bucket created for it, so uploads can be exercised locally without an account anywhere.
- A storage line in the startup banner, and a warning when the configured endpoint is plain http on a non-loopback address.

### Changed

- The shared HTTP state moved from `auth` to `modules/mod.rs` as `ApiState`, so a new route module does not have to depend on `auth` to reach the `AuthenticatedUser` extractor.
- Guard invariants are now documented where they are enforced: an organization keeps one owner, and a role only reaches as far as itself.
- Pagination limits moved to `shared::pagination`, used by every listing endpoint.
- Split the single authentication module into `auth`, `identity`, `session`, and `rbac` slices with one-way dependencies.
- Upgraded Axum from 0.7 to 0.8 so the cookie and OpenAPI integrations share one HTTP stack.
- `POST /auth/register` now only creates the account; clients sign in through `POST /auth/login`.
- Login failures are now serialized consistently for unknown, disabled, locked, and wrong-password cases.
- Email addresses are normalized as they are deserialized, so validation, storage, and lookup always see the same form.
- Local Compose ports now map to the ports PostgreSQL and Redis actually listen on.
- Error responses carry a stable machine-readable `code` alongside the human-readable message.
- Password hashes are re-encoded on successful sign-in when the Argon2 parameters have changed.
- Logs are human-readable by default instead of raw JSON lines.
- The request body limit moved off the transport layer onto each subtree, because a limit applied around the whole router can only be lowered from the inside and the upload route needs far more than every other route.

### Removed

- Resend and Postmark email providers. Delivery now goes through SMTP only, so no third-party account is required.

### Security

- Access tokens pin HS256 and validate issuer, audience, subject, expiry, and not-before claims.
- Refresh tokens are stored only as SHA-256 hashes and detected on replay, which revokes the session family.
- Sessions are re-checked on every authenticated request, so logout takes effect immediately.
- Unknown accounts still perform a password verification, removing the timing oracle from sign-in.
- Repeated failures lock the account for a configurable window.
- Credentials are wrapped in a redacting secret type so they cannot leak through debug output.
- File uploads take the same request path as everything else, so a size limit is enforced by counting the bytes that arrive rather than by trusting a declared size, and an upload abandoned mid-flight is discarded rather than completed.
- Passwords use explicit Argon2id parameters with an optional server-side pepper, and hashes are upgraded on sign-in when the parameters change.
- Authentication responses are marked `Cache-Control: no-store`; security headers, request body limits, and request timeouts apply to the whole service.
- The service refuses to start with a documented placeholder signing key, which a copied deployment would otherwise run with.

### Fixed

- An empty `SMTP_USERNAME` or `SMTP_PASSWORD` was treated as a credential rather than as "not configured". Since `.env.example` ships both blank, the documented setup path made every send fail with `no compatible authentication mechanism was found`. A blank value now means no authentication is attempted, and a half-set pair is rejected at startup.
- Deleting an account that was the last owner of an organization left that organization with no owner and no member, and no API path could repair it. The rule is now enforced by the database on `DELETE FROM users`, so it also covers the bootstrap command and psql, and the refusal names the organizations concerned.
- The last-owner rule on membership was a check-then-act race: two concurrent removals of different owners both read "there are two owners", both passed the check, and the organization was left with none — reproduced in four runs out of five. Every membership change now takes a row lock on the organization and holds it across the check and the write.
