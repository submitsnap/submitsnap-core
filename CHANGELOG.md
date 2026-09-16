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

### Changed

- Split the single authentication module into `auth`, `identity`, `session`, and `rbac` slices with one-way dependencies.
- Upgraded Axum from 0.7 to 0.8 so the cookie and OpenAPI integrations share one HTTP stack.
- `POST /auth/register` now only creates the account; clients sign in through `POST /auth/login`.
- Login failures are now serialized consistently for unknown, disabled, locked, and wrong-password cases.
- Email addresses are normalized as they are deserialized, so validation, storage, and lookup always see the same form.
- Local Compose ports now map to the ports PostgreSQL and Redis actually listen on.
- Error responses carry a stable machine-readable `code` alongside the human-readable message.
- Password hashes are re-encoded on successful sign-in when the Argon2 parameters have changed.
- Logs are human-readable by default instead of raw JSON lines.

### Removed

- Resend and Postmark email providers. Delivery now goes through SMTP only, so no third-party account is required.

### Security

- Access tokens pin HS256 and validate issuer, audience, subject, expiry, and not-before claims.
- Refresh tokens are stored only as SHA-256 hashes and detected on replay, which revokes the session family.
- Sessions are re-checked on every authenticated request, so logout takes effect immediately.
- Unknown accounts still perform a password verification, removing the timing oracle from sign-in.
- Repeated failures lock the account for a configurable window.
- Credentials are wrapped in a redacting secret type so they cannot leak through debug output.
- Passwords use explicit Argon2id parameters with an optional server-side pepper, and hashes are upgraded on sign-in when the parameters change.
- Authentication responses are marked `Cache-Control: no-store`; security headers, request body limits, and request timeouts apply to the whole service.
- The service refuses to start with a documented placeholder signing key, which a copied deployment would otherwise run with.

