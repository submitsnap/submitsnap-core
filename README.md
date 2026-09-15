# SubmitSnap Core

The self-hostable backend for SubmitSnap: an open-source form-submission platform built with Rust, Axum, PostgreSQL, Redis, and Tokio.

> **Project status: foundation.** Authentication, configuration, observability, email delivery, and local infrastructure are in place. Public form ingestion, submissions, workspaces, webhook delivery, and the dashboard are planned but not implemented yet. See the [roadmap](#roadmap).

## Why Core is open source

Core is designed to run completely under your control. You can deploy it with your own PostgreSQL, Redis, domain, and email provider. It does not require SubmitSnap Cloud, a license key, or billing integration.

SubmitSnap Cloud will be an optional managed offering built around this project. Its customer billing, subscriptions, and hosted-service operations live outside this repository.

## Current capabilities

- Axum HTTP service with structured JSON tracing
- PostgreSQL with SQLx migrations
- Redis-backed asynchronous email jobs and a separate worker
- Argon2 password hashing and JWT authentication
- Bearer-token API login and HttpOnly dashboard-cookie login
- Boundary validation with `validator` and IP-based request limiting with `governor`
- SMTP, Resend, or Postmark email delivery adapters
- Docker Compose for local PostgreSQL and Redis

## Quick start

Prerequisites: current stable Rust, Docker Compose, and a local shell.

```bash
git clone https://github.com/submitsnap/submitsnap-core.git
cd submitsnap-core
cp .env.example .env
```

Set a unique `JWT_SECRET` of at least 32 characters in `.env`. Then start the backing services and apply migrations:

```bash
docker compose up -d
cargo install sqlx-cli --no-default-features --features rustls,postgres
sqlx migrate run
```

Run the API and email worker in separate terminals:

```bash
cargo run
cargo run --bin email_worker
```

The API is available at `http://127.0.0.1:8080`; `GET /health` verifies PostgreSQL and Redis connectivity.

## Authentication endpoints

All current API routes are prefixed with `/api/v1`.

| Endpoint | Purpose |
| --- | --- |
| `POST /auth/register` | Register a user with an email and a 12+ character password. |
| `POST /auth/login` | Return a Bearer token for programmatic API clients. |
| `POST /auth/dashboard/login` | Set an HttpOnly, SameSite=Lax cookie without returning a token to dashboard JavaScript. |
| `GET /auth/me` | Return the current user from a Bearer token or dashboard cookie. |

For any HTTPS deployment, set `COOKIE_SECURE=true`. Deployments behind a proxy should enforce client rate limits at the proxy or preserve the actual client socket address; Core intentionally does not trust spoofable forwarded-IP headers.

## Email delivery

Set `EMAIL_PROVIDER` to `disabled`, `smtp`, `resend`, or `postmark`. SMTP is delivered through Lettre; Resend and Postmark use their HTTP APIs. See [.env.example](.env.example) for all configuration values.

The worker moves delivery failures to the Redis dead-letter list `submitsnap:email-dead-letter`. Monitor and replay those jobs as part of normal operations.

## Architecture direction

When form ingestion is introduced, PostgreSQL will remain the durable source of truth:

```text
form POST → validation/rate limit → PostgreSQL submission + outbox event
                                      ↓
                                queue dispatcher → Redis → worker
                                                        ├─ email
                                                        └─ webhook
```

A submission must be stored transactionally before any asynchronous work is accepted. Redis is a delivery mechanism, not the only copy of user data.

## Roadmap

- [ ] Workspace, project, form, and submission data model
- [ ] Public `POST /f/:public_form_id` ingestion endpoint
- [ ] Transactional outbox and reliable webhook/email delivery
- [ ] Submission inbox API and data export
- [ ] JavaScript SDK and React hooks
- [ ] Dashboard integration
- [ ] Self-hosted bootstrap-admin, backup, and upgrade guides

## Testing

```bash
cargo test --lib
```

This runs password and mocked email-provider tests. The SQLx integration test at [tests/database.rs](tests/database.rs) requires a disposable PostgreSQL database through `DATABASE_URL`; SQLx creates an isolated test database and runs migrations.

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Please report vulnerabilities privately as described in [SECURITY.md](SECURITY.md), not through a public issue.

SubmitSnap Core is licensed under the [Apache License 2.0](LICENSE). Use of the SubmitSnap name and logo is governed by [TRADEMARKS.md](TRADEMARKS.md).
