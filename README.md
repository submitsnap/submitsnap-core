# SubmitSnap Core

The self-hostable backend for SubmitSnap: an open-source form-submission platform built with Rust, Axum, PostgreSQL, Redis, and Tokio.

> **Project status: foundation.** Authentication, identity, configuration, observability, email delivery, and local infrastructure are in place. Public form ingestion, submissions, workspaces, webhook delivery, and the dashboard are planned but not implemented yet. See the [roadmap](#roadmap).

## Why Core is open source

Core is designed to run completely under your control. You can deploy it with your own PostgreSQL, Redis, domain, and email provider. It does not require SubmitSnap Cloud, a license key, or billing integration.

SubmitSnap Cloud will be an optional managed offering built around this project. Its customer billing, subscriptions, and hosted-service operations live outside this repository.

## Current capabilities

- Axum HTTP service with structured JSON tracing, request timeouts, body limits, and security headers
- PostgreSQL with SQLx migrations
- Redis-backed asynchronous email jobs and a separate worker
- Argon2id password hashing and short-lived JWT access tokens
- Rotating, revocable refresh tokens with reuse detection
- Email verification, password reset, and password change flows
- Per-account login lockout plus per-IP request limiting
- Role-based authorization with instance-wide `user` and `admin` roles
- Organizations with `owner`, `admin`, and `member` roles, so resources can be managed per tenant
- Append-only audit trail of authentication and authorization events, naming the actor, the subject, and the organization
- Bearer-token login for API clients and HttpOnly cookie login for the dashboard
- OpenAPI document and Swagger UI generated from the handlers
- Local SMTP delivery with STARTTLS, implicit TLS, or explicit plaintext
- Docker Compose for local PostgreSQL and Redis

## Quick start

Prerequisites: current stable Rust, Docker Compose, and a local shell.

```bash
git clone https://github.com/submitsnap/submitsnap-core.git
cd submitsnap-core
cp .env.example .env
```

Set a unique `JWT_SECRET` of at least 32 characters in `.env`. The defaults in `.env.example` match `compose.yaml`, which publishes PostgreSQL on `5499` and Redis on `6399`. Then start the backing services and apply migrations:

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

The `Makefile` wraps the same steps, loading values from `.env`:

```bash
make            # list every target
make bootstrap  # start PostgreSQL and Redis, then rebuild the database from migrations
make run        # API server
make worker     # email worker
```

The API is available at `http://127.0.0.1:8080`. `GET /health` verifies PostgreSQL and Redis connectivity, and `GET /docs` serves the interactive OpenAPI reference.

## Authentication model

Clients receive two credentials:

- **Access token** — a short-lived JWT (15 minutes by default). Send it as `Authorization: Bearer <token>`. Its claims include the account (`sub`), the session (`sid`), a unique token id (`jti`), issuer, audience, and issued/not-before/expiry timestamps. The verifier pins HS256 and validates every one of those claims.
- **Refresh token** — a 256-bit opaque value. Only its SHA-256 hash is stored. It is rotated on every use, and replaying an already-used token is treated as theft: the entire session family is revoked and a `token_reuse_detected` event is recorded.

Because the session is re-checked on every authenticated request, `POST /auth/logout` takes effect immediately rather than when the access token expires.

All current API routes are prefixed with `/api/v1`.

| Endpoint | Auth | Purpose |
| --- | --- | --- |
| `POST /auth/register` | public | Create an account and send the confirmation link. Returns the created user; the client then signs in. |
| `POST /auth/login` | public | Return an access token and a refresh token in the body, for API clients. |
| `POST /auth/dashboard/login` | public | Set HttpOnly cookies and return the user, for browser clients. Tokens never reach JavaScript. |
| `POST /auth/refresh` | refresh token | Rotate the refresh token. API clients pass it in the body; browsers send the cookie and receive new cookies. |
| `POST /auth/logout` | session | Revoke the current session and clear cookies. |
| `POST /auth/logout-all` | session | Revoke every session for the account. |
| `GET /auth/me` | session | Return the current account, including roles. |
| `POST /auth/password/change` | session | Replace the password after confirming the current one; other sessions are signed out. |
| `POST /identity/email/verify` | token | Confirm an email address using a single-use link token. |
| `POST /identity/email/verification` | public | Re-send the confirmation link. Reveals nothing about whether an account exists. |
| `POST /identity/password/forgot` | public | Start a password reset. Always reports acceptance. |
| `POST /identity/password/reset` | token | Complete a reset. The token is single use and every session is revoked. |
| `GET /admin/users` | session + `admin` | Paginated accounts. Filter by `search`, `status`, and `role`. |
| `GET /admin/users/{id}` | session + `admin` | One account, including failed attempts, lock, and last sign-in. |
| `PATCH /admin/users/{id}/status` | session + `admin` | Enable or disable an account. Disabling signs it out everywhere. |
| `PUT /admin/users/{id}/roles` | session + `admin` | Replace the account's roles with exactly the supplied set. |
| `POST /admin/users/{id}/unlock` | session + `admin` | Clear failed attempts and lift a lockout. |
| `DELETE /admin/users/{id}/sessions` | session + `admin` | Sign the account out everywhere without changing its status. |
| `DELETE /admin/users/{id}` | session + `admin` | Permanently remove the account. The body must repeat the address. |
| `GET /admin/audit-events` | session + `admin` | Audit trail, newest first. Filter by `user_id`, `organization_id`, `email`, `event_type`, `since`, `until`. |
| `GET /admin/organizations` | session + `admin` | Read-only listing of every organization. |
| `GET /admin/organizations/{id}` | session + `admin` | Read-only organization detail. |

### Organizations

An organization is the tenant everything else will belong to. An account may belong to as many as it likes, and may belong to none — nothing is provisioned automatically, so an organization is always something somebody deliberately created.

| Method + path | Required | Notes |
| --- | --- | --- |
| `POST /organizations` | any account | Creates it and makes the caller the owner. Any account may do this, which is why no bootstrap step is needed. |
| `GET /organizations` | any account | Only the caller's, each with their role. |
| `GET /organizations/{id}` | member | |
| `PATCH /organizations/{id}` | owner, admin | Rename. |
| `DELETE /organizations/{id}` | owner | Memberships cascade away with it. |
| `GET /organizations/{id}/members` | member | Paginated. |
| `POST /organizations/{id}/members` | owner, admin | By email, because that is what an operator knows about a person. 201 when added, 200 when an existing member's role changed. |
| `PUT /organizations/{id}/members/{user_id}` | owner, admin | Set a member's role. |
| `DELETE /organizations/{id}/members/{user_id}` | owner, admin; anyone may remove themselves | Leaving is always allowed. |

Two rules keep an organization from becoming unmanageable, and both are enforced in the service rather than left to an operator's care:

- **An organization always keeps at least one owner.** Removing or demoting the last one is refused, which is also what makes leaving safe to allow.
- **A role only reaches as far as itself.** An owner reaches everyone; an admin reaches peers and members, so only an owner can create another owner, and nothing but an owner can touch one.

Instance administrators may **read** organizations but never change their membership. That is not a separate rule so much as a consequence of the design: the mutating routes require membership, and the instance role does not grant it. Read-only routes accept the instance role in addition.

### Two role systems, on purpose

| Concept | Stored as | Answers |
| --- | --- | --- |
| Instance role (`user`, `admin`) | the `roles` / `user_roles` tables | Who administers this deployment? |
| Organization role (`owner`, `admin`, `member`) | `organization_members.role` | Who manages this tenant's resources? |

Instance roles are a table because an operator defines them. Organization roles are a fixed hierarchy the code branches on, so they are an enum on both sides — a `match` over one is exhaustive, and an unknown value cannot reach the code at all.

### The scoping rule for tables that come next

Forms, submissions, and everything after them will be owned by an organization. They must follow this shape:

- Carry `organization_id UUID NOT NULL REFERENCES organizations (id) ON DELETE CASCADE`. Never nullable, so a query cannot silently span tenants by forgetting a filter.
- Lead its indexes with `organization_id`, because every read is scoped.
- Take the organization id as an explicit argument in repository methods rather than reading it from an ambient context, so a missing scope is a compile error rather than a leak.
- Resolve authorization with one `access(...)` call per handler, so the check cannot be forgotten.

### Administering an instance

Two rules keep an instance from becoming unadministrable, and both are enforced in the service rather than left to an operator's care:

- **Status changes and deletions cannot target the caller.** The caller is provably an active administrator, so at least one such account always survives them.
- **Role changes may target the caller**, so an administrator can step down, but only while somebody else still holds the role.

Nothing else can hand out the `admin` role, so a fresh instance needs one bootstrap step:

```bash
make grant-admin EMAIL=you@example.com
```

The command talks to the database directly and only ever adds the role. It is also the way back in if the last administrator is ever lost. A role change takes effect on the account's next request, whatever sessions it already holds, because authorization is read from the database rather than baked into the token.

Deleting an account cascades to its sessions, refresh tokens, and role grants. Its audit entries are kept, with the account reference cleared and the email address retained, so the history stays useful.

## Security notes

- **Passwords** are hashed with Argon2id at the OWASP-recommended parameters (19 MiB, 2 iterations). Set `PASSWORD_PEPPER` to mix in a server-side secret; changing it invalidates existing passwords, so treat it as permanent deployment state. Hashes are re-encoded on the next successful sign-in whenever the parameters change.
- **Configuration is checked at startup.** `JWT_SECRET` must be at least 32 characters and must not be a placeholder — the value shipped in `.env.example` is rejected, so a copied deployment cannot run with a publicly known signing key. `EMAIL_PROVIDER=smtp` requires a host and a sender before the service will boot. When the service is bound to a non-loopback address, it logs a warning for every development-friendly setting still in place (`COOKIE_SECURE`, `API_DOCS_ENABLED`, unverified sign-in, disabled email, missing pepper).
- **Account enumeration** is avoided on the routes where it matters most: unknown email addresses still pay the cost of a password verification, sign-in failures return one indistinguishable response, and password recovery always reports acceptance. Two deliberate exceptions reveal that an address is registered — `POST /auth/register` reports a conflict, and a locked or disabled account returns `423`/`403` so its owner knows why they cannot sign in.
- **Brute force** is limited by a per-account lockout after `MAX_FAILED_LOGIN_ATTEMPTS` plus per-IP request budgets. Account-level protection is durable (stored on the account), so it holds across source addresses. Note the trade-off: an attacker who knows an address can lock it for `ACCOUNT_LOCK_DURATION_SECONDS` by failing repeatedly, so keep that window short or add a second factor.
- **Cookies** are `HttpOnly`, `SameSite=Lax`, and scoped to `/api/v1`. All state-changing routes are `POST` and require a JSON body, which is the CSRF boundary. For any HTTPS deployment set `COOKIE_SECURE=true`, which also enables HSTS.
- **CORS** is disabled unless `CORS_ALLOWED_ORIGINS` lists explicit origins. Credentialed requests are never allowed from a wildcard origin.
- **Rate limiting does not trust forwarded-IP headers**, because they are spoofable. Serve the API with real client socket addresses; enforce additional limits at a proxy if you run one.
- **Audit events** are appended to `auth_events` and never block the operation they describe. Each row names the account the event concerns, the authenticated account that caused it, and the organization when one is involved — so an administrative action is attributable, not just visible. `auth_events.email` records the address attempted during failed sign-ins, which is personal data: define a retention policy and prune old rows, for example `DELETE FROM auth_events WHERE created_at < NOW() - INTERVAL '90 days'`. Deleting an account or an organization clears those references from its older rows, which is deliberate: the trail outlives its subjects.

## Email delivery

Core sends mail through your own SMTP server; there is no third-party provider integration. Set `EMAIL_PROVIDER` to `disabled` (the default, which discards messages) or `smtp`, and choose how the connection is protected with `SMTP_TLS_MODE`:

| Mode | Use it for |
| --- | --- |
| `starttls` | Port 587. Connects in the clear, then upgrades. The usual choice. |
| `implicit` | Port 465. TLS from the first byte. |
| `none` | No encryption. Credentials and message bodies travel in the clear, and a warning is logged. |

Check the settings against the real server before relying on them:

```bash
make check-email TO=you@example.com
```

The command loads `.env`, builds the transport, and sends one message, so a wrong host, port, TLS mode, or credential fails immediately instead of during someone's registration. `EMAIL_PROVIDER=disabled` is refused here rather than reporting a success that did not happen.

The worker moves delivery failures to the Redis dead-letter list `submitsnap:email-dead-letter`. Monitor and replay those jobs as part of normal operations.

Verification and reset links point at `APP_BASE_URL` (`/verify-email?token=…` and `/reset-password?token=…`). Point it at the web application that will consume them.

Handing a message to the queue is retried a few times so a brief Redis blip does not lose a verification link, and an exhausted retry is logged. That is a mitigation, not a guarantee: a durable transactional outbox is the correct long-term answer and is on the roadmap. Until then, if the queue is down for long enough, the user can request another link.

## API documentation

The handlers generate an OpenAPI 3 document, served with Swagger UI:

| Path | Contents |
| --- | --- |
| `GET /docs` | Interactive reference, including both security schemes. |
| `GET /api-docs/openapi.json` | The raw document, for code generation and tooling. |

Set `API_DOCS_ENABLED=false` to omit both routes.

## Logging

`LOG_FORMAT` decides how records are rendered:

| Value | Appearance |
| --- | --- |
| `pretty` (default) | Coloured lines, plus a startup banner with the bound address, the database and queue status, the Swagger UI URL, and a one-line summary of the active settings. |
| `json` | One JSON object per line, for a log collector. No banner. |

The default log level also follows the format: a pretty run traces every request (method, URI, status, latency), while a JSON run logs at `info` so a deployed service is not drowned in request lines. Set `RUST_LOG` to override either default, and `NO_COLOR=1` to keep the pretty layout without ANSI escapes.

```
  SubmitSnap Core 0.1.0

  API        http://127.0.0.1:8080
  Health     http://127.0.0.1:8080/health
  Swagger UI http://127.0.0.1:8080/docs
  OpenAPI    http://127.0.0.1:8080/api-docs/openapi.json

  Database   postgres://***@localhost:5499/submitsnap
  Queue      reachable redis://127.0.0.1:6399
  Email      disabled (outgoing messages are discarded)

  email verification optional  ·  insecure cookies (COOKIE_SECURE=false)

  Press Ctrl+C to stop
```

Credentials in connection strings are redacted, so the banner is safe to leave in a terminal or a recorded session.

## Architecture direction

Modules are vertical slices with the same internal shape (handler, service, repository, DTOs, errors):

```text
src/modules/
  api state   modules/mod.rs — the state every router shares
  auth/          login, sessions, access tokens, the authenticated-user extractor, account administration
  identity/      accounts, credentials, email verification, password recovery, audit events
  session/       refresh token families, rotation, and revocation
  rbac/          instance roles and grants
  organization/  tenants, membership, and the access checks over them
```

Dependencies flow one way: `auth` depends on `identity` and `session`; `identity` depends on `session` and `rbac`; `organization` depends on `identity`. The shared `ApiState` lives at the module root, so a new route module never has to borrow another module's state to reach the `AuthenticatedUser` extractor.

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

- [x] Organizations with `owner`, `admin`, and `member` roles
- [ ] Project, form, and submission model, each scoped to an organization
- [ ] Public `POST /f/:public_form_id` ingestion endpoint
- [ ] Transactional outbox and reliable webhook/email delivery
- [ ] Submission inbox API and data export
- [ ] JavaScript SDK and React hooks
- [ ] Dashboard integration
- [ ] First-party (TOTP) and passkey second factors
- [ ] Self-hosted bootstrap-admin, backup, and upgrade guides

## Testing

```bash
make test-unit   # or: cargo test --lib
```

Unit tests cover configuration loading, token signing and verification, password hashing, cookie flags, and error mapping.

Integration tests use `#[sqlx::test]`, which creates a disposable database and applies `migrations/` to it. They require `DATABASE_URL` pointing at a PostgreSQL server where SQLx can create temporary databases, and they deliberately point Redis at an unreachable address so they never depend on a queue being up:

```bash
make test        # or: DATABASE_URL=... cargo test
```

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Please report vulnerabilities privately as described in [SECURITY.md](SECURITY.md), not through a public issue.

SubmitSnap Core is licensed under the [Apache License 2.0](LICENSE). Use of the SubmitSnap name and logo is governed by [TRADEMARKS.md](TRADEMARKS.md).
