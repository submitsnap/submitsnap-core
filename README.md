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
- Forms with a validated field schema, a draft/published/closed lifecycle, and a rotatable public handle
- Public submission ingestion with a honeypot, per-form rate limiting, and open CORS
- A submission inbox with status changes, deletion, and streaming CSV/JSON export
- Optional file uploads to any S3-compatible storage, streamed through the service so size and type limits describe the real file
- Transactional outbox, notification email, and signed webhook delivery with retries and a delivery log
- Append-only audit trail of authentication and authorization events, naming the actor, the subject, and the organization
- Bearer-token login for API clients and HttpOnly cookie login for the dashboard
- OpenAPI document and Swagger UI generated from the handlers
- Local SMTP delivery with STARTTLS, implicit TLS, or explicit plaintext
- Docker Compose for local PostgreSQL, Redis, and MinIO (the last only for file uploads)

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

Run the API and the background worker in separate terminals:

```bash
cargo run
cargo run --bin worker
```

The `Makefile` wraps the same steps, loading values from `.env`:

```bash
make            # list every target
make bootstrap  # start PostgreSQL and Redis, then rebuild the database from migrations
make run        # API server
make worker     # background worker: email, outbox dispatch, webhook delivery
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

### Forms

A form belongs to an organization and is addressed internally by its id. What the public sees is a separate, unguessable handle, so a link can be rotated without touching the row.

| Method + path | Required |
| --- | --- |
| `POST /organizations/{org}/forms` | owner, admin |
| `GET /organizations/{org}/forms` | member |
| `GET /organizations/{org}/forms/{id}` | member |
| `PATCH /organizations/{org}/forms/{id}` | owner, admin |
| `DELETE /organizations/{org}/forms/{id}` | owner, admin — cascades its submissions |
| `POST /organizations/{org}/forms/{id}/publish` | owner, admin |
| `POST /organizations/{org}/forms/{id}/close` | owner, admin |
| `POST /organizations/{org}/forms/{id}/public-id` | owner, admin — invalidates the previous link |

A form is a `draft` until it is published. A draft answers `404` on its public handle rather than `403`, so an unfinished form is not discoverable by anybody who guessed the link. Closing is how a form is retired, and it answers `410 Gone` so its audience is told why it stopped working.

Editing the fields bumps `schema_version`, which is stamped on every submission, so answers written against an older field set stay interpretable.

### Public endpoints

These sit at the root, deliberately outside `/api/v1`:

| Method + path | Notes |
| --- | --- |
| `GET /f/{public_id}` | The definition to render: title, description, and fields. Never the organization. Briefly cacheable. |
| `POST /f/{public_id}` | A submission. |
| `POST /f/{public_id}/files/{field_key}` | A file answer. See [File uploads](#file-uploads). |

A form is embedded on somebody else's site by design, so three things are true of these routes and not of the API:

- **CORS is open.** The response welcomes any origin, without credentials — a submission genuinely arrives cross-origin, and the API's origin allowlist would refuse it.
- **They are cacheable.** The blanket `no-store` on the API does not apply here.
- **They have their own budgets.** A per-caller-IP limit plus a per-form limit, the latter so a flood aimed at one tenant does not consume anybody else's.

A submission is validated against the stored definition and every problem is reported at once, not one at a time. Unknown keys are rejected; keys beginning with `_` are reserved for client-side helpers and dropped. If a honeypot field is filled, the submission is accepted exactly as normal and filed as `spam`, so the bot learns nothing.

### File uploads

Optional, and any S3-compatible storage works: Cloudflare R2, AWS S3, MinIO, Backblaze B2. With no `S3_BUCKET` set, everything still works except that a form containing a file field cannot be published — refused at the moment it would start accepting input, rather than silently dropping answers later.

| Method + path | Required |
| --- | --- |
| `POST /f/{public_id}/files/{field_key}?filename=receipt.png` | public — returns the `key` to submit as the answer |
| `GET /organizations/{org}/submissions/{id}/files/{field_key}` | member — streamed back as an attachment |

**Bytes travel through this service rather than straight to the bucket.** A presigned URL would never show Core the file, so `max_bytes` and the field's `accept` list would only ever validate what a client *claimed*. Here the real size is counted as it arrives and the real leading bytes are inspected, and the checks are enforced by streaming rather than by buffering the file in memory.

That choice has three consequences worth knowing:

- **The bucket needs no CORS configuration and can stay entirely private.** Nothing but Core ever talks to it.
- **Uploads cost this service bandwidth.** That is the price of enforcement, and it is the right way round for a self-hosted deployment.
- **A download never renders inline.** Responses carry `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`, so an uploaded HTML or SVG file cannot run script against this API's own origin. The object key is read from the submission, which is scoped to the organization — an unguessable key is not itself a capability.

An upload that no submission claims is deleted by the worker after `UPLOAD_TTL_HOURS`, so attaching a file and closing the tab does not leave it in the bucket forever. Give the bucket an `AbortIncompleteMultipartUpload` lifecycle rule as well: if the process is killed mid-upload, nothing here gets the chance to abort it.

### The submission inbox

| Method + path | Required |
| --- | --- |
| `GET /organizations/{org}/submissions` | member — every form in the organization |
| `GET /organizations/{org}/forms/{id}/submissions` | member |
| `GET /organizations/{org}/submissions/{id}` | member |
| `PATCH /organizations/{org}/submissions/{id}` | owner, admin — status |
| `DELETE /organizations/{org}/submissions/{id}` | owner, admin |
| `GET /organizations/{org}/submissions/{id}/files/{field_key}` | member — the attachment, streamed |
| `GET /organizations/{org}/forms/{id}/submissions/export?format=csv\|json` | member |

Listings filter by `status`, `since`, `until`, and the value of any answer: `field=topic&value=Support`. That last one is a JSON containment query, which is exactly what the GIN index over the answer document is there for — so filtering by a field the schema knows nothing about is still indexed.

The export reads in batches and writes each one out as it goes, so the size of a form is not the size of the response in memory. Its columns are the form's current fields *plus* every key ever stored, so an export taken after the definition changed still carries answers that no longer have a field.

Exports page by keyset rather than `OFFSET`: `OFFSET` rescans everything already sent, so the last page of a large form would cost more than the whole export. Continuing after the last row seen keeps it one index scan.

### Delivery tables

Two tables carry the work that happens after a request has been answered: `outbox_events` is what this instance owes, and `webhook_deliveries` is one attempt at telling a particular endpoint about it. Both are written by the same statement as the submission they describe.

They are split because the two things fail differently. An outbox event is settled once the work has been handed off; a delivery is retried on its own schedule against a receiver that may be down for hours. Keeping them together would mean retrying the SMTP handshake because a webhook receiver was slow.

### Notifications and webhooks

A submission is written, and the fact that somebody must be told is written **in the same statement**. That is the whole design: there is no window in which a submission exists and its notification does not, and no reconciliation job is needed to find one.

`--bin worker` runs three loops side by side. They are independent on purpose — a queue that is down must not stop webhooks, and a slow receiver must not stop mail.

| Loop | Does |
| --- | --- |
| **email** | Drains the Redis queue and talks SMTP. |
| **outbox** | Claims owed events and turns each into an email job and its webhook deliveries. |
| **webhooks** | Sends the deliveries, signed, with retries. |
| **uploads** | Deletes uploads that no submission ever claimed. |

**The outbox is at-least-once.** Every step is ordered so the failure mode is the cheap one: the webhook fan-out runs first and is idempotent, and the email is enqueued last. A crash in the narrow window between enqueuing mail and settling the event can therefore send a notification email twice. That is deliberate — a duplicate notification is a nuisance, a lost one is a bug report.

Work is reserved by **leasing** rather than locking: claiming pushes `available_at` past a window in one statement, so several workers run at once without holding a database connection open for the length of an SMTP handshake. A failure is rescheduled with a widening delay (5s → 1h) and never dropped; the error stays on the row for an operator to read.

Webhook endpoints are per organization and may be narrowed to one form. An endpoint that answers a non-2xx is retried on its own schedule (10s → 2h) and given up on after 6 attempts, which leaves the row in the log for a manual redelivery.

| Method + path | Required |
| --- | --- |
| `POST /organizations/{org}/webhook-endpoints` | owner, admin — returns the secret, once |
| `GET /organizations/{org}/webhook-endpoints` | member |
| `GET`/`PATCH`/`DELETE /organizations/{org}/webhook-endpoints/{id}` | member to read, owner/admin to change |
| `POST /organizations/{org}/webhook-endpoints/{id}/rotate-secret` | owner, admin |
| `GET /organizations/{org}/webhook-deliveries` | member |
| `POST /organizations/{org}/webhook-deliveries/{id}/redeliver` | owner, admin |

A signing secret is handed out once, at creation or rotation, and is never listed again — a secret that can be listed leaks with a support ticket.

#### Verifying a delivery

A receiver gets three headers and the raw body:

```
X-SubmitSnap-Signature: sha256=<hex>
X-SubmitSnap-Timestamp: 1758000000
X-SubmitSnap-Delivery:  <delivery uuid>
```

The signature is HMAC-SHA256 over **`<timestamp>.<raw body>`** — the timestamp is inside what was signed, so a captured request cannot be replayed later. Reject anything older than a few minutes, and compare in constant time:

```python
import hmac, hashlib, time

def verify(secret: str, timestamp: str, body: bytes, signature: str) -> bool:
    if abs(time.time() - int(timestamp)) > 300:
        return False
    expected = hmac.new(
        secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(signature, f"sha256={expected}")
```

The body is sent as the exact bytes that were signed. Re-serializing it before comparing will produce a different string and break the check.

The payload looks like this:

```json
{
  "event": "submission.received",
  "form": { "id": "…", "name": "Contact us" },
  "submission": {
    "id": "…", "status": "unread", "created_at": "…",
    "data": { "email": "person@example.com" }
  }
}
```

#### Where an endpoint may point

A webhook URL is fetched **by this server**, which makes the link-local range — where cloud instance credentials live — reachable by anyone who can administer an organization. Literal loopback and link-local targets are therefore refused.

This is a check against the obvious mistake, not a defence against a determined one: the host is examined as written rather than as resolved, so a hostname that resolves somewhere private gets through. Set `WEBHOOK_ALLOW_PRIVATE_TARGETS=true` when the receiver genuinely runs on the same host or a private network. Treat an organization's owner and admins as trusted.

### The scoping rule for tables that come next

Forms and submissions follow the shape the organizations work laid down:

- `organization_id UUID NOT NULL REFERENCES organizations (id) ON DELETE CASCADE`, never nullable, so a query cannot silently span tenants.
- Indexes lead with `organization_id`. `submissions` goes further: one composite index serves both the per-form listing and the organization-wide inbox, and a GIN index over the answer document makes filtering by *any* field key indexed.
- Repository methods take the organization id explicitly, so a missing scope is a compile error.
- One `access(...)` call per handler resolves authorization.

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
  form/          forms, the definition contract, and public ingestion
  webhook/       endpoints, signed delivery, and the delivery log
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
- [x] Form model, scoped to an organization, with schema validation and a rotation-able public handle
- [x] Public `GET`/`POST /f/:public_form_id` ingestion
- [x] Submission inbox, status changes, and CSV/JSON export
- [x] Transactional outbox, notification email, and signed webhook delivery
- [x] Optional S3-compatible file uploads and streamed downloads
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

Two groups are exceptions, because the thing under test *is* the external service. The dispatch tests need the Redis from `compose.yaml` (each under a key prefix of its own, so they never see each other's jobs), and `tests/uploads.rs` needs the MinIO from it. Both are in `make up`:

```bash
make up && make test
```

`tests/uploads.rs` inspects the bucket directly rather than inferring storage behaviour from the database. "A refused upload leaves nothing behind" is a claim about the bucket, so that is where it is asserted.

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Please report vulnerabilities privately as described in [SECURITY.md](SECURITY.md), not through a public issue.

SubmitSnap Core is licensed under the [Apache License 2.0](LICENSE). Use of the SubmitSnap name and logo is governed by [TRADEMARKS.md](TRADEMARKS.md).
