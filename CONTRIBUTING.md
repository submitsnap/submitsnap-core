# Contributing to SubmitSnap Core

Thanks for helping improve SubmitSnap Core. By contributing, you agree that your work is licensed under the repository's [Apache License 2.0](LICENSE).

## Before you start

- Search existing issues and pull requests before opening a new one.
- For security vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.
- Discuss a large feature or an API-breaking change in an issue first.

## Local development

1. Copy `.env.example` to `.env` and set a development-only `JWT_SECRET`.
2. Run `docker compose up -d` for PostgreSQL and Redis.
3. Apply migrations with `sqlx migrate run`.
4. Run the API with `cargo run` and the background worker with `cargo run --bin worker`.

The `Makefile` wraps these steps and reads values from `.env`. Run `make` with no arguments to list every target; `make bootstrap` starts the services and rebuilds the database from migrations, and `make db-reset` drops it first.

Before submitting a pull request, run:

```bash
make lint
make test-unit
```

`make lint` checks formatting and runs Clippy with warnings denied. `make test` runs the database-backed integration tests as well; it needs `DATABASE_URL` pointing to a PostgreSQL server where SQLx can create temporary test databases.

## Pull requests

- Keep each pull request focused on one concern.
- Include tests for changed behavior whenever practical.
- Update migrations, `.env.example`, and documentation when the change affects them.
- Do not commit `.env`, credentials, access tokens, database dumps, or generated build artifacts.
- Use clear commit and pull-request descriptions that explain the user-visible effect.

## Design principles

- PostgreSQL is the durable source of truth for submissions.
- Keep transport handlers, domain logic, persistence, and external providers separated.
- Validate untrusted input at the boundary and do not log secrets or tokens.
- Preserve complete self-hosted operation; cloud billing and managed-service concerns do not belong in Core.

## Community conduct

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
