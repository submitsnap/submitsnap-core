# SubmitSnap Core — developer tasks.
#
# Run `make` with no arguments to list the targets.
#
# Values from `.env` are loaded and exported to every recipe, and they win over variables set
# in the ambient environment. Note that this is the opposite of the application's own dotenv
# loader, which leaves an existing environment variable alone. Override on the command line
# instead, where an assignment beats both:
#
#   make run SERVER_PORT=9000
#   make test DATABASE_URL=postgres://postgres:postgres@localhost:5432/other

SHELL   := /bin/bash
CARGO   ?= cargo
SQLX    ?= sqlx
COMPOSE ?= docker compose

DATABASE_URL ?= postgres://postgres:postgres@localhost:5499/submitsnap
REDIS_URL    ?= redis://127.0.0.1:6399

ifneq (,$(wildcard .env))
include .env
export
endif

.DEFAULT_GOAL := help

.PHONY: help up down logs check-sqlx db-create migrate db-reset bootstrap \
        run worker check-email build fmt lint test-unit test ci clean

help: ## List the available targets
	@printf 'SubmitSnap Core\n\nUsage: make <target>\n\nTargets:\n'
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z0-9_-]+:.*## / {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@printf '\nDatabase: %s\n' '$(DATABASE_URL)'

## Local services -----------------------------------------------------------------------

up: ## Start PostgreSQL and Redis, waiting until both are healthy
	$(COMPOSE) up -d --wait

down: ## Stop the local backing services
	$(COMPOSE) down

logs: ## Follow the backing service logs
	$(COMPOSE) logs -f

## Database -----------------------------------------------------------------------------

check-sqlx:
	@command -v $(SQLX) >/dev/null 2>&1 || { \
		printf '\033[31msqlx-cli is required but was not found on PATH.\033[0m\n'; \
		printf 'Install it with:\n  cargo install sqlx-cli --no-default-features --features rustls,postgres\n'; \
		exit 1; }

db-create: check-sqlx ## Create the database named in DATABASE_URL if it is missing
	$(SQLX) database create

migrate: check-sqlx ## Apply every pending migration
	$(SQLX) migrate run

db-reset: check-sqlx ## DESTRUCTIVE: drop, recreate, and re-migrate the database
	@printf '\033[31mDropping %s and rebuilding it from migrations.\033[0m\n' '$(DATABASE_URL)'
	$(SQLX) database drop -y
	$(SQLX) database create
	$(SQLX) migrate run
	@$(SQLX) migrate info

bootstrap: up db-reset ## Start the services and rebuild the database from scratch

## Application --------------------------------------------------------------------------

run: ## Run the API server
	$(CARGO) run

worker: ## Run the email worker
	$(CARGO) run --bin email_worker

check-email: ## Send one test message through the configured SMTP server (TO=you@example.com)
	@test -n '$(TO)' || { \
		printf '\033[31mSet TO=<recipient>:\033[0m make check-email TO=you@example.com\n'; \
		exit 1; }
	$(CARGO) run --bin check_email -- '$(TO)'

build: ## Build the release binaries
	$(CARGO) build --release

## Quality ------------------------------------------------------------------------------

fmt: ## Format the codebase
	$(CARGO) fmt --all

lint: ## Verify formatting and lint with warnings denied
	$(CARGO) fmt --all --check
	$(CARGO) clippy --all-targets -- -D warnings

test-unit: ## Run the tests that need no database
	$(CARGO) test --lib

test: ## Run every test (requires a running PostgreSQL; see `make up`)
	DATABASE_URL='$(DATABASE_URL)' $(CARGO) test

ci: lint test ## What continuous integration runs

clean: ## Remove build artifacts
	$(CARGO) clean
