# Taste

## Communication
- Writes in casual, informal Indonesian and expects the assistant to reply in Indonesian. Confidence: 0.6
- Gives short, high-level directives rather than detailed specs; when the assistant proposes recommendations, expects all of them to be implemented without further confirmation. Confidence: 0.6
- Prefers very compact output: asks for results as a single line rather than verbose, multi-section prose breakdowns. Confidence: 0.55

## Tooling
- For backend services in Rust, prefers Axum (web framework) + Tokio (async runtime) + PostgreSQL with sqlx (database) + Redis for queues + jsonwebtoken/argon2 (auth) + lettre or HTTP provider APIs (email) + envy/dotenv (config) + tracing/tracing-subscriber (logging) + validator (input validation) + governor (rate limiting), tested with sqlx::test and wiremock. Confidence: 0.6
- Uses Command Code agent skills (`cmd skills`); when given the choice between project-local and global scope, prefers installing globally into `~/.commandcode/skills/` so they are available across projects. Confidence: 0.5
