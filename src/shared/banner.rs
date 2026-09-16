use std::net::SocketAddr;

use crate::shared::{config::AppConfig, logging::colors_enabled};

/// What the operator needs to know the moment the process is up.
pub struct Startup<'a> {
    /// The address actually bound, which is what a client must dial.
    pub address: SocketAddr,
    pub config: &'a AppConfig,
    /// Whether the email queue answered at startup. A failure here is not fatal, but it
    /// means verification and reset messages cannot be delivered.
    pub queue_reachable: bool,
}

/// Prints the banner. Only used when logs are human-readable; JSON deployments get a
/// structured record instead.
pub fn print(startup: Startup<'_>) {
    let Startup {
        address,
        config,
        queue_reachable,
    } = startup;

    let paint = Painter::new();
    let base = format!("http://{address}");

    println!();
    println!(
        "  {}",
        paint.bold_cyan(&format!("SubmitSnap Core {}", env!("CARGO_PKG_VERSION")))
    );
    println!();
    println!("  {:<10} {}", paint.bold("API"), paint.cyan(&base));
    println!("  {:<10} {base}/health", paint.bold("Health"));

    if config.api_docs_enabled {
        println!(
            "  {:<10} {}",
            paint.bold("Swagger UI"),
            paint.cyan(&format!("{base}/docs"))
        );
        println!(
            "  {:<10} {base}/api-docs/openapi.json",
            paint.bold("OpenAPI")
        );
    } else {
        println!(
            "  {:<10} {}",
            paint.bold("Docs"),
            paint.dim("disabled (API_DOCS_ENABLED=false)")
        );
    }

    println!();
    println!(
        "  {:<10} {}",
        paint.bold("Database"),
        paint.dim(&redact_url(&config.database_url))
    );
    println!(
        "  {:<10} {} {}",
        paint.bold("Queue"),
        if queue_reachable {
            paint.green("reachable")
        } else {
            paint.red("unreachable")
        },
        paint.dim(&redact_url(&config.redis_url))
    );
    println!("  {:<10} {}", paint.bold("Email"), email_summary(config));

    println!();
    println!("  {}", paint.dim(&summary_line(config)));
    println!();
    println!("  {}", paint.dim("Press Ctrl+C to stop"));
    println!();
}

fn email_summary(config: &AppConfig) -> String {
    if !config.uses_smtp() {
        return "disabled (outgoing messages are discarded)".to_owned();
    }

    let host = config.smtp_host.as_deref().unwrap_or("unset");
    format!(
        "smtp {host}:{} ({})",
        config.smtp_port,
        config.smtp_tls_mode.to_ascii_lowercase()
    )
}

fn summary_line(config: &AppConfig) -> String {
    let mut parts = vec![if config.require_email_verification {
        "email verification required"
    } else {
        "email verification optional"
    }];

    parts.push(if config.cookie_secure {
        "secure cookies"
    } else {
        "insecure cookies (COOKIE_SECURE=false)"
    });

    if config.password_pepper.is_some() {
        parts.push("peppered passwords");
    }

    parts.join("  ·  ")
}

/// Removes credentials from a connection string so the banner never prints a password.
fn redact_url(url: &str) -> String {
    match (url.find("://"), url.rfind('@')) {
        (Some(scheme_end), Some(at)) if at > scheme_end => {
            format!("{}://***@{}", &url[..scheme_end], &url[at + 1..])
        }
        _ => url.to_owned(),
    }
}

/// Wraps text in an ANSI sequence, or returns it untouched when colour is off.
struct Painter {
    color: bool,
}

impl Painter {
    fn new() -> Self {
        Self {
            color: colors_enabled(),
        }
    }

    fn paint(&self, code: &str, text: &str) -> String {
        if self.color {
            format!("\u{1b}[{code}m{text}\u{1b}[0m")
        } else {
            text.to_owned()
        }
    }

    fn bold(&self, text: &str) -> String {
        self.paint("1", text)
    }

    fn dim(&self, text: &str) -> String {
        self.paint("2", text)
    }

    fn cyan(&self, text: &str) -> String {
        self.paint("36", text)
    }

    fn green(&self, text: &str) -> String {
        self.paint("32", text)
    }

    fn red(&self, text: &str) -> String {
        self.paint("31", text)
    }

    fn bold_cyan(&self, text: &str) -> String {
        self.paint("1;36", text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_are_removed_from_connection_strings() {
        assert_eq!(
            redact_url("postgres://postgres:secret@localhost:5499/submitsnap"),
            "postgres://***@localhost:5499/submitsnap"
        );
        assert_eq!(
            redact_url("redis://127.0.0.1:6399"),
            "redis://127.0.0.1:6399"
        );
        assert_eq!(
            redact_url("redis://:hunter2@host:6379"),
            "redis://***@host:6379"
        );
    }

    #[test]
    fn urls_without_credentials_are_untouched() {
        for url in ["postgres://localhost/db", "redis://host:6379", "not-a-url"] {
            assert_eq!(redact_url(url), url);
        }
    }
}
