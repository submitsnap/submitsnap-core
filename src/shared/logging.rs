use std::{io::IsTerminal, str::FromStr};

use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

/// How log records are rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// Human-readable lines, coloured when the terminal supports it.
    Pretty,
    /// One JSON object per line, for a log collector.
    Json,
}

impl FromStr for LogFormat {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "pretty" | "text" | "human" => Ok(Self::Pretty),
            "json" => Ok(Self::Json),
            other => anyhow::bail!("unsupported LOG_FORMAT {other:?}; use pretty or json"),
        }
    }
}

/// Reads `LOG_FORMAT`, defaulting to [`LogFormat::Pretty`]: the reader of a local run is a
/// person, and a deployment that ships logs to a collector sets `json` explicitly.
pub fn configured_format() -> LogFormat {
    std::env::var("LOG_FORMAT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(LogFormat::Pretty)
}

/// Installs the global tracing subscriber. Call once, before anything worth logging happens.
///
/// `RUST_LOG` overrides everything. Without it, the default depends on the format: a pretty
/// run is someone at a terminal, so request-level tracing is useful, while a JSON run is a
/// deployed service where that volume is noise.
pub fn init(format: LogFormat) {
    let default_filter = match format {
        LogFormat::Pretty => "submitsnap_core=debug,tower_http=debug",
        LogFormat::Json => "submitsnap_core=info,tower_http=info",
    };

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| default_filter.into());
    let registry = tracing_subscriber::registry().with(filter);

    match format {
        LogFormat::Json => registry
            .with(tracing_subscriber::fmt::layer().json())
            .init(),
        LogFormat::Pretty => registry
            .with(
                tracing_subscriber::fmt::layer()
                    // The crate name is noise for a single-service binary.
                    .with_target(false)
                    .with_ansi(colors_enabled()),
            )
            .init(),
    }
}

/// Whether ANSI colour should be emitted: never when `NO_COLOR` is set, and only to a
/// terminal, so redirected output stays plain.
pub fn colors_enabled() -> bool {
    std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_are_parsed_and_unknown_values_rejected() {
        assert_eq!("pretty".parse::<LogFormat>().unwrap(), LogFormat::Pretty);
        assert_eq!("TEXT".parse::<LogFormat>().unwrap(), LogFormat::Pretty);
        assert_eq!("json".parse::<LogFormat>().unwrap(), LogFormat::Json);
        assert!("xml".parse::<LogFormat>().is_err());
    }
}
