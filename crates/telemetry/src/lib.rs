use spectra_config::Config;
use tracing_subscriber::{fmt, EnvFilter};

/// Initialize the tracing subscriber for logging.
pub fn init_logging(config: &Config) {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.logging.level));

    match config.logging.format.as_str() {
        "json" => {
            fmt().with_env_filter(env_filter).json().init();
        }
        _ => {
            fmt().with_env_filter(env_filter).init();
        }
    }
}

/// Initialize OpenTelemetry tracing.
pub fn init_telemetry(config: &Config) -> anyhow::Result<()> {
    if !config.telemetry.enabled {
        return Ok(());
    }

    use opentelemetry::global;
    use opentelemetry::sdk::trace::TracerProvider;
    use opentelemetry::sdk::Resource;
    use opentelemetry::KeyValue;

    let provider = TracerProvider::builder()
        .with_config(
            opentelemetry::sdk::trace::Config::default().with_resource(Resource::new(vec![
                KeyValue::new("service.name", "spectra"),
            ])),
        )
        .build();

    global::set_tracer_provider(provider);

    Ok(())
}

/// Shutdown telemetry providers.
pub fn shutdown_telemetry() {
    opentelemetry::global::shutdown_tracer_provider();
}

#[cfg(test)]
mod tests {
    use super::*;
    use spectra_config::Config;

    #[test]
    fn init_logging_text_format() {
        let mut config = Config::default();
        config.logging.format = "text".into();
        // Note: tracing::init() can only be called once per process.
        // When running all tests, only the first call succeeds; subsequent calls panic.
        // In isolation, this works fine.
        let _ = std::panic::catch_unwind(|| {
            init_logging(&config);
        });
    }

    #[test]
    fn init_logging_json_format() {
        let mut config = Config::default();
        config.logging.format = "json".into();
        let _ = std::panic::catch_unwind(|| {
            init_logging(&config);
        });
    }

    #[test]
    fn init_telemetry_disabled() {
        let mut config = Config::default();
        config.telemetry.enabled = false;
        let result = init_telemetry(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn shutdown_telemetry_does_not_panic() {
        shutdown_telemetry();
    }
}
