use serde::{Deserialize, Serialize};
use spectra_core::SpectraError;
use std::path::PathBuf;
use tracing::warn;

/// Configuration error type.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    Parse(#[from] toml::de::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] toml::ser::Error),

    #[error("Missing configuration: {0}")]
    Missing(String),

    #[error("Invalid value for {key}: {message}")]
    Invalid { key: String, message: String },
}

impl From<ConfigError> for SpectraError {
    fn from(e: ConfigError) -> Self {
        Self::Configuration(e.to_string())
    }
}

/// Source of configuration value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigSource {
    Default,
    File(PathBuf),
    Environment,
    Cli,
}

/// Root configuration for Spectra.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub storage: StorageConfig,
    pub search: SearchConfig,
    pub queue: QueueConfig,
    pub scanner: ScannerConfig,
    pub crawler: CrawlerConfig,
    pub ai: AiConfig,
    pub telemetry: TelemetryConfig,
    pub worker: WorkerConfig,
    pub logging: LoggingConfig,
    pub cors: CorsConfig,
}

/// Cross-origin policy for the HTTP API.
///
/// There is deliberately no default allowlist. A wildcard origin is unsafe for
/// an API that authenticates with a bearer token the dashboard keeps in
/// `localStorage`: any page on an allowed origin that is compromised can then
/// read authenticated responses. An unset allowlist means "no cross-origin
/// browser access", not "all origins".
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct CorsConfig {
    /// Origins permitted to make credentialed cross-origin requests.
    pub allowed_origins: Vec<String>,
}

#[allow(clippy::derivable_impls)]
impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            database: DatabaseConfig::default(),
            storage: StorageConfig::default(),
            search: SearchConfig::default(),
            queue: QueueConfig::default(),
            scanner: ScannerConfig::default(),
            crawler: CrawlerConfig::default(),
            ai: AiConfig::default(),
            telemetry: TelemetryConfig::default(),
            worker: WorkerConfig::default(),
            logging: LoggingConfig::default(),
            cors: CorsConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub workers: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 8080,
            workers: 4,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: "postgresql://localhost/spectra".to_string(),
            max_connections: 20,
            min_connections: 5,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StorageConfig {
    pub storage_type: String,
    pub path: String,
    pub s3: Option<S3Config>,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            storage_type: "local".to_string(),
            path: "./storage".to_string(),
            s3: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3Config {
    pub bucket: String,
    pub region: String,
    pub endpoint: String,
    pub access_key: Option<String>,
    pub secret_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SearchConfig {
    pub url: String,
    pub index_prefix: String,
}

impl Default for SearchConfig {
    fn default() -> Self {
        Self {
            url: "http://localhost:9200".to_string(),
            index_prefix: "spectra".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct QueueConfig {
    pub queue_type: String,
    pub url: String,
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            queue_type: "redis".to_string(),
            url: "redis://localhost:6379".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScannerConfig {
    pub max_concurrent: usize,
    pub default_timeout: u64,
    pub rate_limit_per_second: u32,
    /// Permit scans whose target resolves to a loopback, private, link-local or
    /// cloud-metadata address.
    ///
    /// Off by default. A scan makes the server issue outbound requests to a
    /// target the caller chose, so an unvalidated target URL is a server-side
    /// request forgery primitive: `POST /api/v1/scans` with
    /// `http://169.254.169.254/` reads the cloud credentials of the machine
    /// running the scanner. Operators who genuinely need to scan internal
    /// hosts can opt in, at the cost of that protection.
    pub allow_internal_targets: bool,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 10,
            default_timeout: 300,
            rate_limit_per_second: 50,
            allow_internal_targets: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CrawlerConfig {
    pub max_depth: u32,
    pub max_pages: u32,
    pub concurrent_requests: usize,
    pub respect_robots: bool,
    pub user_agent: String,
}

impl Default for CrawlerConfig {
    fn default() -> Self {
        Self {
            max_depth: 10,
            max_pages: 10_000,
            concurrent_requests: 10,
            respect_robots: true,
            user_agent: "Spectra/0.1.0".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AiConfig {
    pub provider: String,
    pub model: String,
    pub api_key_env: String,
    pub enabled: bool,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            provider: "openai".to_string(),
            model: "gpt-4".to_string(),
            api_key_env: "SPECTRA_AI_API_KEY".to_string(),
            enabled: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TelemetryConfig {
    pub enabled: bool,
    pub endpoint: String,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            endpoint: "http://localhost:4317".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WorkerConfig {
    pub heartbeat_interval: u64,
    pub job_timeout: u64,
    pub max_retries: u32,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval: 10,
            job_timeout: 600,
            max_retries: 3,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    pub level: String,
    pub format: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: "text".to_string(),
        }
    }
}

impl Config {
    /// Loads configuration from file, environment, and defaults.
    pub fn load() -> Result<Self, ConfigError> {
        let mut config = Self::default();

        // Load from file
        if let Some(path) = Self::config_file_path() {
            if path.exists() {
                let content = std::fs::read_to_string(&path)?;
                config = toml::from_str(&content)?;
            }
        }

        // Override with environment variables
        config.apply_env_overrides();

        Ok(config)
    }

    /// Returns the path to the configuration file.
    fn config_file_path() -> Option<PathBuf> {
        dirs::config_dir().map(|p| p.join("spectra").join("spectra.toml"))
    }

    /// Applies environment variable overrides.
    fn apply_env_overrides(&mut self) {
        if let Ok(val) = std::env::var("SPECTRA_SERVER_HOST") {
            self.server.host = val;
        }
        if let Ok(val) = std::env::var("SPECTRA_SERVER_PORT") {
            if let Ok(port) = val.parse() {
                self.server.port = port;
            }
        }
        if let Ok(val) = std::env::var("SPECTRA_DATABASE_URL") {
            self.database.url = val;
        }
        if let Ok(val) = std::env::var("SPECTRA_STORAGE_PATH") {
            self.storage.path = val;
        }
        if let Ok(val) = std::env::var("SPECTRA_LOG_LEVEL") {
            self.logging.level = val;
        }
        if let Ok(val) = std::env::var("SPECTRA_ALLOW_INTERNAL_TARGETS") {
            self.scanner.allow_internal_targets = matches!(
                val.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            );
        }
        self.apply_scan_limit_overrides(|name| std::env::var(name).ok());
        // Comma-separated origin allowlist. Unset means no cross-origin access.
        if let Ok(val) = std::env::var("SPECTRA_CORS_ORIGINS") {
            self.cors.allowed_origins = val
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
    }

    /// Ceilings on what a single scan may consume.
    ///
    /// These are the operator's, not the caller's: `POST /api/v1/scans` accepts
    /// `max_depth`, `max_pages` and `timeout_secs` in the request body, and a
    /// caller-supplied value may narrow a scan but never raise it above what is
    /// configured here. Without a ceiling those request fields would be the only
    /// bound on a crawl of a site the caller chose.
    ///
    /// Also covers `max_concurrent` and `rate_limit_per_second`, which were
    /// declared on [`ScannerConfig`], given defaults, and asserted non-zero by a
    /// test, but read by nothing at all. They now drive the `ResourceGovernor`
    /// that bounds how many scans may run at once — the limit per scan says
    /// nothing about how many scans are running.
    ///
    /// Split out from [`Config::apply_env_overrides`] and parameterised on the
    /// lookup so the precedence and the malformed-value behaviour can be tested
    /// directly. Reading the real environment from a test would mean either
    /// `std::env::set_var` — which the workspace forbids, and which races other
    /// tests in the same process regardless — or asserting nothing.
    ///
    /// A malformed value leaves the default in place rather than refusing to
    /// start: a typo in an operator's ceiling should not take the scanner down.
    fn apply_scan_limit_overrides(&mut self, lookup: impl Fn(&str) -> Option<String>) {
        if let Some(raw) = lookup("SPECTRA_CRAWLER_MAX_PAGES") {
            if let Ok(pages) = raw.parse() {
                self.crawler.max_pages = pages;
            } else {
                warn!("Ignoring SPECTRA_CRAWLER_MAX_PAGES={raw:?}: not a number");
            }
        }
        if let Some(raw) = lookup("SPECTRA_CRAWLER_MAX_DEPTH") {
            if let Ok(depth) = raw.parse() {
                self.crawler.max_depth = depth;
            } else {
                warn!("Ignoring SPECTRA_CRAWLER_MAX_DEPTH={raw:?}: not a number");
            }
        }
        if let Some(raw) = lookup("SPECTRA_SCANNER_MAX_CONCURRENT") {
            if let Ok(n) = raw.parse() {
                self.scanner.max_concurrent = n;
            } else {
                warn!("Ignoring SPECTRA_SCANNER_MAX_CONCURRENT={raw:?}: not a number");
            }
        }
        if let Some(raw) = lookup("SPECTRA_SCANNER_RATE_LIMIT_PER_SECOND") {
            if let Ok(n) = raw.parse() {
                self.scanner.rate_limit_per_second = n;
            } else {
                warn!("Ignoring SPECTRA_SCANNER_RATE_LIMIT_PER_SECOND={raw:?}: not a number");
            }
        }
        if let Some(raw) = lookup("SPECTRA_SCANNER_DEFAULT_TIMEOUT") {
            if let Ok(timeout) = raw.parse() {
                self.scanner.default_timeout = timeout;
            } else {
                warn!("Ignoring SPECTRA_SCANNER_DEFAULT_TIMEOUT={raw:?}: not a number");
            }
        }
    }

    /// Saves the configuration to the default file.
    pub fn save(&self) -> Result<(), ConfigError> {
        let path = Self::config_file_path()
            .ok_or_else(|| ConfigError::Missing("config directory".to_string()))?;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Returns the database URL.
    pub fn database_url(&self) -> &str {
        &self.database.url
    }

    /// Returns the server address.
    pub fn server_address(&self) -> String {
        format!("{}:{}", self.server.host, self.server.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let config = Config::default();
        assert_eq!(config.server.port, 8080);
        assert_eq!(config.database.url, "postgresql://localhost/spectra");
    }

    #[test]
    fn config_serialization() {
        let config = Config::default();
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: Config = toml::from_str(&toml_str).unwrap();
        assert_eq!(config.server.port, parsed.server.port);
    }

    #[test]
    fn server_config_defaults() {
        let config = ServerConfig::default();
        assert_eq!(config.host, "0.0.0.0");
        assert_eq!(config.port, 8080);
        assert_eq!(config.workers, 4);
    }

    #[test]
    fn database_config_defaults() {
        let config = DatabaseConfig::default();
        assert!(config.url.contains("spectra"));
        assert!(config.max_connections > 0);
    }

    #[test]
    fn storage_config_defaults() {
        let config = StorageConfig::default();
        assert_eq!(config.storage_type, "local");
        assert!(config.s3.is_none());
    }

    #[test]
    fn s3_config() {
        let config = S3Config {
            bucket: "my-bucket".into(),
            region: "us-east-1".into(),
            endpoint: "https://s3.amazonaws.com".into(),
            access_key: None,
            secret_key: None,
        };
        assert_eq!(config.bucket, "my-bucket");
    }

    #[test]
    fn search_config_defaults() {
        let config = SearchConfig::default();
        assert_eq!(config.index_prefix, "spectra");
    }

    #[test]
    fn queue_config_defaults() {
        let config = QueueConfig::default();
        assert_eq!(config.queue_type, "redis");
    }

    #[test]
    fn scanner_config_defaults() {
        let config = ScannerConfig::default();
        assert!(config.max_concurrent > 0);
        assert!(config.rate_limit_per_second > 0);
    }

    #[test]
    fn crawler_config_defaults() {
        let config = CrawlerConfig::default();
        assert!(config.respect_robots);
        assert!(config.max_depth > 0);
        assert!(config.max_pages > 0);
    }

    #[test]
    fn ai_config_defaults() {
        let config = AiConfig::default();
        assert!(!config.enabled);
        assert!(!config.api_key_env.is_empty());
    }

    #[test]
    fn telemetry_config_defaults() {
        let config = TelemetryConfig::default();
        assert!(config.enabled);
    }

    #[test]
    fn worker_config_defaults() {
        let config = WorkerConfig::default();
        assert!(config.heartbeat_interval > 0);
        assert!(config.job_timeout > 0);
    }

    #[test]
    fn logging_config_defaults() {
        let config = LoggingConfig::default();
        assert!(!config.level.is_empty());
        assert!(!config.format.is_empty());
    }

    #[test]
    fn config_server_address() {
        let config = Config::default();
        assert_eq!(config.server_address(), "0.0.0.0:8080");
    }

    #[test]
    fn config_database_url() {
        let config = Config::default();
        assert_eq!(config.database_url(), "postgresql://localhost/spectra");
    }

    #[test]
    fn config_from_toml() {
        let toml_str = r#"
[server]
host = "127.0.0.1"
port = 9090
workers = 8

[database]
url = "postgresql://remote/db"
max_connections = 50

[logging]
level = "debug"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.server.port, 9090);
        assert_eq!(config.server.workers, 8);
        assert_eq!(config.database.url, "postgresql://remote/db");
        assert_eq!(config.database.max_connections, 50);
        assert_eq!(config.logging.level, "debug");
    }

    #[test]
    fn config_partial_toml() {
        let toml_str = r#"
[server]
port = 3000
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.server.port, 3000);
        assert_eq!(config.database.url, "postgresql://localhost/spectra");
    }

    #[test]
    fn config_clone() {
        let config = Config::default();
        let cloned = config.clone();
        assert_eq!(config.server.port, cloned.server.port);
        assert_eq!(config.database.url, cloned.database.url);
    }

    #[test]
    fn config_debug() {
        let config = Config::default();
        let debug = format!("{:?}", config);
        assert!(debug.contains("ServerConfig"));
    }

    #[test]
    fn config_source_variants() {
        let sources = [
            ConfigSource::Default,
            ConfigSource::File(PathBuf::from("/tmp/config.toml")),
            ConfigSource::Environment,
            ConfigSource::Cli,
        ];
        assert_eq!(sources.len(), 4);
    }

    #[test]
    fn config_error_display() {
        let err = ConfigError::Missing("key".into());
        assert!(err.to_string().contains("Missing"));

        let err = ConfigError::Invalid {
            key: "port".into(),
            message: "must be > 0".into(),
        };
        assert!(err.to_string().contains("port"));
    }

    #[test]
    fn config_error_into_spectra_error() {
        let err = ConfigError::Missing("test".into());
        let spectra_err: SpectraError = err.into();
        assert_eq!(spectra_err.kind(), spectra_core::ErrorKind::Configuration);
    }
}

#[cfg(test)]
mod limit_override_tests {
    use super::*;

    fn lookup<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| (*v).to_string())
        }
    }

    /// The ceilings are the operator's, so they have to be settable without a
    /// rebuild. Before these overrides existed, the only bound on a crawl was a
    /// hardcoded `CrawlerConfig::default()` inside the engine.
    #[test]
    fn ceilings_can_be_set_from_the_environment() {
        let mut config = Config::default();

        config.apply_scan_limit_overrides(lookup(&[
            ("SPECTRA_CRAWLER_MAX_PAGES", "25"),
            ("SPECTRA_CRAWLER_MAX_DEPTH", "2"),
            ("SPECTRA_SCANNER_DEFAULT_TIMEOUT", "45"),
            ("SPECTRA_SCANNER_MAX_CONCURRENT", "3"),
            ("SPECTRA_SCANNER_RATE_LIMIT_PER_SECOND", "7"),
        ]));

        assert_eq!(config.crawler.max_pages, 25);
        assert_eq!(config.crawler.max_depth, 2);
        assert_eq!(config.scanner.default_timeout, 45);
        assert_eq!(config.scanner.max_concurrent, 3);
        assert_eq!(config.scanner.rate_limit_per_second, 7);
    }

    /// The two limits that bound concurrent scans were unreachable before this.
    /// Nothing read them, so an operator setting `SPECTRA_SCANNER_MAX_CONCURRENT=1`
    /// got no effect whatsoever.
    #[test]
    fn the_concurrency_and_rate_limits_are_settable() {
        let mut config = Config::default();

        config.apply_scan_limit_overrides(lookup(&[
            ("SPECTRA_SCANNER_MAX_CONCURRENT", "2"),
            ("SPECTRA_SCANNER_RATE_LIMIT_PER_SECOND", "9"),
        ]));

        assert_eq!(config.scanner.max_concurrent, 2);
        assert_eq!(config.scanner.rate_limit_per_second, 9);
    }

    #[test]
    fn a_malformed_concurrency_limit_leaves_the_default() {
        let mut config = Config::default();
        let default = config.scanner.max_concurrent;

        config.apply_scan_limit_overrides(lookup(&[("SPECTRA_SCANNER_MAX_CONCURRENT", "lots")]));

        assert_eq!(config.scanner.max_concurrent, default);
    }

    #[test]
    fn an_unset_ceiling_leaves_the_default() {
        let mut config = Config::default();
        let before = (
            config.crawler.max_pages,
            config.crawler.max_depth,
            config.scanner.default_timeout,
        );

        config.apply_scan_limit_overrides(lookup(&[]));

        assert_eq!(
            (
                config.crawler.max_pages,
                config.crawler.max_depth,
                config.scanner.default_timeout
            ),
            before
        );
    }

    /// A typo must not take the scanner down, and must not silently become
    /// something other than the default either.
    #[test]
    fn a_malformed_ceiling_leaves_the_default_in_place() {
        let mut config = Config::default();
        let default_pages = config.crawler.max_pages;

        config.apply_scan_limit_overrides(lookup(&[("SPECTRA_CRAWLER_MAX_PAGES", "lots")]));

        assert_eq!(config.crawler.max_pages, default_pages);
    }

    #[test]
    fn a_zero_ceiling_is_honoured_because_it_is_valid() {
        // Distinct from the malformed case: 0 parses, and refusing it would
        // leave the operator with no way to express "scan nothing".
        let mut config = Config::default();

        config.apply_scan_limit_overrides(lookup(&[("SPECTRA_CRAWLER_MAX_PAGES", "0")]));

        assert_eq!(config.crawler.max_pages, 0);
    }

    #[test]
    fn a_negative_ceiling_leaves_the_default() {
        // `u32::parse` rejects it, so an operator who writes -1 gets the default
        // rather than a ceiling that is not a ceiling.
        let mut config = Config::default();
        let default_depth = config.crawler.max_depth;

        config.apply_scan_limit_overrides(lookup(&[("SPECTRA_CRAWLER_MAX_DEPTH", "-1")]));

        assert_eq!(config.crawler.max_depth, default_depth);
    }
}
