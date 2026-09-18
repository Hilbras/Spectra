use serde::{Deserialize, Serialize};
use spectra_core::SpectraError;
use std::path::PathBuf;

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
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 10,
            default_timeout: 300,
            rate_limit_per_second: 50,
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
        let sources = vec![
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
