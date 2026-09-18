use std::fmt;

/// Unified error type for the Spectra platform.
#[derive(Debug, thiserror::Error)]
pub enum SpectraError {
    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Authentication required")]
    Authentication,

    #[error("Authorization denied: {0}")]
    Authorization(String),

    #[error("Scope violation: {0}")]
    ScopeViolation(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Rate limited: {0}")]
    RateLimited(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("IO error: {0}")]
    Io(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Plugin error: {plugin}: {error}")]
    Plugin { plugin: String, error: String },

    #[error("Worker error: {0}")]
    Worker(String),

    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("{0}")]
    Custom(String),
}

impl SpectraError {
    /// Returns the error kind for programmatic matching.
    #[must_use]
    pub const fn kind(&self) -> ErrorKind {
        match self {
            Self::NotFound(_) => ErrorKind::NotFound,
            Self::Validation(_) => ErrorKind::Validation,
            Self::Authentication => ErrorKind::Authentication,
            Self::Authorization(_) => ErrorKind::Authorization,
            Self::ScopeViolation(_) => ErrorKind::ScopeViolation,
            Self::Conflict(_) => ErrorKind::Conflict,
            Self::Timeout(_) => ErrorKind::Timeout,
            Self::RateLimited(_) => ErrorKind::RateLimited,
            Self::Database(_) => ErrorKind::Database,
            Self::Storage(_) => ErrorKind::Storage,
            Self::Network(_) => ErrorKind::Network,
            Self::Io(_) => ErrorKind::Io,
            Self::Serialization(_) => ErrorKind::Serialization,
            Self::Plugin { .. } => ErrorKind::Plugin,
            Self::Worker(_) => ErrorKind::Worker,
            Self::Configuration(_) => ErrorKind::Configuration,
            Self::Internal(_) => ErrorKind::Internal,
            Self::Custom(_) => ErrorKind::Custom,
        }
    }

    /// Returns true if this error is retryable.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self.kind(),
            ErrorKind::Timeout | ErrorKind::RateLimited | ErrorKind::Network | ErrorKind::Database
        )
    }
}

/// Error classification for programmatic handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    NotFound,
    Validation,
    Authentication,
    Authorization,
    ScopeViolation,
    Conflict,
    Timeout,
    RateLimited,
    Database,
    Storage,
    Network,
    Io,
    Serialization,
    Plugin,
    Worker,
    Configuration,
    Internal,
    Custom,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "not_found"),
            Self::Validation => write!(f, "validation"),
            Self::Authentication => write!(f, "authentication"),
            Self::Authorization => write!(f, "authorization"),
            Self::ScopeViolation => write!(f, "scope_violation"),
            Self::Conflict => write!(f, "conflict"),
            Self::Timeout => write!(f, "timeout"),
            Self::RateLimited => write!(f, "rate_limited"),
            Self::Database => write!(f, "database"),
            Self::Storage => write!(f, "storage"),
            Self::Network => write!(f, "network"),
            Self::Io => write!(f, "io"),
            Self::Serialization => write!(f, "serialization"),
            Self::Plugin => write!(f, "plugin"),
            Self::Worker => write!(f, "worker"),
            Self::Configuration => write!(f, "configuration"),
            Self::Internal => write!(f, "internal"),
            Self::Custom => write!(f, "custom"),
        }
    }
}

impl From<std::io::Error> for SpectraError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

impl From<serde_json::Error> for SpectraError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serialization(e.to_string())
    }
}

impl From<toml::de::Error> for SpectraError {
    fn from(e: toml::de::Error) -> Self {
        Self::Serialization(e.to_string())
    }
}

impl From<toml::ser::Error> for SpectraError {
    fn from(e: toml::ser::Error) -> Self {
        Self::Serialization(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_kind_matches() {
        let err = SpectraError::NotFound("test".to_string());
        assert_eq!(err.kind(), ErrorKind::NotFound);
        assert!(!err.is_retryable());
    }

    #[test]
    fn retryable_errors() {
        assert!(SpectraError::Timeout("test".to_string()).is_retryable());
        assert!(SpectraError::Network("test".to_string()).is_retryable());
        assert!(!SpectraError::Validation("test".to_string()).is_retryable());
    }
}
