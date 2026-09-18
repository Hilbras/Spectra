use thiserror::Error;

/// Errors specific to crawler operations.
#[derive(Debug, Error)]
pub enum CrawlerError {
    #[error("Request failed: {0}")]
    RequestFailed(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Rate limited")]
    RateLimited,

    #[error("Target unreachable: {0}")]
    Unreachable(String),

    #[error("Timeout after {0}ms")]
    Timeout(u64),

    #[error("Scope violation: {0}")]
    ScopeViolation(String),

    #[error("IO error: {0}")]
    Io(String),
}

impl From<CrawlerError> for spectra_core::SpectraError {
    fn from(e: CrawlerError) -> Self {
        match &e {
            CrawlerError::RequestFailed(_) => Self::Network(e.to_string()),
            CrawlerError::ParseError(_) => Self::Validation(e.to_string()),
            CrawlerError::RateLimited => Self::RateLimited(e.to_string()),
            CrawlerError::Unreachable(_) => Self::Network(e.to_string()),
            CrawlerError::Timeout(_) => Self::Timeout(e.to_string()),
            CrawlerError::ScopeViolation(_) => Self::ScopeViolation(e.to_string()),
            CrawlerError::Io(_) => Self::Io(e.to_string()),
        }
    }
}

/// Result type for crawler operations.
pub type CrawlerResult<T> = Result<T, CrawlerError>;
