use thiserror::Error;

/// HTTP client errors.
#[derive(Debug, Error)]
pub enum HttpError {
    #[error("Request failed: {0}")]
    RequestFailed(String),

    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Timeout after {0}ms")]
    Timeout(u64),

    #[error("Too many redirects")]
    TooManyRedirects,

    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    #[error("Invalid header: {0}")]
    InvalidHeader(String),

    #[error("Connection pool exhausted")]
    PoolExhausted,

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("DNS resolution failed: {0}")]
    DnsResolution(String),

    #[error("IO error: {0}")]
    Io(String),

    #[error("Rate limited")]
    RateLimited,

    #[error("Request too large: {0} bytes")]
    RequestTooLarge(u64),

    #[error("Response too large: {0} bytes")]
    ResponseTooLarge(u64),

    #[error("{0}")]
    Custom(String),
}

impl HttpError {
    /// Returns true if this error is retryable.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Timeout(_)
                | Self::ConnectionFailed(_)
                | Self::RateLimited
                | Self::TooManyRedirects
        )
    }
}

impl From<reqwest::Error> for HttpError {
    fn from(e: reqwest::Error) -> Self {
        if e.is_timeout() {
            Self::Timeout(0)
        } else if e.is_connect() {
            Self::ConnectionFailed(e.to_string())
        } else if e.is_redirect() {
            Self::TooManyRedirects
        } else if e.is_builder() {
            Self::InvalidUrl(e.to_string())
        } else {
            Self::RequestFailed(e.to_string())
        }
    }
}

impl From<url::ParseError> for HttpError {
    fn from(e: url::ParseError) -> Self {
        Self::InvalidUrl(e.to_string())
    }
}

impl From<std::io::Error> for HttpError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

impl From<HttpError> for spectra_core::SpectraError {
    fn from(e: HttpError) -> Self {
        match &e {
            HttpError::Timeout(_) => Self::Timeout(e.to_string()),
            HttpError::ConnectionFailed(_) => Self::Network(e.to_string()),
            HttpError::RateLimited => Self::RateLimited(e.to_string()),
            _ => Self::Network(e.to_string()),
        }
    }
}

/// Result type for HTTP operations.
pub type HttpResult<T> = Result<T, HttpError>;
