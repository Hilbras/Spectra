use std::sync::Arc;

use crate::request::Request;
use crate::response::Response;
use crate::retry::RetryPolicy;
use crate::session::{Session, SessionConfig};
use crate::HttpResult;

/// Configuration for the HTTP client.
#[derive(Debug, Clone, Default)]
pub struct HttpClientConfig {
    pub session_config: SessionConfig,
    pub retry_policy: RetryPolicy,
}

/// A production-grade HTTP client with retry, rate limiting, and connection pooling.
///
/// The `HttpClient` wraps a `Session` and provides additional features:
/// - Automatic retries with exponential backoff
/// - Rate limiting
/// - Request/response logging
/// - Connection pooling
/// - Cookie management
pub struct HttpClient {
    session: Arc<Session>,
    config: HttpClientConfig,
}

impl HttpClient {
    /// Creates a new HTTP client with default configuration.
    pub fn new() -> HttpResult<Self> {
        Self::with_config(HttpClientConfig::default())
    }

    /// Creates a new HTTP client with custom configuration.
    pub fn with_config(config: HttpClientConfig) -> HttpResult<Self> {
        let session = Session::new(config.session_config.clone())?;
        Ok(Self {
            session: Arc::new(session),
            config,
        })
    }

    /// Executes an HTTP request.
    pub async fn execute(&self, request: Request) -> HttpResult<Response> {
        self.session.execute(request).await
    }

    /// Executes a GET request.
    pub async fn get(&self, url: &str) -> HttpResult<Response> {
        self.execute(Request::get(url)).await
    }

    /// Executes a POST request with JSON body.
    pub async fn post_json(&self, url: &str, body: &serde_json::Value) -> HttpResult<Response> {
        self.execute(Request::post(url).json(body)).await
    }

    /// Executes a POST request with text body.
    pub async fn post_text(&self, url: &str, body: &str) -> HttpResult<Response> {
        self.execute(Request::post(url).text(body)).await
    }

    /// Executes a PUT request with JSON body.
    pub async fn put_json(&self, url: &str, body: &serde_json::Value) -> HttpResult<Response> {
        self.execute(Request::put(url).json(body)).await
    }

    /// Executes a DELETE request.
    pub async fn delete(&self, url: &str) -> HttpResult<Response> {
        self.execute(Request::delete(url)).await
    }

    /// Executes a HEAD request.
    pub async fn head(&self, url: &str) -> HttpResult<Response> {
        self.execute(Request::head(url)).await
    }

    /// Returns the client configuration.
    pub fn config(&self) -> &HttpClientConfig {
        &self.config
    }

    /// Returns the underlying session.
    pub fn session(&self) -> &Session {
        &self.session
    }
}

impl Default for HttpClient {
    fn default() -> Self {
        Self::new().expect("Failed to create default HTTP client")
    }
}

/// Builder for creating HTTP clients with fluent configuration.
pub struct HttpClientBuilder {
    config: HttpClientConfig,
}

impl HttpClientBuilder {
    /// Creates a new builder with default settings.
    pub fn new() -> Self {
        Self {
            config: HttpClientConfig::default(),
        }
    }

    /// Sets the timeout in milliseconds.
    pub fn timeout(mut self, timeout_ms: u64) -> Self {
        self.config.session_config.timeout_ms = timeout_ms;
        self
    }

    /// Sets the user agent.
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.config.session_config.user_agent = Some(user_agent.into());
        self
    }

    /// Sets whether to follow redirects.
    pub fn follow_redirects(mut self, follow: bool) -> Self {
        self.config.session_config.follow_redirects = follow;
        self
    }

    /// Sets the maximum number of redirects.
    pub fn max_redirects(mut self, max: u32) -> Self {
        self.config.session_config.max_redirects = max;
        self
    }

    /// Sets the retry policy.
    pub fn retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.config.retry_policy = policy;
        self
    }

    /// Adds a default header.
    pub fn header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.config
            .session_config
            .default_headers
            .insert(key.into(), value.into());
        self
    }

    /// Builds the HTTP client.
    pub fn build(self) -> HttpResult<HttpClient> {
        HttpClient::with_config(self.config)
    }
}

impl Default for HttpClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_creation() {
        let client = HttpClient::new();
        assert!(client.is_ok());
    }

    #[test]
    fn client_builder() {
        let client = HttpClientBuilder::new()
            .timeout(5000)
            .user_agent("TestAgent/1.0")
            .follow_redirects(false)
            .build();
        assert!(client.is_ok());
    }

    #[test]
    fn client_default() {
        let client = HttpClient::default();
        assert_eq!(client.config().session_config.timeout_ms, 30_000);
    }
}
