use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::request::Request;
use crate::response::{Response, StatusCode};
use crate::retry::RetryPolicy;
use crate::{HttpError, HttpResult};

/// Configuration for an HTTP session.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub default_headers: HashMap<String, String>,
    pub timeout_ms: u64,
    pub follow_redirects: bool,
    pub max_redirects: u32,
    pub retry_policy: RetryPolicy,
    pub user_agent: Option<String>,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            default_headers: HashMap::new(),
            timeout_ms: 30_000,
            follow_redirects: true,
            max_redirects: 10,
            retry_policy: RetryPolicy::default(),
            user_agent: Some(format!("Spectra/{}", env!("CARGO_PKG_VERSION"))),
        }
    }
}

/// An HTTP session for making multiple requests with shared configuration.
///
/// Sessions maintain cookies, default headers, and connection state.
pub struct Session {
    client: reqwest::Client,
    config: SessionConfig,
    cookies: Arc<RwLock<HashMap<String, String>>>,
}

impl Session {
    /// Creates a new session with the given configuration.
    pub fn new(config: SessionConfig) -> HttpResult<Self> {
        let mut builder = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(config.timeout_ms))
            .redirect(if config.follow_redirects {
                reqwest::redirect::Policy::limited(config.max_redirects as usize)
            } else {
                reqwest::redirect::Policy::none()
            });

        if let Some(ref ua) = config.user_agent {
            builder = builder.user_agent(ua);
        }

        // Add default headers
        let mut headers = reqwest::header::HeaderMap::new();
        for (key, value) in &config.default_headers {
            if let (Ok(name), Ok(val)) = (
                reqwest::header::HeaderName::from_bytes(key.as_bytes()),
                reqwest::header::HeaderValue::from_str(value),
            ) {
                headers.insert(name, val);
            }
        }
        builder = builder.default_headers(headers);

        let client = builder
            .build()
            .map_err(|e| HttpError::ConnectionFailed(e.to_string()))?;

        Ok(Self {
            client,
            config,
            cookies: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Executes an HTTP request with retry logic.
    pub async fn execute(&self, request: Request) -> HttpResult<Response> {
        let mut last_error = None;
        let max_retries = self.config.retry_policy.max_retries;

        for attempt in 0..=max_retries {
            if attempt > 0 {
                let delay = self.config.retry_policy.delay_for_attempt(attempt);
                debug!(attempt = attempt, delay_ms = delay, "Retrying request");
                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
            }

            match self.execute_once(&request).await {
                Ok(response) => {
                    if response.status.is_retryable()
                        && self
                            .config
                            .retry_policy
                            .should_retry_status(response.status.as_u16())
                        && self.config.retry_policy.can_retry(attempt)
                    {
                        warn!(
                            status = %response.status,
                            attempt = attempt,
                            "Received retryable status"
                        );
                        last_error = Some(HttpError::RequestFailed(format!(
                            "Retryable status: {}",
                            response.status
                        )));
                        continue;
                    }
                    return Ok(response);
                }
                Err(e) => {
                    if e.is_retryable() && self.config.retry_policy.can_retry(attempt) {
                        warn!(
                            error = %e,
                            attempt = attempt,
                            "Request failed with retryable error"
                        );
                        last_error = Some(e);
                        continue;
                    }
                    return Err(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| HttpError::Custom("Max retries exceeded".to_string())))
    }

    /// Executes a single HTTP request without retry.
    async fn execute_once(&self, request: &Request) -> HttpResult<Response> {
        let url = &request.url;
        let method: reqwest::Method = request.method.clone().into();

        debug!(method = %method, url = %url, "Executing HTTP request");

        let mut req_builder = self.client.request(method, url);

        // Add cookies
        let cookies = self.cookies.read().await;
        for (name, value) in cookies.iter() {
            req_builder =
                req_builder.header(reqwest::header::COOKIE, format!("{}={}", name, value));
        }

        // Add request headers
        for (key, value) in &request.headers {
            req_builder = req_builder.header(key.as_str(), value.as_str());
        }

        // Set timeout if specified
        if let Some(timeout_ms) = request.timeout_ms {
            req_builder = req_builder.timeout(std::time::Duration::from_millis(timeout_ms));
        }

        // Set body
        if let Some(ref body) = request.body {
            req_builder = req_builder.body(body.clone());
        }

        // Execute request
        let start = std::time::Instant::now();
        let resp = req_builder.send().await?;
        let elapsed = start.elapsed().as_millis() as u64;

        // Extract cookies from response headers
        drop(cookies);
        let mut cookies = self.cookies.write().await;
        if let Some(set_cookie) = resp.headers().get("set-cookie") {
            if let Ok(cookie_str) = set_cookie.to_str() {
                // Parse simple cookie format: name=value; ...
                if let Some((name_value, _)) = cookie_str.split_once(';') {
                    if let Some((name, value)) = name_value.split_once('=') {
                        cookies.insert(name.trim().to_string(), value.trim().to_string());
                    }
                }
            }
        }

        // Build response
        let status = StatusCode::new(resp.status().as_u16());
        let url = resp.url().to_string();
        let headers = resp
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_lowercase(),
                    v.to_str().unwrap_or("").to_string(),
                )
            })
            .collect();

        let body = resp.bytes().await?.to_vec();

        debug!(
            status = %status,
            body_size = body.len(),
            elapsed_ms = elapsed,
            "HTTP request completed"
        );

        Ok(Response {
            status,
            headers,
            body,
            url,
            redirect_url: None,
            elapsed_ms: elapsed,
        })
    }

    /// Returns the session configuration.
    pub fn config(&self) -> &SessionConfig {
        &self.config
    }

    /// Clears all stored cookies.
    pub async fn clear_cookies(&self) {
        let mut cookies = self.cookies.write().await;
        cookies.clear();
    }

    /// Returns the current cookies.
    pub async fn cookies(&self) -> HashMap<String, String> {
        self.cookies.read().await.clone()
    }
}

impl Default for Session {
    fn default() -> Self {
        Self::new(SessionConfig::default()).expect("Failed to create default session")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_config_default() {
        let config = SessionConfig::default();
        assert_eq!(config.timeout_ms, 30_000);
        assert!(config.follow_redirects);
        assert_eq!(config.max_redirects, 10);
    }

    #[test]
    fn session_creation() {
        let session = Session::new(SessionConfig::default());
        assert!(session.is_ok());
    }
}
