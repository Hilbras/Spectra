use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// HTTP status code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StatusCode(u16);

impl StatusCode {
    pub const OK: Self = Self(200);
    pub const CREATED: Self = Self(201);
    pub const NO_CONTENT: Self = Self(204);
    pub const MOVED_PERMANENTLY: Self = Self(301);
    pub const FOUND: Self = Self(302);
    pub const NOT_MODIFIED: Self = Self(304);
    pub const BAD_REQUEST: Self = Self(400);
    pub const UNAUTHORIZED: Self = Self(401);
    pub const FORBIDDEN: Self = Self(403);
    pub const NOT_FOUND: Self = Self(404);
    pub const METHOD_NOT_ALLOWED: Self = Self(405);
    pub const TOO_MANY_REQUESTS: Self = Self(429);
    pub const INTERNAL_SERVER_ERROR: Self = Self(500);
    pub const BAD_GATEWAY: Self = Self(502);
    pub const SERVICE_UNAVAILABLE: Self = Self(503);

    /// Creates a new status code.
    pub fn new(code: u16) -> Self {
        Self(code)
    }

    /// Returns the status code as u16.
    pub fn as_u16(&self) -> u16 {
        self.0
    }

    /// Returns true if the status code is 2xx.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.0)
    }

    /// Returns true if the status code is 3xx.
    pub fn is_redirect(&self) -> bool {
        (300..400).contains(&self.0)
    }

    /// Returns true if the status code is 4xx.
    pub fn is_client_error(&self) -> bool {
        (400..500).contains(&self.0)
    }

    /// Returns true if the status code is 5xx.
    pub fn is_server_error(&self) -> bool {
        (500..600).contains(&self.0)
    }

    /// Returns true if the status code indicates a retryable error.
    pub fn is_retryable(&self) -> bool {
        matches!(self.0, 408 | 429 | 500 | 502 | 503 | 504)
    }

    /// Returns the canonical reason phrase.
    pub fn canonical_reason(&self) -> &'static str {
        match self.0 {
            200 => "OK",
            201 => "Created",
            204 => "No Content",
            301 => "Moved Permanently",
            302 => "Found",
            304 => "Not Modified",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            429 => "Too Many Requests",
            500 => "Internal Server Error",
            502 => "Bad Gateway",
            503 => "Service Unavailable",
            _ => "Unknown",
        }
    }
}

impl From<u16> for StatusCode {
    fn from(code: u16) -> Self {
        Self(code)
    }
}

impl From<StatusCode> for u16 {
    fn from(status: StatusCode) -> Self {
        status.0
    }
}

impl std::fmt::Display for StatusCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.0, self.canonical_reason())
    }
}

/// An HTTP response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub status: StatusCode,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub url: String,
    pub redirect_url: Option<String>,
    pub elapsed_ms: u64,
}

impl Response {
    /// Creates a new response.
    pub fn new(status: StatusCode) -> Self {
        Self {
            status,
            headers: HashMap::new(),
            body: Vec::new(),
            url: String::new(),
            redirect_url: None,
            elapsed_ms: 0,
        }
    }

    /// Returns true if the response indicates success.
    pub fn is_success(&self) -> bool {
        self.status.is_success()
    }

    /// Returns the content type.
    pub fn content_type(&self) -> Option<&str> {
        self.headers.get("content-type").map(|s| s.as_str())
    }

    /// Returns the content length.
    pub fn content_length(&self) -> Option<u64> {
        self.headers
            .get("content-length")
            .and_then(|s| s.parse().ok())
    }

    /// Returns the body as text.
    pub fn text(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.body)
    }

    /// Returns the body as JSON.
    pub fn json(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::from_slice(&self.body)
    }

    /// Returns the body as bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.body
    }

    /// Returns the body length.
    pub fn body_length(&self) -> usize {
        self.body.len()
    }

    /// Returns the value of a header.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(&name.to_lowercase()).map(|s| s.as_str())
    }

    /// Returns all headers.
    pub fn headers(&self) -> &HashMap<String, String> {
        &self.headers
    }

    /// Checks if the response indicates the resource was not modified.
    pub fn is_not_modified(&self) -> bool {
        self.status == StatusCode::NOT_MODIFIED
    }

    /// Checks if the response is a redirect.
    pub fn is_redirect(&self) -> bool {
        self.status.is_redirect()
    }

    /// Returns the redirect URL if this is a redirect response.
    pub fn redirect_url(&self) -> Option<&str> {
        self.redirect_url.as_deref()
    }
}

impl From<reqwest::Response> for Response {
    fn from(resp: reqwest::Response) -> Self {
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

        Self {
            status,
            headers,
            body: Vec::new(), // Body will be filled separately
            url,
            redirect_url: None,
            elapsed_ms: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_code_success() {
        assert!(StatusCode::OK.is_success());
        assert!(StatusCode::CREATED.is_success());
        assert!(!StatusCode::NOT_FOUND.is_success());
        assert!(!StatusCode::INTERNAL_SERVER_ERROR.is_success());
    }

    #[test]
    fn status_code_retryable() {
        assert!(StatusCode::TOO_MANY_REQUESTS.is_retryable());
        assert!(StatusCode::INTERNAL_SERVER_ERROR.is_retryable());
        assert!(StatusCode::BAD_GATEWAY.is_retryable());
        assert!(StatusCode::SERVICE_UNAVAILABLE.is_retryable());
        assert!(!StatusCode::OK.is_retryable());
        assert!(!StatusCode::NOT_FOUND.is_retryable());
    }

    #[test]
    fn response_creation() {
        let resp = Response::new(StatusCode::OK);
        assert!(resp.is_success());
        assert_eq!(resp.body_length(), 0);
    }

    #[test]
    fn response_with_body() {
        let mut resp = Response::new(StatusCode::OK);
        resp.body = b"Hello, World!".to_vec();
        assert_eq!(resp.text().unwrap(), "Hello, World!");
        assert_eq!(resp.body_length(), 13);
    }

    #[test]
    fn response_json() {
        let json = serde_json::json!({"key": "value"});
        let mut resp = Response::new(StatusCode::OK);
        resp.body = serde_json::to_vec(&json).unwrap();
        assert_eq!(resp.json().unwrap(), json);
    }
}
