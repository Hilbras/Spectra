use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// HTTP methods.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Method {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Head,
    Options,
}

impl std::fmt::Display for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Get => write!(f, "GET"),
            Self::Post => write!(f, "POST"),
            Self::Put => write!(f, "PUT"),
            Self::Patch => write!(f, "PATCH"),
            Self::Delete => write!(f, "DELETE"),
            Self::Head => write!(f, "HEAD"),
            Self::Options => write!(f, "OPTIONS"),
        }
    }
}

impl From<Method> for reqwest::Method {
    fn from(method: Method) -> Self {
        match method {
            Method::Get => reqwest::Method::GET,
            Method::Post => reqwest::Method::POST,
            Method::Put => reqwest::Method::PUT,
            Method::Patch => reqwest::Method::PATCH,
            Method::Delete => reqwest::Method::DELETE,
            Method::Head => reqwest::Method::HEAD,
            Method::Options => reqwest::Method::OPTIONS,
        }
    }
}

/// An HTTP request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub method: Method,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
    pub timeout_ms: Option<u64>,
    pub follow_redirects: bool,
    pub max_redirects: Option<u32>,
}

impl Request {
    /// Creates a new GET request.
    pub fn get(url: impl Into<String>) -> Self {
        Self {
            method: Method::Get,
            url: url.into(),
            headers: HashMap::new(),
            body: None,
            timeout_ms: None,
            follow_redirects: true,
            max_redirects: Some(10),
        }
    }

    /// Creates a new POST request.
    pub fn post(url: impl Into<String>) -> Self {
        Self {
            method: Method::Post,
            url: url.into(),
            headers: HashMap::new(),
            body: None,
            timeout_ms: None,
            follow_redirects: true,
            max_redirects: Some(10),
        }
    }

    /// Creates a new PUT request.
    pub fn put(url: impl Into<String>) -> Self {
        Self {
            method: Method::Put,
            url: url.into(),
            headers: HashMap::new(),
            body: None,
            timeout_ms: None,
            follow_redirects: true,
            max_redirects: Some(10),
        }
    }

    /// Creates a new DELETE request.
    pub fn delete(url: impl Into<String>) -> Self {
        Self {
            method: Method::Delete,
            url: url.into(),
            headers: HashMap::new(),
            body: None,
            timeout_ms: None,
            follow_redirects: true,
            max_redirects: Some(10),
        }
    }

    /// Creates a new HEAD request.
    pub fn head(url: impl Into<String>) -> Self {
        Self {
            method: Method::Head,
            url: url.into(),
            headers: HashMap::new(),
            body: None,
            timeout_ms: None,
            follow_redirects: true,
            max_redirects: Some(10),
        }
    }

    /// Adds a header to the request.
    pub fn header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }

    /// Sets the request body.
    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.body = Some(body);
        self
    }

    /// Sets the request body as JSON.
    pub fn json(mut self, json: &serde_json::Value) -> Self {
        self.body = Some(serde_json::to_vec(json).unwrap_or_default());
        self.headers
            .insert("Content-Type".to_string(), "application/json".to_string());
        self
    }

    /// Sets the request body as text.
    pub fn text(mut self, text: impl Into<String>) -> Self {
        let text = text.into();
        self.body = Some(text.into_bytes());
        self.headers
            .insert("Content-Type".to_string(), "text/plain".to_string());
        self
    }

    /// Sets the timeout in milliseconds.
    pub fn timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = Some(timeout_ms);
        self
    }

    /// Sets whether to follow redirects.
    pub fn follow_redirects(mut self, follow: bool) -> Self {
        self.follow_redirects = follow;
        self
    }

    /// Sets the maximum number of redirects.
    pub fn max_redirects(mut self, max: u32) -> Self {
        self.max_redirects = Some(max);
        self
    }

    /// Extracts the host from the URL.
    pub fn host(&self) -> Option<String> {
        url::Url::parse(&self.url)
            .ok()
            .and_then(|u| u.host_str().map(|s| s.to_string()))
    }

    /// Extracts the path from the URL.
    pub fn path(&self) -> String {
        url::Url::parse(&self.url)
            .ok()
            .map(|u| u.path().to_string())
            .unwrap_or_default()
    }

    /// Returns the content length if set.
    pub fn content_length(&self) -> Option<u64> {
        self.body.as_ref().map(|b| b.len() as u64)
    }

    /// Returns true if this is a state-changing method.
    pub fn is_state_changing(&self) -> bool {
        matches!(
            self.method,
            Method::Post | Method::Put | Method::Patch | Method::Delete
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_creation() {
        let req = Request::get("https://example.com");
        assert_eq!(req.method, Method::Get);
        assert_eq!(req.url, "https://example.com");
        assert!(req.follow_redirects);
    }

    #[test]
    fn request_with_headers() {
        let req = Request::get("https://example.com")
            .header("Authorization", "Bearer token")
            .header("Accept", "application/json");
        assert_eq!(req.headers.len(), 2);
        assert_eq!(req.headers.get("Authorization").unwrap(), "Bearer token");
    }

    #[test]
    fn request_with_json_body() {
        let json = serde_json::json!({"key": "value"});
        let req = Request::post("https://example.com").json(&json);
        assert!(req.body.is_some());
        assert_eq!(req.headers.get("Content-Type").unwrap(), "application/json");
    }

    #[test]
    fn request_host_extraction() {
        let req = Request::get("https://example.com:8080/path");
        assert_eq!(req.host().unwrap(), "example.com");
        assert_eq!(req.path(), "/path");
    }

    #[test]
    fn method_display() {
        assert_eq!(Method::Get.to_string(), "GET");
        assert_eq!(Method::Post.to_string(), "POST");
        assert_eq!(Method::Put.to_string(), "PUT");
        assert_eq!(Method::Delete.to_string(), "DELETE");
    }

    #[test]
    fn is_state_changing() {
        assert!(!Request::get("http://x.com").is_state_changing());
        assert!(Request::post("http://x.com").is_state_changing());
        assert!(Request::put("http://x.com").is_state_changing());
        assert!(Request::delete("http://x.com").is_state_changing());
    }
}
