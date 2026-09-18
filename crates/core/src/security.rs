use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SecurityError {
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Token generation failed: {0}")]
    TokenGenerationFailed(String),
    #[error("Validation failed: {0}")]
    ValidationFailed(String),
}

pub type SecurityResult<T> = Result<T, SecurityError>;

/// Token types for API authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenType {
    ApiKey,
    Bearer,
    Session,
}

impl std::fmt::Display for TokenType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiKey => write!(f, "api_key"),
            Self::Bearer => write!(f, "bearer"),
            Self::Session => write!(f, "session"),
        }
    }
}

/// API token with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiToken {
    pub token_type: TokenType,
    pub token: String,
    pub created_at: String,
    pub expires_at: Option<String>,
}

impl ApiToken {
    pub fn new_api_key() -> Self {
        let token = generate_token(32);
        Self {
            token_type: TokenType::ApiKey,
            token,
            created_at: chrono::Utc::now().to_rfc3339(),
            expires_at: None,
        }
    }

    pub fn new_bearer() -> Self {
        let token = generate_token(48);
        Self {
            token_type: TokenType::Bearer,
            token,
            created_at: chrono::Utc::now().to_rfc3339(),
            expires_at: None,
        }
    }

    pub fn with_expiry(mut self, expires_at: String) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    pub fn is_expired(&self) -> bool {
        if let Some(ref expires) = self.expires_at {
            if let Ok(exp) = chrono::DateTime::parse_from_rfc3339(expires) {
                return chrono::Utc::now() > exp;
            }
        }
        false
    }
}

/// Input validator for security-sensitive operations.
#[derive(Debug, Clone)]
pub struct InputValidator {
    max_length: usize,
    blocked_patterns: Vec<String>,
    allowed_chars: Option<String>,
}

impl Default for InputValidator {
    fn default() -> Self {
        Self {
            max_length: 10000,
            blocked_patterns: vec![
                "<script".to_string(),
                "javascript:".to_string(),
                "onerror=".to_string(),
                "onload=".to_string(),
                "eval(".to_string(),
                "exec(".to_string(),
            ],
            allowed_chars: None,
        }
    }
}

impl InputValidator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_max_length(mut self, max: usize) -> Self {
        self.max_length = max;
        self
    }

    pub fn with_blocked_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.blocked_patterns.push(pattern.into());
        self
    }

    pub fn with_allowed_chars(mut self, chars: impl Into<String>) -> Self {
        self.allowed_chars = Some(chars.into());
        self
    }

    /// Validate input returns sanitized string or error.
    pub fn validate(&self, input: &str) -> SecurityResult<String> {
        if input.len() > self.max_length {
            return Err(SecurityError::InvalidInput(format!(
                "Input length {} exceeds maximum {}",
                input.len(),
                self.max_length
            )));
        }

        let lower = input.to_lowercase();
        for pattern in &self.blocked_patterns {
            if lower.contains(&pattern.to_lowercase()) {
                return Err(SecurityError::InvalidInput(format!(
                    "Input contains blocked pattern: {}",
                    pattern
                )));
            }
        }

        if let Some(ref allowed) = self.allowed_chars {
            for ch in input.chars() {
                if !allowed.contains(ch) {
                    return Err(SecurityError::InvalidInput(format!(
                        "Character '{}' is not allowed",
                        ch
                    )));
                }
            }
        }

        Ok(input.to_string())
    }

    /// Check if input looks like a URL.
    pub fn is_url(&self, input: &str) -> bool {
        input.starts_with("http://") || input.starts_with("https://")
    }

    /// Sanitize URL to prevent SSRF.
    pub fn sanitize_url(&self, url: &str) -> SecurityResult<String> {
        if !self.is_url(url) {
            return Err(SecurityError::InvalidInput(
                "URL must start with http:// or https://".into(),
            ));
        }

        if url.contains("@") || url.contains("\\") {
            return Err(SecurityError::InvalidInput(
                "URL contains suspicious characters".into(),
            ));
        }

        Ok(url.to_string())
    }
}

/// Rate limiter for API endpoints.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    max_requests: u32,
    window_seconds: u64,
    requests: Vec<u64>,
}

impl RateLimiter {
    pub fn new(max_requests: u32, window_seconds: u64) -> Self {
        Self {
            max_requests,
            window_seconds,
            requests: Vec::new(),
        }
    }

    pub fn is_allowed(&mut self) -> bool {
        let now = timestamp_seconds();
        self.requests.retain(|&t| now - t < self.window_seconds);
        if self.requests.len() < self.max_requests as usize {
            self.requests.push(now);
            true
        } else {
            false
        }
    }

    pub fn remaining(&self) -> u32 {
        let now = timestamp_seconds();
        let recent = self
            .requests
            .iter()
            .filter(|&&t| now - t < self.window_seconds)
            .count();
        self.max_requests.saturating_sub(recent as u32)
    }

    pub fn reset(&mut self) {
        self.requests.clear();
    }
}

/// Hash utility for sensitive data.
pub fn hash_sha256(data: &[u8]) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    data.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

/// Generate a random token of specified length (hex characters).
pub fn generate_token(length: usize) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mut result = String::with_capacity(length);
    for i in 0..length {
        let byte = ((now >> (i % 16 * 4)) & 0xf) as u8;
        result.push_str(&format!("{:x}", byte));
    }
    result
}

/// Constant-time string comparison to prevent timing attacks.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    let mut result = 0u8;
    for i in 0..a_bytes.len() {
        result |= a_bytes[i] ^ b_bytes[i];
    }
    result == 0
}

fn timestamp_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_key_token() {
        let token = ApiToken::new_api_key();
        assert_eq!(token.token_type, TokenType::ApiKey);
        assert_eq!(token.token.len(), 32);
        assert!(!token.is_expired());
    }

    #[test]
    fn bearer_token() {
        let token = ApiToken::new_bearer();
        assert_eq!(token.token_type, TokenType::Bearer);
        assert_eq!(token.token.len(), 48);
    }

    #[test]
    fn token_expiry() {
        let token = ApiToken::new_api_key().with_expiry("2020-01-01T00:00:00Z".into());
        assert!(token.is_expired());
    }

    #[test]
    fn validator_default() {
        let v = InputValidator::new();
        assert!(v.validate("hello world").is_ok());
        assert!(v.validate("<script>alert(1)</script>").is_err());
    }

    #[test]
    fn validator_max_length() {
        let v = InputValidator::new().with_max_length(5);
        assert!(v.validate("hi").is_ok());
        assert!(v.validate("hello world").is_err());
    }

    #[test]
    fn validator_custom_block() {
        let v = InputValidator::new().with_blocked_pattern("DROP TABLE");
        assert!(v.validate("hello").is_ok());
        assert!(v.validate("DROP TABLE users").is_err());
    }

    #[test]
    fn validator_allowed_chars() {
        let v = InputValidator::new().with_allowed_chars("abc123");
        assert!(v.validate("abc").is_ok());
        assert!(v.validate("xyz").is_err());
    }

    #[test]
    fn url_detection() {
        let v = InputValidator::new();
        assert!(v.is_url("https://example.com"));
        assert!(v.is_url("http://localhost"));
        assert!(!v.is_url("not a url"));
    }

    #[test]
    fn url_sanitization() {
        let v = InputValidator::new();
        assert!(v.sanitize_url("https://example.com").is_ok());
        assert!(v.sanitize_url("ftp://example.com").is_err());
        assert!(v.sanitize_url("https://user@host.com").is_err());
        assert!(v.sanitize_url("https://host\\path").is_err());
    }

    #[test]
    fn rate_limiter_allows() {
        let mut limiter = RateLimiter::new(3, 60);
        assert!(limiter.is_allowed());
        assert!(limiter.is_allowed());
        assert!(limiter.is_allowed());
        assert!(!limiter.is_allowed());
    }

    #[test]
    fn rate_limiter_remaining() {
        let mut limiter = RateLimiter::new(5, 60);
        assert_eq!(limiter.remaining(), 5);
        limiter.is_allowed();
        limiter.is_allowed();
        assert_eq!(limiter.remaining(), 3);
    }

    #[test]
    fn rate_limiter_reset() {
        let mut limiter = RateLimiter::new(1, 60);
        assert!(limiter.is_allowed());
        assert!(!limiter.is_allowed());
        limiter.reset();
        assert!(limiter.is_allowed());
    }

    #[test]
    fn hash_deterministic() {
        let h1 = hash_sha256(b"test");
        let h2 = hash_sha256(b"test");
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_different_inputs() {
        let h1 = hash_sha256(b"test");
        let h2 = hash_sha256(b"other");
        assert_ne!(h1, h2);
    }

    #[test]
    fn generate_token_length() {
        let t1 = generate_token(16);
        let t2 = generate_token(32);
        assert_eq!(t1.len(), 16);
        assert_eq!(t2.len(), 32);
    }

    #[test]
    fn constant_time_eq_equal() {
        assert!(constant_time_eq("hello", "hello"));
    }

    #[test]
    fn constant_time_eq_different() {
        assert!(!constant_time_eq("hello", "world"));
    }

    #[test]
    fn constant_time_eq_different_lengths() {
        assert!(!constant_time_eq("hi", "hello"));
    }
}
