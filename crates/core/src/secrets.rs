use std::collections::HashMap;
use std::env;
use std::sync::RwLock;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SecretError {
    #[error("Secret not found: {0}")]
    NotFound(String),
    #[error("Secret expired: {0}")]
    Expired(String),
    #[error("Invalid secret format: {0}")]
    InvalidFormat(String),
    #[error("Environment error: {0}")]
    EnvironmentError(String),
}

pub type SecretResult<T> = Result<T, SecretError>;

/// A secret value that is redacted in Debug output.
#[derive(Clone)]
pub struct Secret {
    value: String,
    name: String,
}

impl Secret {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn expose(&self) -> &str {
        &self.value
    }

    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secret({})", self.name)
    }
}

impl std::fmt::Display for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "********")
    }
}

impl PartialEq for Secret {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl Eq for Secret {}

/// Redactor for sensitive values in strings.
#[derive(Debug, Clone, Default)]
pub struct SecretRedactor {
    patterns: Vec<String>,
}

impl SecretRedactor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.patterns.push(pattern.into());
        self
    }

    pub fn with_default_patterns(self) -> Self {
        let defaults = vec![
            "password".to_string(),
            "secret".to_string(),
            "api_key".to_string(),
            "apikey".to_string(),
            "api-key".to_string(),
            "token".to_string(),
            "authorization".to_string(),
            "auth".to_string(),
            "credential".to_string(),
            "private_key".to_string(),
            "private-key".to_string(),
            "access_key".to_string(),
            "access-key".to_string(),
            "session".to_string(),
            "jwt".to_string(),
        ];

        let mut redactor = self;
        for pattern in defaults {
            if !redactor.patterns.contains(&pattern) {
                redactor.patterns.push(pattern);
            }
        }
        redactor
    }

    /// Redact sensitive values in a string.
    pub fn redact(&self, input: &str) -> String {
        let mut result = input.to_string();

        // Redact common secret patterns
        for pattern in &self.patterns {
            // Case-insensitive search for "pattern=value" or "pattern: value" patterns
            let lower = result.to_lowercase();
            let pat_lower = pattern.to_lowercase();

            // Find all occurrences of the pattern
            let mut pos = 0;
            while let Some(idx) = lower[pos..].find(&pat_lower) {
                let actual_idx = pos + idx;
                let pattern_end = actual_idx + pattern.len();

                // Look for = or : after the pattern
                if pattern_end < result.len() {
                    let after_char = result.as_bytes()[pattern_end];
                    if after_char == b'=' || after_char == b':' {
                        // Find the end of the value (space, comma, newline, or end)
                        let value_start = pattern_end + 1;
                        let value_end = result[value_start..]
                            .find(|c: char| c.is_whitespace() || c == ',')
                            .map(|e| value_start + e)
                            .unwrap_or(result.len());

                        if value_start < value_end {
                            let value = &result[value_start..value_end].to_string();
                            if !value.is_empty() && value != "********" {
                                result = format!(
                                    "{}********{}",
                                    &result[..value_start],
                                    &result[value_end..]
                                );
                            }
                        }
                    }
                }

                pos = actual_idx + 1;
            }
        }

        result
    }

    /// Redact JSON values.
    pub fn redact_json(&self, json: &str) -> String {
        match serde_json::from_str::<serde_json::Value>(json) {
            Ok(mut value) => {
                self.redact_json_value(&mut value);
                serde_json::to_string_pretty(&value).unwrap_or_else(|_| json.to_string())
            }
            Err(_) => json.to_string(),
        }
    }

    fn redact_json_value(&self, value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, val) in map.iter_mut() {
                    let key_lower = key.to_lowercase();
                    let is_secret = self
                        .patterns
                        .iter()
                        .any(|p| key_lower.contains(&p.to_lowercase()));

                    if is_secret {
                        if let serde_json::Value::String(s) = val {
                            if !s.is_empty() && s != "********" {
                                *val = serde_json::Value::String("********".to_string());
                            }
                        }
                    } else {
                        self.redact_json_value(val);
                    }
                }
            }
            serde_json::Value::Array(arr) => {
                for item in arr.iter_mut() {
                    self.redact_json_value(item);
                }
            }
            _ => {}
        }
    }
}

/// Environment-based secret provider.
pub struct EnvSecretProvider {
    prefix: String,
    cache: RwLock<HashMap<String, Secret>>,
}

impl EnvSecretProvider {
    pub fn new(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// Load a secret from environment variable.
    pub fn load(&self, name: &str) -> SecretResult<Secret> {
        // Check cache first
        {
            let cache = self
                .cache
                .read()
                .map_err(|_| SecretError::EnvironmentError("Lock poisoned".into()))?;
            if let Some(secret) = cache.get(name) {
                return Ok(secret.clone());
            }
        }

        // Try to load from environment
        let env_key = format!("{}_{}", self.prefix, name.to_uppercase());
        match env::var(&env_key) {
            Ok(value) => {
                let secret = Secret::new(name, value);
                let mut cache = self
                    .cache
                    .write()
                    .map_err(|_| SecretError::EnvironmentError("Lock poisoned".into()))?;
                cache.insert(name.to_string(), secret.clone());
                Ok(secret)
            }
            Err(_) => {
                // Try without prefix
                let env_key = name.to_uppercase();
                match env::var(&env_key) {
                    Ok(value) => {
                        let secret = Secret::new(name, value);
                        let mut cache = self
                            .cache
                            .write()
                            .map_err(|_| SecretError::EnvironmentError("Lock poisoned".into()))?;
                        cache.insert(name.to_string(), secret.clone());
                        Ok(secret)
                    }
                    Err(_) => Err(SecretError::NotFound(name.to_string())),
                }
            }
        }
    }

    /// Check if a secret exists.
    pub fn has(&self, name: &str) -> bool {
        self.load(name).is_ok()
    }

    /// Clear cache.
    pub fn clear_cache(&self) {
        if let Ok(mut cache) = self.cache.write() {
            cache.clear();
        }
    }
}

/// SecretManager that manages multiple secrets.
pub struct SecretManager {
    provider: EnvSecretProvider,
    redactor: SecretRedactor,
}

impl SecretManager {
    pub fn new(prefix: impl Into<String>) -> Self {
        Self {
            provider: EnvSecretProvider::new(prefix),
            redactor: SecretRedactor::new().with_default_patterns(),
        }
    }

    pub fn with_redactor(mut self, redactor: SecretRedactor) -> Self {
        self.redactor = redactor;
        self
    }

    /// Load a secret.
    pub fn get_secret(&self, name: &str) -> SecretResult<Secret> {
        self.provider.load(name)
    }

    /// Check if secret exists.
    pub fn has_secret(&self, name: &str) -> bool {
        self.provider.has(name)
    }

    /// Redact sensitive values in a string.
    pub fn redact(&self, input: &str) -> String {
        self.redactor.redact(input)
    }

    /// Redact JSON values.
    pub fn redact_json(&self, json: &str) -> String {
        self.redactor.redact_json(json)
    }

    /// Get redactor.
    pub fn redactor(&self) -> &SecretRedactor {
        &self.redactor
    }
}

/// Trait for types that contain secrets.
pub trait RedactExt {
    fn redact(&self, redactor: &SecretRedactor) -> String;
}

impl RedactExt for str {
    fn redact(&self, redactor: &SecretRedactor) -> String {
        redactor.redact(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_creation() {
        let secret = Secret::new("api_key", "super-secret-value");
        assert_eq!(secret.name(), "api_key");
        assert_eq!(secret.expose(), "super-secret-value");
        assert!(!secret.is_empty());
    }

    #[test]
    fn secret_debug_redacted() {
        let secret = Secret::new("api_key", "super-secret-value");
        let debug = format!("{:?}", secret);
        assert!(!debug.contains("super-secret-value"));
        assert!(debug.contains("api_key"));
    }

    #[test]
    fn secret_display_redacted() {
        let secret = Secret::new("api_key", "super-secret-value");
        assert_eq!(secret.to_string(), "********");
    }

    #[test]
    fn secret_equality() {
        let s1 = Secret::new("key", "value1");
        let s2 = Secret::new("key", "value1");
        let s3 = Secret::new("key", "value2");
        assert_eq!(s1, s2);
        assert_ne!(s1, s3);
    }

    #[test]
    fn redactor_default_patterns() {
        let redactor = SecretRedactor::new().with_default_patterns();
        assert!(redactor.patterns.len() > 5);
    }

    #[test]
    fn redact_password() {
        let redactor = SecretRedactor::new().with_default_patterns();
        let input = "password=secret123";
        let result = redactor.redact(input);
        assert!(!result.contains("secret123"));
        assert!(result.contains("********"));
    }

    #[test]
    fn redact_api_key() {
        let redactor = SecretRedactor::new().with_default_patterns();
        let input = "api_key=my-secret-key";
        let result = redactor.redact(input);
        assert!(!result.contains("my-secret-key"));
        assert!(result.contains("********"));
    }

    #[test]
    fn redact_token() {
        let redactor = SecretRedactor::new().with_default_patterns();
        let input = "token=eyJhbGciOiJIUzI1NiJ9.secret.signature";
        let result = redactor.redact(input);
        assert!(!result.contains("eyJhbGciOiJIUzI1NiJ9"));
    }

    #[test]
    fn redact_json_object() {
        let redactor = SecretRedactor::new().with_default_patterns();
        let json = r#"{"password": "secret123", "username": "admin"}"#;
        let result = redactor.redact_json(json);
        assert!(!result.contains("secret123"));
        assert!(result.contains("admin"));
        assert!(result.contains("********"));
    }

    #[test]
    fn env_secret_provider() {
        env::set_var("TEST_SECRET_MY_KEY", "my-secret-value");
        let provider = EnvSecretProvider::new("TEST_SECRET");
        let secret = provider.load("my_key").unwrap();
        assert_eq!(secret.expose(), "my-secret-value");
        env::remove_var("TEST_SECRET_MY_KEY");
    }

    #[test]
    fn env_secret_provider_fallback() {
        env::set_var("FALLBACK_KEY", "fallback-value");
        let provider = EnvSecretProvider::new("NONEXISTENT");
        let secret = provider.load("FALLBACK_KEY").unwrap();
        assert_eq!(secret.expose(), "fallback-value");
        env::remove_var("FALLBACK_KEY");
    }

    #[test]
    fn env_secret_provider_not_found() {
        let provider = EnvSecretProvider::new("NONEXISTENT");
        assert!(provider.load("DOES_NOT_EXIST").is_err());
    }

    #[test]
    fn secret_manager() {
        env::set_var("SPECTRA_TEST_SECRET", "test-value");
        let manager = SecretManager::new("SPECTRA_TEST");
        let secret = manager.get_secret("SECRET").unwrap();
        assert_eq!(secret.expose(), "test-value");
        env::remove_var("SPECTRA_TEST_SECRET");
    }

    #[test]
    fn redact_ext_trait() {
        let redactor = SecretRedactor::new().with_default_patterns();
        let input = "password=secret";
        let result = input.redact(&redactor);
        assert!(!result.contains("secret"));
    }
}
