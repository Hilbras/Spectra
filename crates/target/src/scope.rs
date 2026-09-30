use once_cell::sync::Lazy;
use regex::Regex;

use crate::models::{Scope, ScopeRuleType, TargetError, TargetResult};

/// Private IP ranges (RFC 1918, loopback, link-local).
static PRIVATE_IP_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$").unwrap(),
        Regex::new(r"^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$").unwrap(),
        Regex::new(r"^172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}$").unwrap(),
        Regex::new(r"^192\.168\.\d{1,3}\.\d{1,3}$").unwrap(),
        Regex::new(r"^169\.254\.\d{1,3}\.\d{1,3}$").unwrap(),
        Regex::new(r"^0\.0\.0\.0$").unwrap(),
        Regex::new(r"^::1$").unwrap(),
        Regex::new(r"^fe80:.*").unwrap(),
    ]
});

/// Engine for validating operations against scopes.
///
/// The ScopeEngine ensures that all operations stay within authorized boundaries.
/// Every active operation must pass scope validation before execution.
pub struct ScopeEngine;

impl ScopeEngine {
    /// Validates that a target value is within the given scope.
    pub fn validate_target(scope: &Scope, target_value: &str) -> TargetResult<()> {
        if !scope.is_allowed(target_value) {
            return Err(TargetError::ScopeViolation(format!(
                "Target '{}' is not within the allowed scope",
                target_value
            )));
        }
        Ok(())
    }

    /// Validates that a URL is within the given scope.
    pub fn validate_url(scope: &Scope, url: &str) -> TargetResult<()> {
        let host = Self::extract_host(url)?;
        Self::validate_target(scope, &host)
    }

    /// Validates that a port is allowed by the scope.
    pub fn validate_port(scope: &Scope, port: u16) -> TargetResult<()> {
        let has_port_rules = scope
            .allowed
            .iter()
            .chain(scope.excluded.iter())
            .any(|rule| rule.rule_type == ScopeRuleType::Port);

        if !has_port_rules {
            return Ok(());
        }

        let port_str = port.to_string();
        if scope.is_allowed(&port_str) {
            Ok(())
        } else {
            Err(TargetError::ScopeViolation(format!(
                "Port {} is not within the allowed scope",
                port
            )))
        }
    }

    /// Validates that a path is within the given scope.
    pub fn validate_path(scope: &Scope, path: &str) -> TargetResult<()> {
        let has_path_rules = scope
            .allowed
            .iter()
            .chain(scope.excluded.iter())
            .any(|rule| rule.rule_type == ScopeRuleType::Path);

        if !has_path_rules {
            return Ok(());
        }

        if scope.is_allowed(path) {
            Ok(())
        } else {
            Err(TargetError::ScopeViolation(format!(
                "Path '{}' is not within the allowed scope",
                path
            )))
        }
    }

    /// Validates a complete operation (URL + method + path).
    pub fn validate_operation(
        scope: &Scope,
        url: &str,
        _method: &str,
        path: &str,
    ) -> TargetResult<()> {
        Self::validate_url(scope, url)?;
        Self::validate_path(scope, path)?;
        Ok(())
    }

    /// Checks if an IP address is a private/reserved address.
    pub fn is_private_ip(ip: &str) -> bool {
        PRIVATE_IP_PATTERNS.iter().any(|re| re.is_match(ip))
    }

    /// Validates that an IP address is not private/reserved.
    pub fn validate_public_ip(ip: &str) -> TargetResult<()> {
        if Self::is_private_ip(ip) {
            Err(TargetError::ScopeViolation(format!(
                "IP address '{}' is a private/reserved address and cannot be scanned",
                ip
            )))
        } else {
            Ok(())
        }
    }

    /// Validates a scope with regex pattern support.
    pub fn validate_with_regex(scope: &Scope, value: &str) -> TargetResult<()> {
        // Check exclusions first
        for rule in &scope.excluded {
            if Self::rule_matches_regex(rule, value) {
                return Err(TargetError::ScopeViolation(format!(
                    "Value '{}' matches exclusion rule: {}",
                    value, rule.value
                )));
            }
        }

        // Check inclusions
        if scope.allowed.is_empty() {
            return Ok(());
        }

        let any_match = scope
            .allowed
            .iter()
            .any(|rule| Self::rule_matches_regex(rule, value));

        if any_match {
            Ok(())
        } else {
            Err(TargetError::ScopeViolation(format!(
                "Value '{}' is not within the allowed scope",
                value
            )))
        }
    }

    /// Checks if a rule matches a value, supporting regex patterns.
    fn rule_matches_regex(rule: &crate::models::ScopeRule, value: &str) -> bool {
        match rule.rule_type {
            ScopeRuleType::Allow | ScopeRuleType::Exclude => {
                // Try regex match if the pattern contains regex chars
                if rule.value.starts_with("regex:") {
                    let pattern = &rule.value[6..];
                    if let Ok(re) = Regex::new(pattern) {
                        return re.is_match(value);
                    }
                    return false;
                }

                // Fallback to standard matching
                rule.matches(value)
            }
            _ => rule.matches(value),
        }
    }

    /// Extracts the host from a URL.
    pub fn extract_host(url: &str) -> TargetResult<String> {
        if let Some(rest) = url.strip_prefix("http://") {
            return Ok(rest
                .split('/')
                .next()
                .unwrap_or(rest)
                .split(':')
                .next()
                .unwrap_or(rest)
                .to_string());
        }
        if let Some(rest) = url.strip_prefix("https://") {
            return Ok(rest
                .split('/')
                .next()
                .unwrap_or(rest)
                .split(':')
                .next()
                .unwrap_or(rest)
                .to_string());
        }

        if let Some(host) = url.split('/').next() {
            let host = host.split(':').next().unwrap_or(host);
            if !host.is_empty() {
                return Ok(host.to_string());
            }
        }

        Err(TargetError::InvalidTargetValue(format!(
            "Could not extract host from '{}'",
            url
        )))
    }

    /// Creates a summary of scope validation rules.
    pub fn summarize_scope(scope: &Scope) -> ScopeSummary {
        let allow_count = scope
            .allowed
            .iter()
            .filter(|r| r.rule_type == ScopeRuleType::Allow)
            .count();
        let exclude_count = scope
            .excluded
            .iter()
            .filter(|r| r.rule_type == ScopeRuleType::Exclude)
            .count();
        let port_count = scope
            .allowed
            .iter()
            .chain(scope.excluded.iter())
            .filter(|r| r.rule_type == ScopeRuleType::Port)
            .count();
        let path_count = scope
            .allowed
            .iter()
            .chain(scope.excluded.iter())
            .filter(|r| r.rule_type == ScopeRuleType::Path)
            .count();

        ScopeSummary {
            allow_rules: allow_count,
            exclude_rules: exclude_count,
            port_rules: port_count,
            path_rules: path_count,
            has_rate_limits: scope.rate_limits.requests_per_second.is_some()
                || scope.rate_limits.requests_per_minute.is_some(),
            has_execution_limits: scope.execution_limits.max_duration_secs.is_some()
                || scope.execution_limits.max_depth.is_some(),
        }
    }
}

/// Summary of scope configuration.
#[derive(Debug, Clone)]
pub struct ScopeSummary {
    pub allow_rules: usize,
    pub exclude_rules: usize,
    pub port_rules: usize,
    pub path_rules: usize,
    pub has_rate_limits: bool,
    pub has_execution_limits: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{RateLimits, Scope, ScopeRule};

    fn test_scope() -> Scope {
        Scope {
            allowed: vec![
                ScopeRule::allow("*.example.com"),
                ScopeRule::allow("192.168.1.0/24"),
            ],
            excluded: vec![ScopeRule::exclude("admin.example.com")],
            rate_limits: RateLimits {
                requests_per_second: Some(10),
                ..Default::default()
            },
            execution_limits: Default::default(),
        }
    }

    #[test]
    fn validate_target_allowed() {
        let scope = test_scope();
        assert!(ScopeEngine::validate_target(&scope, "sub.example.com").is_ok());
    }

    #[test]
    fn validate_target_excluded() {
        let scope = test_scope();
        assert!(ScopeEngine::validate_target(&scope, "admin.example.com").is_err());
    }

    #[test]
    fn validate_target_not_allowed() {
        let scope = test_scope();
        assert!(ScopeEngine::validate_target(&scope, "other.com").is_err());
    }

    #[test]
    fn validate_url() {
        let scope = test_scope();
        assert!(ScopeEngine::validate_url(&scope, "https://sub.example.com/path").is_ok());
        assert!(ScopeEngine::validate_url(&scope, "https://admin.example.com/path").is_err());
    }

    #[test]
    fn extract_host_from_url() {
        assert_eq!(
            ScopeEngine::extract_host("https://example.com/path").unwrap(),
            "example.com"
        );
        assert_eq!(
            ScopeEngine::extract_host("http://example.com:8080/path").unwrap(),
            "example.com"
        );
        assert_eq!(
            ScopeEngine::extract_host("example.com").unwrap(),
            "example.com"
        );
    }

    #[test]
    fn scope_summary() {
        let scope = test_scope();
        let summary = ScopeEngine::summarize_scope(&scope);
        assert_eq!(summary.allow_rules, 2);
        assert_eq!(summary.exclude_rules, 1);
        assert!(summary.has_rate_limits);
    }

    #[test]
    fn private_ip_detection() {
        assert!(ScopeEngine::is_private_ip("127.0.0.1"));
        assert!(ScopeEngine::is_private_ip("10.0.0.1"));
        assert!(ScopeEngine::is_private_ip("172.16.0.1"));
        assert!(ScopeEngine::is_private_ip("192.168.1.1"));
        assert!(ScopeEngine::is_private_ip("169.254.1.1"));
        assert!(ScopeEngine::is_private_ip("0.0.0.0"));
        assert!(!ScopeEngine::is_private_ip("8.8.8.8"));
        assert!(!ScopeEngine::is_private_ip("1.1.1.1"));
    }

    #[test]
    fn validate_public_ip() {
        assert!(ScopeEngine::validate_public_ip("8.8.8.8").is_ok());
        assert!(ScopeEngine::validate_public_ip("1.1.1.1").is_ok());
        assert!(ScopeEngine::validate_public_ip("192.168.1.1").is_err());
        assert!(ScopeEngine::validate_public_ip("127.0.0.1").is_err());
    }

    #[test]
    fn validate_with_regex() {
        let scope = Scope {
            allowed: vec![ScopeRule {
                rule_type: ScopeRuleType::Allow,
                value: "regex:.*\\.example\\.com".to_string(),
                description: None,
            }],
            excluded: vec![],
            rate_limits: Default::default(),
            execution_limits: Default::default(),
        };

        assert!(ScopeEngine::validate_with_regex(&scope, "test.example.com").is_ok());
        assert!(ScopeEngine::validate_with_regex(&scope, "sub.test.example.com").is_ok());
        assert!(ScopeEngine::validate_with_regex(&scope, "other.com").is_err());
    }
}
