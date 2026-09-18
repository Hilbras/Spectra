use crate::models::{Scope, ScopeRuleType, TargetError, TargetResult};

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
        // Extract host from URL for validation
        let host = Self::extract_host(url)?;
        Self::validate_target(scope, &host)
    }

    /// Validates that a port is allowed by the scope.
    pub fn validate_port(scope: &Scope, port: u16) -> TargetResult<()> {
        // Check if any port rules exist
        let has_port_rules = scope
            .allowed
            .iter()
            .chain(scope.excluded.iter())
            .any(|rule| rule.rule_type == ScopeRuleType::Port);

        if !has_port_rules {
            return Ok(()); // No port restrictions
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
        // Check if any path rules exist
        let has_path_rules = scope
            .allowed
            .iter()
            .chain(scope.excluded.iter())
            .any(|rule| rule.rule_type == ScopeRuleType::Path);

        if !has_path_rules {
            return Ok(()); // No path restrictions
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
        // Validate the URL/host
        Self::validate_url(scope, url)?;

        // Validate the path
        Self::validate_path(scope, path)?;

        // Method restrictions could be added here in the future

        Ok(())
    }

    /// Extracts the host from a URL.
    fn extract_host(url: &str) -> TargetResult<String> {
        // Handle URLs with protocol
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

        // Handle plain hostnames
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
}
