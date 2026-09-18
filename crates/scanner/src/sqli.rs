use tracing::{debug, info};

use crate::{
    Finding, ScanResult, Scanner, ScannerConfig, ScannerError, ScannerMetadata, ScannerResult,
    Severity, VulnerabilityCategory,
};

/// SQL injection detection patterns.
const SQL_ERROR_PATTERNS: &[&str] = &[
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "microsoft ole db provider for odbc drivers",
    "microsoft ole db provider for sql server",
    "incorrect syntax near",
    "unterminated quoted string",
    "invalid query",
    "sql command not properly ended",
    "pg_query",
    "pg_exec",
    "sqlite3::",
    "sqlite_error",
    "sqlite3.OperationalError",
    "ora-00933",
    "ora-00921",
    "ora-01756",
    "postgresql",
    "valid mysql result",
    "mysql_fetch",
    "mysql_num_rows",
    "supplied argument is not a valid mysql",
    "supplied argument is not a valid postgresql",
    "mysql_result",
    "sqlite",
    "sqlstate",
];

/// SQL injection payloads for testing.
const SQLI_PAYLOADS: &[(&str, &str)] = &[
    ("'", "Single quote - basic syntax error"),
    ("' OR '1'='1", "Tautology-based injection"),
    ("' OR '1'='1' --", "Comment-based bypass"),
    ("1; SELECT 1--", "Stacked queries"),
    ("' UNION SELECT NULL--", "UNION-based injection"),
    ("1' AND SLEEP(5)--", "Time-based blind"),
    ("' AND '1'='1", "Boolean-based blind"),
    ("admin'--", "Comment truncation"),
    ("1' ORDER BY 100--", "Column count enumeration"),
    ("' HAVING 1=1--", "GROUP BY injection"),
];

/// SQL injection scanner.
pub struct SqlInjectionScanner {
    config: ScannerConfig,
    http_client: reqwest::Client,
    time_based_threshold_ms: u64,
}

impl SqlInjectionScanner {
    pub fn new() -> Self {
        Self {
            config: ScannerConfig::default(),
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("Failed to create HTTP client"),
            time_based_threshold_ms: 5000,
        }
    }

    /// Tests a single parameter for SQL injection.
    async fn test_parameter(
        &self,
        url: &str,
        param_name: &str,
        _param_value: &str,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (payload, description) in SQLI_PAYLOADS {
            let test_url = format!("{}?{}={}", url, param_name, urlencoding::encode(payload));

            debug!(url = %test_url, payload = %payload, "Testing SQL injection");

            let start = std::time::Instant::now();
            if let Ok(response) = self.http_client.get(&test_url).send().await {
                let status = response.status().as_u16();
                let body = response.text().await.unwrap_or_default();
                let body_lower = body.to_lowercase();
                let elapsed = start.elapsed().as_millis() as u64;

                // Check for SQL error messages in response
                for pattern in SQL_ERROR_PATTERNS {
                    if body_lower.contains(&pattern.to_lowercase()) {
                        let finding = Finding::new(
                            format!("SQL Injection in parameter '{}'", param_name),
                            format!(
                                "Parameter '{}' is vulnerable to SQL injection. {}",
                                param_name, description
                            ),
                            Severity::High,
                            VulnerabilityCategory::Injection,
                        )
                        .with_url(&test_url)
                        .with_evidence(format!("Response contained: {}", pattern))
                        .with_evidence(format!("Payload: {}", payload))
                        .with_remediation("Use parameterized queries or prepared statements")
                        .with_cvss(8.6);

                        findings.push(finding);
                        return findings;
                    }
                }

                // Time-based detection
                if payload.contains("SLEEP") && elapsed >= self.time_based_threshold_ms {
                    let finding = Finding::new(
                        format!("Time-based SQL Injection in '{}'", param_name),
                        format!(
                            "Parameter '{}' appears vulnerable to time-based blind SQL injection",
                            param_name
                        ),
                        Severity::High,
                        VulnerabilityCategory::Injection,
                    )
                    .with_url(&test_url)
                    .with_evidence(format!(
                        "Response took {}ms (threshold: {}ms)",
                        elapsed, self.time_based_threshold_ms
                    ))
                    .with_remediation("Use parameterized queries or prepared statements")
                    .with_cvss(8.6);

                    findings.push(finding);
                    return findings;
                }

                // Check for 500 errors with SQL-like content
                if status == 500
                    && (body_lower.contains("sql")
                        || body_lower.contains("database")
                        || body_lower.contains("query"))
                {
                    let finding = Finding::new(
                        format!("Potential SQL Injection in '{}'", param_name),
                        format!(
                            "Server error with SQL-related content when testing parameter '{}'",
                            param_name
                        ),
                        Severity::Medium,
                        VulnerabilityCategory::Injection,
                    )
                    .with_url(&test_url)
                    .with_evidence("HTTP 500 with SQL-related error content".to_string());

                    findings.push(finding);
                    return findings;
                }
            }
        }

        findings
    }

    /// Extracts query parameters from a URL.
    fn extract_params(url: &str) -> Vec<(String, String)> {
        let mut params = Vec::new();
        if let Ok(parsed) = url::Url::parse(url) {
            for (key, value) in parsed.query_pairs() {
                params.push((key.to_string(), value.to_string()));
            }
        }
        params
    }
}

impl Default for SqlInjectionScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Scanner for SqlInjectionScanner {
    fn metadata(&self) -> ScannerMetadata {
        ScannerMetadata {
            name: "SQL Injection Scanner".to_string(),
            version: "0.1.0".to_string(),
            supported_targets: vec!["url".to_string(), "domain".to_string()],
            categories: vec![VulnerabilityCategory::Injection],
        }
    }

    async fn initialize(&mut self, config: ScannerConfig) -> ScannerResult<()> {
        self.config = config;
        Ok(())
    }

    async fn scan(&self, target: &spectra_target::Target) -> ScannerResult<ScanResult> {
        let mut result = ScanResult::new(target.id.clone(), "sql-injection");

        let base_url = match target.target_type {
            spectra_target::TargetType::Url => target.value().to_string(),
            spectra_target::TargetType::Domain => format!("https://{}", target.value()),
            _ => {
                return Err(ScannerError::InvalidConfig(format!(
                    "Cannot scan target type {:?}",
                    target.target_type
                )));
            }
        };

        info!(url = %base_url, "Starting SQL injection scan");

        // Test the base URL with common parameter names
        let common_params = vec![
            "id", "user", "uid", "item", "page", "search", "q", "query", "name", "cat", "type",
            "sort", "order", "limit", "offset", "file", "path", "dir", "action", "cmd", "exec",
        ];

        // First, try the URL as-is with its existing params
        let params = Self::extract_params(&base_url);
        if !params.is_empty() {
            for (param_name, param_value) in &params {
                let findings = self
                    .test_parameter(&base_url, param_name, param_value)
                    .await;
                for finding in findings {
                    result.add_finding(finding);
                }
            }
        }

        // Also test with common parameter names
        let separator = if base_url.contains('?') { '&' } else { '?' };
        for param in &common_params {
            let test_url = format!("{}{}{}=test", base_url, separator, param);
            let findings = self.test_parameter(&test_url, param, "test").await;
            for finding in findings {
                result.add_finding(finding);
            }
        }

        result.finish();
        Ok(result)
    }

    async fn cleanup(&self) -> ScannerResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scanner_metadata() {
        let scanner = SqlInjectionScanner::new();
        let meta = scanner.metadata();
        assert_eq!(meta.name, "SQL Injection Scanner");
        assert!(meta.categories.contains(&VulnerabilityCategory::Injection));
    }

    #[test]
    fn extract_params_basic() {
        let params = SqlInjectionScanner::extract_params("https://example.com/page?id=1&name=test");
        assert_eq!(params.len(), 2);
        assert!(params.iter().any(|(k, _)| k == "id"));
        assert!(params.iter().any(|(k, _)| k == "name"));
    }

    #[test]
    fn extract_params_none() {
        let params = SqlInjectionScanner::extract_params("https://example.com/page");
        assert!(params.is_empty());
    }
}
