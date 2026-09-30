use tracing::{debug, info};

use crate::{
    Finding, ScanResult, Scanner, ScannerConfig, ScannerError, ScannerMetadata, ScannerResult,
    Severity, VulnerabilityCategory,
};

/// External URLs to test for open redirect.
const REDIRECT_PAYLOADS: &[(&str, &str)] = &[
    ("https://evil.com", "External domain redirect"),
    ("https://evil.com%00.example.com", "Null byte injection"),
    ("//evil.com", "Protocol-relative redirect"),
    ("https://evil.com@target.com", "Userinfo abuse"),
    ("https://evil.com\\@target.com", "Backslash userinfo"),
    (
        "https://evil.com%0d%0aLocation:%20evil.com",
        "CRLF injection",
    ),
    ("javascript:alert(1)", "JavaScript protocol"),
    ("data:text/html,<script>alert(1)</script>", "Data protocol"),
];

/// Parameters commonly used for redirects.
const REDIRECT_PARAMS: &[&str] = &[
    "url",
    "redirect",
    "redirect_url",
    "redirect_uri",
    "return",
    "return_url",
    "return_to",
    "next",
    "next_url",
    "goto",
    "go",
    "out",
    "to",
    "dest",
    "destination",
    "continue",
    "target",
    "redir",
    "redirect_to",
    "callback",
    "comeback",
    "checkout_url",
    "forward",
    "ref",
    "referer",
    "rurl",
];

/// Open Redirect Scanner - detects URL redirect vulnerabilities.
pub struct OpenRedirectScanner {
    config: ScannerConfig,
    http_client: reqwest::Client,
}

impl OpenRedirectScanner {
    pub fn new() -> Self {
        Self {
            config: ScannerConfig::default(),
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("Failed to create HTTP client"),
        }
    }

    /// Tests a URL parameter for open redirect.
    async fn test_parameter(&self, url: &str, param_name: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let parsed = match url::Url::parse(url) {
            Ok(u) => u,
            Err(_) => return findings,
        };

        let base_params: Vec<(String, String)> = parsed
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        for (payload, desc) in REDIRECT_PAYLOADS {
            let mut test_parsed = parsed.clone();
            let mut new_params: Vec<(String, String)> = base_params
                .iter()
                .map(|(k, v)| {
                    if k == param_name {
                        (k.clone(), payload.to_string())
                    } else {
                        (k.clone(), v.clone())
                    }
                })
                .collect();

            if !new_params.iter().any(|(k, _)| k == param_name) {
                new_params.push((param_name.to_string(), payload.to_string()));
            }

            let query: String = new_params
                .iter()
                .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
                .collect::<Vec<_>>()
                .join("&");
            test_parsed.set_query(Some(&query));
            let full_url = test_parsed.to_string();

            debug!(url = %full_url, payload = %payload, "Testing open redirect");

            if let Ok(response) = self.http_client.get(&full_url).send().await {
                let status = response.status().as_u16();

                // Check for 3xx redirects
                if (300..400).contains(&status) {
                    if let Some(location) = response.headers().get("location") {
                        if let Ok(loc_str) = location.to_str() {
                            if loc_str.contains("evil.com") || loc_str == *payload {
                                let finding = Finding::new(
                                    format!("Open Redirect via parameter '{}'", param_name),
                                    format!(
                                        "Parameter '{}' redirects to an external URL: {}. {}",
                                        param_name, loc_str, desc
                                    ),
                                    Severity::Medium,
                                    VulnerabilityCategory::BrokenAccessControl,
                                )
                                .with_url(&full_url)
                                .with_evidence(format!("Redirect location: {}", loc_str))
                                .with_evidence(format!("Payload: {}", payload))
                                .with_remediation(
                                    "Validate redirect targets against a whitelist of allowed domains",
                                )
                                .with_cvss(6.1);

                                findings.push(finding);
                                return findings;
                            }
                        }
                    }
                }

                // Check for JavaScript/data protocol in meta refresh or body
                let body = response.text().await.unwrap_or_default();
                let body_lower = body.to_lowercase();

                if body_lower.contains("evil.com")
                    && (body_lower.contains("meta") || body_lower.contains("refresh"))
                {
                    let finding = Finding::new(
                        format!("Open Redirect (meta refresh) via '{}'", param_name),
                        format!(
                            "Parameter '{}' triggers a meta refresh redirect to evil.com",
                            param_name
                        ),
                        Severity::Medium,
                        VulnerabilityCategory::BrokenAccessControl,
                    )
                    .with_url(&full_url)
                    .with_evidence(
                        "Response contained meta refresh redirect to evil.com".to_string(),
                    )
                    .with_remediation("Validate redirect targets against a whitelist");

                    findings.push(finding);
                    return findings;
                }
            }
        }

        findings
    }

    fn extract_params(url: &str) -> Vec<String> {
        if let Ok(parsed) = url::Url::parse(url) {
            parsed.query_pairs().map(|(k, _)| k.to_string()).collect()
        } else {
            Vec::new()
        }
    }
}

impl Default for OpenRedirectScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Scanner for OpenRedirectScanner {
    fn metadata(&self) -> ScannerMetadata {
        ScannerMetadata {
            name: "Open Redirect Scanner".to_string(),
            version: "0.1.0".to_string(),
            supported_targets: vec!["url".to_string(), "domain".to_string()],
            categories: vec![VulnerabilityCategory::BrokenAccessControl],
        }
    }

    async fn initialize(&mut self, config: ScannerConfig) -> ScannerResult<()> {
        self.config = config;
        Ok(())
    }

    async fn scan(&self, target: &spectra_target::Target) -> ScannerResult<ScanResult> {
        let mut result = ScanResult::new(target.id.clone(), "open-redirect");

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

        info!(url = %base_url, "Starting open redirect scan");

        let params = Self::extract_params(&base_url);
        for param in &params {
            let findings = self.test_parameter(&base_url, param).await;
            for finding in findings {
                result.add_finding(finding);
            }
        }

        let separator = if base_url.contains('?') { '&' } else { '?' };
        for param in REDIRECT_PARAMS {
            if !params.iter().any(|p| p == param) {
                let test_url = format!("{}{}{}=https://example.com", base_url, separator, param);
                let findings = self.test_parameter(&test_url, param).await;
                for finding in findings {
                    result.add_finding(finding);
                }
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
        let scanner = OpenRedirectScanner::new();
        let meta = scanner.metadata();
        assert_eq!(meta.name, "Open Redirect Scanner");
        assert!(meta
            .categories
            .contains(&VulnerabilityCategory::BrokenAccessControl));
    }

    #[test]
    fn extract_params_basic() {
        let params =
            OpenRedirectScanner::extract_params("https://example.com/r?url=https://test.com");
        assert_eq!(params.len(), 1);
        assert!(params.contains(&"url".to_string()));
    }

    #[test]
    fn redirect_payloads_count() {
        assert!(REDIRECT_PAYLOADS.len() >= 5);
    }

    #[test]
    fn redirect_params_count() {
        assert!(REDIRECT_PARAMS.len() >= 10);
    }
}
