use tracing::{debug, info};

use crate::{
    Finding, ScanResult, Scanner, ScannerConfig, ScannerError, ScannerMetadata, ScannerResult,
    Severity, VulnerabilityCategory,
};

/// SSRF payloads that attempt to reach internal/metadata services.
const SSRF_PAYLOADS: &[(&str, &str, &str)] = &[
    (
        "http://127.0.0.1",
        "Loopback IPv4",
        "http://127.0.0.1/latest/meta-data/",
    ),
    (
        "http://localhost",
        "Loopback hostname",
        "http://localhost/latest/meta-data/",
    ),
    (
        "http://169.254.169.254",
        "AWS metadata IP",
        "http://169.254.169.254/latest/meta-data/",
    ),
    (
        "http://[::1]",
        "Loopback IPv6",
        "http://[::1]/latest/meta-data/",
    ),
    (
        "http://0x7f000001",
        "Hex-encoded loopback",
        "http://0x7f000001/latest/meta-data/",
    ),
    (
        "http://2130706433",
        "Decimal-encoded loopback",
        "http://2130706433/latest/meta-data/",
    ),
    (
        "http://127.1",
        "Short-form loopback",
        "http://127.1/latest/meta-data/",
    ),
    (
        "http://0177.0.0.1",
        "Octal-encoded loopback",
        "http://0177.0.0.1/latest/meta-data/",
    ),
];

/// SSRF response indicators that suggest the request reached an internal service.
const SSRF_INDICATORS: &[&str] = &[
    "ami-id",
    "instance-id",
    "instance-type",
    "local-hostname",
    "mac",
    "iam/security-credentials",
    "user-data",
    "metadata",
    "169.254.",
    "404 - null",
    "Not Found",
];

/// Parameters commonly vulnerable to SSRF.
const SSRF_PARAMS: &[&str] = &[
    "url", "uri", "path", "dest", "redirect", "href", "link", "src", "img", "fetch", "load",
    "page", "site", "target", "callback", "return", "next", "continue", "ref", "file", "document",
    "folder", "dir", "host", "port",
];

/// SSRF Scanner - detects Server-Side Request Forgery vulnerabilities.
pub struct SsrfScanner {
    config: ScannerConfig,
    http_client: reqwest::Client,
}

impl SsrfScanner {
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

    /// Tests a URL parameter for SSRF by injecting internal URLs.
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

        for (internal_url, desc, test_url) in SSRF_PAYLOADS {
            // Rebuild URL with the SSRF payload as the parameter value
            let mut test_parsed = parsed.clone();
            let mut new_params: Vec<(String, String)> = base_params
                .iter()
                .map(|(k, v)| {
                    if k == param_name {
                        (k.clone(), test_url.to_string())
                    } else {
                        (k.clone(), v.clone())
                    }
                })
                .collect();

            // If the param wasn't in the original URL, add it
            if !new_params.iter().any(|(k, _)| k == param_name) {
                new_params.push((param_name.to_string(), test_url.to_string()));
            }

            // Rebuild query string
            let query: String = new_params
                .iter()
                .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
                .collect::<Vec<_>>()
                .join("&");
            test_parsed.set_query(Some(&query));

            let full_url = test_parsed.to_string();
            debug!(url = %full_url, payload = %internal_url, "Testing SSRF");

            if let Ok(response) = self.http_client.get(&full_url).send().await {
                let status = response.status();

                // Check for redirect to internal IP (302/301 to internal)
                if status.is_redirection() {
                    if let Some(location) = response.headers().get("location") {
                        if let Ok(loc_str) = location.to_str() {
                            let loc_lower = loc_str.to_lowercase();
                            if loc_lower.starts_with("http://127.")
                                || loc_lower.starts_with("http://localhost")
                                || loc_lower.starts_with("http://169.254.")
                                || loc_lower.starts_with("http://10.")
                                || loc_lower.starts_with("http://172.")
                                || loc_lower.starts_with("http://192.168.")
                            {
                                let finding = Finding::new(
                                    format!("SSRF Redirect via '{}'", param_name),
                                    format!(
                                        "Parameter '{}' causes a redirect to an internal address: {}",
                                        param_name, loc_str
                                    ),
                                    Severity::High,
                                    VulnerabilityCategory::BrokenAccessControl,
                                )
                                .with_url(&full_url)
                                .with_evidence(format!("Redirect location: {}", loc_str))
                                .with_remediation("Validate redirect URLs against an allowlist");

                                findings.push(finding);
                                return findings;
                            }
                        }
                    }
                }

                let body = response.text().await.unwrap_or_default();
                let body_lower = body.to_lowercase();

                // Check if response contains metadata indicators
                for indicator in SSRF_INDICATORS {
                    if body_lower.contains(&indicator.to_lowercase()) {
                        let finding = Finding::new(
                            format!("SSRF via parameter '{}'", param_name),
                            format!(
                                "Parameter '{}' allows Server-Side Request Forgery. {} was reachable.",
                                param_name, desc
                            ),
                            Severity::Critical,
                            VulnerabilityCategory::BrokenAccessControl,
                        )
                        .with_url(&full_url)
                        .with_evidence(format!("Response contained: {}", indicator))
                        .with_evidence(format!("Internal URL tested: {}", internal_url))
                        .with_remediation(
                            "Validate and sanitize URL inputs. Block access to internal IPs and metadata endpoints.",
                        )
                        .with_cvss(9.8);

                        findings.push(finding);
                        return findings;
                    }
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

impl Default for SsrfScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Scanner for SsrfScanner {
    fn metadata(&self) -> ScannerMetadata {
        ScannerMetadata {
            name: "SSRF Scanner".to_string(),
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
        let mut result = ScanResult::new(target.id.clone(), "ssrf");

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

        info!(url = %base_url, "Starting SSRF scan");

        // Test existing parameters
        let params = Self::extract_params(&base_url);
        for param in &params {
            let findings = self.test_parameter(&base_url, param).await;
            for finding in findings {
                result.add_finding(finding);
            }
        }

        // Test with common SSRF-vulnerable parameter names
        let separator = if base_url.contains('?') { '&' } else { '?' };
        for param in SSRF_PARAMS {
            if !params.iter().any(|p| p == param) {
                let test_url = format!("{}{}{}=http://127.0.0.1", base_url, separator, param);
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
        let scanner = SsrfScanner::new();
        let meta = scanner.metadata();
        assert_eq!(meta.name, "SSRF Scanner");
        assert!(meta
            .categories
            .contains(&VulnerabilityCategory::BrokenAccessControl));
    }

    #[test]
    fn extract_params_basic() {
        let params = SsrfScanner::extract_params("https://example.com/page?url=test&id=1");
        assert_eq!(params.len(), 2);
        assert!(params.contains(&"url".to_string()));
        assert!(params.contains(&"id".to_string()));
    }

    #[test]
    fn extract_params_none() {
        let params = SsrfScanner::extract_params("https://example.com/page");
        assert!(params.is_empty());
    }

    #[test]
    fn ssrf_payloads_count() {
        assert!(SSRF_PAYLOADS.len() >= 5);
    }

    #[test]
    fn ssrf_params_count() {
        assert!(SSRF_PARAMS.len() >= 10);
    }
}
