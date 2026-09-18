use tracing::{debug, info};

use crate::{
    Finding, ScanResult, Scanner, ScannerConfig, ScannerError, ScannerMetadata, ScannerResult,
    Severity, VulnerabilityCategory,
};

/// XSS payloads for testing reflected XSS.
const XSS_PAYLOADS: &[(&str, &str)] = &[
    ("<script>alert('XSS')</script>", "Basic script tag"),
    ("<img src=x onerror=alert(1)>", "Image onerror handler"),
    ("<svg onload=alert(1)>", "SVG onload handler"),
    ("javascript:alert(1)", "JavaScript URI"),
    ("<body onload=alert(1)>", "Body onload handler"),
    (
        "<input onfocus=alert(1) autofocus>",
        "Input onfocus handler",
    ),
    ("<marquee onstart=alert(1)>", "Marquee onstart handler"),
    (
        "<details open ontoggle=alert(1)>",
        "Details ontoggle handler",
    ),
    ("'-alert(1)-'", "Event handler in attribute"),
    (
        "<iframe src=\"javascript:alert(1)\">",
        "Iframe JavaScript URI",
    ),
];

/// XSS scanner for detecting reflected cross-site scripting.
pub struct XssScanner {
    config: ScannerConfig,
    http_client: reqwest::Client,
}

impl XssScanner {
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

    /// Tests a single parameter for XSS.
    async fn test_parameter(&self, url: &str, param_name: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (payload, description) in XSS_PAYLOADS {
            let test_url = format!("{}?{}={}", url, param_name, urlencoding::encode(payload));

            debug!(url = %test_url, payload = %payload, "Testing XSS");

            if let Ok(response) = self.http_client.get(&test_url).send().await {
                let status = response.status().as_u16();
                let body = response.text().await.unwrap_or_default();

                // Check if the payload is reflected unescaped
                if body.contains(payload) {
                    let finding = Finding::new(
                        format!("Reflected XSS in parameter '{}'", param_name),
                        format!(
                            "Parameter '{}' reflects user input without proper encoding. {}",
                            param_name, description
                        ),
                        Severity::Medium,
                        VulnerabilityCategory::Xss,
                    )
                    .with_url(&test_url)
                    .with_evidence(format!("Payload reflected in response: {}", payload))
                    .with_remediation(
                        "Encode all user input before rendering in HTML. Use Content-Security-Policy headers.",
                    )
                    .with_cvss(6.1);

                    findings.push(finding);
                    return findings;
                }

                // Check for partial reflection (may indicate filtering)
                if status == 200 {
                    let body_lower = body.to_lowercase();
                    let payload_lower = payload.to_lowercase();

                    // Check if part of the payload got through
                    if payload_lower.contains("<script>") && body_lower.contains("<script>") {
                        let finding = Finding::new(
                            format!("Potential XSS in '{}'", param_name),
                            format!(
                                "Script tag partially reflected in response for parameter '{}'",
                                param_name
                            ),
                            Severity::Low,
                            VulnerabilityCategory::Xss,
                        )
                        .with_url(&test_url)
                        .with_evidence("Partial script tag reflection detected".to_string())
                        .with_remediation("Apply strict output encoding and CSP headers")
                        .with_cvss(4.7);

                        findings.push(finding);
                        return findings;
                    }
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

    /// Checks security headers for XSS protection.
    fn check_security_headers(
        &self,
        url: &str,
        headers: &std::collections::HashMap<String, String>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        let has_csp = headers
            .iter()
            .any(|(k, _)| k.to_lowercase() == "content-security-policy");

        if !has_csp {
            findings.push(
                Finding::new(
                    "Missing Content-Security-Policy Header",
                    "No Content-Security-Policy header is set, which helps prevent XSS attacks",
                    Severity::Medium,
                    VulnerabilityCategory::SecurityMisconfiguration,
                )
                .with_url(url)
                .with_remediation("Implement a Content-Security-Policy header"),
            );
        }

        let has_xcto = headers
            .iter()
            .any(|(k, v)| k.to_lowercase() == "x-content-type-options" && v == "nosniff");

        if !has_xcto {
            findings.push(
                Finding::new(
                    "Missing X-Content-Type-Options Header",
                    "No X-Content-Type-Options header is set",
                    Severity::Low,
                    VulnerabilityCategory::SecurityMisconfiguration,
                )
                .with_url(url)
                .with_remediation("Set X-Content-Type-Options: nosniff"),
            );
        }

        findings
    }
}

impl Default for XssScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Scanner for XssScanner {
    fn metadata(&self) -> ScannerMetadata {
        ScannerMetadata {
            name: "XSS Scanner".to_string(),
            version: "0.1.0".to_string(),
            supported_targets: vec!["url".to_string(), "domain".to_string()],
            categories: vec![VulnerabilityCategory::Xss],
        }
    }

    async fn initialize(&mut self, config: ScannerConfig) -> ScannerResult<()> {
        self.config = config;
        Ok(())
    }

    async fn scan(&self, target: &spectra_target::Target) -> ScannerResult<ScanResult> {
        let mut result = ScanResult::new(target.id.clone(), "xss");

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

        info!(url = %base_url, "Starting XSS scan");

        // Check security headers first
        match self.http_client.get(&base_url).send().await {
            Ok(response) => {
                let headers: std::collections::HashMap<String, String> = response
                    .headers()
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                    .collect();

                let header_findings = self.check_security_headers(&base_url, &headers);
                for finding in header_findings {
                    result.add_finding(finding);
                }

                // Test parameters
                let params = Self::extract_params(&base_url);
                if !params.is_empty() {
                    for (param_name, _) in &params {
                        let findings = self.test_parameter(&base_url, param_name).await;
                        for finding in findings {
                            result.add_finding(finding);
                        }
                    }
                }
            }
            Err(e) => {
                result.errors.push(format!("Failed to fetch target: {}", e));
            }
        }

        // Test common parameter names
        let separator = if base_url.contains('?') { '&' } else { '?' };
        let common_params = vec![
            "q", "search", "query", "name", "page", "redirect", "url", "return", "next", "goto",
            "link", "ref", "comment", "input",
        ];

        for param in &common_params {
            let test_url = format!("{}{}{}=test", base_url, separator, param);
            let findings = self.test_parameter(&test_url, param).await;
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
        let scanner = XssScanner::new();
        let meta = scanner.metadata();
        assert_eq!(meta.name, "XSS Scanner");
        assert!(meta.categories.contains(&VulnerabilityCategory::Xss));
    }

    #[test]
    fn extract_params_basic() {
        let params = XssScanner::extract_params("https://example.com/search?q=test&page=1");
        assert_eq!(params.len(), 2);
        assert!(params.iter().any(|(k, _)| k == "q"));
        assert!(params.iter().any(|(k, _)| k == "page"));
    }

    #[test]
    fn security_headers_missing() {
        let scanner = XssScanner::new();
        let headers = std::collections::HashMap::new();
        let findings = scanner.check_security_headers("https://example.com", &headers);
        assert!(findings
            .iter()
            .any(|f| f.title.contains("Content-Security-Policy")));
    }

    #[test]
    fn security_headers_present() {
        let scanner = XssScanner::new();
        let mut headers = std::collections::HashMap::new();
        headers.insert(
            "content-security-policy".to_string(),
            "default-src 'self'".to_string(),
        );
        headers.insert("x-content-type-options".to_string(), "nosniff".to_string());
        let findings = scanner.check_security_headers("https://example.com", &headers);
        assert!(!findings
            .iter()
            .any(|f| f.title.contains("Content-Security-Policy")));
    }
}
