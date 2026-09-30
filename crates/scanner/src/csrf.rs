use tracing::info;

use crate::{
    Finding, ScanResult, Scanner, ScannerConfig, ScannerError, ScannerMetadata, ScannerResult,
    Severity, VulnerabilityCategory,
};

/// CSRF anti-patterns: missing or weak protections.
const CSRF_PROTECTION_HEADERS: &[&str] = &[
    "x-csrf-token",
    "x-xsrf-token",
    "csrf-token",
    "x-csrf-header",
    "x-requested-with",
];

/// Sensitive state-changing methods.
const STATE_CHANGING_METHODS: &[&str] = &["POST", "PUT", "PATCH", "DELETE"];

/// CSRF Scanner - detects Cross-Site Request Forgery vulnerabilities.
pub struct CsrfScanner {
    config: ScannerConfig,
    http_client: reqwest::Client,
}

impl CsrfScanner {
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

    /// Checks if a response to a state-changing endpoint lacks CSRF protections.
    async fn check_endpoint(&self, url: &str, method: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let request = match method {
            "POST" => self.http_client.post(url),
            "PUT" => self.http_client.put(url),
            "PATCH" => self.http_client.patch(url),
            "DELETE" => self.http_client.delete(url),
            _ => return findings,
        };

        let request = request
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body("test=1");

        if let Ok(response) = request.send().await {
            // Capture ALL header info before consuming body
            let header_names: Vec<String> = response
                .headers()
                .keys()
                .map(|k| k.as_str().to_lowercase())
                .collect();

            let has_csrf_cookie = header_names
                .iter()
                .any(|h| h.contains("csrf") || h.contains("xsrf"));

            let mut has_samesite = false;
            let mut is_lax_only = false;
            for value in response.headers().get_all("set-cookie").iter() {
                if let Ok(v) = value.to_str() {
                    let vl = v.to_lowercase();
                    if vl.contains("samesite") {
                        has_samesite = true;
                        if vl.contains("samesite=lax") && !vl.contains("samesite=strict") {
                            is_lax_only = true;
                        }
                    }
                }
            }

            let has_custom_header = CSRF_PROTECTION_HEADERS
                .iter()
                .any(|h| response.headers().get(*h).is_some());

            let status_code = response.status().as_u16();

            // NOW consume the body
            let body = response.text().await.unwrap_or_default();
            let body_lower = body.to_lowercase();
            let has_csrf_in_body = body_lower.contains("csrf")
                || body_lower.contains("xsrf")
                || body_lower.contains("_token")
                || body_lower.contains("authenticity_token");

            // If no CSRF protection at all
            if !has_csrf_cookie && !has_csrf_in_body && !has_custom_header && !has_samesite {
                // Don't flag if it's a 4xx (likely auth required)
                if status_code == 200 || status_code == 403 {
                    let finding = Finding::new(
                        format!("Missing CSRF Protection on {}", method),
                        format!(
                            "State-changing endpoint '{}' ({}) lacks CSRF token protection. \
                             No anti-CSRF token found in request headers, cookies, or response body.",
                            url, method
                        ),
                        Severity::Medium,
                        VulnerabilityCategory::BrokenAccessControl,
                    )
                    .with_url(url)
                    .with_evidence(format!("Method: {}, Status: {}", method, status_code))
                    .with_remediation(
                        "Implement anti-CSRF tokens ( synchronizer token pattern ) or use SameSite cookie attribute",
                    )
                    .with_cvss(8.0);

                    findings.push(finding);
                }
            }

            // Check for weak SameSite (Lax may be insufficient for sensitive actions)
            if has_samesite
                && is_lax_only
                && !has_csrf_cookie
                && !has_csrf_in_body
                && !has_custom_header
            {
                let finding = Finding::new(
                    format!("Weak CSRF Protection (SameSite=Lax) on {}", method),
                    format!(
                        "Endpoint '{}' ({}) uses SameSite=Lax which may be insufficient for sensitive state changes.",
                        url, method
                    ),
                    Severity::Low,
                    VulnerabilityCategory::BrokenAccessControl,
                )
                .with_url(url)
                .with_remediation("Use SameSite=Strict or implement explicit anti-CSRF tokens");

                findings.push(finding);
            }
        }

        findings
    }
}

impl Default for CsrfScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Scanner for CsrfScanner {
    fn metadata(&self) -> ScannerMetadata {
        ScannerMetadata {
            name: "CSRF Scanner".to_string(),
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
        let mut result = ScanResult::new(target.id.clone(), "csrf");

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

        info!(url = %base_url, "Starting CSRF scan");

        // Test the base URL with common state-changing paths
        let common_paths = [
            "",
            "/login",
            "/register",
            "/signup",
            "/submit",
            "/form",
            "/api/v1/users",
            "/api/v1/settings",
            "/update",
            "/delete",
            "/admin",
            "/profile",
            "/account",
            "/change-password",
        ];

        for path in &common_paths {
            let url = format!("{}{}", base_url, path);
            for method in STATE_CHANGING_METHODS {
                let findings = self.check_endpoint(&url, method).await;
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
        let scanner = CsrfScanner::new();
        let meta = scanner.metadata();
        assert_eq!(meta.name, "CSRF Scanner");
        assert!(meta
            .categories
            .contains(&VulnerabilityCategory::BrokenAccessControl));
    }

    #[test]
    fn state_changing_methods() {
        assert!(STATE_CHANGING_METHODS.contains(&"POST"));
        assert!(STATE_CHANGING_METHODS.contains(&"PUT"));
        assert!(STATE_CHANGING_METHODS.contains(&"DELETE"));
    }

    #[test]
    fn protection_headers_count() {
        assert!(CSRF_PROTECTION_HEADERS.len() >= 4);
    }
}
