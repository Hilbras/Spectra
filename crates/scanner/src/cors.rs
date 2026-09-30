use tracing::{debug, info};

use crate::{
    Finding, ScanResult, Scanner, ScannerConfig, ScannerError, ScannerMetadata, ScannerResult,
    Severity, VulnerabilityCategory,
};

/// CORS Scanner - detects Cross-Origin Resource Sharing misconfigurations.
pub struct CorsScanner {
    config: ScannerConfig,
    http_client: reqwest::Client,
}

impl CorsScanner {
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

    /// Tests an endpoint for CORS misconfigurations.
    async fn test_endpoint(&self, url: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Test 1: Check if server reflects arbitrary Origin headers
        let test_origins = [
            ("https://evil.com", "Arbitrary external origin"),
            ("null", "Null origin"),
            ("https://subdomain.example.com", "Subdomain origin"),
            ("https://example.com.evil.com", "Domain prefix attack"),
            ("https://evil-example.com", "Domain suffix attack"),
        ];

        for (origin, desc) in &test_origins {
            debug!(url = %url, origin = %origin, "Testing CORS");

            let response = self
                .http_client
                .get(url)
                .header("Origin", *origin)
                .send()
                .await;

            if let Ok(resp) = response {
                if let Some(acao) = resp.headers().get("access-control-allow-origin") {
                    if let Ok(acao_str) = acao.to_str() {
                        // Check if origin is reflected back (wildcard or specific reflection)
                        if acao_str == *origin || acao_str == "*" {
                            let severity = if *origin == "null" || acao_str == "*" {
                                Severity::High
                            } else {
                                Severity::Medium
                            };

                            let finding = Finding::new(
                                format!("CORS Misconfiguration - {}", desc),
                                format!(
                                    "Endpoint '{}' reflects the Origin header '{}' in Access-Control-Allow-Origin. \
                                     This may allow cross-origin requests from malicious websites.",
                                    url, acao_str
                                ),
                                severity,
                                VulnerabilityCategory::SecurityMisconfiguration,
                            )
                            .with_url(url)
                            .with_evidence(format!("Origin: {}", origin))
                            .with_evidence(format!("ACAOrigin: {}", acao_str))
                            .with_remediation(
                                "Whitelist trusted origins. Never reflect arbitrary origins back.",
                            )
                            .with_cvss(7.5);

                            findings.push(finding);

                            // Also check if credentials are allowed (more severe)
                            if let Some(acac) =
                                resp.headers().get("access-control-allow-credentials")
                            {
                                if let Ok("true") = acac.to_str() {
                                    let finding = Finding::new(
                                        format!("CORS with Credentials - {}", desc),
                                        format!(
                                            "Endpoint '{}' reflects origin '{}' AND allows credentials. \
                                             This enables full account takeover from any origin.",
                                            url, acao_str
                                        ),
                                        Severity::Critical,
                                        VulnerabilityCategory::SecurityMisconfiguration,
                                    )
                                    .with_url(url)
                                    .with_evidence(format!("Origin: {}", origin))
                                    .with_evidence(format!("ACAOrigin: {}", acao_str))
                                    .with_evidence("Allow-Credentials: true".to_string())
                                    .with_remediation(
                                        "Never combine reflected origins with Access-Control-Allow-Credentials: true",
                                    )
                                    .with_cvss(9.8);

                                    findings.push(finding);
                                }
                            }

                            return findings;
                        }
                    }
                }
            }
        }

        // Test 2: Check if server sends overly permissive CORS headers without Origin
        let response = self.http_client.get(url).send().await;
        if let Ok(resp) = response {
            // Check for preflight that allows all methods
            if let Some(acam) = resp.headers().get("access-control-allow-methods") {
                if let Ok(methods_str) = acam.to_str() {
                    let methods_upper = methods_str.to_uppercase();
                    if methods_upper.contains("*")
                        || (methods_upper.contains("DELETE")
                            && methods_upper.contains("PUT")
                            && methods_upper.contains("PATCH"))
                    {
                        let finding = Finding::new(
                            "Overly Permissive CORS Methods",
                            format!(
                                "Endpoint '{}' allows all or many HTTP methods via CORS: {}",
                                url, methods_str
                            ),
                            Severity::Low,
                            VulnerabilityCategory::SecurityMisconfiguration,
                        )
                        .with_url(url)
                        .with_evidence(format!("Methods: {}", methods_str))
                        .with_remediation(
                            "Restrict Access-Control-Allow-Methods to only necessary methods",
                        )
                        .with_cvss(3.7);

                        findings.push(finding);
                    }
                }
            }

            // Check for overly permissive headers
            if let Some(ach) = resp.headers().get("access-control-allow-headers") {
                if let Ok(headers_str) = ach.to_str() {
                    if headers_str == "*" {
                        let finding = Finding::new(
                            "Overly Permissive CORS Headers",
                            format!("Endpoint '{}' allows any request header via CORS", url),
                            Severity::Low,
                            VulnerabilityCategory::SecurityMisconfiguration,
                        )
                        .with_url(url)
                        .with_evidence(format!("Headers: {}", headers_str))
                        .with_remediation(
                            "Restrict Access-Control-Allow-Headers to only necessary headers",
                        )
                        .with_cvss(3.7);

                        findings.push(finding);
                    }
                }
            }

            // Check for wildcard with credentials
            if let Some(acao) = resp.headers().get("access-control-allow-origin") {
                if let Ok("*") = acao.to_str() {
                    if let Some(acac) = resp.headers().get("access-control-allow-credentials") {
                        if let Ok("true") = acac.to_str() {
                            let finding = Finding::new(
                                "Wildcard CORS with Credentials",
                                format!(
                                    "Endpoint '{}' sends wildcard ACAOrigin with credentials. \
                                     This is explicitly forbidden by the CORS spec but some browsers may allow it.",
                                    url
                                ),
                                Severity::High,
                                VulnerabilityCategory::SecurityMisconfiguration,
                            )
                            .with_url(url)
                            .with_evidence("ACAOrigin: *".to_string())
                            .with_evidence("ACAC: true".to_string())
                            .with_remediation(
                                "Do not use wildcard ACAOrigin with Access-Control-Allow-Credentials: true",
                            )
                            .with_cvss(7.5);

                            findings.push(finding);
                        }
                    }
                }
            }
        }

        findings
    }
}

impl Default for CorsScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Scanner for CorsScanner {
    fn metadata(&self) -> ScannerMetadata {
        ScannerMetadata {
            name: "CORS Scanner".to_string(),
            version: "0.1.0".to_string(),
            supported_targets: vec!["url".to_string(), "domain".to_string()],
            categories: vec![VulnerabilityCategory::SecurityMisconfiguration],
        }
    }

    async fn initialize(&mut self, config: ScannerConfig) -> ScannerResult<()> {
        self.config = config;
        Ok(())
    }

    async fn scan(&self, target: &spectra_target::Target) -> ScannerResult<ScanResult> {
        let mut result = ScanResult::new(target.id.clone(), "cors");

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

        info!(url = %base_url, "Starting CORS scan");

        // Test the base URL
        let findings = self.test_endpoint(&base_url).await;
        for finding in findings {
            result.add_finding(finding);
        }

        // Test common API endpoints
        let api_paths = [
            "/api",
            "/api/v1",
            "/api/v1/user",
            "/api/v1/data",
            "/api/v1/admin",
            "/graphql",
            "/webhook",
        ];

        for path in &api_paths {
            let url = format!("{}{}", base_url, path);
            let findings = self.test_endpoint(&url).await;
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
        let scanner = CorsScanner::new();
        let meta = scanner.metadata();
        assert_eq!(meta.name, "CORS Scanner");
        assert!(meta
            .categories
            .contains(&VulnerabilityCategory::SecurityMisconfiguration));
    }
}
