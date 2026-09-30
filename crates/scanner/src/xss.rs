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
}

/// Unique benign marker sent in a control request.
///
/// A finding is only reportable if this marker comes back in the response *and*
/// the payload does. That proves the parameter is actually reflected by the
/// target, which rules out the case where both strings appear for unrelated
/// reasons (static page content, an error page, the site's own JavaScript).
const REFLECTION_SENTINEL: &str = "xSsSpEcTrA7qZ";

/// Where in the markup a payload landed, and whether that is executable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReflectionContext {
    /// Inside a tag but outside any quoted attribute value.
    /// Injecting here can add attributes and event handlers.
    TagNameOrUnquotedAttribute,
    /// Inside a quoted attribute value, and the payload does not escape the quote.
    QuotedAttribute,
    /// Inside a quoted attribute value and the payload breaks out of the quote.
    /// This is a real breakout: `foo="` + `onload=alert(1)` is executable.
    AttributeBreakout,
    /// In a text node between tags. This is HTML injection, not script execution.
    TextNode,
}

impl ReflectionContext {
    /// Whether script execution is actually achievable at this location.
    fn is_executable(self) -> bool {
        matches!(
            self,
            Self::TagNameOrUnquotedAttribute | Self::AttributeBreakout
        )
    }

    fn label(self) -> &'static str {
        match self {
            Self::TagNameOrUnquotedAttribute => "unquoted tag/attribute context",
            Self::QuotedAttribute => "quoted attribute value (no breakout)",
            Self::AttributeBreakout => "quoted attribute value with quote breakout",
            Self::TextNode => "HTML text node",
        }
    }
}

/// Classify where a reflected payload appears in the response body.
fn classify_reflection(body: &str, payload: &str) -> Option<ReflectionContext> {
    let idx = body.find(payload)?;

    let before = &body[..idx];

    // Find whether we are inside a tag: the nearest unclosed '<' comes after
    // the last '>'. If not, the payload sits in a text node.
    let last_open = before.rfind('<');
    let last_close = before.rfind('>');
    let inside_tag = match (last_open, last_close) {
        (Some(o), Some(c)) => o > c,
        (Some(_), None) => true,
        (None, _) => false,
    };

    if !inside_tag {
        return Some(ReflectionContext::TextNode);
    }

    // Inside a tag. Determine whether we are within a quoted attribute value by
    // looking for an unmatched quote immediately preceding the payload.
    let tail: String = before
        .chars()
        .rev()
        .take(2)
        .collect::<Vec<char>>()
        .into_iter()
        .rev()
        .collect();
    let trimmed = tail.trim_start();

    let in_dq = trimmed.ends_with('"') && count_unmatched(before, '"') % 2 == 1;
    let in_sq = trimmed.ends_with('\'') && count_unmatched(before, '\'') % 2 == 1;

    if in_dq || in_sq {
        let quote = if in_dq { '"' } else { '\'' };
        // A breakout is a payload that introduces the closing quote itself.
        if payload.contains(quote) {
            Some(ReflectionContext::AttributeBreakout)
        } else {
            Some(ReflectionContext::QuotedAttribute)
        }
    } else {
        Some(ReflectionContext::TagNameOrUnquotedAttribute)
    }
}

/// Count occurrences of `needle` that are not escaped by a preceding backslash.
fn count_unmatched(haystack: &str, needle: char) -> usize {
    let mut count = 0usize;
    let mut prev_escaped = false;
    for ch in haystack.chars() {
        if ch == needle && !prev_escaped {
            count += 1;
        }
        prev_escaped = ch == '\\' && !prev_escaped;
    }
    count
}

/// Build a URL with `name=value` appended, respecting any existing query string.
fn with_param(url: &str, name: &str, value: &str) -> String {
    let encoded = urlencoding::encode(value);
    if url.contains('?') {
        format!("{}&{}={}", url, name, encoded)
    } else {
        format!("{}?{}={}", url, name, encoded)
    }
}

/// Extract a short excerpt around `needle` for use as evidence.
fn excerpt_around(body: &str, needle: &str, radius: usize) -> String {
    match body.find(needle) {
        Some(idx) => {
            let start = body[..idx]
                .char_indices()
                .rev()
                .take(radius)
                .last()
                .map(|(i, _)| i)
                .unwrap_or(0);
            let end = body[idx..]
                .char_indices()
                .take(radius)
                .last()
                .map(|(i, c)| idx + i + c.len_utf8())
                .unwrap_or(body.len());
            body.get(start..end).unwrap_or(needle).to_string()
        }
        None => String::new(),
    }
}

impl XssScanner {
    /// Tests a single parameter for reflected XSS.
    ///
    /// Detection is differential: a control request carrying [`REFLECTION_SENTINEL`]
    /// establishes that the parameter is reflected at all, and only then are payloads
    /// sent. A finding additionally requires the payload to appear in a context where
    /// script execution is actually achievable.
    async fn test_parameter(&self, url: &str, param_name: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Control request. If the sentinel is not reflected, this parameter cannot
        // produce a reflected-XSS finding and there is nothing to detect.
        let control_url = with_param(url, param_name, REFLECTION_SENTINEL);
        let control_body = match self.http_client.get(&control_url).send().await {
            Ok(response) => response.text().await.unwrap_or_default(),
            Err(_) => return findings,
        };

        if !control_body.contains(REFLECTION_SENTINEL) {
            return findings;
        }

        for (payload, description) in XSS_PAYLOADS {
            let test_url = with_param(url, param_name, payload);

            debug!(url = %test_url, payload = %payload, "Testing XSS");

            if let Ok(response) = self.http_client.get(&test_url).send().await {
                let status = response.status().as_u16();
                let body = response.text().await.unwrap_or_default();

                if !body.contains(payload) {
                    continue;
                }

                // The payload was reflected. Only report it if it landed somewhere
                // that can actually execute script.
                let context =
                    classify_reflection(&body, payload).unwrap_or(ReflectionContext::TextNode);

                if !context.is_executable() {
                    debug!(
                        param = %param_name,
                        context = context.label(),
                        "Payload reflected but not in an executable context"
                    );
                    continue;
                }

                let severity = match context {
                    ReflectionContext::AttributeBreakout => Severity::High,
                    ReflectionContext::TagNameOrUnquotedAttribute => Severity::High,
                    _ => Severity::Medium,
                };
                let cvss = if context == ReflectionContext::AttributeBreakout {
                    8.2
                } else {
                    7.1
                };

                let excerpt = excerpt_around(&body, payload, 60);

                let finding = Finding::new(
                format!("Reflected XSS in parameter '{}'", param_name),
                format!(
                    "Parameter '{}' reflects user input unencoded in an executable context ({}). {} \
                     Verified by differential testing: a benign control value is reflected by this \
                     endpoint, and the payload is reflected verbatim without escaping.",
                    param_name,
                    context.label(),
                    description
                ),
                severity,
                VulnerabilityCategory::Xss,
            )
            .with_url(&test_url)
            .with_evidence(format!(
                "HTTP {} — payload reflected verbatim in {}",
                status, context.label()
            ))
            .with_evidence(format!("Response excerpt: {}", excerpt))
            .with_evidence(format!(
                "Control request confirmed the parameter is reflected: {}",
                control_url
            ))
            .with_remediation(
                "Encode all user input before rendering in HTML. Use Content-Security-Policy headers.",
            )
            .with_cvss(cvss);

                findings.push(finding);
                return findings;
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
        let common_params = vec![
            "q", "search", "query", "name", "page", "redirect", "url", "return", "next", "goto",
            "link", "ref", "comment", "input",
        ];

        for param in &common_params {
            // `test_parameter` appends the parameter itself, so pass the base URL
            // and let it build the query. Building it here as well produced a
            // duplicated `?`, so the payload never reached the named parameter.
            let findings = self.test_parameter(&base_url, param).await;
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

    // --- Regression tests for the fabricated-finding defect -----------------
    //
    // Previously the detector reported "Potential XSS" whenever the response
    // contained `<script>`, because the payload table was tested instead of the
    // target. Any page with its own JavaScript produced a finding. These tests
    // pin the corrected, context-sensitive behaviour.

    #[test]
    fn regression_page_with_own_script_tag_is_not_a_finding() {
        // A completely normal page. It contains <script> because the site has
        // its own JavaScript. The payload is not reflected at all.
        let body = "<html><head><script src=\"/app.js\"></script></head><body>hi</body></html>";
        let payload = "<script>alert('XSS')</script>";

        assert!(
            !body.contains(payload),
            "precondition: the payload must not be present"
        );
        // Because the payload is absent there is nothing to classify, so no
        // finding can be produced. This is the case the old code mis-handled by
        // matching the payload table against the body.
        assert!(classify_reflection(body, payload).is_none());
    }

    #[test]
    fn reflection_in_text_node_is_not_executable() {
        let payload = "<script>alert('XSS')</script>";
        let body = format!("<html><body><p>You searched: {}</p></body></html>", payload);

        let ctx = classify_reflection(&body, payload).expect("payload is present");
        assert_eq!(ctx, ReflectionContext::TextNode);
        assert!(
            !ctx.is_executable(),
            "reflection into a text node is HTML injection, not XSS"
        );
    }

    #[test]
    fn reflection_into_unquoted_attribute_is_executable() {
        let payload = "<script>alert('XSS')</script>";
        // The payload is injected inside a tag, outside any quoted value, so the
        // surrounding markup becomes attacker-controlled.
        let body = format!("<div class={}>text</div>", payload);

        let ctx = classify_reflection(&body, payload).expect("payload is present");
        assert_eq!(ctx, ReflectionContext::TagNameOrUnquotedAttribute);
        assert!(ctx.is_executable());
    }

    #[test]
    fn reflection_inside_quoted_attribute_without_breakout_is_not_executable() {
        let payload = "javascript:alert(1)";
        let body = format!("<a href=\"{}\">click</a>", payload);

        let ctx = classify_reflection(&body, payload).expect("payload is present");
        assert_eq!(ctx, ReflectionContext::QuotedAttribute);
        assert!(
            !ctx.is_executable(),
            "a javascript: URI inside a quoted href is not reflected XSS"
        );
    }

    #[test]
    fn quote_breakout_is_executable() {
        // Payload closes the attribute and opens an event handler.
        let payload = "\"><img src=x onerror=alert(1)>";
        let body = format!("<a href=\"{}\">click</a>", payload);

        let ctx = classify_reflection(&body, payload).expect("payload is present");
        assert_eq!(ctx, ReflectionContext::AttributeBreakout);
        assert!(ctx.is_executable());
    }

    #[test]
    fn with_param_preserves_existing_query_string() {
        // Regression: the old code produced `...?q=test?q=<payload>`, so the
        // payload never arrived as the value of the named parameter.
        let built = with_param("https://example.com/s?q=test", "q", "<script>");
        assert_eq!(built.matches('?').count(), 1);
        assert!(built.starts_with("https://example.com/s?q=test&q="));
    }

    #[test]
    fn with_param_adds_query_when_absent() {
        let built = with_param("https://example.com/s", "q", "hello");
        assert_eq!(built, "https://example.com/s?q=hello");
    }

    #[test]
    fn with_param_encodes_payload() {
        let built = with_param("https://example.com/", "q", "<script>alert(1)</script>");
        assert!(
            !built.contains("<script>"),
            "payload must be percent-encoded"
        );
        assert!(built.contains("%3Cscript%3E"));
    }

    #[test]
    fn excerpt_around_captures_context() {
        let body = "prefix-padding <img src=x onerror=alert(1)> suffix-padding";
        let payload = "<img";
        let excerpt = excerpt_around(body, payload, 10);
        assert!(excerpt.contains("img"));
        assert!(excerpt.len() < body.len());
    }

    #[test]
    fn excerpt_around_handles_missing_needle() {
        assert_eq!(excerpt_around("abc", "zzz", 5), "");
    }

    #[test]
    fn count_unmatched_ignores_escaped_quotes() {
        // Plain quotes are all counted.
        assert_eq!(count_unmatched("a\"b\"", '"'), 2);
        // A quote preceded by a backslash is escaped and must not be counted.
        assert_eq!(count_unmatched("a\\\"b", '"'), 0);
        // Mixed: the escaped one is skipped, the trailing one is counted.
        assert_eq!(count_unmatched("a\\\"b\"", '"'), 1);
    }

    #[test]
    fn sentinel_is_not_a_plausible_page_substring() {
        // The sentinel must be distinctive enough that its presence in a
        // response is meaningful evidence of reflection.
        assert!(REFLECTION_SENTINEL.len() >= 12);
        assert!(
            REFLECTION_SENTINEL.chars().any(|c| c.is_uppercase())
                && REFLECTION_SENTINEL.chars().any(|c| c.is_lowercase())
        );
    }
}
