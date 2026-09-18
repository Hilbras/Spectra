use std::collections::HashMap;
use tracing::{debug, info};

use crate::rules::RuleDatabase;
use crate::{DetectionMethod, Fingerprint, Technology};

/// Input data for fingerprinting.
#[derive(Debug, Clone)]
pub struct FingerprintInput {
    /// HTTP response headers (lowercase keys).
    pub headers: HashMap<String, String>,
    /// HTML body content.
    pub html: String,
    /// Page URL.
    pub url: String,
    /// Cookies set by the response.
    pub cookies: Vec<String>,
}

/// Fingerprinting engine that applies detection rules.
pub struct FingerprintEngine {
    rule_db: RuleDatabase,
}

impl FingerprintEngine {
    /// Creates a new fingerprint engine with default rules.
    pub fn new() -> Self {
        Self {
            rule_db: RuleDatabase::new(),
        }
    }

    /// Creates a fingerprint engine with a custom rule database.
    pub fn with_rules(rule_db: RuleDatabase) -> Self {
        Self { rule_db }
    }

    /// Performs fingerprinting on the given input.
    pub fn fingerprint(&self, input: &FingerprintInput) -> Fingerprint {
        let mut fingerprint = Fingerprint::new(spectra_core::Id::new());

        // Check headers
        self.detect_from_headers(input, &mut fingerprint);

        // Check HTML content
        self.detect_from_html(input, &mut fingerprint);

        // Check cookies
        self.detect_from_cookies(input, &mut fingerprint);

        // Check JavaScript globals in HTML
        self.detect_from_javascript(input, &mut fingerprint);

        // Check URL patterns
        self.detect_from_url(input, &mut fingerprint);

        info!(
            url = %input.url,
            technologies = fingerprint.technologies.len(),
            "Fingerprint completed"
        );

        fingerprint
    }

    fn detect_from_headers(&self, input: &FingerprintInput, fp: &mut Fingerprint) {
        let rules = self.rule_db.rules_for_method(&DetectionMethod::HttpHeaders);

        for rule in rules {
            for pattern in &rule.patterns {
                if self.header_matches(input, pattern) {
                    let version = rule
                        .version_pattern
                        .as_ref()
                        .and_then(|vp| self.extract_version_from_headers(input, vp));

                    let header_text: String = input
                        .headers
                        .values()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(" ");

                    if !self.has_negative_match(&rule.negative_patterns, &header_text) {
                        fp.add_technology(Technology {
                            name: rule.technology.clone(),
                            category: rule.category.clone(),
                            version,
                            confidence: rule.confidence,
                            detection_method: DetectionMethod::HttpHeaders,
                        });
                        debug!(technology = %rule.technology, "Detected from headers");
                    }
                }
            }
        }
    }

    fn detect_from_html(&self, input: &FingerprintInput, fp: &mut Fingerprint) {
        let rules = self.rule_db.rules_for_method(&DetectionMethod::HtmlContent);

        for rule in rules {
            for pattern in &rule.patterns {
                if input.html.contains(pattern.as_str())
                    && !self.has_negative_match_html(&rule.negative_patterns, &input.html)
                {
                    fp.add_technology(Technology {
                        name: rule.technology.clone(),
                        category: rule.category.clone(),
                        version: None,
                        confidence: rule.confidence,
                        detection_method: DetectionMethod::HtmlContent,
                    });
                    debug!(technology = %rule.technology, "Detected from HTML");
                }
            }
        }
    }

    fn detect_from_cookies(&self, input: &FingerprintInput, fp: &mut Fingerprint) {
        let rules = self.rule_db.rules_for_method(&DetectionMethod::Cookies);

        for rule in rules {
            for pattern in &rule.patterns {
                if input.cookies.iter().any(|c| c.contains(pattern.as_str())) {
                    fp.add_technology(Technology {
                        name: rule.technology.clone(),
                        category: rule.category.clone(),
                        version: None,
                        confidence: rule.confidence,
                        detection_method: DetectionMethod::Cookies,
                    });
                    debug!(technology = %rule.technology, "Detected from cookies");
                }
            }
        }
    }

    fn detect_from_javascript(&self, input: &FingerprintInput, fp: &mut Fingerprint) {
        let rules = self.rule_db.rules_for_method(&DetectionMethod::JavaScript);

        for rule in rules {
            for pattern in &rule.patterns {
                if input.html.contains(pattern.as_str()) {
                    fp.add_technology(Technology {
                        name: rule.technology.clone(),
                        category: rule.category.clone(),
                        version: None,
                        confidence: rule.confidence,
                        detection_method: DetectionMethod::JavaScript,
                    });
                    debug!(technology = %rule.technology, "Detected from JavaScript");
                }
            }
        }
    }

    fn detect_from_url(&self, input: &FingerprintInput, fp: &mut Fingerprint) {
        let rules = self.rule_db.rules_for_method(&DetectionMethod::UrlPatterns);

        for rule in rules {
            for pattern in &rule.patterns {
                if input.url.contains(pattern.as_str()) {
                    fp.add_technology(Technology {
                        name: rule.technology.clone(),
                        category: rule.category.clone(),
                        version: None,
                        confidence: rule.confidence,
                        detection_method: DetectionMethod::UrlPatterns,
                    });
                    debug!(technology = %rule.technology, "Detected from URL");
                }
            }
        }
    }

    fn header_matches(&self, input: &FingerprintInput, pattern: &str) -> bool {
        if let Some((key, value)) = pattern.split_once(':') {
            let key = key.trim().to_lowercase();
            let value = value.trim();
            input
                .headers
                .get(&key)
                .map(|v| v.contains(value))
                .unwrap_or(false)
        } else {
            false
        }
    }

    fn extract_version_from_headers(
        &self,
        input: &FingerprintInput,
        pattern: &str,
    ) -> Option<String> {
        for header_value in input.headers.values() {
            if let Ok(re) = regex::Regex::new(pattern) {
                if let Some(caps) = re.captures(header_value) {
                    if let Some(version) = caps.get(1) {
                        return Some(version.as_str().to_string());
                    }
                }
            }
        }
        None
    }

    fn has_negative_match(&self, negative_patterns: &[String], text: &str) -> bool {
        negative_patterns.iter().any(|p| text.contains(p.as_str()))
    }

    fn has_negative_match_html(&self, negative_patterns: &[String], html: &str) -> bool {
        negative_patterns.iter().any(|p| html.contains(p.as_str()))
    }
}

impl Default for FingerprintEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_input(headers: Vec<(&str, &str)>, html: &str) -> FingerprintInput {
        FingerprintInput {
            headers: headers
                .into_iter()
                .map(|(k, v)| (k.to_lowercase(), v.to_string()))
                .collect(),
            html: html.to_string(),
            url: "https://example.com".to_string(),
            cookies: Vec::new(),
        }
    }

    #[test]
    fn detect_nginx_from_header() {
        let engine = FingerprintEngine::new();
        let input = make_input(vec![("server", "nginx/1.21.0")], "");
        let fp = engine.fingerprint(&input);
        assert!(fp.has_technology("Nginx"));
    }

    #[test]
    fn detect_apache_from_header() {
        let engine = FingerprintEngine::new();
        let input = make_input(vec![("server", "Apache/2.4.41")], "");
        let fp = engine.fingerprint(&input);
        assert!(fp.has_technology("Apache"));
    }

    #[test]
    fn detect_cloudflare_from_header() {
        let engine = FingerprintEngine::new();
        let input = make_input(vec![("server", "cloudflare"), ("cf-ray", "abc123")], "");
        let fp = engine.fingerprint(&input);
        assert!(fp.has_technology("Cloudflare"));
    }

    #[test]
    fn detect_wordpress_from_html() {
        let engine = FingerprintEngine::new();
        let input = make_input(
            vec![],
            r#"<html><link href="/wp-content/themes/style.css"></html>"#,
        );
        let fp = engine.fingerprint(&input);
        assert!(fp.has_technology("WordPress"));
    }

    #[test]
    fn detect_nextjs_from_html() {
        let engine = FingerprintEngine::new();
        let input = make_input(
            vec![],
            r#"<html><script id="__NEXT_DATA__"></script></html>"#,
        );
        let fp = engine.fingerprint(&input);
        assert!(fp.has_technology("Next.js"));
    }

    #[test]
    fn detect_laravel_from_cookies() {
        let engine = FingerprintEngine::new();
        let mut input = make_input(vec![], "");
        input.cookies = vec!["laravel_session=abc123".to_string()];
        let fp = engine.fingerprint(&input);
        assert!(fp.has_technology("Laravel"));
    }

    #[test]
    fn detect_google_analytics_from_js() {
        let engine = FingerprintEngine::new();
        let input = make_input(
            vec![],
            r#"<html><script src="https://www.google-analytics.com/analytics.js"></script></html>"#,
        );
        let fp = engine.fingerprint(&input);
        assert!(fp.has_technology("Google Analytics"));
    }

    #[test]
    fn detect_php_from_header() {
        let engine = FingerprintEngine::new();
        let input = make_input(vec![("x-powered-by", "PHP/8.1.0")], "");
        let fp = engine.fingerprint(&input);
        assert!(fp.has_technology("PHP"));
    }

    #[test]
    fn no_false_positives() {
        let engine = FingerprintEngine::new();
        let input = make_input(
            vec![("server", "CustomServer/1.0")],
            "<html><body>Hello</body></html>",
        );
        let fp = engine.fingerprint(&input);
        assert!(fp.technologies.is_empty());
    }
}
