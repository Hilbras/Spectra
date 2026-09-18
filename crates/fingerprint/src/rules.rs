use serde::{Deserialize, Serialize};

use crate::{DetectionMethod, TechnologyCategory};

/// A single detection rule for a technology.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRule {
    /// Technology this rule detects.
    pub technology: String,
    /// Technology category.
    pub category: TechnologyCategory,
    /// Detection method.
    pub method: DetectionMethod,
    /// Patterns to match (headers, HTML content, JS globals, cookies, URLs).
    pub patterns: Vec<String>,
    /// Confidence boost when this rule matches (0.0 - 1.0).
    pub confidence: f64,
    /// Version extraction regex (optional).
    pub version_pattern: Option<String>,
    /// Negative patterns that indicate the technology is NOT present.
    pub negative_patterns: Vec<String>,
}

impl DetectionRule {
    pub fn new(
        technology: impl Into<String>,
        category: TechnologyCategory,
        method: DetectionMethod,
        patterns: Vec<String>,
        confidence: f64,
    ) -> Self {
        Self {
            technology: technology.into(),
            category,
            method,
            patterns,
            confidence,
            version_pattern: None,
            negative_patterns: Vec::new(),
        }
    }

    pub fn with_version_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.version_pattern = Some(pattern.into());
        self
    }

    pub fn with_negative_patterns(mut self, patterns: Vec<String>) -> Self {
        self.negative_patterns = patterns;
        self
    }
}

/// Pre-built detection rule database.
pub struct RuleDatabase {
    rules: Vec<DetectionRule>,
}

impl RuleDatabase {
    /// Creates a new rule database with built-in rules.
    pub fn new() -> Self {
        let mut rules = Vec::new();
        Self::add_web_server_rules(&mut rules);
        Self::add_framework_rules(&mut rules);
        Self::add_cms_rules(&mut rules);
        Self::add_analytics_rules(&mut rules);
        Self::add_cdn_rules(&mut rules);
        Self::add_waf_rules(&mut rules);
        Self::add_programming_language_rules(&mut rules);
        Self::add_database_rules(&mut rules);
        Self::add_cache_rules(&mut rules);

        Self { rules }
    }

    /// Returns all detection rules.
    pub fn rules(&self) -> &[DetectionRule] {
        &self.rules
    }

    /// Returns rules for a specific detection method.
    pub fn rules_for_method(&self, method: &DetectionMethod) -> Vec<&DetectionRule> {
        self.rules.iter().filter(|r| r.method == *method).collect()
    }

    fn add_web_server_rules(rules: &mut Vec<DetectionRule>) {
        rules.push(DetectionRule::new(
            "Apache",
            TechnologyCategory::WebServer,
            DetectionMethod::HttpHeaders,
            vec!["Server: Apache".to_string()],
            0.9,
        ));
        rules.push(DetectionRule::new(
            "Nginx",
            TechnologyCategory::WebServer,
            DetectionMethod::HttpHeaders,
            vec!["Server: nginx".to_string()],
            0.9,
        ));
        rules.push(
            DetectionRule::new(
                "IIS",
                TechnologyCategory::WebServer,
                DetectionMethod::HttpHeaders,
                vec!["Server: Microsoft-IIS".to_string()],
                0.9,
            )
            .with_version_pattern(r"Microsoft-IIS/(\d+\.\d+)"),
        );
        rules.push(DetectionRule::new(
            "LiteSpeed",
            TechnologyCategory::WebServer,
            DetectionMethod::HttpHeaders,
            vec!["Server: LiteSpeed".to_string()],
            0.9,
        ));
        rules.push(DetectionRule::new(
            "Caddy",
            TechnologyCategory::WebServer,
            DetectionMethod::HttpHeaders,
            vec!["Server: Caddy".to_string()],
            0.9,
        ));
        rules.push(DetectionRule::new(
            "OpenResty",
            TechnologyCategory::WebServer,
            DetectionMethod::HttpHeaders,
            vec!["Server: openresty".to_string()],
            0.9,
        ));
        rules.push(DetectionRule::new(
            "Apache Tomcat",
            TechnologyCategory::WebServer,
            DetectionMethod::HttpHeaders,
            vec!["Server: Apache-Coyote".to_string()],
            0.9,
        ));
    }

    fn add_framework_rules(rules: &mut Vec<DetectionRule>) {
        // PHP frameworks
        rules.push(DetectionRule::new(
            "Laravel",
            TechnologyCategory::Framework,
            DetectionMethod::Cookies,
            vec!["laravel_session".to_string()],
            0.95,
        ));
        rules.push(DetectionRule::new(
            "Symfony",
            TechnologyCategory::Framework,
            DetectionMethod::Cookies,
            vec!["symfony".to_string(), "sf_session".to_string()],
            0.9,
        ));

        // Python frameworks
        rules.push(
            DetectionRule::new(
                "Django",
                TechnologyCategory::Framework,
                DetectionMethod::Cookies,
                vec!["csrftoken".to_string(), "sessionid".to_string()],
                0.85,
            )
            .with_negative_patterns(vec!["django".to_string()]),
        );
        rules.push(DetectionRule::new(
            "Flask",
            TechnologyCategory::Framework,
            DetectionMethod::Cookies,
            vec!["session=ey".to_string()],
            0.7,
        ));

        // JavaScript frameworks
        rules.push(DetectionRule::new(
            "Express.js",
            TechnologyCategory::Framework,
            DetectionMethod::Cookies,
            vec!["connect.sid".to_string()],
            0.9,
        ));
        rules.push(DetectionRule::new(
            "Next.js",
            TechnologyCategory::Framework,
            DetectionMethod::HtmlContent,
            vec![
                "__next".to_string(),
                "_next/static".to_string(),
                "__NEXT_DATA__".to_string(),
            ],
            0.95,
        ));
        rules.push(DetectionRule::new(
            "Nuxt.js",
            TechnologyCategory::Framework,
            DetectionMethod::HtmlContent,
            vec![
                "__nuxt".to_string(),
                "_nuxt/".to_string(),
                "__NUXT__".to_string(),
            ],
            0.95,
        ));
        rules.push(DetectionRule::new(
            "React",
            TechnologyCategory::Framework,
            DetectionMethod::HtmlContent,
            vec![
                "__react".to_string(),
                "_reactRoot".to_string(),
                "data-reactroot".to_string(),
            ],
            0.8,
        ));
        rules.push(DetectionRule::new(
            "Vue.js",
            TechnologyCategory::Framework,
            DetectionMethod::HtmlContent,
            vec![
                "__vue__".to_string(),
                "data-v-".to_string(),
                "Vue.js".to_string(),
            ],
            0.85,
        ));
        rules.push(DetectionRule::new(
            "Angular",
            TechnologyCategory::Framework,
            DetectionMethod::HtmlContent,
            vec![
                "ng-version".to_string(),
                "ng-app".to_string(),
                "angular.js".to_string(),
            ],
            0.85,
        ));
        rules.push(DetectionRule::new(
            "jQuery",
            TechnologyCategory::Framework,
            DetectionMethod::JavaScript,
            vec!["jQuery".to_string(), "jquery.min.js".to_string()],
            0.8,
        ));

        // Ruby frameworks
        rules.push(DetectionRule::new(
            "Ruby on Rails",
            TechnologyCategory::Framework,
            DetectionMethod::Cookies,
            vec!["_session_id".to_string(), "_csrf_token".to_string()],
            0.9,
        ));

        // Java frameworks
        rules.push(
            DetectionRule::new(
                "Spring",
                TechnologyCategory::Framework,
                DetectionMethod::Cookies,
                vec!["JSESSIONID".to_string()],
                0.75,
            )
            .with_negative_patterns(vec!["Apache".to_string(), "Tomcat".to_string()]),
        );
    }

    fn add_cms_rules(rules: &mut Vec<DetectionRule>) {
        rules.push(DetectionRule::new(
            "WordPress",
            TechnologyCategory::Cms,
            DetectionMethod::HtmlContent,
            vec![
                "wp-content".to_string(),
                "wp-includes".to_string(),
                "wp-json".to_string(),
                "wordpress".to_string(),
            ],
            0.95,
        ));
        rules.push(
            DetectionRule::new(
                "Drupal",
                TechnologyCategory::Cms,
                DetectionMethod::HtmlContent,
                vec![
                    "Drupal.settings".to_string(),
                    "sites/default/files".to_string(),
                    "drupal.js".to_string(),
                ],
                0.9,
            )
            .with_version_pattern(r"Drupal (\d+\.\d+)"),
        );
        rules.push(DetectionRule::new(
            "Joomla",
            TechnologyCategory::Cms,
            DetectionMethod::HtmlContent,
            vec![
                "/media/jui/".to_string(),
                "Joomla!".to_string(),
                "com_content".to_string(),
            ],
            0.9,
        ));
        rules.push(
            DetectionRule::new(
                "Shopify",
                TechnologyCategory::Cms,
                DetectionMethod::HtmlContent,
                vec![
                    "cdn.shopify.com".to_string(),
                    "Shopify.theme".to_string(),
                    "shopify".to_string(),
                ],
                0.95,
            )
            .with_negative_patterns(vec!["shopify.dev".to_string()]),
        );
        rules.push(DetectionRule::new(
            "Wix",
            TechnologyCategory::Cms,
            DetectionMethod::HtmlContent,
            vec!["wix.com".to_string(), "wixstatic.com".to_string()],
            0.9,
        ));
        rules.push(DetectionRule::new(
            "Squarespace",
            TechnologyCategory::Cms,
            DetectionMethod::HtmlContent,
            vec!["squarespace.com".to_string(), "sqsp".to_string()],
            0.9,
        ));
        rules.push(DetectionRule::new(
            "Ghost",
            TechnologyCategory::Cms,
            DetectionMethod::HtmlContent,
            vec!["ghost/".to_string(), "ghost.io".to_string()],
            0.85,
        ));
        rules.push(DetectionRule::new(
            "MediaWiki",
            TechnologyCategory::Cms,
            DetectionMethod::HtmlContent,
            vec!["mediawiki".to_string(), "mw-content-text".to_string()],
            0.9,
        ));
    }

    fn add_analytics_rules(rules: &mut Vec<DetectionRule>) {
        rules.push(DetectionRule::new(
            "Google Analytics",
            TechnologyCategory::Analytics,
            DetectionMethod::JavaScript,
            vec![
                "google-analytics.com".to_string(),
                "gtag(".to_string(),
                "ga(".to_string(),
                "GoogleAnalyticsObject".to_string(),
            ],
            0.9,
        ));
        rules.push(DetectionRule::new(
            "Google Tag Manager",
            TechnologyCategory::Analytics,
            DetectionMethod::JavaScript,
            vec!["googletagmanager.com".to_string(), "gtm.js".to_string()],
            0.9,
        ));
        rules.push(DetectionRule::new(
            "Hotjar",
            TechnologyCategory::Analytics,
            DetectionMethod::JavaScript,
            vec!["hotjar.com".to_string(), "hj(".to_string()],
            0.9,
        ));
        rules.push(DetectionRule::new(
            "Mixpanel",
            TechnologyCategory::Analytics,
            DetectionMethod::JavaScript,
            vec!["mixpanel.com".to_string(), "mixpanel.track".to_string()],
            0.9,
        ));
        rules.push(DetectionRule::new(
            "Segment",
            TechnologyCategory::Analytics,
            DetectionMethod::JavaScript,
            vec!["segment.com".to_string(), "analytics.js".to_string()],
            0.8,
        ));
        rules.push(DetectionRule::new(
            "Plausible",
            TechnologyCategory::Analytics,
            DetectionMethod::JavaScript,
            vec!["plausible.io".to_string(), "plausible.js".to_string()],
            0.9,
        ));
    }

    fn add_cdn_rules(rules: &mut Vec<DetectionRule>) {
        rules.push(DetectionRule::new(
            "Cloudflare",
            TechnologyCategory::Cdn,
            DetectionMethod::HttpHeaders,
            vec!["Server: cloudflare".to_string(), "cf-ray".to_string()],
            0.95,
        ));
        rules.push(DetectionRule::new(
            "Akamai",
            TechnologyCategory::Cdn,
            DetectionMethod::HttpHeaders,
            vec!["X-Akamai".to_string(), "AkamaiGHost".to_string()],
            0.9,
        ));
        rules.push(DetectionRule::new(
            "Fastly",
            TechnologyCategory::Cdn,
            DetectionMethod::HttpHeaders,
            vec!["Fastly-Debug".to_string(), "x-fastly".to_string()],
            0.9,
        ));
        rules.push(DetectionRule::new(
            "AWS CloudFront",
            TechnologyCategory::Cdn,
            DetectionMethod::HttpHeaders,
            vec!["CloudFront".to_string(), "X-Amz-Cf-Pop".to_string()],
            0.95,
        ));
        rules.push(DetectionRule::new(
            "KeyCDN",
            TechnologyCategory::Cdn,
            DetectionMethod::HttpHeaders,
            vec!["Server: keycdn-engine".to_string()],
            0.9,
        ));
        rules.push(DetectionRule::new(
            "BunnyCDN",
            TechnologyCategory::Cdn,
            DetectionMethod::HttpHeaders,
            vec!["Server: BunnyCDN".to_string()],
            0.9,
        ));
    }

    fn add_waf_rules(rules: &mut Vec<DetectionRule>) {
        rules.push(DetectionRule::new(
            "Cloudflare WAF",
            TechnologyCategory::Waf,
            DetectionMethod::HttpHeaders,
            vec!["cf-ray".to_string(), "cf-cache-status".to_string()],
            0.85,
        ));
        rules.push(DetectionRule::new(
            "AWS WAF",
            TechnologyCategory::Waf,
            DetectionMethod::HttpHeaders,
            vec!["X-Amzn-Trace-Id".to_string(), "x-amzn-waf".to_string()],
            0.8,
        ));
        rules.push(DetectionRule::new(
            "Sucuri",
            TechnologyCategory::Waf,
            DetectionMethod::HttpHeaders,
            vec!["X-Sucuri-ID".to_string(), "Server: Sucuri".to_string()],
            0.9,
        ));
        rules.push(DetectionRule::new(
            "Imperva",
            TechnologyCategory::Waf,
            DetectionMethod::HttpHeaders,
            vec!["X-CDN: Imperva".to_string(), "incap_ses".to_string()],
            0.9,
        ));
        rules.push(DetectionRule::new(
            "ModSecurity",
            TechnologyCategory::Waf,
            DetectionMethod::HttpHeaders,
            vec!["Server: Mod_Security".to_string(), "NOYB".to_string()],
            0.85,
        ));
    }

    fn add_programming_language_rules(rules: &mut Vec<DetectionRule>) {
        rules.push(
            DetectionRule::new(
                "PHP",
                TechnologyCategory::ProgrammingLanguage,
                DetectionMethod::HttpHeaders,
                vec!["X-Powered-By: PHP".to_string()],
                0.95,
            )
            .with_version_pattern(r"PHP/(\d+\.\d+\.\d+)"),
        );
        rules.push(DetectionRule::new(
            "PHP",
            TechnologyCategory::ProgrammingLanguage,
            DetectionMethod::UrlPatterns,
            vec![".php".to_string()],
            0.7,
        ));
        rules.push(
            DetectionRule::new(
                "ASP.NET",
                TechnologyCategory::ProgrammingLanguage,
                DetectionMethod::HttpHeaders,
                vec![
                    "X-Powered-By: ASP.NET".to_string(),
                    "X-AspNet-Version".to_string(),
                ],
                0.95,
            )
            .with_version_pattern(r"X-AspNet-Version: (\d+[\.\d]*)"),
        );
        rules.push(DetectionRule::new(
            "Python",
            TechnologyCategory::ProgrammingLanguage,
            DetectionMethod::HttpHeaders,
            vec![
                "Server: Python".to_string(),
                "X-Powered-By: Python".to_string(),
            ],
            0.9,
        ));
        rules.push(DetectionRule::new(
            "Ruby",
            TechnologyCategory::ProgrammingLanguage,
            DetectionMethod::HttpHeaders,
            vec![
                "Server: Phusion Passenger".to_string(),
                "X-Powered-By: Phusion Passenger".to_string(),
            ],
            0.9,
        ));
        rules.push(DetectionRule::new(
            "Java",
            TechnologyCategory::ProgrammingLanguage,
            DetectionMethod::HttpHeaders,
            vec![
                "Server: Apache-Coyote".to_string(),
                "X-Powered-By: Servlet".to_string(),
            ],
            0.85,
        ));
    }

    fn add_database_rules(rules: &mut Vec<DetectionRule>) {
        rules.push(DetectionRule::new(
            "MySQL",
            TechnologyCategory::Database,
            DetectionMethod::ErrorMessages,
            vec!["mysql".to_string(), "MySQLSyntaxErrorException".to_string()],
            0.8,
        ));
        rules.push(DetectionRule::new(
            "PostgreSQL",
            TechnologyCategory::Database,
            DetectionMethod::ErrorMessages,
            vec!["postgresql".to_string(), "pg_query".to_string()],
            0.8,
        ));
        rules.push(DetectionRule::new(
            "SQLite",
            TechnologyCategory::Database,
            DetectionMethod::ErrorMessages,
            vec!["sqlite".to_string(), "SQLite3::".to_string()],
            0.8,
        ));
        rules.push(DetectionRule::new(
            "MongoDB",
            TechnologyCategory::Database,
            DetectionMethod::ErrorMessages,
            vec!["MongoError".to_string(), "mongo".to_string()],
            0.7,
        ));
    }

    fn add_cache_rules(rules: &mut Vec<DetectionRule>) {
        rules.push(DetectionRule::new(
            "Redis",
            TechnologyCategory::Cache,
            DetectionMethod::ErrorMessages,
            vec!["redis".to_string(), "RedisError".to_string()],
            0.7,
        ));
        rules.push(DetectionRule::new(
            "Memcached",
            TechnologyCategory::Cache,
            DetectionMethod::ErrorMessages,
            vec!["memcached".to_string()],
            0.7,
        ));
        rules.push(DetectionRule::new(
            "Varnish",
            TechnologyCategory::Cache,
            DetectionMethod::HttpHeaders,
            vec!["X-Varnish".to_string(), "Via: varnish".to_string()],
            0.9,
        ));
    }
}

impl Default for RuleDatabase {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_database_has_rules() {
        let db = RuleDatabase::new();
        assert!(!db.rules().is_empty());
    }

    #[test]
    fn rule_database_has_web_server_rules() {
        let db = RuleDatabase::new();
        let rules = db.rules_for_method(&DetectionMethod::HttpHeaders);
        assert!(rules.iter().any(|r| r.technology == "Apache"));
        assert!(rules.iter().any(|r| r.technology == "Nginx"));
        assert!(rules.iter().any(|r| r.technology == "IIS"));
    }

    #[test]
    fn rule_database_has_framework_rules() {
        let db = RuleDatabase::new();
        assert!(db.rules().iter().any(|r| r.technology == "Laravel"));
        assert!(db.rules().iter().any(|r| r.technology == "Django"));
        assert!(db.rules().iter().any(|r| r.technology == "Express.js"));
        assert!(db.rules().iter().any(|r| r.technology == "Next.js"));
    }

    #[test]
    fn rule_database_has_cms_rules() {
        let db = RuleDatabase::new();
        assert!(db.rules().iter().any(|r| r.technology == "WordPress"));
        assert!(db.rules().iter().any(|r| r.technology == "Drupal"));
        assert!(db.rules().iter().any(|r| r.technology == "Shopify"));
    }

    #[test]
    fn rule_confidence_in_range() {
        let db = RuleDatabase::new();
        for rule in db.rules() {
            assert!(
                (0.0..=1.0).contains(&rule.confidence),
                "Rule {} has confidence {}",
                rule.technology,
                rule.confidence
            );
        }
    }

    #[test]
    fn detection_rule_builder() {
        let rule = DetectionRule::new(
            "TestTech",
            TechnologyCategory::Other("test".to_string()),
            DetectionMethod::HttpHeaders,
            vec!["X-Test".to_string()],
            0.8,
        )
        .with_version_pattern(r"TestTech/(\d+\.\d+)")
        .with_negative_patterns(vec!["not-test".to_string()]);

        assert_eq!(rule.technology, "TestTech");
        assert_eq!(rule.confidence, 0.8);
        assert!(rule.version_pattern.is_some());
        assert_eq!(rule.negative_patterns.len(), 1);
    }
}
