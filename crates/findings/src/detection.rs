use crate::observation::{Observation, ObservationType};
use crate::{DetectionSource, FindingType, ManagedFinding};
use serde::{Deserialize, Serialize};
use spectra_scanner::{Finding, Severity, VulnerabilityCategory};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DetectionError {
    #[error("Detection failed: {0}")]
    Failed(String),
    #[error("Invalid pattern: {0}")]
    InvalidPattern(String),
    #[error("Rule not found: {0}")]
    RuleNotFound(String),
}

pub type DetectionResult<T> = Result<T, DetectionError>;

/// A detection rule that matches observations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub observation_type: ObservationType,
    pub matcher: RuleMatcher,
    pub finding_title: String,
    pub finding_description: String,
    pub severity: Severity,
    pub category: VulnerabilityCategory,
    pub finding_type: FindingType,
    pub confidence_boost: f64,
    pub enabled: bool,
}

/// How a detection rule matches observation data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleMatcher {
    /// Match if a JSON field contains a substring
    FieldContains {
        field: String,
        value: String,
        case_sensitive: bool,
    },
    /// Match if a JSON field equals a value
    FieldEquals { field: String, value: String },
    /// Match if a JSON field exists and is not null
    FieldExists { field: String },
    /// Match if a JSON field matches a regex
    FieldRegex { field: String, pattern: String },
    /// Match if a status code is in a range
    StatusCodeRange { min: u16, max: u16 },
    /// Match all observations of the configured type
    Always,
    /// Composite AND matcher
    All(Vec<RuleMatcher>),
    /// Composite OR matcher
    Any(Vec<RuleMatcher>),
}

impl RuleMatcher {
    pub fn matches(&self, observation: &Observation) -> bool {
        match self {
            Self::FieldContains {
                field,
                value,
                case_sensitive,
            } => {
                if let Some(field_val) = get_json_field(&observation.data, field) {
                    if *case_sensitive {
                        field_val.contains(value)
                    } else {
                        field_val.to_lowercase().contains(&value.to_lowercase())
                    }
                } else {
                    false
                }
            }
            Self::FieldEquals { field, value } => {
                if let Some(field_val) = get_json_field(&observation.data, field) {
                    field_val == value.as_str()
                } else {
                    false
                }
            }
            Self::FieldExists { field } => has_json_field(&observation.data, field),
            Self::FieldRegex { field, pattern } => {
                if let Some(field_val) = get_json_field(&observation.data, field) {
                    regex::Regex::new(pattern)
                        .map(|re| re.is_match(field_val))
                        .unwrap_or(false)
                } else {
                    false
                }
            }
            Self::StatusCodeRange { min, max } => {
                if let Some(status) = observation.data.get("status_code").and_then(|v| v.as_u64()) {
                    status >= *min as u64 && status <= *max as u64
                } else {
                    false
                }
            }
            Self::Always => true,
            Self::All(matchers) => matchers.iter().all(|m| m.matches(observation)),
            Self::Any(matchers) => matchers.iter().any(|m| m.matches(observation)),
        }
    }
}

fn get_json_field<'a>(data: &'a serde_json::Value, field: &str) -> Option<&'a str> {
    let parts: Vec<&str> = field.split('.').collect();
    let mut current = data;
    for part in parts {
        current = current.get(part)?;
    }
    current.as_str()
}

fn has_json_field(data: &serde_json::Value, field: &str) -> bool {
    let parts: Vec<&str> = field.split('.').collect();
    let mut current = data;
    for part in parts {
        match current.get(part) {
            Some(v) => current = v,
            None => return false,
        }
    }
    true
}

/// A detection engine that applies rules to observations.
pub struct DetectionEngine {
    rules: Vec<DetectionRule>,
}

impl Default for DetectionEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl DetectionEngine {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn with_rule(mut self, rule: DetectionRule) -> Self {
        self.rules.push(rule);
        self
    }

    pub fn with_rules(mut self, rules: Vec<DetectionRule>) -> Self {
        self.rules.extend(rules);
        self
    }

    /// Returns the number of loaded rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Runs detection rules against observations, returning findings.
    pub fn detect(&self, observations: &[Observation]) -> DetectionResult<Vec<ManagedFinding>> {
        let mut findings = Vec::new();

        for observation in observations {
            for rule in &self.rules {
                if !rule.enabled {
                    continue;
                }
                if observation.observation_type != rule.observation_type {
                    continue;
                }
                if rule.matcher.matches(observation) {
                    let _confidence = (observation.confidence + rule.confidence_boost).min(1.0);

                    let finding = Finding::new(
                        &rule.finding_title,
                        &rule.finding_description,
                        rule.severity.clone(),
                        rule.category.clone(),
                    );

                    let source = match &rule.id[..] {
                        id if id.starts_with("sqli") => DetectionSource::SqlInjectionScanner,
                        id if id.starts_with("xss") => DetectionSource::XssScanner,
                        id if id.starts_with("dir") => DetectionSource::DirSearchScanner,
                        id if id.starts_with("finger") => DetectionSource::Fingerprinter,
                        id if id.starts_with("crawl") => DetectionSource::Crawler,
                        _ => DetectionSource::Other(rule.name.clone()),
                    };

                    let mut managed = ManagedFinding::new(finding, source);
                    managed.correlation_id = Some(rule.id.clone());
                    managed.tags.push(rule.name.clone());

                    findings.push(managed);
                }
            }
        }

        Ok(findings)
    }

    /// Lists all loaded rules.
    pub fn list_rules(&self) -> &[DetectionRule] {
        &self.rules
    }

    /// Disables a rule by id.
    pub fn disable_rule(&mut self, rule_id: &str) -> DetectionResult<()> {
        self.rules
            .iter_mut()
            .find(|r| r.id == rule_id)
            .map(|r| r.enabled = false)
            .ok_or_else(|| DetectionError::RuleNotFound(rule_id.to_string()))
    }

    /// Enables a rule by id.
    pub fn enable_rule(&mut self, rule_id: &str) -> DetectionResult<()> {
        self.rules
            .iter_mut()
            .find(|r| r.id == rule_id)
            .map(|r| r.enabled = true)
            .ok_or_else(|| DetectionError::RuleNotFound(rule_id.to_string()))
    }
}

/// Built-in detection rules for common vulnerability patterns.
pub fn default_rules() -> Vec<DetectionRule> {
    vec![
        DetectionRule {
            id: "sqli-error".into(),
            name: "SQL Injection (Error-based)".into(),
            description: "Detects SQL error messages in responses".into(),
            observation_type: ObservationType::ScannerOutput,
            matcher: RuleMatcher::Any(vec![
                RuleMatcher::FieldContains {
                    field: "response_body".into(),
                    value: "SQL syntax".into(),
                    case_sensitive: false,
                },
                RuleMatcher::FieldContains {
                    field: "response_body".into(),
                    value: "mysql_fetch".into(),
                    case_sensitive: false,
                },
                RuleMatcher::FieldContains {
                    field: "response_body".into(),
                    value: "ORA-".into(),
                    case_sensitive: false,
                },
                RuleMatcher::FieldContains {
                    field: "response_body".into(),
                    value: "PostgreSQL".into(),
                    case_sensitive: false,
                },
                RuleMatcher::FieldContains {
                    field: "response_body".into(),
                    value: "SQLite".into(),
                    case_sensitive: false,
                },
            ]),
            finding_title: "SQL Injection Detected (Error-based)".into(),
            finding_description: "The application is vulnerable to SQL injection as evidenced by SQL error messages in the response.".into(),
            severity: Severity::High,
            category: VulnerabilityCategory::Injection,
            finding_type: FindingType::Vulnerability,
            confidence_boost: 0.3,
            enabled: true,
        },
        DetectionRule {
            id: "sqli-boolean".into(),
            name: "SQL Injection (Boolean-based)".into(),
            description: "Detects boolean-based blind SQL injection".into(),
            observation_type: ObservationType::ScannerOutput,
            matcher: RuleMatcher::FieldContains {
                field: "technique".into(),
                value: "boolean".into(),
                case_sensitive: false,
            },
            finding_title: "SQL Injection Detected (Boolean-based Blind)".into(),
            finding_description: "The application is vulnerable to boolean-based blind SQL injection.".into(),
            severity: Severity::High,
            category: VulnerabilityCategory::Injection,
            finding_type: FindingType::Vulnerability,
            confidence_boost: 0.2,
            enabled: true,
        },
        DetectionRule {
            id: "xss-reflected".into(),
            name: "Reflected XSS".into(),
            description: "Detects reflected cross-site scripting".into(),
            observation_type: ObservationType::ScannerOutput,
            matcher: RuleMatcher::FieldContains {
                field: "reflected_payload".into(),
                value: "<script".into(),
                case_sensitive: false,
            },
            finding_title: "Reflected XSS Detected".into(),
            finding_description: "User input is reflected in the response without proper sanitization, allowing cross-site scripting.".into(),
            severity: Severity::High,
            category: VulnerabilityCategory::Xss,
            finding_type: FindingType::Vulnerability,
            confidence_boost: 0.3,
            enabled: true,
        },
        DetectionRule {
            id: "xss-stored".into(),
            name: "Stored XSS".into(),
            description: "Detects stored cross-site scripting".into(),
            observation_type: ObservationType::ScannerOutput,
            matcher: RuleMatcher::All(vec![
                RuleMatcher::FieldContains {
                    field: "reflected_payload".into(),
                    value: "<script".into(),
                    case_sensitive: false,
                },
                RuleMatcher::FieldEquals {
                    field: "technique".into(),
                    value: "stored".into(),
                },
            ]),
            finding_title: "Stored XSS Detected".into(),
            finding_description: "User input is stored and later rendered without sanitization, allowing persistent XSS.".into(),
            severity: Severity::Critical,
            category: VulnerabilityCategory::Xss,
            finding_type: FindingType::Vulnerability,
            confidence_boost: 0.4,
            enabled: true,
        },
        DetectionRule {
            id: "dir-listing".into(),
            name: "Directory Listing".into(),
            description: "Detects open directory listings".into(),
            observation_type: ObservationType::DirectoryDiscovery,
            matcher: RuleMatcher::All(vec![
                RuleMatcher::FieldContains {
                    field: "response_body".into(),
                    value: "Index of".into(),
                    case_sensitive: false,
                },
                RuleMatcher::FieldContains {
                    field: "response_body".into(),
                    value: "<pre>".into(),
                    case_sensitive: false,
                },
            ]),
            finding_title: "Directory Listing Enabled".into(),
            finding_description: "The web server has directory listing enabled, exposing directory contents.".into(),
            severity: Severity::Medium,
            category: VulnerabilityCategory::SecurityMisconfiguration,
            finding_type: FindingType::Misconfiguration,
            confidence_boost: 0.2,
            enabled: true,
        },
        DetectionRule {
            id: "sensitive-file".into(),
            name: "Sensitive File Exposed".into(),
            description: "Detects exposed sensitive files".into(),
            observation_type: ObservationType::DirectoryDiscovery,
            matcher: RuleMatcher::Any(vec![
                RuleMatcher::FieldEquals {
                    field: "path".into(),
                    value: "/.env".into(),
                },
                RuleMatcher::FieldEquals {
                    field: "path".into(),
                    value: "/.git/config".into(),
                },
                RuleMatcher::FieldEquals {
                    field: "path".into(),
                    value: "/wp-config.php".into(),
                },
                RuleMatcher::FieldEquals {
                    field: "path".into(),
                    value: "/server-status".into(),
                },
                RuleMatcher::FieldEquals {
                    field: "path".into(),
                    value: "/phpinfo.php".into(),
                },
            ]),
            finding_title: "Sensitive File Exposed".into(),
            finding_description: "A sensitive file is publicly accessible.".into(),
            severity: Severity::Medium,
            category: VulnerabilityCategory::SecurityMisconfiguration,
            finding_type: FindingType::InformationDisclosure,
            confidence_boost: 0.1,
            enabled: true,
        },
        DetectionRule {
            id: "ssl-weak-cipher".into(),
            name: "Weak SSL/TLS Cipher".into(),
            description: "Detects weak SSL/TLS cipher suites".into(),
            observation_type: ObservationType::CertificateInfo,
            matcher: RuleMatcher::FieldContains {
                field: "cipher".into(),
                value: "RC4".into(),
                case_sensitive: false,
            },
            finding_title: "Weak SSL/TLS Cipher Suite".into(),
            finding_description: "The server supports weak cipher suites that may be vulnerable to attack.".into(),
            severity: Severity::Medium,
            category: VulnerabilityCategory::SecurityMisconfiguration,
            finding_type: FindingType::SecurityWeakness,
            confidence_boost: 0.2,
            enabled: true,
        },
        DetectionRule {
            id: "open-port".into(),
            name: "Potentially Unnecessary Open Port".into(),
            description: "Flags non-standard open ports".into(),
            observation_type: ObservationType::PortScan,
            matcher: RuleMatcher::FieldContains {
                field: "service".into(),
                value: "unknown".into(),
                case_sensitive: false,
            },
            finding_title: "Unrecognized Service on Open Port".into(),
            finding_description: "An open port is running an unrecognized service that may need review.".into(),
            severity: Severity::Info,
            category: VulnerabilityCategory::Other("service_discovery".into()),
            finding_type: FindingType::SecurityWeakness,
            confidence_boost: 0.0,
            enabled: true,
        },
    ]
}

/// Creates a default detection engine with built-in rules.
pub fn default_detection_engine() -> DetectionEngine {
    DetectionEngine::new().with_rules(default_rules())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observation::Observation;
    use serde_json::json;

    fn make_observation(data: serde_json::Value) -> Observation {
        Observation::new(
            "scan-1",
            "test-scanner",
            ObservationType::ScannerOutput,
            data,
        )
    }

    #[test]
    fn field_contains_match() {
        let rule = DetectionRule {
            id: "test".into(),
            name: "test".into(),
            description: "test".into(),
            observation_type: ObservationType::ScannerOutput,
            matcher: RuleMatcher::FieldContains {
                field: "body".into(),
                value: "SQL".into(),
                case_sensitive: false,
            },
            finding_title: "Test".into(),
            finding_description: "Test".into(),
            severity: Severity::High,
            category: VulnerabilityCategory::Injection,
            finding_type: FindingType::Vulnerability,
            confidence_boost: 0.0,
            enabled: true,
        };

        let obs = make_observation(json!({"body": "SQL syntax error"}));
        assert!(rule.matcher.matches(&obs));

        let obs2 = make_observation(json!({"body": "no match here"}));
        assert!(!rule.matcher.matches(&obs2));
    }

    #[test]
    fn field_equals_match() {
        let matcher = RuleMatcher::FieldEquals {
            field: "status".into(),
            value: "vulnerable".into(),
        };

        let obs = make_observation(json!({"status": "vulnerable"}));
        assert!(matcher.matches(&obs));

        let obs2 = make_observation(json!({"status": "safe"}));
        assert!(!matcher.matches(&obs2));
    }

    #[test]
    fn field_exists_match() {
        let matcher = RuleMatcher::FieldExists {
            field: "secret_key".into(),
        };

        let obs = make_observation(json!({"secret_key": "abc123"}));
        assert!(matcher.matches(&obs));

        let obs2 = make_observation(json!({"other": "value"}));
        assert!(!matcher.matches(&obs2));
    }

    #[test]
    fn field_regex_match() {
        let matcher = RuleMatcher::FieldRegex {
            field: "email".into(),
            pattern: r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$".into(),
        };

        let obs = make_observation(json!({"email": "test@example.com"}));
        assert!(matcher.matches(&obs));

        let obs2 = make_observation(json!({"email": "not-an-email"}));
        assert!(!matcher.matches(&obs2));
    }

    #[test]
    fn status_code_range_match() {
        let matcher = RuleMatcher::StatusCodeRange { min: 400, max: 499 };

        let obs = make_observation(json!({"status_code": 404}));
        assert!(matcher.matches(&obs));

        let obs2 = make_observation(json!({"status_code": 200}));
        assert!(!matcher.matches(&obs2));
    }

    #[test]
    fn always_matcher() {
        let matcher = RuleMatcher::Always;
        let obs = make_observation(json!({}));
        assert!(matcher.matches(&obs));
    }

    #[test]
    fn all_composite_matcher() {
        let matcher = RuleMatcher::All(vec![
            RuleMatcher::FieldExists { field: "a".into() },
            RuleMatcher::FieldExists { field: "b".into() },
        ]);

        let obs = make_observation(json!({"a": 1, "b": 2}));
        assert!(matcher.matches(&obs));

        let obs2 = make_observation(json!({"a": 1}));
        assert!(!matcher2_matches(&matcher, &obs2));
    }

    fn matcher2_matches(matcher: &RuleMatcher, obs: &Observation) -> bool {
        matcher.matches(obs)
    }

    #[test]
    fn any_composite_matcher() {
        let matcher = RuleMatcher::Any(vec![
            RuleMatcher::FieldExists { field: "a".into() },
            RuleMatcher::FieldExists { field: "b".into() },
        ]);

        let obs = make_observation(json!({"a": 1}));
        assert!(matcher.matches(&obs));

        let obs2 = make_observation(json!({"c": 3}));
        assert!(!matcher.matches(&obs2));
    }

    #[test]
    fn nested_field_match() {
        let matcher = RuleMatcher::FieldContains {
            field: "response.headers.content-type".into(),
            value: "text/html".into(),
            case_sensitive: false,
        };

        let obs = make_observation(json!({
            "response": {
                "headers": {
                    "content-type": "text/html; charset=utf-8"
                }
            }
        }));
        assert!(matcher.matches(&obs));
    }

    #[test]
    fn detection_engine_detects() {
        let rule = DetectionRule {
            id: "sqli-test".into(),
            name: "SQLi Test".into(),
            description: "test".into(),
            observation_type: ObservationType::ScannerOutput,
            matcher: RuleMatcher::FieldContains {
                field: "body".into(),
                value: "SQL syntax".into(),
                case_sensitive: false,
            },
            finding_title: "SQL Injection".into(),
            finding_description: "SQL error found".into(),
            severity: Severity::High,
            category: VulnerabilityCategory::Injection,
            finding_type: FindingType::Vulnerability,
            confidence_boost: 0.3,
            enabled: true,
        };

        let engine = DetectionEngine::new().with_rule(rule);
        let observations = vec![make_observation(
            json!({"body": "SQL syntax error near line 5"}),
        )];

        let findings = engine.detect(&observations).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].finding.severity, Severity::High);
        assert_eq!(findings[0].finding.title, "SQL Injection");
    }

    #[test]
    fn detection_engine_skips_disabled_rules() {
        let rule = DetectionRule {
            id: "disabled-test".into(),
            name: "Disabled".into(),
            description: "test".into(),
            observation_type: ObservationType::ScannerOutput,
            matcher: RuleMatcher::Always,
            finding_title: "Test".into(),
            finding_description: "Test".into(),
            severity: Severity::Low,
            category: VulnerabilityCategory::Other("test".into()),
            finding_type: FindingType::Vulnerability,
            confidence_boost: 0.0,
            enabled: false,
        };

        let engine = DetectionEngine::new().with_rule(rule);
        let observations = vec![make_observation(json!({}))];

        let findings = engine.detect(&observations).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn detection_engine_skips_wrong_observation_type() {
        let rule = DetectionRule {
            id: "test".into(),
            name: "test".into(),
            description: "test".into(),
            observation_type: ObservationType::DnsRecord,
            matcher: RuleMatcher::Always,
            finding_title: "Test".into(),
            finding_description: "Test".into(),
            severity: Severity::Low,
            category: VulnerabilityCategory::Other("test".into()),
            finding_type: FindingType::Vulnerability,
            confidence_boost: 0.0,
            enabled: true,
        };

        let engine = DetectionEngine::new().with_rule(rule);
        let observations = vec![make_observation(json!({}))];

        let findings = engine.detect(&observations).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn detection_engine_multiple_rules() {
        let engine = DetectionEngine::new().with_rules(vec![
            DetectionRule {
                id: "rule1".into(),
                name: "Rule 1".into(),
                description: "test".into(),
                observation_type: ObservationType::ScannerOutput,
                matcher: RuleMatcher::FieldEquals {
                    field: "type".into(),
                    value: "sqli".into(),
                },
                finding_title: "SQLi".into(),
                finding_description: "SQL injection".into(),
                severity: Severity::High,
                category: VulnerabilityCategory::Injection,
                finding_type: FindingType::Vulnerability,
                confidence_boost: 0.0,
                enabled: true,
            },
            DetectionRule {
                id: "rule2".into(),
                name: "Rule 2".into(),
                description: "test".into(),
                observation_type: ObservationType::ScannerOutput,
                matcher: RuleMatcher::FieldEquals {
                    field: "type".into(),
                    value: "xss".into(),
                },
                finding_title: "XSS".into(),
                finding_description: "Cross-site scripting".into(),
                severity: Severity::Medium,
                category: VulnerabilityCategory::Xss,
                finding_type: FindingType::Vulnerability,
                confidence_boost: 0.0,
                enabled: true,
            },
        ]);

        let observations = vec![
            make_observation(json!({"type": "sqli"})),
            make_observation(json!({"type": "xss"})),
        ];

        let findings = engine.detect(&observations).unwrap();
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn disable_enable_rule() {
        let mut engine = DetectionEngine::new().with_rule(DetectionRule {
            id: "toggle-test".into(),
            name: "Toggle".into(),
            description: "test".into(),
            observation_type: ObservationType::ScannerOutput,
            matcher: RuleMatcher::Always,
            finding_title: "Test".into(),
            finding_description: "Test".into(),
            severity: Severity::Info,
            category: VulnerabilityCategory::Other("test".into()),
            finding_type: FindingType::Vulnerability,
            confidence_boost: 0.0,
            enabled: true,
        });

        engine.disable_rule("toggle-test").unwrap();
        assert!(!engine.list_rules()[0].enabled);

        engine.enable_rule("toggle-test").unwrap();
        assert!(engine.list_rules()[0].enabled);
    }

    #[test]
    fn disable_nonexistent_rule() {
        let mut engine = DetectionEngine::new();
        assert!(engine.disable_rule("nope").is_err());
    }

    #[test]
    fn default_rules_created() {
        let engine = default_detection_engine();
        assert!(engine.rule_count() > 0);
    }

    #[test]
    fn confidence_boost_applied() {
        let rule = DetectionRule {
            id: "boost-test".into(),
            name: "Boost".into(),
            description: "test".into(),
            observation_type: ObservationType::ScannerOutput,
            matcher: RuleMatcher::Always,
            finding_title: "Test".into(),
            finding_description: "Test".into(),
            severity: Severity::Low,
            category: VulnerabilityCategory::Other("test".into()),
            finding_type: FindingType::Vulnerability,
            confidence_boost: 0.5,
            enabled: true,
        };

        let engine = DetectionEngine::new().with_rule(rule);
        let obs = Observation::new("scan-1", "test", ObservationType::ScannerOutput, json!({}))
            .with_confidence(0.4);

        let findings = engine.detect(&[obs]).unwrap();
        assert_eq!(findings.len(), 1);
    }
}
