pub mod dirsearch;
pub mod sqli;
pub mod xss;

pub use dirsearch::DirSearchScanner;
pub use sqli::SqlInjectionScanner;
pub use xss::XssScanner;

use serde::{Deserialize, Serialize};
use spectra_core::Id;
use spectra_target::TargetId;
use thiserror::Error;

/// Marker type for finding identifiers.
#[derive(Debug, Clone)]
pub struct FindingId;

/// Errors specific to scanner operations.
#[derive(Debug, Error)]
pub enum ScannerError {
    #[error("Scanner initialization failed: {0}")]
    InitFailed(String),

    #[error("Scan execution failed: {0}")]
    ExecutionFailed(String),

    #[error("Scanner not found: {0}")]
    NotFound(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Timeout")]
    Timeout,
}

/// Result type for scanner operations.
pub type ScannerResult<T> = Result<T, ScannerError>;

/// The severity level of a finding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Critical => write!(f, "Critical"),
            Self::High => write!(f, "High"),
            Self::Medium => write!(f, "Medium"),
            Self::Low => write!(f, "Low"),
            Self::Info => write!(f, "Info"),
        }
    }
}

/// A vulnerability category.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum VulnerabilityCategory {
    Injection,
    BrokenAuth,
    SensitiveDataExposure,
    Xss,
    BrokenAccessControl,
    SecurityMisconfiguration,
    InsecureDeserialization,
    UsingComponentsWithKnownVulnerabilities,
    InsufficientLogging,
    DirectoryListing,
    Other(String),
}

impl std::fmt::Display for VulnerabilityCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Injection => write!(f, "Injection"),
            Self::BrokenAuth => write!(f, "Broken Authentication"),
            Self::SensitiveDataExposure => write!(f, "Sensitive Data Exposure"),
            Self::Xss => write!(f, "Cross-Site Scripting"),
            Self::BrokenAccessControl => write!(f, "Broken Access Control"),
            Self::SecurityMisconfiguration => write!(f, "Security Misconfiguration"),
            Self::InsecureDeserialization => write!(f, "Insecure Deserialization"),
            Self::UsingComponentsWithKnownVulnerabilities => {
                write!(f, "Vulnerable Components")
            }
            Self::InsufficientLogging => write!(f, "Insufficient Logging"),
            Self::DirectoryListing => write!(f, "Directory Listing"),
            Self::Other(s) => write!(f, "{}", s),
        }
    }
}

/// Configuration for a scanner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerConfig {
    pub name: String,
    pub version: String,
    pub enabled: bool,
    pub settings: std::collections::HashMap<String, String>,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            version: "0.1.0".to_string(),
            enabled: true,
            settings: std::collections::HashMap::new(),
        }
    }
}

/// Metadata about a scanner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerMetadata {
    pub name: String,
    pub version: String,
    pub supported_targets: Vec<String>,
    pub categories: Vec<VulnerabilityCategory>,
}

/// Trait that all scanners must implement.
#[async_trait::async_trait]
pub trait Scanner: Send + Sync {
    fn metadata(&self) -> ScannerMetadata;
    async fn initialize(&mut self, config: ScannerConfig) -> ScannerResult<()>;
    async fn scan(&self, target: &spectra_target::Target) -> ScannerResult<ScanResult>;
    async fn cleanup(&self) -> ScannerResult<()>;
}

/// Result of a scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub target_id: Id<TargetId>,
    pub scanner_name: String,
    pub findings: Vec<Finding>,
    pub started_at: String,
    pub completed_at: String,
    pub duration_ms: u64,
    pub errors: Vec<String>,
}

/// A single finding from a scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: Id<FindingId>,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub category: VulnerabilityCategory,
    pub affected_url: Option<String>,
    pub evidence: Vec<String>,
    pub remediation: Option<String>,
    pub cvss_score: Option<f64>,
    pub cve_id: Option<String>,
}

impl Finding {
    pub fn new(
        title: impl Into<String>,
        description: impl Into<String>,
        severity: Severity,
        category: VulnerabilityCategory,
    ) -> Self {
        Self {
            id: Id::new(),
            title: title.into(),
            description: description.into(),
            severity,
            category,
            affected_url: None,
            evidence: Vec::new(),
            remediation: None,
            cvss_score: None,
            cve_id: None,
        }
    }

    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.affected_url = Some(url.into());
        self
    }

    pub fn with_evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence.push(evidence.into());
        self
    }

    pub fn with_remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(remediation.into());
        self
    }

    pub fn with_cvss(mut self, score: f64) -> Self {
        self.cvss_score = Some(score);
        self
    }
}

impl ScanResult {
    pub fn new(target_id: Id<TargetId>, scanner_name: impl Into<String>) -> Self {
        Self {
            target_id,
            scanner_name: scanner_name.into(),
            findings: Vec::new(),
            started_at: chrono::Utc::now().to_rfc3339(),
            completed_at: String::new(),
            duration_ms: 0,
            errors: Vec::new(),
        }
    }

    pub fn add_finding(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    pub fn findings_by_severity(&self, severity: &Severity) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| &f.severity == severity)
            .collect()
    }

    pub fn total_findings(&self) -> usize {
        self.findings.len()
    }

    pub fn finish(&mut self) {
        self.completed_at = chrono::Utc::now().to_rfc3339();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering() {
        assert!(Severity::Info > Severity::Low);
        assert!(Severity::Low > Severity::Medium);
        assert!(Severity::Medium > Severity::High);
        assert!(Severity::High > Severity::Critical);
    }

    #[test]
    fn finding_builder() {
        let finding = Finding::new(
            "SQL Injection",
            "Input not sanitized",
            Severity::High,
            VulnerabilityCategory::Injection,
        )
        .with_url("https://example.com/search?q=test")
        .with_evidence("Response contained SQL error message")
        .with_remediation("Use parameterized queries")
        .with_cvss(8.6);

        assert_eq!(finding.title, "SQL Injection");
        assert_eq!(finding.severity, Severity::High);
        assert!(finding.affected_url.is_some());
        assert_eq!(finding.evidence.len(), 1);
        assert_eq!(finding.cvss_score, Some(8.6));
    }

    #[test]
    fn scan_result_operations() {
        let mut result = ScanResult::new(Id::new(), "TestScanner");
        assert_eq!(result.total_findings(), 0);

        result.add_finding(Finding::new(
            "Test Finding",
            "Description",
            Severity::Low,
            VulnerabilityCategory::Other("test".to_string()),
        ));

        assert_eq!(result.total_findings(), 1);
        assert_eq!(result.findings_by_severity(&Severity::Low).len(), 1);
        assert_eq!(result.findings_by_severity(&Severity::High).len(), 0);
    }
}
