pub mod correlate;
pub mod detection;
pub mod manage;
pub mod observation;
pub mod report;

pub use correlate::{CorrelationEngine, FindingGroup};
pub use detection::{
    default_detection_engine, default_rules, DetectionEngine, DetectionError, DetectionResult,
    DetectionRule, RuleMatcher,
};
pub use manage::InMemoryFindingsManager;
pub use observation::{
    InMemoryObservationStore, Observation, ObservationEngine, ObservationError, ObservationId,
    ObservationResult, ObservationSeverity, ObservationStore, ObservationType,
};
pub use report::ReportGenerator;

use spectra_core::Id;
use spectra_target::TargetId;
use thiserror::Error;

/// Re-export scanner types used by findings.
pub use spectra_scanner::{Finding, FindingId, Severity};

/// Errors specific to findings operations.
#[derive(Debug, Error)]
pub enum FindingsError {
    #[error("Finding not found: {0}")]
    NotFound(String),

    #[error("Invalid data: {0}")]
    InvalidData(String),

    #[error("Storage error: {0}")]
    Storage(String),
}

/// Result type for findings operations.
pub type FindingsResult<T> = Result<T, FindingsError>;

/// The type of a finding.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq, Hash)]
pub enum FindingType {
    Vulnerability,
    Misconfiguration,
    InformationDisclosure,
    SecurityWeakness,
    ComplianceViolation,
    Custom(String),
}

impl std::fmt::Display for FindingType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Vulnerability => write!(f, "Vulnerability"),
            Self::Misconfiguration => write!(f, "Misconfiguration"),
            Self::InformationDisclosure => write!(f, "Information Disclosure"),
            Self::SecurityWeakness => write!(f, "Security Weakness"),
            Self::ComplianceViolation => write!(f, "Compliance Violation"),
            Self::Custom(s) => write!(f, "{}", s),
        }
    }
}

/// Detection source of a finding.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum DetectionSource {
    SqlInjectionScanner,
    XssScanner,
    DirSearchScanner,
    Fingerprinter,
    Crawler,
    Manual,
    Other(String),
}

impl std::fmt::Display for DetectionSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SqlInjectionScanner => write!(f, "SQL Injection Scanner"),
            Self::XssScanner => write!(f, "XSS Scanner"),
            Self::DirSearchScanner => write!(f, "Directory Search Scanner"),
            Self::Fingerprinter => write!(f, "Fingerprinter"),
            Self::Crawler => write!(f, "Crawler"),
            Self::Manual => write!(f, "Manual"),
            Self::Other(s) => write!(f, "{}", s),
        }
    }
}

/// Verification status of a finding.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum VerificationStatus {
    #[default]
    Unverified,
    Verified,
    Disputed,
    Exploited,
}

/// A managed finding with lifecycle tracking.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ManagedFinding {
    pub finding: Finding,
    pub status: FindingStatus,
    pub finding_type: FindingType,
    pub detection_source: DetectionSource,
    pub verification_status: VerificationStatus,
    pub assigned_to: Option<String>,
    pub notes: Vec<FindingNote>,
    pub first_seen: String,
    pub last_seen: String,
    pub occurrence_count: u32,
    pub tags: Vec<String>,
    pub correlation_id: Option<String>,
}

impl ManagedFinding {
    pub fn new(finding: Finding, source: DetectionSource) -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        let finding_type = match &finding.category {
            spectra_scanner::VulnerabilityCategory::Injection => FindingType::Vulnerability,
            spectra_scanner::VulnerabilityCategory::Xss => FindingType::Vulnerability,
            spectra_scanner::VulnerabilityCategory::SecurityMisconfiguration => {
                FindingType::Misconfiguration
            }
            spectra_scanner::VulnerabilityCategory::SensitiveDataExposure => {
                FindingType::InformationDisclosure
            }
            _ => FindingType::SecurityWeakness,
        };

        Self {
            finding,
            status: FindingStatus::New,
            finding_type,
            detection_source: source,
            verification_status: VerificationStatus::default(),
            assigned_to: None,
            notes: Vec::new(),
            first_seen: now.clone(),
            last_seen: now,
            occurrence_count: 1,
            tags: Vec::new(),
            correlation_id: None,
        }
    }

    pub fn with_status(mut self, status: FindingStatus) -> Self {
        self.status = status;
        self
    }

    pub fn add_note(&mut self, author: impl Into<String>, content: impl Into<String>) {
        self.notes.push(FindingNote {
            author: author.into(),
            content: content.into(),
            created_at: chrono::Utc::now().to_rfc3339(),
        });
    }

    pub fn increment_occurrence(&mut self) {
        self.occurrence_count += 1;
        self.last_seen = chrono::Utc::now().to_rfc3339();
    }
}

/// A note attached to a finding.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FindingNote {
    pub author: String,
    pub content: String,
    pub created_at: String,
}

/// Finding lifecycle status.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum FindingStatus {
    New,
    Confirmed,
    FalsePositive,
    Investigating,
    Fixed,
    Accepted,
    Duplicate,
}

impl std::fmt::Display for FindingStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::New => write!(f, "New"),
            Self::Confirmed => write!(f, "Confirmed"),
            Self::FalsePositive => write!(f, "False Positive"),
            Self::Investigating => write!(f, "Investigating"),
            Self::Fixed => write!(f, "Fixed"),
            Self::Accepted => write!(f, "Accepted"),
            Self::Duplicate => write!(f, "Duplicate"),
        }
    }
}

/// Summary statistics for a findings report.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct FindingsSummary {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

impl FindingsSummary {
    pub fn from_findings(findings: &[ManagedFinding]) -> Self {
        let mut summary = Self {
            total: findings.len(),
            ..Default::default()
        };
        for f in findings {
            match f.finding.severity {
                Severity::Critical => summary.critical += 1,
                Severity::High => summary.high += 1,
                Severity::Medium => summary.medium += 1,
                Severity::Low => summary.low += 1,
                Severity::Info => summary.info += 1,
            }
        }
        summary
    }
}

/// A report of findings for a target.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FindingsReport {
    pub target_id: Id<TargetId>,
    pub findings: Vec<ManagedFinding>,
    pub summary: FindingsSummary,
    pub generated_at: String,
}

impl FindingsReport {
    pub fn new(target_id: Id<TargetId>) -> Self {
        Self {
            target_id,
            findings: Vec::new(),
            summary: FindingsSummary::default(),
            generated_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    pub fn add_finding(&mut self, finding: ManagedFinding) {
        self.findings.push(finding);
        self.summary = FindingsSummary::from_findings(&self.findings);
    }

    pub fn findings_by_severity(&self, severity: &Severity) -> Vec<&ManagedFinding> {
        self.findings
            .iter()
            .filter(|f| &f.finding.severity == severity)
            .collect()
    }

    pub fn findings_by_status(&self, status: &FindingStatus) -> Vec<&ManagedFinding> {
        self.findings
            .iter()
            .filter(|f| &f.status == status)
            .collect()
    }
}

/// Trait for managing findings.
#[async_trait::async_trait]
pub trait FindingsManager: Send + Sync {
    async fn save_finding(&self, finding: ManagedFinding) -> FindingsResult<()>;
    async fn get_finding(&self, id: &str) -> FindingsResult<ManagedFinding>;
    async fn list_findings(&self, target_id: &Id<TargetId>) -> FindingsResult<Vec<ManagedFinding>>;
    async fn update_status(&self, id: &str, status: FindingStatus) -> FindingsResult<()>;
    async fn generate_report(&self, target_id: &Id<TargetId>) -> FindingsResult<FindingsReport>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use spectra_scanner::VulnerabilityCategory;

    fn make_finding(title: &str, severity: Severity) -> Finding {
        Finding::new(
            title,
            "Description",
            severity,
            VulnerabilityCategory::Injection,
        )
    }

    #[test]
    fn managed_finding_creation() {
        let f = make_finding("Test", Severity::High);
        let mf = ManagedFinding::new(f, DetectionSource::SqlInjectionScanner);
        assert_eq!(mf.status, FindingStatus::New);
        assert_eq!(mf.occurrence_count, 1);
        assert!(!mf.first_seen.is_empty());
    }

    #[test]
    fn managed_finding_notes() {
        let f = make_finding("Test", Severity::Low);
        let mut mf = ManagedFinding::new(f, DetectionSource::Manual);
        mf.add_note("analyst", "Needs investigation");
        assert_eq!(mf.notes.len(), 1);
        assert_eq!(mf.notes[0].author, "analyst");
    }

    #[test]
    fn finding_type_from_category() {
        let f = Finding::new(
            "SQLi",
            "desc",
            Severity::High,
            VulnerabilityCategory::Injection,
        );
        let mf = ManagedFinding::new(f, DetectionSource::SqlInjectionScanner);
        assert_eq!(mf.finding_type, FindingType::Vulnerability);

        let f2 = Finding::new(
            "Misconfig",
            "desc",
            Severity::Medium,
            VulnerabilityCategory::SecurityMisconfiguration,
        );
        let mf2 = ManagedFinding::new(f2, DetectionSource::DirSearchScanner);
        assert_eq!(mf2.finding_type, FindingType::Misconfiguration);
    }

    #[test]
    fn findings_summary() {
        let findings = vec![
            ManagedFinding::new(
                make_finding("A", Severity::Critical),
                DetectionSource::SqlInjectionScanner,
            ),
            ManagedFinding::new(
                make_finding("B", Severity::High),
                DetectionSource::XssScanner,
            ),
            ManagedFinding::new(
                make_finding("C", Severity::Medium),
                DetectionSource::DirSearchScanner,
            ),
        ];

        let summary = FindingsSummary::from_findings(&findings);
        assert_eq!(summary.total, 3);
        assert_eq!(summary.critical, 1);
        assert_eq!(summary.high, 1);
        assert_eq!(summary.medium, 1);
    }

    #[test]
    fn findings_report() {
        let target_id = Id::new();
        let mut report = FindingsReport::new(target_id);
        report.add_finding(ManagedFinding::new(
            make_finding("Test", Severity::High),
            DetectionSource::XssScanner,
        ));

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.summary.total, 1);
        assert_eq!(report.summary.high, 1);
    }
}
