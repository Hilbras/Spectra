use serde::{Deserialize, Serialize};
use spectra_findings::{DetectionSource, FindingStatus, ManagedFinding};
use spectra_scanner::Severity;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("Verification failed: {0}")]
    Failed(String),
    #[error("Finding not found: {0}")]
    NotFound(String),
    #[error("Network error: {0}")]
    Network(#[from] spectra_network::NetworkError),
}

pub type VerificationResult<T> = Result<T, VerificationError>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum VerificationMethod {
    ActiveScan,
    PassiveCheck,
    ManualReview,
    AutomatedTest,
}

impl std::fmt::Display for VerificationMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ActiveScan => write!(f, "Active Scan"),
            Self::PassiveCheck => write!(f, "Passive Check"),
            Self::ManualReview => write!(f, "Manual Review"),
            Self::AutomatedTest => write!(f, "Automated Test"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum VerificationOutcome {
    Verified,
    NotVerified,
    PartiallyVerified,
    UnableToVerify,
}

impl std::fmt::Display for VerificationOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Verified => write!(f, "Verified"),
            Self::NotVerified => write!(f, "Not Verified"),
            Self::PartiallyVerified => write!(f, "Partially Verified"),
            Self::UnableToVerify => write!(f, "Unable to Verify"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationRecord {
    pub finding_id: String,
    pub status: VerificationOutcome,
    pub method: VerificationMethod,
    pub confidence: f64,
    pub details: String,
    pub verified_at: String,
    pub verifier: String,
}

#[derive(Debug, Clone, Default)]
pub struct InMemoryVerificationStore {
    records: Arc<tokio::sync::RwLock<HashMap<String, Vec<VerificationRecord>>>>,
}

impl InMemoryVerificationStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn save(&self, record: VerificationRecord) {
        let mut records = self.records.write().await;
        records
            .entry(record.finding_id.clone())
            .or_default()
            .push(record);
    }

    pub async fn get_records(&self, finding_id: &str) -> Vec<VerificationRecord> {
        let records = self.records.read().await;
        records.get(finding_id).cloned().unwrap_or_default()
    }

    pub async fn get_latest(&self, finding_id: &str) -> Option<VerificationRecord> {
        let records = self.records.read().await;
        records.get(finding_id).and_then(|r| r.last().cloned())
    }

    pub async fn verified_count(&self) -> usize {
        let records = self.records.read().await;
        records
            .values()
            .flatten()
            .filter(|r| r.status == VerificationOutcome::Verified)
            .count()
    }

    pub async fn total_verifications(&self) -> usize {
        let records = self.records.read().await;
        records.values().map(|r| r.len()).sum()
    }

    pub async fn average_confidence(&self, finding_id: &str) -> f64 {
        let records = self.records.read().await;
        match records.get(finding_id) {
            Some(recs) if !recs.is_empty() => {
                recs.iter().map(|r| r.confidence).sum::<f64>() / recs.len() as f64
            }
            _ => 0.0,
        }
    }

    pub async fn findings_by_outcome(&self, outcome: &VerificationOutcome) -> Vec<String> {
        let records = self.records.read().await;
        records
            .iter()
            .filter(|(_, recs)| recs.last().map(|r| &r.status == outcome).unwrap_or(false))
            .map(|(id, _)| id.clone())
            .collect()
    }

    pub async fn clear(&self) {
        let mut records = self.records.write().await;
        records.clear();
    }
}

/// Verification strategy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationStrategy {
    pub auto_verify_high_confidence: bool,
    pub min_confidence_for_verify: f64,
    pub skip_info_severity: bool,
    pub batch_size: usize,
}

impl Default for VerificationStrategy {
    fn default() -> Self {
        Self {
            auto_verify_high_confidence: true,
            min_confidence_for_verify: 0.7,
            skip_info_severity: true,
            batch_size: 50,
        }
    }
}

pub struct VerificationEngine {
    store: InMemoryVerificationStore,
    strategy: VerificationStrategy,
}

impl Default for VerificationEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl VerificationEngine {
    pub fn new() -> Self {
        Self {
            store: InMemoryVerificationStore::new(),
            strategy: VerificationStrategy::default(),
        }
    }

    pub fn with_strategy(strategy: VerificationStrategy) -> Self {
        Self {
            store: InMemoryVerificationStore::new(),
            strategy,
        }
    }

    pub fn store(&self) -> &InMemoryVerificationStore {
        &self.store
    }

    pub fn strategy(&self) -> &VerificationStrategy {
        &self.strategy
    }

    pub async fn verify_finding(
        &self,
        finding: &ManagedFinding,
    ) -> VerificationResult<VerificationRecord> {
        if self.strategy.skip_info_severity && matches!(finding.finding.severity, Severity::Info) {
            return Err(VerificationError::Failed(
                "Info severity findings are skipped by strategy".into(),
            ));
        }

        let method = self.select_method(finding);
        let outcome = self.determine_outcome(finding);
        let confidence = self.calculate_confidence(finding, &outcome);
        let details = self.generate_details(finding, &outcome);

        let record = VerificationRecord {
            finding_id: finding.finding.id.to_string(),
            status: outcome,
            method: method.clone(),
            confidence,
            details,
            verified_at: chrono::Utc::now().to_rfc3339(),
            verifier: "spectra-auto".into(),
        };

        self.store.save(record.clone()).await;
        Ok(record)
    }

    pub async fn verify_batch(
        &self,
        findings: &[ManagedFinding],
    ) -> Vec<VerificationResult<VerificationRecord>> {
        let mut results = Vec::with_capacity(findings.len());
        for finding in findings.chunks(self.strategy.batch_size) {
            for f in finding {
                results.push(self.verify_finding(f).await);
            }
        }
        results
    }

    /// Returns the overall verification summary.
    pub async fn summary(&self) -> VerificationSummary {
        let total = self.store.total_verifications().await;
        let verified = self.store.verified_count().await;
        let not_verified = self
            .store
            .findings_by_outcome(&VerificationOutcome::NotVerified)
            .await
            .len();
        let partial = self
            .store
            .findings_by_outcome(&VerificationOutcome::PartiallyVerified)
            .await
            .len();

        VerificationSummary {
            total_verifications: total,
            verified,
            not_verified,
            partially_verified: partial,
        }
    }

    fn select_method(&self, finding: &ManagedFinding) -> VerificationMethod {
        match finding.detection_source {
            DetectionSource::SqlInjectionScanner | DetectionSource::XssScanner => {
                VerificationMethod::ActiveScan
            }
            DetectionSource::DirSearchScanner => VerificationMethod::AutomatedTest,
            DetectionSource::Crawler => VerificationMethod::PassiveCheck,
            DetectionSource::Fingerprinter => VerificationMethod::PassiveCheck,
            DetectionSource::Manual => VerificationMethod::ManualReview,
            DetectionSource::Other(_) => VerificationMethod::AutomatedTest,
        }
    }

    fn determine_outcome(&self, finding: &ManagedFinding) -> VerificationOutcome {
        match finding.status {
            FindingStatus::Confirmed => VerificationOutcome::Verified,
            FindingStatus::FalsePositive => VerificationOutcome::NotVerified,
            FindingStatus::Fixed => VerificationOutcome::NotVerified,
            FindingStatus::Duplicate => VerificationOutcome::PartiallyVerified,
            FindingStatus::New => {
                if matches!(
                    finding.finding.severity,
                    Severity::Critical | Severity::High
                ) {
                    VerificationOutcome::PartiallyVerified
                } else {
                    VerificationOutcome::UnableToVerify
                }
            }
            FindingStatus::Investigating | FindingStatus::Accepted => {
                VerificationOutcome::PartiallyVerified
            }
        }
    }

    fn calculate_confidence(&self, finding: &ManagedFinding, outcome: &VerificationOutcome) -> f64 {
        let base: f64 = match outcome {
            VerificationOutcome::Verified => 0.9,
            VerificationOutcome::PartiallyVerified => 0.5,
            VerificationOutcome::NotVerified => 0.1,
            VerificationOutcome::UnableToVerify => 0.0,
        };

        let severity_bonus: f64 = match finding.finding.severity {
            Severity::Critical => 0.05,
            Severity::High => 0.03,
            Severity::Medium => 0.01,
            Severity::Low => 0.0,
            Severity::Info => -0.05,
        };

        let evidence_bonus: f64 = if finding.finding.evidence.is_empty() {
            -0.1
        } else {
            0.05
        };

        (base + severity_bonus + evidence_bonus).clamp(0.0, 1.0)
    }

    fn generate_details(&self, finding: &ManagedFinding, outcome: &VerificationOutcome) -> String {
        match outcome {
            VerificationOutcome::Verified => {
                format!(
                    "Finding '{}' confirmed. Evidence: {} item(s). Category: {}.",
                    finding.finding.title,
                    finding.finding.evidence.len(),
                    finding.finding.category
                )
            }
            VerificationOutcome::PartiallyVerified => {
                format!(
                    "Finding '{}' partially verified. Status: {:?}. Needs manual review.",
                    finding.finding.title, finding.status
                )
            }
            VerificationOutcome::NotVerified => {
                format!(
                    "Finding '{}' not verified. Status: {:?}.",
                    finding.finding.title, finding.status
                )
            }
            VerificationOutcome::UnableToVerify => {
                format!(
                    "Unable to verify finding '{}'. Insufficient data.",
                    finding.finding.title
                )
            }
        }
    }
}

/// Summary of verification results.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VerificationSummary {
    pub total_verifications: usize,
    pub verified: usize,
    pub not_verified: usize,
    pub partially_verified: usize,
}

impl VerificationSummary {
    pub fn verification_rate(&self) -> f64 {
        if self.total_verifications == 0 {
            0.0
        } else {
            self.verified as f64 / self.total_verifications as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spectra_scanner::{Finding, VulnerabilityCategory};

    fn make_finding(
        title: &str,
        severity: Severity,
        category: VulnerabilityCategory,
        status: FindingStatus,
    ) -> ManagedFinding {
        let mut f = Finding::new(title, "desc", severity, category);
        f.evidence = vec!["evidence1".into()];
        ManagedFinding::new(f, DetectionSource::SqlInjectionScanner).with_status(status)
    }

    #[tokio::test]
    async fn verify_confirmed_finding() {
        let engine = VerificationEngine::new();
        let finding = make_finding(
            "SQLi",
            Severity::High,
            VulnerabilityCategory::Injection,
            FindingStatus::Confirmed,
        );

        let result = engine.verify_finding(&finding).await.unwrap();
        assert_eq!(result.status, VerificationOutcome::Verified);
        assert!(result.confidence > 0.8);
        assert_eq!(result.method, VerificationMethod::ActiveScan);
    }

    #[tokio::test]
    async fn verify_false_positive() {
        let engine = VerificationEngine::new();
        let finding = make_finding(
            "FP",
            Severity::Low,
            VulnerabilityCategory::Xss,
            FindingStatus::FalsePositive,
        );

        let result = engine.verify_finding(&finding).await.unwrap();
        assert_eq!(result.status, VerificationOutcome::NotVerified);
    }

    #[tokio::test]
    async fn verify_new_critical() {
        let engine = VerificationEngine::new();
        let finding = make_finding(
            "Critical",
            Severity::Critical,
            VulnerabilityCategory::Injection,
            FindingStatus::New,
        );

        let result = engine.verify_finding(&finding).await.unwrap();
        assert_eq!(result.status, VerificationOutcome::PartiallyVerified);
        assert!(result.confidence > 0.5);
    }

    #[tokio::test]
    async fn verify_new_low() {
        let engine = VerificationEngine::new();
        let finding = make_finding(
            "Low",
            Severity::Low,
            VulnerabilityCategory::Xss,
            FindingStatus::New,
        );

        let result = engine.verify_finding(&finding).await.unwrap();
        assert_eq!(result.status, VerificationOutcome::UnableToVerify);
    }

    #[tokio::test]
    async fn store_records() {
        let engine = VerificationEngine::new();
        let finding = make_finding(
            "Test",
            Severity::Medium,
            VulnerabilityCategory::Xss,
            FindingStatus::Confirmed,
        );

        engine.verify_finding(&finding).await.unwrap();

        let records = engine
            .store()
            .get_records(&finding.finding.id.to_string())
            .await;
        assert_eq!(records.len(), 1);

        let latest = engine
            .store()
            .get_latest(&finding.finding.id.to_string())
            .await;
        assert!(latest.is_some());
    }

    #[tokio::test]
    async fn store_counts() {
        let engine = VerificationEngine::new();
        let f1 = make_finding(
            "A",
            Severity::High,
            VulnerabilityCategory::Injection,
            FindingStatus::Confirmed,
        );
        let f2 = make_finding(
            "B",
            Severity::Low,
            VulnerabilityCategory::Xss,
            FindingStatus::FalsePositive,
        );

        engine.verify_finding(&f1).await.unwrap();
        engine.verify_finding(&f2).await.unwrap();

        assert_eq!(engine.store().total_verifications().await, 2);
        assert_eq!(engine.store().verified_count().await, 1);
    }

    #[tokio::test]
    async fn batch_verify() {
        let engine = VerificationEngine::new();
        let findings = vec![
            make_finding(
                "A",
                Severity::High,
                VulnerabilityCategory::Injection,
                FindingStatus::Confirmed,
            ),
            make_finding(
                "B",
                Severity::Medium,
                VulnerabilityCategory::Xss,
                FindingStatus::New,
            ),
        ];

        let results = engine.verify_batch(&findings).await;
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.is_ok()));
    }

    #[tokio::test]
    async fn method_selection() {
        let engine = VerificationEngine::new();

        let f1 = make_finding(
            "SQLi",
            Severity::High,
            VulnerabilityCategory::Injection,
            FindingStatus::Confirmed,
        );
        assert_eq!(engine.select_method(&f1), VerificationMethod::ActiveScan);

        let f2 = ManagedFinding::new(
            Finding::new(
                "Dir",
                "desc",
                Severity::Medium,
                VulnerabilityCategory::DirectoryListing,
            ),
            DetectionSource::DirSearchScanner,
        );
        assert_eq!(engine.select_method(&f2), VerificationMethod::AutomatedTest);

        let f3 = ManagedFinding::new(
            Finding::new(
                "Tech",
                "desc",
                Severity::Info,
                VulnerabilityCategory::SecurityMisconfiguration,
            ),
            DetectionSource::Fingerprinter,
        );
        assert_eq!(engine.select_method(&f3), VerificationMethod::PassiveCheck);
    }

    #[tokio::test]
    async fn confidence_no_evidence() {
        let engine = VerificationEngine::new();
        let mut f = Finding::new(
            "NoEvidence",
            "desc",
            Severity::Medium,
            VulnerabilityCategory::Xss,
        );
        f.evidence = Vec::new();
        let managed =
            ManagedFinding::new(f, DetectionSource::Crawler).with_status(FindingStatus::Confirmed);

        let result = engine.verify_finding(&managed).await.unwrap();
        assert!(result.confidence < 0.9);
    }

    #[test]
    fn outcome_equality() {
        assert_eq!(VerificationOutcome::Verified, VerificationOutcome::Verified);
        assert_ne!(
            VerificationOutcome::Verified,
            VerificationOutcome::NotVerified
        );
    }

    #[tokio::test]
    async fn average_confidence() {
        let engine = VerificationEngine::new();
        let finding = make_finding(
            "Test",
            Severity::High,
            VulnerabilityCategory::Injection,
            FindingStatus::Confirmed,
        );

        engine.verify_finding(&finding).await.unwrap();
        let avg = engine
            .store()
            .average_confidence(&finding.finding.id.to_string())
            .await;
        assert!(avg > 0.0);
    }

    #[tokio::test]
    async fn findings_by_outcome() {
        let engine = VerificationEngine::new();
        let f1 = make_finding(
            "A",
            Severity::High,
            VulnerabilityCategory::Injection,
            FindingStatus::Confirmed,
        );
        let f2 = make_finding(
            "B",
            Severity::Low,
            VulnerabilityCategory::Xss,
            FindingStatus::FalsePositive,
        );

        engine.verify_finding(&f1).await.unwrap();
        engine.verify_finding(&f2).await.unwrap();

        let verified = engine
            .store()
            .findings_by_outcome(&VerificationOutcome::Verified)
            .await;
        assert_eq!(verified.len(), 1);

        let not_verified = engine
            .store()
            .findings_by_outcome(&VerificationOutcome::NotVerified)
            .await;
        assert_eq!(not_verified.len(), 1);
    }

    #[tokio::test]
    async fn store_clear() {
        let engine = VerificationEngine::new();
        let finding = make_finding(
            "Test",
            Severity::High,
            VulnerabilityCategory::Injection,
            FindingStatus::Confirmed,
        );

        engine.verify_finding(&finding).await.unwrap();
        assert_eq!(engine.store().total_verifications().await, 1);

        engine.store().clear().await;
        assert_eq!(engine.store().total_verifications().await, 0);
    }

    #[test]
    fn strategy_default() {
        let strategy = VerificationStrategy::default();
        assert!(strategy.auto_verify_high_confidence);
        assert_eq!(strategy.min_confidence_for_verify, 0.7);
        assert!(strategy.skip_info_severity);
        assert_eq!(strategy.batch_size, 50);
    }

    #[tokio::test]
    async fn skip_info_severity() {
        let engine = VerificationEngine::new();
        let finding = ManagedFinding::new(
            Finding::new(
                "Info",
                "desc",
                Severity::Info,
                VulnerabilityCategory::Other("test".into()),
            ),
            DetectionSource::Crawler,
        )
        .with_status(FindingStatus::New);

        let result = engine.verify_finding(&finding).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn summary() {
        let engine = VerificationEngine::new();
        let f1 = make_finding(
            "A",
            Severity::High,
            VulnerabilityCategory::Injection,
            FindingStatus::Confirmed,
        );
        let f2 = make_finding(
            "B",
            Severity::Low,
            VulnerabilityCategory::Xss,
            FindingStatus::FalsePositive,
        );

        engine.verify_finding(&f1).await.unwrap();
        engine.verify_finding(&f2).await.unwrap();

        let summary = engine.summary().await;
        assert_eq!(summary.total_verifications, 2);
        assert_eq!(summary.verified, 1);
        assert_eq!(summary.not_verified, 1);
    }

    #[test]
    fn summary_verification_rate() {
        let summary = VerificationSummary {
            total_verifications: 10,
            verified: 7,
            not_verified: 3,
            partially_verified: 0,
        };
        assert!((summary.verification_rate() - 0.7).abs() < 0.001);

        let empty = VerificationSummary::default();
        assert_eq!(empty.verification_rate(), 0.0);
    }

    #[test]
    fn outcome_display() {
        assert_eq!(VerificationOutcome::Verified.to_string(), "Verified");
        assert_eq!(
            VerificationOutcome::PartiallyVerified.to_string(),
            "Partially Verified"
        );
        assert_eq!(
            VerificationOutcome::UnableToVerify.to_string(),
            "Unable to Verify"
        );
    }

    #[tokio::test]
    async fn manual_review_method() {
        let engine = VerificationEngine::new();
        let finding = ManagedFinding::new(
            Finding::new(
                "Manual",
                "desc",
                Severity::Medium,
                VulnerabilityCategory::Other("test".into()),
            ),
            DetectionSource::Manual,
        )
        .with_status(FindingStatus::Investigating);

        let result = engine.verify_finding(&finding).await.unwrap();
        assert_eq!(result.method, VerificationMethod::ManualReview);
    }

    #[tokio::test]
    async fn duplicate_finding_partial() {
        let engine = VerificationEngine::new();
        let finding = make_finding(
            "Dup",
            Severity::Medium,
            VulnerabilityCategory::Xss,
            FindingStatus::Duplicate,
        );

        let result = engine.verify_finding(&finding).await.unwrap();
        assert_eq!(result.status, VerificationOutcome::PartiallyVerified);
    }
}
