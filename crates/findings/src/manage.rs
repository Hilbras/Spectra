use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::{
    FindingStatus, FindingsError, FindingsManager, FindingsReport, FindingsResult, ManagedFinding,
    Severity,
};
use spectra_core::Id;
use spectra_target::TargetId;

/// In-memory findings manager for testing and development.
pub struct InMemoryFindingsManager {
    findings: Arc<RwLock<HashMap<String, ManagedFinding>>>,
}

impl InMemoryFindingsManager {
    pub fn new() -> Self {
        Self {
            findings: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Count total findings.
    pub async fn count(&self) -> usize {
        self.findings.read().await.len()
    }

    /// Count findings by severity.
    pub async fn count_by_severity(&self, severity: &Severity) -> usize {
        self.findings
            .read()
            .await
            .values()
            .filter(|f| &f.finding.severity == severity)
            .count()
    }

    /// Count findings by status.
    pub async fn count_by_status(&self, status: &FindingStatus) -> usize {
        self.findings
            .read()
            .await
            .values()
            .filter(|f| &f.status == status)
            .count()
    }

    /// List findings filtered by severity.
    pub async fn list_by_severity(
        &self,
        severity: &Severity,
    ) -> FindingsResult<Vec<ManagedFinding>> {
        Ok(self
            .findings
            .read()
            .await
            .values()
            .filter(|f| &f.finding.severity == severity)
            .cloned()
            .collect())
    }

    /// List findings filtered by status.
    pub async fn list_by_status(
        &self,
        status: &FindingStatus,
    ) -> FindingsResult<Vec<ManagedFinding>> {
        Ok(self
            .findings
            .read()
            .await
            .values()
            .filter(|f| &f.status == status)
            .cloned()
            .collect())
    }

    /// Delete a finding.
    pub async fn delete(&self, id: &str) -> FindingsResult<()> {
        self.findings
            .write()
            .await
            .remove(id)
            .ok_or_else(|| FindingsError::NotFound(id.to_string()))?;
        Ok(())
    }

    /// Check if a finding exists.
    pub async fn exists(&self, id: &str) -> bool {
        self.findings.read().await.contains_key(id)
    }

    /// Get all finding IDs.
    pub async fn ids(&self) -> Vec<String> {
        self.findings.read().await.keys().cloned().collect()
    }

    /// Get findings with highest severity.
    pub async fn critical_findings(&self) -> FindingsResult<Vec<ManagedFinding>> {
        self.list_by_severity(&Severity::Critical).await
    }

    /// Get total evidence count across all findings.
    pub async fn total_evidence_count(&self) -> usize {
        self.findings
            .read()
            .await
            .values()
            .map(|f| f.notes.len())
            .sum()
    }
}

impl Default for InMemoryFindingsManager {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl FindingsManager for InMemoryFindingsManager {
    async fn save_finding(&self, finding: ManagedFinding) -> FindingsResult<()> {
        let id = finding.finding.id.to_string();
        self.findings.write().await.insert(id, finding);
        Ok(())
    }

    async fn get_finding(&self, id: &str) -> FindingsResult<ManagedFinding> {
        self.findings
            .read()
            .await
            .get(id)
            .cloned()
            .ok_or_else(|| FindingsError::NotFound(id.to_string()))
    }

    async fn list_findings(&self, target_id: &Id<TargetId>) -> FindingsResult<Vec<ManagedFinding>> {
        let findings = self.findings.read().await;
        Ok(findings
            .values()
            .filter(|f| f.finding.id.to_string() == target_id.to_string())
            .cloned()
            .collect())
    }

    async fn update_status(&self, id: &str, status: FindingStatus) -> FindingsResult<()> {
        let mut findings = self.findings.write().await;
        let finding = findings
            .get_mut(id)
            .ok_or_else(|| FindingsError::NotFound(id.to_string()))?;
        finding.status = status;
        Ok(())
    }

    async fn generate_report(&self, target_id: &Id<TargetId>) -> FindingsResult<FindingsReport> {
        let findings = self.list_findings(target_id).await?;
        let mut report = FindingsReport::new(target_id.clone());
        for finding in findings {
            report.add_finding(finding);
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DetectionSource, Severity};
    use spectra_scanner::{Finding, VulnerabilityCategory};

    #[tokio::test]
    async fn save_and_get_finding() {
        let manager = InMemoryFindingsManager::new();
        let finding = ManagedFinding::new(
            Finding::new(
                "Test",
                "desc",
                Severity::High,
                VulnerabilityCategory::Injection,
            ),
            DetectionSource::SqlInjectionScanner,
        );
        let id = finding.finding.id.to_string();

        manager.save_finding(finding).await.unwrap();
        let retrieved = manager.get_finding(&id).await.unwrap();
        assert_eq!(retrieved.finding.title, "Test");
    }

    #[tokio::test]
    async fn update_finding_status() {
        let manager = InMemoryFindingsManager::new();
        let finding = ManagedFinding::new(
            Finding::new("Test", "desc", Severity::Low, VulnerabilityCategory::Xss),
            DetectionSource::Manual,
        );
        let id = finding.finding.id.to_string();

        manager.save_finding(finding).await.unwrap();
        manager
            .update_status(&id, FindingStatus::Confirmed)
            .await
            .unwrap();

        let retrieved = manager.get_finding(&id).await.unwrap();
        assert_eq!(retrieved.status, FindingStatus::Confirmed);
    }

    #[tokio::test]
    async fn get_nonexistent_finding() {
        let manager = InMemoryFindingsManager::new();
        let result = manager.get_finding("nonexistent").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn count_findings() {
        let manager = InMemoryFindingsManager::new();
        assert_eq!(manager.count().await, 0);

        manager
            .save_finding(ManagedFinding::new(
                Finding::new(
                    "A",
                    "desc",
                    Severity::High,
                    VulnerabilityCategory::Injection,
                ),
                DetectionSource::SqlInjectionScanner,
            ))
            .await
            .unwrap();

        assert_eq!(manager.count().await, 1);
    }

    #[tokio::test]
    async fn count_by_severity() {
        let manager = InMemoryFindingsManager::new();
        manager
            .save_finding(ManagedFinding::new(
                Finding::new(
                    "A",
                    "desc",
                    Severity::High,
                    VulnerabilityCategory::Injection,
                ),
                DetectionSource::SqlInjectionScanner,
            ))
            .await
            .unwrap();
        manager
            .save_finding(ManagedFinding::new(
                Finding::new("B", "desc", Severity::Low, VulnerabilityCategory::Xss),
                DetectionSource::XssScanner,
            ))
            .await
            .unwrap();

        assert_eq!(manager.count_by_severity(&Severity::High).await, 1);
        assert_eq!(manager.count_by_severity(&Severity::Low).await, 1);
        assert_eq!(manager.count_by_severity(&Severity::Critical).await, 0);
    }

    #[tokio::test]
    async fn count_by_status() {
        let manager = InMemoryFindingsManager::new();
        let f1 = ManagedFinding::new(
            Finding::new(
                "A",
                "desc",
                Severity::High,
                VulnerabilityCategory::Injection,
            ),
            DetectionSource::SqlInjectionScanner,
        );
        let f2 = ManagedFinding::new(
            Finding::new("B", "desc", Severity::Low, VulnerabilityCategory::Xss),
            DetectionSource::XssScanner,
        );
        let id1 = f1.finding.id.to_string();
        let id2 = f2.finding.id.to_string();

        manager.save_finding(f1).await.unwrap();
        manager.save_finding(f2).await.unwrap();
        manager
            .update_status(&id1, FindingStatus::Confirmed)
            .await
            .unwrap();

        assert_eq!(manager.count_by_status(&FindingStatus::Confirmed).await, 1);
        assert_eq!(manager.count_by_status(&FindingStatus::New).await, 1);
    }

    #[tokio::test]
    async fn list_by_severity() {
        let manager = InMemoryFindingsManager::new();
        manager
            .save_finding(ManagedFinding::new(
                Finding::new(
                    "A",
                    "desc",
                    Severity::Critical,
                    VulnerabilityCategory::Injection,
                ),
                DetectionSource::SqlInjectionScanner,
            ))
            .await
            .unwrap();
        manager
            .save_finding(ManagedFinding::new(
                Finding::new("B", "desc", Severity::Critical, VulnerabilityCategory::Xss),
                DetectionSource::XssScanner,
            ))
            .await
            .unwrap();
        manager
            .save_finding(ManagedFinding::new(
                Finding::new("C", "desc", Severity::Low, VulnerabilityCategory::Xss),
                DetectionSource::XssScanner,
            ))
            .await
            .unwrap();

        let critical = manager.list_by_severity(&Severity::Critical).await.unwrap();
        assert_eq!(critical.len(), 2);
    }

    #[tokio::test]
    async fn list_by_status() {
        let manager = InMemoryFindingsManager::new();
        let f1 = ManagedFinding::new(
            Finding::new(
                "A",
                "desc",
                Severity::High,
                VulnerabilityCategory::Injection,
            ),
            DetectionSource::SqlInjectionScanner,
        );
        let id1 = f1.finding.id.to_string();
        manager.save_finding(f1).await.unwrap();
        manager
            .update_status(&id1, FindingStatus::Fixed)
            .await
            .unwrap();

        manager
            .save_finding(ManagedFinding::new(
                Finding::new("B", "desc", Severity::Low, VulnerabilityCategory::Xss),
                DetectionSource::XssScanner,
            ))
            .await
            .unwrap();

        let fixed = manager.list_by_status(&FindingStatus::Fixed).await.unwrap();
        assert_eq!(fixed.len(), 1);
    }

    #[tokio::test]
    async fn delete_finding() {
        let manager = InMemoryFindingsManager::new();
        let finding = ManagedFinding::new(
            Finding::new(
                "Test",
                "desc",
                Severity::High,
                VulnerabilityCategory::Injection,
            ),
            DetectionSource::SqlInjectionScanner,
        );
        let id = finding.finding.id.to_string();
        manager.save_finding(finding).await.unwrap();
        assert!(manager.exists(&id).await);

        manager.delete(&id).await.unwrap();
        assert!(!manager.exists(&id).await);
    }

    #[tokio::test]
    async fn delete_nonexistent() {
        let manager = InMemoryFindingsManager::new();
        assert!(manager.delete("nope").await.is_err());
    }

    #[tokio::test]
    async fn ids() {
        let manager = InMemoryFindingsManager::new();
        manager
            .save_finding(ManagedFinding::new(
                Finding::new(
                    "A",
                    "desc",
                    Severity::High,
                    VulnerabilityCategory::Injection,
                ),
                DetectionSource::SqlInjectionScanner,
            ))
            .await
            .unwrap();

        let ids = manager.ids().await;
        assert_eq!(ids.len(), 1);
    }

    #[tokio::test]
    async fn critical_findings() {
        let manager = InMemoryFindingsManager::new();
        manager
            .save_finding(ManagedFinding::new(
                Finding::new(
                    "A",
                    "desc",
                    Severity::Critical,
                    VulnerabilityCategory::Injection,
                ),
                DetectionSource::SqlInjectionScanner,
            ))
            .await
            .unwrap();
        manager
            .save_finding(ManagedFinding::new(
                Finding::new("B", "desc", Severity::High, VulnerabilityCategory::Xss),
                DetectionSource::XssScanner,
            ))
            .await
            .unwrap();

        let critical = manager.critical_findings().await.unwrap();
        assert_eq!(critical.len(), 1);
        assert_eq!(critical[0].finding.title, "A");
    }

    #[tokio::test]
    async fn total_evidence_count() {
        let manager = InMemoryFindingsManager::new();
        let mut f1 = ManagedFinding::new(
            Finding::new(
                "A",
                "desc",
                Severity::High,
                VulnerabilityCategory::Injection,
            ),
            DetectionSource::SqlInjectionScanner,
        );
        f1.add_note("user1", "note1");
        f1.add_note("user1", "note2");
        manager.save_finding(f1).await.unwrap();

        let mut f2 = ManagedFinding::new(
            Finding::new("B", "desc", Severity::Low, VulnerabilityCategory::Xss),
            DetectionSource::XssScanner,
        );
        f2.add_note("user2", "note3");
        manager.save_finding(f2).await.unwrap();

        assert_eq!(manager.total_evidence_count().await, 3);
    }
}
