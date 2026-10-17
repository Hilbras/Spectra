use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use spectra_core::Id;

use crate::StorageResult;

// =============================================================================
// Organization Repository
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationRecord {
    pub id: Id<OrganizationRecord>,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[async_trait]
pub trait OrganizationRepository: Send + Sync {
    async fn create(&self, org: &OrganizationRecord) -> StorageResult<OrganizationRecord>;
    async fn get(&self, id: &Id<OrganizationRecord>) -> StorageResult<Option<OrganizationRecord>>;
    async fn list(&self) -> StorageResult<Vec<OrganizationRecord>>;
    async fn update(&self, org: &OrganizationRecord) -> StorageResult<()>;
    async fn delete(&self, id: &Id<OrganizationRecord>) -> StorageResult<()>;
    async fn find_by_slug(&self, slug: &str) -> StorageResult<Option<OrganizationRecord>>;
}

// =============================================================================
// Project Repository
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectRecord {
    pub id: Id<ProjectRecord>,
    pub organization_id: Id<OrganizationRecord>,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

#[async_trait]
pub trait ProjectRepository: Send + Sync {
    async fn create(&self, project: &ProjectRecord) -> StorageResult<ProjectRecord>;
    async fn get(&self, id: &Id<ProjectRecord>) -> StorageResult<Option<ProjectRecord>>;
    async fn list_by_organization(
        &self,
        org_id: &Id<OrganizationRecord>,
    ) -> StorageResult<Vec<ProjectRecord>>;
    async fn update(&self, project: &ProjectRecord) -> StorageResult<()>;
    async fn delete(&self, id: &Id<ProjectRecord>) -> StorageResult<()>;
}

// =============================================================================
// Target Repository
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetRecord {
    pub id: Id<TargetRecord>,
    pub project_id: Id<ProjectRecord>,
    pub name: String,
    pub target_type: String,
    pub value: String,
    pub environment: String,
    pub active: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[async_trait]
pub trait TargetRepository: Send + Sync {
    async fn create(&self, target: &TargetRecord) -> StorageResult<TargetRecord>;
    async fn get(&self, id: &Id<TargetRecord>) -> StorageResult<Option<TargetRecord>>;
    async fn list_by_project(
        &self,
        project_id: &Id<ProjectRecord>,
    ) -> StorageResult<Vec<TargetRecord>>;
    async fn update(&self, target: &TargetRecord) -> StorageResult<()>;
    async fn delete(&self, id: &Id<TargetRecord>) -> StorageResult<()>;
}

// =============================================================================
// Scan Repository
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRecord {
    pub id: Id<ScanRecord>,
    pub target_id: Id<TargetRecord>,
    pub scan_type: String,
    pub status: String,
    pub progress: f64,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub error: Option<String>,
    pub created_at: String,
}

#[async_trait]
pub trait ScanRepository: Send + Sync {
    async fn create(&self, scan: &ScanRecord) -> StorageResult<ScanRecord>;
    async fn get(&self, id: &Id<ScanRecord>) -> StorageResult<Option<ScanRecord>>;
    async fn list(&self) -> StorageResult<Vec<ScanRecord>>;
    async fn update(&self, scan: &ScanRecord) -> StorageResult<()>;
    async fn delete(&self, id: &Id<ScanRecord>) -> StorageResult<()>;
    async fn list_by_target(&self, target_id: &Id<TargetRecord>) -> StorageResult<Vec<ScanRecord>>;
}

// =============================================================================
// Job Repository
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobRecord {
    pub id: Id<JobRecord>,
    pub scan_id: Id<ScanRecord>,
    pub job_type: String,
    pub status: String,
    pub priority: u32,
    pub payload: serde_json::Value,
    pub result: Option<serde_json::Value>,
    pub error: Option<String>,
    pub attempts: u32,
    pub max_attempts: u32,
    pub worker_id: Option<String>,
    pub queued_at: String,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
}

#[async_trait]
pub trait JobRepository: Send + Sync {
    async fn create(&self, job: &JobRecord) -> StorageResult<JobRecord>;
    async fn get(&self, id: &Id<JobRecord>) -> StorageResult<Option<JobRecord>>;
    async fn list_all(&self) -> StorageResult<Vec<JobRecord>>;
    async fn list_by_scan(&self, scan_id: &Id<ScanRecord>) -> StorageResult<Vec<JobRecord>>;
    async fn update(&self, job: &JobRecord) -> StorageResult<()>;
    async fn delete(&self, id: &Id<JobRecord>) -> StorageResult<()>;
    async fn list_pending(&self) -> StorageResult<Vec<JobRecord>>;
    async fn list_by_status(&self, status: &str) -> StorageResult<Vec<JobRecord>>;
}

// =============================================================================
// Finding Repository
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingRecord {
    pub id: Id<FindingRecord>,
    pub scan_id: Id<ScanRecord>,
    pub finding_type: String,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub status: String,
    pub confidence: f64,
    pub detection_source: String,
    pub verification_status: String,
    pub evidence_count: u32,
    pub created_at: String,
    pub updated_at: String,
}

#[async_trait]
pub trait FindingRepository: Send + Sync {
    async fn create(&self, finding: &FindingRecord) -> StorageResult<FindingRecord>;
    async fn get(&self, id: &Id<FindingRecord>) -> StorageResult<Option<FindingRecord>>;
    async fn list(&self) -> StorageResult<Vec<FindingRecord>>;
    async fn list_by_scan(&self, scan_id: &Id<ScanRecord>) -> StorageResult<Vec<FindingRecord>>;
    async fn list_by_severity(&self, severity: &str) -> StorageResult<Vec<FindingRecord>>;
    async fn list_by_status(&self, status: &str) -> StorageResult<Vec<FindingRecord>>;
    async fn update(&self, finding: &FindingRecord) -> StorageResult<()>;
    async fn delete(&self, id: &Id<FindingRecord>) -> StorageResult<()>;
    async fn count(&self) -> StorageResult<u64>;
    async fn count_by_severity(&self) -> StorageResult<Vec<(String, u64)>>;
}

// =============================================================================
// Observation Repository
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservationRecord {
    pub id: Id<ObservationRecord>,
    pub scan_id: Id<ScanRecord>,
    pub observation_type: String,
    pub severity: String,
    pub confidence: f64,
    pub title: String,
    pub description: String,
    pub metadata: serde_json::Value,
    pub created_at: String,
}

#[async_trait]
pub trait ObservationRepository: Send + Sync {
    async fn create(&self, obs: &ObservationRecord) -> StorageResult<ObservationRecord>;
    async fn get(&self, id: &Id<ObservationRecord>) -> StorageResult<Option<ObservationRecord>>;
    async fn list_by_scan(&self, scan_id: &Id<ScanRecord>)
        -> StorageResult<Vec<ObservationRecord>>;
    async fn delete(&self, id: &Id<ObservationRecord>) -> StorageResult<()>;
}

// =============================================================================
// Evidence Repository
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub id: Id<EvidenceRecord>,
    pub finding_id: Id<FindingRecord>,
    pub evidence_type: String,
    pub data_hash: String,
    pub content_type: String,
    pub size_bytes: u64,
    pub redacted: bool,
    pub storage_path: Option<String>,
    pub created_at: String,
}

#[async_trait]
pub trait EvidenceRepository: Send + Sync {
    async fn create(&self, evidence: &EvidenceRecord) -> StorageResult<EvidenceRecord>;
    async fn get(&self, id: &Id<EvidenceRecord>) -> StorageResult<Option<EvidenceRecord>>;
    async fn list_by_finding(
        &self,
        finding_id: &Id<FindingRecord>,
    ) -> StorageResult<Vec<EvidenceRecord>>;
    async fn delete(&self, id: &Id<EvidenceRecord>) -> StorageResult<()>;
}

// =============================================================================
// Worker Repository
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerRecord {
    pub id: String,
    pub hostname: String,
    pub status: String,
    pub capacity: u32,
    pub active_jobs: u32,
    pub started_at: String,
    pub last_heartbeat: String,
}

#[async_trait]
pub trait WorkerRepository: Send + Sync {
    async fn upsert(&self, worker: &WorkerRecord) -> StorageResult<()>;
    async fn get(&self, id: &str) -> StorageResult<Option<WorkerRecord>>;
    async fn list(&self) -> StorageResult<Vec<WorkerRecord>>;
    async fn delete(&self, id: &str) -> StorageResult<()>;
    async fn update_heartbeat(&self, id: &str) -> StorageResult<()>;
    async fn mark_stale(&self, threshold_secs: u64) -> StorageResult<u64>;
}

// =============================================================================
// Audit Repository
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub id: Id<AuditRecord>,
    pub actor: String,
    pub action: String,
    pub resource_type: String,
    pub resource_id: String,
    pub details: serde_json::Value,
    pub timestamp: String,
}

#[async_trait]
pub trait AuditRepository: Send + Sync {
    async fn create(&self, record: &AuditRecord) -> StorageResult<()>;
    async fn list_recent(&self, limit: u64) -> StorageResult<Vec<AuditRecord>>;
    async fn list_by_resource(
        &self,
        resource_type: &str,
        resource_id: &str,
    ) -> StorageResult<Vec<AuditRecord>>;
}

// =============================================================================
// Metrics Repository
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricRecord {
    pub name: String,
    pub value: f64,
    pub labels: serde_json::Value,
    pub timestamp: String,
}

#[async_trait]
pub trait MetricsRepository: Send + Sync {
    async fn record(&self, metric: &MetricRecord) -> StorageResult<()>;
    async fn query(&self, name: &str, since: &str) -> StorageResult<Vec<MetricRecord>>;
}
