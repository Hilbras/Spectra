use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::repositories::{
    AuditRecord, AuditRepository, EvidenceRecord, EvidenceRepository, FindingRecord,
    FindingRepository, JobRecord, JobRepository, MetricRecord, MetricsRepository,
    ObservationRecord, ObservationRepository, OrganizationRecord, OrganizationRepository,
    ProjectRecord, ProjectRepository, ScanRecord, ScanRepository, TargetRecord, TargetRepository,
    WorkerRecord, WorkerRepository,
};
use crate::StorageResult;

pub struct InMemoryOrganizationRepository {
    inner: Arc<RwLock<HashMap<String, OrganizationRecord>>>,
}

impl Default for InMemoryOrganizationRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryOrganizationRepository {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait::async_trait]
impl OrganizationRepository for InMemoryOrganizationRepository {
    async fn create(&self, org: &OrganizationRecord) -> StorageResult<OrganizationRecord> {
        let mut map = self.inner.write().await;
        map.insert(org.id.to_string(), org.clone());
        Ok(org.clone())
    }

    async fn get(
        &self,
        id: &spectra_core::Id<OrganizationRecord>,
    ) -> StorageResult<Option<OrganizationRecord>> {
        let map = self.inner.read().await;
        Ok(map.get(&id.to_string()).cloned())
    }

    async fn list(&self) -> StorageResult<Vec<OrganizationRecord>> {
        let map = self.inner.read().await;
        Ok(map.values().cloned().collect())
    }

    async fn update(&self, org: &OrganizationRecord) -> StorageResult<()> {
        let mut map = self.inner.write().await;
        map.insert(org.id.to_string(), org.clone());
        Ok(())
    }

    async fn delete(&self, id: &spectra_core::Id<OrganizationRecord>) -> StorageResult<()> {
        let mut map = self.inner.write().await;
        map.remove(&id.to_string());
        Ok(())
    }

    async fn find_by_slug(&self, slug: &str) -> StorageResult<Option<OrganizationRecord>> {
        let map = self.inner.read().await;
        Ok(map.values().find(|o| o.slug == slug).cloned())
    }
}

pub struct InMemoryProjectRepository {
    inner: Arc<RwLock<HashMap<String, ProjectRecord>>>,
}

impl Default for InMemoryProjectRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryProjectRepository {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait::async_trait]
impl ProjectRepository for InMemoryProjectRepository {
    async fn create(&self, project: &ProjectRecord) -> StorageResult<ProjectRecord> {
        let mut map = self.inner.write().await;
        map.insert(project.id.to_string(), project.clone());
        Ok(project.clone())
    }

    async fn get(
        &self,
        id: &spectra_core::Id<ProjectRecord>,
    ) -> StorageResult<Option<ProjectRecord>> {
        let map = self.inner.read().await;
        Ok(map.get(&id.to_string()).cloned())
    }

    async fn list_by_organization(
        &self,
        org_id: &spectra_core::Id<OrganizationRecord>,
    ) -> StorageResult<Vec<ProjectRecord>> {
        let map = self.inner.read().await;
        let org_str = org_id.to_string();
        Ok(map
            .values()
            .filter(|p| p.organization_id.to_string() == org_str)
            .cloned()
            .collect())
    }

    async fn update(&self, project: &ProjectRecord) -> StorageResult<()> {
        let mut map = self.inner.write().await;
        map.insert(project.id.to_string(), project.clone());
        Ok(())
    }

    async fn delete(&self, id: &spectra_core::Id<ProjectRecord>) -> StorageResult<()> {
        let mut map = self.inner.write().await;
        map.remove(&id.to_string());
        Ok(())
    }
}

pub struct InMemoryTargetRepository {
    inner: Arc<RwLock<HashMap<String, TargetRecord>>>,
}

impl Default for InMemoryTargetRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryTargetRepository {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait::async_trait]
impl TargetRepository for InMemoryTargetRepository {
    async fn create(&self, target: &TargetRecord) -> StorageResult<TargetRecord> {
        let mut map = self.inner.write().await;
        map.insert(target.id.to_string(), target.clone());
        Ok(target.clone())
    }

    async fn get(
        &self,
        id: &spectra_core::Id<TargetRecord>,
    ) -> StorageResult<Option<TargetRecord>> {
        let map = self.inner.read().await;
        Ok(map.get(&id.to_string()).cloned())
    }

    async fn list_by_project(
        &self,
        project_id: &spectra_core::Id<ProjectRecord>,
    ) -> StorageResult<Vec<TargetRecord>> {
        let map = self.inner.read().await;
        let proj_str = project_id.to_string();
        Ok(map
            .values()
            .filter(|t| t.project_id.to_string() == proj_str)
            .cloned()
            .collect())
    }

    async fn update(&self, target: &TargetRecord) -> StorageResult<()> {
        let mut map = self.inner.write().await;
        map.insert(target.id.to_string(), target.clone());
        Ok(())
    }

    async fn delete(&self, id: &spectra_core::Id<TargetRecord>) -> StorageResult<()> {
        let mut map = self.inner.write().await;
        map.remove(&id.to_string());
        Ok(())
    }
}

pub struct InMemoryScanRepository {
    inner: Arc<RwLock<HashMap<String, ScanRecord>>>,
}

impl Default for InMemoryScanRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryScanRepository {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait::async_trait]
impl ScanRepository for InMemoryScanRepository {
    async fn create(&self, scan: &ScanRecord) -> StorageResult<ScanRecord> {
        let mut map = self.inner.write().await;
        map.insert(scan.id.to_string(), scan.clone());
        Ok(scan.clone())
    }

    async fn get(&self, id: &spectra_core::Id<ScanRecord>) -> StorageResult<Option<ScanRecord>> {
        let map = self.inner.read().await;
        Ok(map.get(&id.to_string()).cloned())
    }

    async fn list(&self) -> StorageResult<Vec<ScanRecord>> {
        let map = self.inner.read().await;
        Ok(map.values().cloned().collect())
    }

    async fn update(&self, scan: &ScanRecord) -> StorageResult<()> {
        let mut map = self.inner.write().await;
        map.insert(scan.id.to_string(), scan.clone());
        Ok(())
    }

    async fn delete(&self, id: &spectra_core::Id<ScanRecord>) -> StorageResult<()> {
        let mut map = self.inner.write().await;
        map.remove(&id.to_string());
        Ok(())
    }

    async fn list_by_target(
        &self,
        target_id: &spectra_core::Id<TargetRecord>,
    ) -> StorageResult<Vec<ScanRecord>> {
        let map = self.inner.read().await;
        let target_str = target_id.to_string();
        Ok(map
            .values()
            .filter(|s| s.target_id.to_string() == target_str)
            .cloned()
            .collect())
    }
}

pub struct InMemoryJobRepository {
    inner: Arc<RwLock<HashMap<String, JobRecord>>>,
}

impl Default for InMemoryJobRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryJobRepository {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait::async_trait]
impl JobRepository for InMemoryJobRepository {
    async fn create(&self, job: &JobRecord) -> StorageResult<JobRecord> {
        let mut map = self.inner.write().await;
        map.insert(job.id.to_string(), job.clone());
        Ok(job.clone())
    }

    async fn get(&self, id: &spectra_core::Id<JobRecord>) -> StorageResult<Option<JobRecord>> {
        let map = self.inner.read().await;
        Ok(map.get(&id.to_string()).cloned())
    }

    async fn list_all(&self) -> StorageResult<Vec<JobRecord>> {
        let map = self.inner.read().await;
        Ok(map.values().cloned().collect())
    }

    async fn list_by_scan(
        &self,
        scan_id: &spectra_core::Id<ScanRecord>,
    ) -> StorageResult<Vec<JobRecord>> {
        let map = self.inner.read().await;
        let scan_str = scan_id.to_string();
        Ok(map
            .values()
            .filter(|j| j.scan_id.to_string() == scan_str)
            .cloned()
            .collect())
    }

    async fn update(&self, job: &JobRecord) -> StorageResult<()> {
        let mut map = self.inner.write().await;
        map.insert(job.id.to_string(), job.clone());
        Ok(())
    }

    async fn delete(&self, id: &spectra_core::Id<JobRecord>) -> StorageResult<()> {
        let mut map = self.inner.write().await;
        map.remove(&id.to_string());
        Ok(())
    }

    async fn list_pending(&self) -> StorageResult<Vec<JobRecord>> {
        let map = self.inner.read().await;
        Ok(map
            .values()
            .filter(|j| j.status == "queued")
            .cloned()
            .collect())
    }

    async fn list_by_status(&self, status: &str) -> StorageResult<Vec<JobRecord>> {
        let map = self.inner.read().await;
        Ok(map
            .values()
            .filter(|j| j.status == status)
            .cloned()
            .collect())
    }
}

pub struct InMemoryFindingRepository {
    inner: Arc<RwLock<HashMap<String, FindingRecord>>>,
}

impl Default for InMemoryFindingRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryFindingRepository {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait::async_trait]
impl FindingRepository for InMemoryFindingRepository {
    async fn create(&self, finding: &FindingRecord) -> StorageResult<FindingRecord> {
        let mut map = self.inner.write().await;
        map.insert(finding.id.to_string(), finding.clone());
        Ok(finding.clone())
    }

    async fn get(
        &self,
        id: &spectra_core::Id<FindingRecord>,
    ) -> StorageResult<Option<FindingRecord>> {
        let map = self.inner.read().await;
        Ok(map.get(&id.to_string()).cloned())
    }

    async fn list(&self) -> StorageResult<Vec<FindingRecord>> {
        let map = self.inner.read().await;
        Ok(map.values().cloned().collect())
    }

    async fn list_by_scan(
        &self,
        scan_id: &spectra_core::Id<ScanRecord>,
    ) -> StorageResult<Vec<FindingRecord>> {
        let map = self.inner.read().await;
        let scan_str = scan_id.to_string();
        Ok(map
            .values()
            .filter(|f| f.scan_id.to_string() == scan_str)
            .cloned()
            .collect())
    }

    async fn list_by_severity(&self, severity: &str) -> StorageResult<Vec<FindingRecord>> {
        let map = self.inner.read().await;
        Ok(map
            .values()
            .filter(|f| f.severity == severity)
            .cloned()
            .collect())
    }

    async fn list_by_status(&self, status: &str) -> StorageResult<Vec<FindingRecord>> {
        let map = self.inner.read().await;
        Ok(map
            .values()
            .filter(|f| f.status == status)
            .cloned()
            .collect())
    }

    async fn update(&self, finding: &FindingRecord) -> StorageResult<()> {
        let mut map = self.inner.write().await;
        map.insert(finding.id.to_string(), finding.clone());
        Ok(())
    }

    async fn delete(&self, id: &spectra_core::Id<FindingRecord>) -> StorageResult<()> {
        let mut map = self.inner.write().await;
        map.remove(&id.to_string());
        Ok(())
    }

    async fn count(&self) -> StorageResult<u64> {
        let map = self.inner.read().await;
        Ok(map.len() as u64)
    }

    async fn count_by_severity(&self) -> StorageResult<Vec<(String, u64)>> {
        let map = self.inner.read().await;
        let mut counts: HashMap<String, u64> = HashMap::new();
        for finding in map.values() {
            *counts.entry(finding.severity.clone()).or_insert(0) += 1;
        }
        Ok(counts.into_iter().collect())
    }
}

pub struct InMemoryObservationRepository {
    inner: Arc<RwLock<HashMap<String, ObservationRecord>>>,
}

impl Default for InMemoryObservationRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryObservationRepository {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait::async_trait]
impl ObservationRepository for InMemoryObservationRepository {
    async fn create(&self, obs: &ObservationRecord) -> StorageResult<ObservationRecord> {
        let mut map = self.inner.write().await;
        map.insert(obs.id.to_string(), obs.clone());
        Ok(obs.clone())
    }

    async fn get(
        &self,
        id: &spectra_core::Id<ObservationRecord>,
    ) -> StorageResult<Option<ObservationRecord>> {
        let map = self.inner.read().await;
        Ok(map.get(&id.to_string()).cloned())
    }

    async fn list_by_scan(
        &self,
        scan_id: &spectra_core::Id<ScanRecord>,
    ) -> StorageResult<Vec<ObservationRecord>> {
        let map = self.inner.read().await;
        let scan_str = scan_id.to_string();
        Ok(map
            .values()
            .filter(|o| o.scan_id.to_string() == scan_str)
            .cloned()
            .collect())
    }

    async fn delete(&self, id: &spectra_core::Id<ObservationRecord>) -> StorageResult<()> {
        let mut map = self.inner.write().await;
        map.remove(&id.to_string());
        Ok(())
    }
}

pub struct InMemoryEvidenceRepository {
    inner: Arc<RwLock<HashMap<String, EvidenceRecord>>>,
}

impl Default for InMemoryEvidenceRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryEvidenceRepository {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait::async_trait]
impl EvidenceRepository for InMemoryEvidenceRepository {
    async fn create(&self, evidence: &EvidenceRecord) -> StorageResult<EvidenceRecord> {
        let mut map = self.inner.write().await;
        map.insert(evidence.id.to_string(), evidence.clone());
        Ok(evidence.clone())
    }

    async fn get(
        &self,
        id: &spectra_core::Id<EvidenceRecord>,
    ) -> StorageResult<Option<EvidenceRecord>> {
        let map = self.inner.read().await;
        Ok(map.get(&id.to_string()).cloned())
    }

    async fn list_by_finding(
        &self,
        finding_id: &spectra_core::Id<FindingRecord>,
    ) -> StorageResult<Vec<EvidenceRecord>> {
        let map = self.inner.read().await;
        let finding_str = finding_id.to_string();
        Ok(map
            .values()
            .filter(|e| e.finding_id.to_string() == finding_str)
            .cloned()
            .collect())
    }

    async fn delete(&self, id: &spectra_core::Id<EvidenceRecord>) -> StorageResult<()> {
        let mut map = self.inner.write().await;
        map.remove(&id.to_string());
        Ok(())
    }
}

pub struct InMemoryWorkerRepository {
    inner: Arc<RwLock<HashMap<String, WorkerRecord>>>,
}

impl Default for InMemoryWorkerRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryWorkerRepository {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait::async_trait]
impl WorkerRepository for InMemoryWorkerRepository {
    async fn upsert(&self, worker: &WorkerRecord) -> StorageResult<()> {
        let mut map = self.inner.write().await;
        map.insert(worker.id.clone(), worker.clone());
        Ok(())
    }

    async fn get(&self, id: &str) -> StorageResult<Option<WorkerRecord>> {
        let map = self.inner.read().await;
        Ok(map.get(id).cloned())
    }

    async fn list(&self) -> StorageResult<Vec<WorkerRecord>> {
        let map = self.inner.read().await;
        Ok(map.values().cloned().collect())
    }

    async fn delete(&self, id: &str) -> StorageResult<()> {
        let mut map = self.inner.write().await;
        map.remove(id);
        Ok(())
    }

    async fn update_heartbeat(&self, id: &str) -> StorageResult<()> {
        let mut map = self.inner.write().await;
        if let Some(worker) = map.get_mut(id) {
            worker.last_heartbeat = chrono::Utc::now().to_rfc3339();
        }
        Ok(())
    }

    async fn mark_stale(&self, threshold_secs: u64) -> StorageResult<u64> {
        let mut map = self.inner.write().await;
        let mut count = 0;
        let now = chrono::Utc::now();
        for worker in map.values_mut() {
            if let Ok(heartbeat) = chrono::DateTime::parse_from_rfc3339(&worker.last_heartbeat) {
                if now.signed_duration_since(heartbeat).num_seconds() > threshold_secs as i64 {
                    worker.status = "offline".into();
                    count += 1;
                }
            }
        }
        Ok(count)
    }
}

pub struct InMemoryAuditRepository {
    inner: Arc<RwLock<Vec<AuditRecord>>>,
}

impl Default for InMemoryAuditRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryAuditRepository {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(Vec::new())),
        }
    }
}

#[async_trait::async_trait]
impl AuditRepository for InMemoryAuditRepository {
    async fn create(&self, record: &AuditRecord) -> StorageResult<()> {
        let mut vec = self.inner.write().await;
        vec.push(record.clone());
        Ok(())
    }

    async fn list_recent(&self, limit: u64) -> StorageResult<Vec<AuditRecord>> {
        let vec = self.inner.read().await;
        Ok(vec.iter().rev().take(limit as usize).cloned().collect())
    }

    async fn list_by_resource(
        &self,
        resource_type: &str,
        resource_id: &str,
    ) -> StorageResult<Vec<AuditRecord>> {
        let vec = self.inner.read().await;
        Ok(vec
            .iter()
            .filter(|r| r.resource_type == resource_type && r.resource_id == resource_id)
            .cloned()
            .collect())
    }
}

pub struct InMemoryMetricsRepository {
    inner: Arc<RwLock<Vec<MetricRecord>>>,
}

impl Default for InMemoryMetricsRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryMetricsRepository {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(Vec::new())),
        }
    }
}

#[async_trait::async_trait]
impl MetricsRepository for InMemoryMetricsRepository {
    async fn record(&self, metric: &MetricRecord) -> StorageResult<()> {
        let mut vec = self.inner.write().await;
        vec.push(metric.clone());
        Ok(())
    }

    async fn query(&self, name: &str, since: &str) -> StorageResult<Vec<MetricRecord>> {
        let vec = self.inner.read().await;
        Ok(vec
            .iter()
            .filter(|m| m.name == name && m.timestamp.as_str() >= since)
            .cloned()
            .collect())
    }
}
