use serde::{Deserialize, Serialize};
use spectra_core::Id;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;

/// Marker type for observation identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ObservationId;

#[derive(Debug, Error)]
pub enum ObservationError {
    #[error("Observation not found: {0}")]
    NotFound(String),
    #[error("Invalid observation data: {0}")]
    InvalidData(String),
    #[error("Storage error: {0}")]
    Storage(String),
}

pub type ObservationResult<T> = Result<T, ObservationError>;

/// The type/class of an observation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ObservationType {
    /// HTTP request/response pair
    HttpRequest,
    /// DNS resolution record
    DnsRecord,
    /// Port scan result
    PortScan,
    /// Service fingerprint
    ServiceFingerprint,
    /// Technology fingerprint
    TechnologyFingerprint,
    /// Directory/file discovery
    DirectoryDiscovery,
    /// Subdomain discovery
    SubdomainDiscovery,
    /// SSL/TLS certificate info
    CertificateInfo,
    /// Scanner output (raw finding candidate)
    ScannerOutput,
    /// Crawler-discovered link or form
    CrawlerDiscovery,
    /// Network traffic capture
    NetworkCapture,
    /// Screenshot
    Screenshot,
    /// Custom observation
    Custom(String),
}

impl std::fmt::Display for ObservationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HttpRequest => write!(f, "HTTP Request"),
            Self::DnsRecord => write!(f, "DNS Record"),
            Self::PortScan => write!(f, "Port Scan"),
            Self::ServiceFingerprint => write!(f, "Service Fingerprint"),
            Self::TechnologyFingerprint => write!(f, "Technology Fingerprint"),
            Self::DirectoryDiscovery => write!(f, "Directory Discovery"),
            Self::SubdomainDiscovery => write!(f, "Subdomain Discovery"),
            Self::CertificateInfo => write!(f, "Certificate Info"),
            Self::ScannerOutput => write!(f, "Scanner Output"),
            Self::CrawlerDiscovery => write!(f, "Crawler Discovery"),
            Self::NetworkCapture => write!(f, "Network Capture"),
            Self::Screenshot => write!(f, "Screenshot"),
            Self::Custom(s) => write!(f, "Custom: {}", s),
        }
    }
}

/// Severity level of an observation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ObservationSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for ObservationSeverity {
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

impl std::str::FromStr for ObservationSeverity {
    type Err = ObservationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "critical" => Ok(Self::Critical),
            "high" => Ok(Self::High),
            "medium" => Ok(Self::Medium),
            "low" => Ok(Self::Low),
            "info" => Ok(Self::Info),
            _ => Err(ObservationError::InvalidData(format!(
                "Invalid severity: {}",
                s
            ))),
        }
    }
}

/// An observation: a raw signal/data point collected during a scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub id: Id<ObservationId>,
    pub scan_id: String,
    pub scan_job_id: Option<String>,
    pub asset_id: Option<String>,
    pub endpoint_id: Option<String>,
    pub source: String,
    pub observation_type: ObservationType,
    pub data: serde_json::Value,
    pub confidence: f64,
    pub severity: Option<ObservationSeverity>,
    pub evidence_refs: Vec<String>,
    pub metadata: HashMap<String, serde_json::Value>,
    pub observed_at: String,
    pub created_at: String,
}

impl Observation {
    pub fn new(
        scan_id: impl Into<String>,
        source: impl Into<String>,
        observation_type: ObservationType,
        data: serde_json::Value,
    ) -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        Self {
            id: Id::new(),
            scan_id: scan_id.into(),
            scan_job_id: None,
            asset_id: None,
            endpoint_id: None,
            source: source.into(),
            observation_type,
            data,
            confidence: 0.0,
            severity: None,
            evidence_refs: Vec::new(),
            metadata: HashMap::new(),
            observed_at: now.clone(),
            created_at: now,
        }
    }

    pub fn with_scan_job_id(mut self, id: impl Into<String>) -> Self {
        self.scan_job_id = Some(id.into());
        self
    }

    pub fn with_asset_id(mut self, id: impl Into<String>) -> Self {
        self.asset_id = Some(id.into());
        self
    }

    pub fn with_endpoint_id(mut self, id: impl Into<String>) -> Self {
        self.endpoint_id = Some(id.into());
        self
    }

    pub fn with_confidence(mut self, confidence: f64) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }

    pub fn with_severity(mut self, severity: ObservationSeverity) -> Self {
        self.severity = Some(severity);
        self
    }

    pub fn with_evidence_ref(mut self, ref_id: impl Into<String>) -> Self {
        self.evidence_refs.push(ref_id.into());
        self
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }
}

/// Trait for storing and retrieving observations.
#[async_trait::async_trait]
pub trait ObservationStore: Send + Sync {
    async fn save(&self, observation: Observation) -> ObservationResult<()>;
    async fn get(&self, id: &str) -> ObservationResult<Observation>;
    async fn list_by_scan(&self, scan_id: &str) -> ObservationResult<Vec<Observation>>;
    async fn list_by_type(
        &self,
        scan_id: &str,
        observation_type: &ObservationType,
    ) -> ObservationResult<Vec<Observation>>;
    async fn list_by_severity(
        &self,
        scan_id: &str,
        severity: &ObservationSeverity,
    ) -> ObservationResult<Vec<Observation>>;
    async fn delete(&self, id: &str) -> ObservationResult<()>;
    async fn count(&self, scan_id: &str) -> ObservationResult<usize>;
}

/// In-memory observation store.
#[derive(Clone)]
pub struct InMemoryObservationStore {
    observations: Arc<tokio::sync::RwLock<HashMap<String, Observation>>>,
}

impl Default for InMemoryObservationStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryObservationStore {
    pub fn new() -> Self {
        Self {
            observations: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait::async_trait]
impl ObservationStore for InMemoryObservationStore {
    async fn save(&self, observation: Observation) -> ObservationResult<()> {
        let mut store = self.observations.write().await;
        store.insert(observation.id.to_string(), observation);
        Ok(())
    }

    async fn get(&self, id: &str) -> ObservationResult<Observation> {
        let store = self.observations.read().await;
        store
            .get(id)
            .cloned()
            .ok_or_else(|| ObservationError::NotFound(id.to_string()))
    }

    async fn list_by_scan(&self, scan_id: &str) -> ObservationResult<Vec<Observation>> {
        let store = self.observations.read().await;
        Ok(store
            .values()
            .filter(|o| o.scan_id == scan_id)
            .cloned()
            .collect())
    }

    async fn list_by_type(
        &self,
        scan_id: &str,
        observation_type: &ObservationType,
    ) -> ObservationResult<Vec<Observation>> {
        let store = self.observations.read().await;
        Ok(store
            .values()
            .filter(|o| o.scan_id == scan_id && o.observation_type == *observation_type)
            .cloned()
            .collect())
    }

    async fn list_by_severity(
        &self,
        scan_id: &str,
        severity: &ObservationSeverity,
    ) -> ObservationResult<Vec<Observation>> {
        let store = self.observations.read().await;
        Ok(store
            .values()
            .filter(|o| o.scan_id == scan_id && o.severity.as_ref() == Some(severity))
            .cloned()
            .collect())
    }

    async fn delete(&self, id: &str) -> ObservationResult<()> {
        let mut store = self.observations.write().await;
        store
            .remove(id)
            .ok_or_else(|| ObservationError::NotFound(id.to_string()))?;
        Ok(())
    }

    async fn count(&self, scan_id: &str) -> ObservationResult<usize> {
        let store = self.observations.read().await;
        Ok(store.values().filter(|o| o.scan_id == scan_id).count())
    }
}

/// Observation engine that orchestrates observation creation and storage.
pub struct ObservationEngine<S: ObservationStore> {
    store: S,
}

impl<S: ObservationStore> ObservationEngine<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    /// Records a new observation.
    pub async fn record(
        &self,
        scan_id: impl Into<String>,
        source: impl Into<String>,
        observation_type: ObservationType,
        data: serde_json::Value,
    ) -> ObservationResult<Observation> {
        let observation = Observation::new(scan_id, source, observation_type, data);
        self.store.save(observation.clone()).await?;
        Ok(observation)
    }

    /// Records an observation with full configuration.
    pub async fn record_with(&self, observation: Observation) -> ObservationResult<()> {
        self.store.save(observation).await
    }

    /// Gets all observations for a scan.
    pub async fn get_scan_observations(
        &self,
        scan_id: &str,
    ) -> ObservationResult<Vec<Observation>> {
        self.store.list_by_scan(scan_id).await
    }

    /// Gets observations filtered by type.
    pub async fn get_by_type(
        &self,
        scan_id: &str,
        observation_type: &ObservationType,
    ) -> ObservationResult<Vec<Observation>> {
        self.store.list_by_type(scan_id, observation_type).await
    }

    /// Gets observations filtered by severity.
    pub async fn get_by_severity(
        &self,
        scan_id: &str,
        severity: &ObservationSeverity,
    ) -> ObservationResult<Vec<Observation>> {
        self.store.list_by_severity(scan_id, severity).await
    }

    /// Gets high-confidence observations above a threshold.
    pub async fn get_high_confidence(
        &self,
        scan_id: &str,
        threshold: f64,
    ) -> ObservationResult<Vec<Observation>> {
        let store = &self.store;
        let all = store.list_by_scan(scan_id).await?;
        Ok(all
            .into_iter()
            .filter(|o| o.confidence >= threshold)
            .collect())
    }

    /// Deletes an observation.
    pub async fn delete(&self, id: &str) -> ObservationResult<()> {
        self.store.delete(id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_observation() -> Observation {
        Observation::new(
            "scan-123",
            "sqli-scanner",
            ObservationType::ScannerOutput,
            serde_json::json!({
                "url": "https://example.com/page?id=1",
                "payload": "' OR 1=1--",
                "response_length": 1234
            }),
        )
    }

    #[test]
    fn observation_creation() {
        let obs = test_observation();
        assert_eq!(obs.scan_id, "scan-123");
        assert_eq!(obs.source, "sqli-scanner");
        assert_eq!(obs.observation_type, ObservationType::ScannerOutput);
        assert_eq!(obs.confidence, 0.0);
        assert!(obs.severity.is_none());
    }

    #[test]
    fn observation_builder() {
        let obs = Observation::new(
            "scan-1",
            "crawler",
            ObservationType::CrawlerDiscovery,
            serde_json::json!({}),
        )
        .with_scan_job_id("job-1")
        .with_asset_id("asset-1")
        .with_endpoint_id("ep-1")
        .with_confidence(0.85)
        .with_severity(ObservationSeverity::High)
        .with_evidence_ref("ev-1")
        .with_evidence_ref("ev-2")
        .with_metadata("key", serde_json::json!("value"));

        assert_eq!(obs.scan_job_id, Some("job-1".into()));
        assert_eq!(obs.asset_id, Some("asset-1".into()));
        assert_eq!(obs.endpoint_id, Some("ep-1".into()));
        assert_eq!(obs.confidence, 0.85);
        assert_eq!(obs.severity, Some(ObservationSeverity::High));
        assert_eq!(obs.evidence_refs.len(), 2);
        assert_eq!(obs.metadata.get("key"), Some(&serde_json::json!("value")));
    }

    #[test]
    fn confidence_clamped() {
        let obs = Observation::new(
            "scan-1",
            "test",
            ObservationType::ScannerOutput,
            serde_json::json!({}),
        )
        .with_confidence(1.5);
        assert_eq!(obs.confidence, 1.0);

        let obs2 = Observation::new(
            "scan-1",
            "test",
            ObservationType::ScannerOutput,
            serde_json::json!({}),
        )
        .with_confidence(-0.5);
        assert_eq!(obs2.confidence, 0.0);
    }

    #[test]
    fn observation_type_display() {
        assert_eq!(ObservationType::HttpRequest.to_string(), "HTTP Request");
        assert_eq!(ObservationType::DnsRecord.to_string(), "DNS Record");
        assert_eq!(ObservationType::PortScan.to_string(), "Port Scan");
        assert_eq!(
            ObservationType::Custom("test".into()).to_string(),
            "Custom: test"
        );
    }

    #[test]
    fn severity_display() {
        assert_eq!(ObservationSeverity::Critical.to_string(), "Critical");
        assert_eq!(ObservationSeverity::Info.to_string(), "Info");
    }

    #[test]
    fn severity_from_str() {
        assert_eq!(
            "high".parse::<ObservationSeverity>().unwrap(),
            ObservationSeverity::High
        );
        assert_eq!(
            "MEDIUM".parse::<ObservationSeverity>().unwrap(),
            ObservationSeverity::Medium
        );
        assert!("invalid".parse::<ObservationSeverity>().is_err());
    }

    #[test]
    fn severity_ordering() {
        assert!(ObservationSeverity::Critical < ObservationSeverity::High);
        assert!(ObservationSeverity::High < ObservationSeverity::Medium);
        assert!(ObservationSeverity::Medium < ObservationSeverity::Low);
        assert!(ObservationSeverity::Low < ObservationSeverity::Info);
    }

    #[tokio::test]
    async fn in_memory_store_save_and_get() {
        let store = InMemoryObservationStore::new();
        let obs = test_observation();
        let id = obs.id.to_string();

        store.save(obs).await.unwrap();
        let found = store.get(&id).await.unwrap();
        assert_eq!(found.source, "sqli-scanner");
    }

    #[tokio::test]
    async fn in_memory_store_not_found() {
        let store = InMemoryObservationStore::new();
        assert!(store.get("nonexistent").await.is_err());
    }

    #[tokio::test]
    async fn in_memory_store_list_by_scan() {
        let store = InMemoryObservationStore::new();
        store.save(test_observation()).await.unwrap();
        store
            .save(Observation::new(
                "scan-123",
                "xss-scanner",
                ObservationType::ScannerOutput,
                serde_json::json!({}),
            ))
            .await
            .unwrap();
        store
            .save(Observation::new(
                "scan-456",
                "sqli-scanner",
                ObservationType::ScannerOutput,
                serde_json::json!({}),
            ))
            .await
            .unwrap();

        let results = store.list_by_scan("scan-123").await.unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn in_memory_store_list_by_type() {
        let store = InMemoryObservationStore::new();
        store.save(test_observation()).await.unwrap();
        store
            .save(Observation::new(
                "scan-123",
                "crawler",
                ObservationType::CrawlerDiscovery,
                serde_json::json!({}),
            ))
            .await
            .unwrap();

        let results = store
            .list_by_type("scan-123", &ObservationType::ScannerOutput)
            .await
            .unwrap();
        assert_eq!(results.len(), 1);
    }

    #[tokio::test]
    async fn in_memory_store_list_by_severity() {
        let store = InMemoryObservationStore::new();
        store
            .save(
                test_observation()
                    .with_severity(ObservationSeverity::High)
                    .clone(),
            )
            .await
            .unwrap();
        store
            .save(
                Observation::new(
                    "scan-123",
                    "xss",
                    ObservationType::ScannerOutput,
                    serde_json::json!({}),
                )
                .with_severity(ObservationSeverity::Low)
                .clone(),
            )
            .await
            .unwrap();

        let results = store
            .list_by_severity("scan-123", &ObservationSeverity::High)
            .await
            .unwrap();
        assert_eq!(results.len(), 1);
    }

    #[tokio::test]
    async fn in_memory_store_delete() {
        let store = InMemoryObservationStore::new();
        let obs = test_observation();
        let id = obs.id.to_string();
        store.save(obs).await.unwrap();
        store.delete(&id).await.unwrap();
        assert!(store.get(&id).await.is_err());
    }

    #[tokio::test]
    async fn in_memory_store_delete_not_found() {
        let store = InMemoryObservationStore::new();
        assert!(store.delete("nonexistent").await.is_err());
    }

    #[tokio::test]
    async fn in_memory_store_count() {
        let store = InMemoryObservationStore::new();
        store.save(test_observation()).await.unwrap();
        assert_eq!(store.count("scan-123").await.unwrap(), 1);
        assert_eq!(store.count("scan-999").await.unwrap(), 0);
    }

    #[tokio::test]
    async fn observation_engine_record() {
        let store = InMemoryObservationStore::new();
        let engine = ObservationEngine::new(store);

        let obs = engine
            .record(
                "scan-1",
                "port-scanner",
                ObservationType::PortScan,
                serde_json::json!({"ports": [80, 443]}),
            )
            .await
            .unwrap();

        assert_eq!(obs.source, "port-scanner");
        let all = engine.get_scan_observations("scan-1").await.unwrap();
        assert_eq!(all.len(), 1);
    }

    #[tokio::test]
    async fn observation_engine_get_high_confidence() {
        let store = InMemoryObservationStore::new();
        let engine = ObservationEngine::new(store);

        engine
            .record_with(
                Observation::new(
                    "scan-1",
                    "sqli",
                    ObservationType::ScannerOutput,
                    serde_json::json!({}),
                )
                .with_confidence(0.9),
            )
            .await
            .unwrap();

        engine
            .record_with(
                Observation::new(
                    "scan-1",
                    "xss",
                    ObservationType::ScannerOutput,
                    serde_json::json!({}),
                )
                .with_confidence(0.3),
            )
            .await
            .unwrap();

        let high = engine.get_high_confidence("scan-1", 0.5).await.unwrap();
        assert_eq!(high.len(), 1);
        assert_eq!(high[0].source, "sqli");
    }

    #[tokio::test]
    async fn observation_engine_delete() {
        let store = InMemoryObservationStore::new();
        let engine = ObservationEngine::new(store);

        let obs = engine
            .record(
                "scan-1",
                "test",
                ObservationType::Screenshot,
                serde_json::json!({}),
            )
            .await
            .unwrap();

        engine.delete(&obs.id.to_string()).await.unwrap();
        assert!(engine
            .get_scan_observations("scan-1")
            .await
            .unwrap()
            .is_empty());
    }
}
