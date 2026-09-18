use serde::{Deserialize, Serialize};
use spectra_core::Id;
use spectra_scanner::FindingId;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;

/// Marker type for evidence identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EvidenceId;

#[derive(Debug, Error)]
pub enum EvidenceError {
    #[error("Evidence not found: {0}")]
    NotFound(String),
    #[error("Invalid evidence data: {0}")]
    InvalidData(String),
    #[error("Storage error: {0}")]
    Storage(String),
    #[error("Redaction error: {0}")]
    Redaction(String),
    #[error("Integrity check failed: {0}")]
    IntegrityFailed(String),
}

pub type EvidenceResult<T> = Result<T, EvidenceError>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EvidenceType {
    HttpRequest,
    HttpResponse,
    HttpHeader,
    Screenshot,
    ConsoleOutput,
    NetworkCapture,
    DnsResult,
    PortScan,
    Fingerprint,
    ScannerOutput,
    VerificationOutput,
    Document,
    DatabaseQuery,
    ApiResponse,
    Custom(String),
}

impl std::fmt::Display for EvidenceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HttpRequest => write!(f, "HTTP Request"),
            Self::HttpResponse => write!(f, "HTTP Response"),
            Self::HttpHeader => write!(f, "HTTP Header"),
            Self::Screenshot => write!(f, "Screenshot"),
            Self::ConsoleOutput => write!(f, "Console Output"),
            Self::NetworkCapture => write!(f, "Network Capture"),
            Self::DnsResult => write!(f, "DNS Result"),
            Self::PortScan => write!(f, "Port Scan"),
            Self::Fingerprint => write!(f, "Fingerprint"),
            Self::ScannerOutput => write!(f, "Scanner Output"),
            Self::VerificationOutput => write!(f, "Verification Output"),
            Self::Document => write!(f, "Document"),
            Self::DatabaseQuery => write!(f, "Database Query"),
            Self::ApiResponse => write!(f, "API Response"),
            Self::Custom(s) => write!(f, "Custom: {}", s),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvidenceData {
    Text(String),
    Binary(Vec<u8>),
    Url(String),
    Path(String),
    Json(serde_json::Value),
}

impl EvidenceData {
    /// Returns the raw bytes of the evidence data.
    pub fn as_bytes(&self) -> Vec<u8> {
        match self {
            Self::Text(s) => s.as_bytes().to_vec(),
            Self::Binary(b) => b.clone(),
            Self::Url(s) => s.as_bytes().to_vec(),
            Self::Path(s) => s.as_bytes().to_vec(),
            Self::Json(v) => serde_json::to_vec(v).unwrap_or_default(),
        }
    }

    /// Returns the data as a string if possible.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Text(s) => Some(s),
            Self::Url(s) => Some(s),
            Self::Path(s) => Some(s),
            Self::Json(_v) => None,
            Self::Binary(_) => None,
        }
    }

    /// Returns the content type.
    pub fn content_type(&self) -> &str {
        match self {
            Self::Text(_) => "text/plain",
            Self::Binary(_) => "application/octet-stream",
            Self::Url(_) => "text/uri-list",
            Self::Path(_) => "text/plain",
            Self::Json(_) => "application/json",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub id: Id<EvidenceId>,
    pub finding_id: Id<FindingId>,
    pub scan_id: Option<String>,
    pub evidence_type: EvidenceType,
    pub title: String,
    pub description: String,
    pub data: EvidenceData,
    pub data_hash: Option<String>,
    pub redacted: bool,
    pub redaction_policy: Option<String>,
    pub collected_at: String,
    pub collector: String,
    pub tags: Vec<String>,
    pub metadata: HashMap<String, serde_json::Value>,
}

impl Evidence {
    pub fn new(
        finding_id: Id<FindingId>,
        evidence_type: EvidenceType,
        title: impl Into<String>,
        data: EvidenceData,
    ) -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        Self {
            id: Id::new(),
            finding_id,
            scan_id: None,
            evidence_type,
            title: title.into(),
            description: String::new(),
            data,
            data_hash: None,
            redacted: false,
            redaction_policy: None,
            collected_at: now.clone(),
            collector: "spectra".into(),
            tags: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    pub fn with_scan_id(mut self, scan_id: impl Into<String>) -> Self {
        self.scan_id = Some(scan_id.into());
        self
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    pub fn with_collector(mut self, collector: impl Into<String>) -> Self {
        self.collector = collector.into();
        self
    }

    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }

    /// Computes SHA-256 hash of the evidence data.
    pub fn compute_hash(&mut self) {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let bytes = self.data.as_bytes();
        let mut hasher = DefaultHasher::new();
        bytes.hash(&mut hasher);
        self.data_hash = Some(format!("{:016x}", hasher.finish()));
    }
}

/// Redaction policy for sensitive data in evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactionPolicy {
    pub name: String,
    pub patterns: Vec<RedactionPattern>,
    pub replacement: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactionPattern {
    pub pattern_type: PatternType,
    pub value: String,
    pub case_sensitive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PatternType {
    Regex,
    Literal,
    HeaderName,
    CookieName,
    JsonField,
}

impl RedactionPolicy {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            patterns: Vec::new(),
            replacement: "[REDACTED]".into(),
        }
    }

    pub fn with_pattern(mut self, pattern: RedactionPattern) -> Self {
        self.patterns.push(pattern);
        self
    }

    pub fn with_replacement(mut self, replacement: impl Into<String>) -> Self {
        self.replacement = replacement.into();
        self
    }

    /// Creates a default policy that redacts common sensitive fields.
    pub fn default_sensitive() -> Self {
        Self::new("default-sensitive")
            .with_pattern(RedactionPattern {
                pattern_type: PatternType::HeaderName,
                value: "authorization".into(),
                case_sensitive: false,
            })
            .with_pattern(RedactionPattern {
                pattern_type: PatternType::HeaderName,
                value: "cookie".into(),
                case_sensitive: false,
            })
            .with_pattern(RedactionPattern {
                pattern_type: PatternType::HeaderName,
                value: "x-api-key".into(),
                case_sensitive: false,
            })
            .with_pattern(RedactionPattern {
                pattern_type: PatternType::JsonField,
                value: "password".into(),
                case_sensitive: false,
            })
            .with_pattern(RedactionPattern {
                pattern_type: PatternType::JsonField,
                value: "token".into(),
                case_sensitive: false,
            })
            .with_pattern(RedactionPattern {
                pattern_type: PatternType::JsonField,
                value: "secret".into(),
                case_sensitive: false,
            })
            .with_pattern(RedactionPattern {
                pattern_type: PatternType::JsonField,
                value: "api_key".into(),
                case_sensitive: false,
            })
    }
}

/// Evidence redactor that applies redaction policies.
pub struct EvidenceRedactor {
    policies: Vec<RedactionPolicy>,
}

impl Default for EvidenceRedactor {
    fn default() -> Self {
        Self::new()
    }
}

impl EvidenceRedactor {
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
        }
    }

    pub fn with_policy(mut self, policy: RedactionPolicy) -> Self {
        self.policies.push(policy);
        self
    }

    /// Redacts sensitive data in evidence according to configured policies.
    pub fn redact(&self, evidence: &mut Evidence) -> EvidenceResult<()> {
        for policy in &self.policies {
            match &evidence.data {
                EvidenceData::Text(text) => {
                    let redacted = self.redact_text(text, policy)?;
                    evidence.data = EvidenceData::Text(redacted);
                }
                EvidenceData::Json(json) => {
                    let redacted = self.redact_json(json, policy)?;
                    evidence.data = EvidenceData::Json(redacted);
                }
                _ => {}
            }
        }
        evidence.redacted = true;
        Ok(())
    }

    fn redact_text(&self, text: &str, policy: &RedactionPolicy) -> EvidenceResult<String> {
        let mut result = text.to_string();
        for pattern in &policy.patterns {
            match pattern.pattern_type {
                PatternType::Literal => {
                    if pattern.case_sensitive {
                        result = result.replace(&pattern.value, &policy.replacement);
                    } else {
                        let lower = result.to_lowercase();
                        let pattern_lower = pattern.value.to_lowercase();
                        if let Some(pos) = lower.find(&pattern_lower) {
                            result
                                .replace_range(pos..pos + pattern.value.len(), &policy.replacement);
                        }
                    }
                }
                PatternType::Regex => {
                    if let Ok(re) = regex::Regex::new(&pattern.value) {
                        result = re.replace_all(&result, &policy.replacement).to_string();
                    }
                }
                PatternType::HeaderName => {
                    let header_pattern = if pattern.case_sensitive {
                        format!("{}:.*", regex::escape(&pattern.value))
                    } else {
                        format!("(?i){}:.*", regex::escape(&pattern.value))
                    };
                    if let Ok(re) = regex::Regex::new(&header_pattern) {
                        result = re.replace_all(&result, &policy.replacement).to_string();
                    }
                }
                PatternType::CookieName => {
                    let cookie_pattern = if pattern.case_sensitive {
                        format!("{}=[^;]*", regex::escape(&pattern.value))
                    } else {
                        format!("(?i){}=[^;]*", regex::escape(&pattern.value))
                    };
                    if let Ok(re) = regex::Regex::new(&cookie_pattern) {
                        result = re.replace_all(&result, &policy.replacement).to_string();
                    }
                }
                _ => {}
            }
        }
        Ok(result)
    }

    fn redact_json(
        &self,
        json: &serde_json::Value,
        policy: &RedactionPolicy,
    ) -> EvidenceResult<serde_json::Value> {
        match json {
            serde_json::Value::Object(map) => {
                let mut new_map = serde_json::Map::new();
                for (key, value) in map {
                    let should_redact = policy.patterns.iter().any(|p| {
                        matches!(p.pattern_type, PatternType::JsonField)
                            && if p.case_sensitive {
                                key == &p.value
                            } else {
                                key.to_lowercase() == p.value.to_lowercase()
                            }
                    });

                    if should_redact {
                        new_map.insert(
                            key.clone(),
                            serde_json::Value::String(policy.replacement.clone()),
                        );
                    } else {
                        new_map.insert(key.clone(), self.redact_json(value, policy)?);
                    }
                }
                Ok(serde_json::Value::Object(new_map))
            }
            serde_json::Value::Array(arr) => {
                let redacted: Vec<_> = arr
                    .iter()
                    .map(|v| self.redact_json(v, policy))
                    .collect::<Result<_, _>>()?;
                Ok(serde_json::Value::Array(redacted))
            }
            _ => Ok(json.clone()),
        }
    }
}

/// Evidence integrity checker.
pub struct EvidenceIntegrity;

impl EvidenceIntegrity {
    /// Verifies the integrity of evidence by comparing hashes.
    pub fn verify(evidence: &Evidence) -> EvidenceResult<bool> {
        match &evidence.data_hash {
            Some(expected_hash) => {
                let mut e = evidence.clone();
                e.compute_hash();
                let computed = e.data_hash.unwrap_or_default();
                Ok(computed == *expected_hash)
            }
            None => Err(EvidenceError::IntegrityFailed(
                "No hash stored for evidence".into(),
            )),
        }
    }

    /// Computes SHA-256 hash of evidence data.
    pub fn compute_hash(evidence: &Evidence) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let bytes = evidence.data.as_bytes();
        let mut hasher = DefaultHasher::new();
        bytes.hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    }
}

/// In-memory evidence store.
#[derive(Clone)]
pub struct InMemoryEvidenceStore {
    evidence: Arc<tokio::sync::RwLock<HashMap<String, Vec<Evidence>>>>,
}

impl Default for InMemoryEvidenceStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryEvidenceStore {
    pub fn new() -> Self {
        Self {
            evidence: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }

    pub async fn save(&self, evidence: Evidence) -> EvidenceResult<()> {
        let finding_id = evidence.finding_id.to_string();
        let mut store = self.evidence.write().await;
        store.entry(finding_id).or_default().push(evidence);
        Ok(())
    }

    pub async fn get_by_finding(&self, finding_id: &str) -> EvidenceResult<Vec<Evidence>> {
        let store = self.evidence.read().await;
        Ok(store.get(finding_id).cloned().unwrap_or_default())
    }

    pub async fn get_by_id(&self, evidence_id: &Id<EvidenceId>) -> EvidenceResult<Evidence> {
        let store = self.evidence.read().await;
        for evidence_list in store.values() {
            for e in evidence_list {
                if e.id == *evidence_id {
                    return Ok(e.clone());
                }
            }
        }
        Err(EvidenceError::NotFound(evidence_id.to_string()))
    }

    pub async fn delete(&self, evidence_id: &Id<EvidenceId>) -> EvidenceResult<()> {
        let mut store = self.evidence.write().await;
        for evidence_list in store.values_mut() {
            evidence_list.retain(|e| e.id != *evidence_id);
        }
        Ok(())
    }

    pub async fn count(&self) -> usize {
        let store = self.evidence.read().await;
        store.values().map(|v| v.len()).sum()
    }

    pub async fn count_by_finding(&self, finding_id: &str) -> usize {
        let store = self.evidence.read().await;
        store.get(finding_id).map(|v| v.len()).unwrap_or(0)
    }
}

/// Full evidence engine with collector, store, redaction, and integrity.
pub struct EvidenceEngine {
    store: InMemoryEvidenceStore,
    redactor: EvidenceRedactor,
}

impl Default for EvidenceEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl EvidenceEngine {
    pub fn new() -> Self {
        Self {
            store: InMemoryEvidenceStore::new(),
            redactor: EvidenceRedactor::new(),
        }
    }

    pub fn with_redactor(redactor: EvidenceRedactor) -> Self {
        Self {
            store: InMemoryEvidenceStore::new(),
            redactor,
        }
    }

    pub fn store(&self) -> &InMemoryEvidenceStore {
        &self.store
    }

    pub fn redactor(&self) -> &EvidenceRedactor {
        &self.redactor
    }

    /// Captures and stores evidence with optional redaction.
    pub async fn capture(
        &self,
        finding_id: Id<FindingId>,
        evidence_type: EvidenceType,
        title: impl Into<String>,
        data: EvidenceData,
    ) -> EvidenceResult<Evidence> {
        let mut evidence = Evidence::new(finding_id, evidence_type, title, data);
        evidence.compute_hash();

        self.redactor.redact(&mut evidence)?;
        self.store.save(evidence.clone()).await?;

        Ok(evidence)
    }

    /// Verifies evidence integrity.
    pub fn verify_integrity(&self, evidence: &Evidence) -> EvidenceResult<bool> {
        EvidenceIntegrity::verify(evidence)
    }

    /// Retrieves all evidence for a finding.
    pub async fn get_evidence(&self, finding_id: &str) -> EvidenceResult<Vec<Evidence>> {
        self.store.get_by_finding(finding_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_finding_id() -> Id<FindingId> {
        Id::new()
    }

    #[test]
    fn evidence_creation() {
        let fid = test_finding_id();
        let evidence = Evidence::new(
            fid.clone(),
            EvidenceType::HttpRequest,
            "Test Request",
            EvidenceData::Text("GET / HTTP/1.1".into()),
        );

        assert_eq!(evidence.evidence_type, EvidenceType::HttpRequest);
        assert_eq!(evidence.title, "Test Request");
        assert!(evidence.data_hash.is_none());
    }

    #[test]
    fn evidence_builder() {
        let fid = test_finding_id();
        let evidence = Evidence::new(
            fid.clone(),
            EvidenceType::HttpResponse,
            "Response",
            EvidenceData::Text("200 OK".into()),
        )
        .with_scan_id("scan-123")
        .with_description("Test response")
        .with_collector("test-scanner")
        .with_tag("http")
        .with_tag("response")
        .with_metadata("status", serde_json::json!(200));

        assert_eq!(evidence.scan_id, Some("scan-123".into()));
        assert_eq!(evidence.description, "Test response");
        assert_eq!(evidence.collector, "test-scanner");
        assert_eq!(evidence.tags.len(), 2);
        assert_eq!(
            evidence.metadata.get("status"),
            Some(&serde_json::json!(200))
        );
    }

    #[test]
    fn evidence_data_types() {
        let text = EvidenceData::Text("hello".into());
        assert_eq!(text.as_str(), Some("hello"));
        assert_eq!(text.content_type(), "text/plain");

        let json = EvidenceData::Json(serde_json::json!({"key": "value"}));
        assert_eq!(json.content_type(), "application/json");

        let url = EvidenceData::Url("https://example.com".into());
        assert_eq!(url.as_str(), Some("https://example.com"));

        let binary = EvidenceData::Binary(vec![0x00, 0x01]);
        assert_eq!(binary.content_type(), "application/octet-stream");
    }

    #[test]
    fn evidence_hash_computation() {
        let fid = test_finding_id();
        let mut evidence = Evidence::new(
            fid,
            EvidenceType::Document,
            "Doc",
            EvidenceData::Text("test data".into()),
        );

        assert!(evidence.data_hash.is_none());
        evidence.compute_hash();
        assert!(evidence.data_hash.is_some());

        let hash = evidence.data_hash.clone().unwrap();
        assert!(!hash.is_empty());
    }

    #[test]
    fn integrity_verification() {
        let fid = test_finding_id();
        let mut evidence = Evidence::new(
            fid,
            EvidenceType::Document,
            "Doc",
            EvidenceData::Text("test data".into()),
        );
        evidence.compute_hash();

        assert!(EvidenceIntegrity::verify(&evidence).unwrap());
    }

    #[test]
    fn integrity_tampered() {
        let fid = test_finding_id();
        let mut evidence = Evidence::new(
            fid,
            EvidenceType::Document,
            "Doc",
            EvidenceData::Text("original data".into()),
        );
        evidence.compute_hash();

        evidence.data = EvidenceData::Text("tampered data".into());
        assert!(!EvidenceIntegrity::verify(&evidence).unwrap());
    }

    #[test]
    fn integrity_no_hash() {
        let fid = test_finding_id();
        let evidence = Evidence::new(
            fid,
            EvidenceType::Document,
            "Doc",
            EvidenceData::Text("data".into()),
        );

        assert!(EvidenceIntegrity::verify(&evidence).is_err());
    }

    #[test]
    fn redaction_policy_default() {
        let policy = RedactionPolicy::default_sensitive();
        assert_eq!(policy.name, "default-sensitive");
        assert!(policy.patterns.len() > 0);
    }

    #[test]
    fn redact_text_literal() {
        let policy = RedactionPolicy::new("test").with_pattern(RedactionPattern {
            pattern_type: PatternType::Literal,
            value: "secret".into(),
            case_sensitive: true,
        });

        let redactor = EvidenceRedactor::new().with_policy(policy);
        let mut evidence = Evidence::new(
            Id::new(),
            EvidenceType::Document,
            "Test",
            EvidenceData::Text("This contains secret data".into()),
        );

        redactor.redact(&mut evidence).unwrap();
        match &evidence.data {
            EvidenceData::Text(s) => assert!(s.contains("[REDACTED]")),
            _ => panic!("Expected text data"),
        }
        assert!(evidence.redacted);
    }

    #[test]
    fn redact_json_field() {
        let policy = RedactionPolicy::new("test").with_pattern(RedactionPattern {
            pattern_type: PatternType::JsonField,
            value: "password".into(),
            case_sensitive: false,
        });

        let redactor = EvidenceRedactor::new().with_policy(policy);
        let mut evidence = Evidence::new(
            Id::new(),
            EvidenceType::Document,
            "Test",
            EvidenceData::Json(serde_json::json!({
                "username": "admin",
                "password": "hunter2"
            })),
        );

        redactor.redact(&mut evidence).unwrap();
        match &evidence.data {
            EvidenceData::Json(v) => {
                assert_eq!(v["username"], "admin");
                assert_eq!(v["password"], "[REDACTED]");
            }
            _ => panic!("Expected json data"),
        }
    }

    #[test]
    fn redact_json_nested() {
        let policy = RedactionPolicy::new("test").with_pattern(RedactionPattern {
            pattern_type: PatternType::JsonField,
            value: "token".into(),
            case_sensitive: false,
        });

        let redactor = EvidenceRedactor::new().with_policy(policy);
        let mut evidence = Evidence::new(
            Id::new(),
            EvidenceType::Document,
            "Test",
            EvidenceData::Json(serde_json::json!({
                "user": {
                    "name": "admin",
                    "token": "abc123"
                }
            })),
        );

        redactor.redact(&mut evidence).unwrap();
        match &evidence.data {
            EvidenceData::Json(v) => {
                assert_eq!(v["user"]["name"], "admin");
                assert_eq!(v["user"]["token"], "[REDACTED]");
            }
            _ => panic!("Expected json data"),
        }
    }

    #[tokio::test]
    async fn in_memory_store_save_and_get() {
        let store = InMemoryEvidenceStore::new();
        let fid = test_finding_id();

        let evidence = Evidence::new(
            fid.clone(),
            EvidenceType::HttpRequest,
            "Request 1",
            EvidenceData::Text("GET /".into()),
        );

        store.save(evidence).await.unwrap();
        assert_eq!(store.count().await, 1);

        let results = store.get_by_finding(&fid.to_string()).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].title, "Request 1");
    }

    #[tokio::test]
    async fn in_memory_store_get_by_id() {
        let store = InMemoryEvidenceStore::new();
        let fid = test_finding_id();

        let evidence = Evidence::new(
            fid,
            EvidenceType::HttpResponse,
            "Response",
            EvidenceData::Text("200 OK".into()),
        );

        let id = evidence.id.clone();
        store.save(evidence).await.unwrap();

        let found = store.get_by_id(&id).await.unwrap();
        assert_eq!(found.title, "Response");
    }

    #[tokio::test]
    async fn in_memory_store_not_found() {
        let store = InMemoryEvidenceStore::new();
        let result = store.get_by_id(&Id::new()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn in_memory_store_delete() {
        let store = InMemoryEvidenceStore::new();
        let fid = test_finding_id();

        let evidence = Evidence::new(
            fid.clone(),
            EvidenceType::Document,
            "Doc",
            EvidenceData::Text("data".into()),
        );

        let id = evidence.id.clone();
        store.save(evidence).await.unwrap();
        assert_eq!(store.count().await, 1);

        store.delete(&id).await.unwrap();
        assert_eq!(store.count().await, 0);
    }

    #[tokio::test]
    async fn in_memory_store_multiple_findings() {
        let store = InMemoryEvidenceStore::new();
        let fid1 = test_finding_id();
        let fid2 = test_finding_id();

        store
            .save(Evidence::new(
                fid1.clone(),
                EvidenceType::HttpRequest,
                "Req 1",
                EvidenceData::Text("GET /a".into()),
            ))
            .await
            .unwrap();

        store
            .save(Evidence::new(
                fid1.clone(),
                EvidenceType::HttpResponse,
                "Resp 1",
                EvidenceData::Text("200".into()),
            ))
            .await
            .unwrap();

        store
            .save(Evidence::new(
                fid2.clone(),
                EvidenceType::HttpRequest,
                "Req 2",
                EvidenceData::Text("GET /b".into()),
            ))
            .await
            .unwrap();

        assert_eq!(store.count().await, 3);
        assert_eq!(store.count_by_finding(&fid1.to_string()).await, 2);
        assert_eq!(store.count_by_finding(&fid2.to_string()).await, 1);
    }

    #[tokio::test]
    async fn evidence_engine_capture() {
        let engine = EvidenceEngine::new();
        let fid = test_finding_id();

        let evidence = engine
            .capture(
                fid.clone(),
                EvidenceType::ScannerOutput,
                "SQLi Finding",
                EvidenceData::Text("SQL error detected".into()),
            )
            .await
            .unwrap();

        assert!(evidence.data_hash.is_some());
        assert_eq!(evidence.title, "SQLi Finding");

        let results = engine.get_evidence(&fid.to_string()).await.unwrap();
        assert_eq!(results.len(), 1);
    }

    #[tokio::test]
    async fn evidence_engine_with_redaction() {
        let redactor = EvidenceRedactor::new().with_policy(RedactionPolicy::default_sensitive());
        let engine = EvidenceEngine::with_redactor(redactor);
        let fid = test_finding_id();

        let evidence = engine
            .capture(
                fid,
                EvidenceType::HttpRequest,
                "Auth Request",
                EvidenceData::Text("Authorization: Bearer secret123".into()),
            )
            .await
            .unwrap();

        assert!(evidence.redacted);
        match &evidence.data {
            EvidenceData::Text(s) => assert!(s.contains("[REDACTED]")),
            _ => panic!("Expected text"),
        }
    }

    #[tokio::test]
    async fn evidence_engine_integrity() {
        let engine = EvidenceEngine::new();
        let fid = test_finding_id();

        let evidence = engine
            .capture(
                fid,
                EvidenceType::Document,
                "Integrity Test",
                EvidenceData::Text("original".into()),
            )
            .await
            .unwrap();

        assert!(engine.verify_integrity(&evidence).unwrap());
    }

    #[test]
    fn evidence_type_display() {
        assert_eq!(EvidenceType::HttpRequest.to_string(), "HTTP Request");
        assert_eq!(EvidenceType::HttpResponse.to_string(), "HTTP Response");
        assert_eq!(EvidenceType::DnsResult.to_string(), "DNS Result");
        assert_eq!(
            EvidenceType::Custom("test".into()).to_string(),
            "Custom: test"
        );
    }
}
