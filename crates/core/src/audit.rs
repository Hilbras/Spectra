use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("Audit log write failed: {0}")]
    WriteFailed(String),
    #[error("Invalid event: {0}")]
    InvalidEvent(String),
}

pub type AuditResult<T> = Result<T, AuditError>;

/// Severity level for audit events.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuditSeverity {
    Info,
    Warning,
    Critical,
}

impl std::fmt::Display for AuditSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Warning => write!(f, "warning"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

/// Audit event category.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AuditCategory {
    Authentication,
    Authorization,
    DataAccess,
    DataModification,
    Configuration,
    Security,
    System,
    Scan,
    Plugin,
}

impl std::fmt::Display for AuditCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Authentication => write!(f, "authentication"),
            Self::Authorization => write!(f, "authorization"),
            Self::DataAccess => write!(f, "data_access"),
            Self::DataModification => write!(f, "data_modification"),
            Self::Configuration => write!(f, "configuration"),
            Self::Security => write!(f, "security"),
            Self::System => write!(f, "system"),
            Self::Scan => write!(f, "scan"),
            Self::Plugin => write!(f, "plugin"),
        }
    }
}

/// An audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: String,
    pub timestamp: String,
    pub category: AuditCategory,
    pub severity: AuditSeverity,
    pub action: String,
    pub actor: Option<String>,
    pub target: Option<String>,
    pub details: HashMap<String, String>,
    pub ip_address: Option<String>,
    pub success: bool,
}

impl AuditEntry {
    pub fn new(
        category: AuditCategory,
        severity: AuditSeverity,
        action: impl Into<String>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            category,
            severity,
            action: action.into(),
            actor: None,
            target: None,
            details: HashMap::new(),
            ip_address: None,
            success: true,
        }
    }

    pub fn with_actor(mut self, actor: impl Into<String>) -> Self {
        self.actor = Some(actor.into());
        self
    }

    pub fn with_target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    pub fn with_detail(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }

    pub fn with_ip(mut self, ip: impl Into<String>) -> Self {
        self.ip_address = Some(ip.into());
        self
    }

    pub fn with_success(mut self, success: bool) -> Self {
        self.success = success;
        self
    }
}

/// Audit log storage trait.
#[async_trait::async_trait]
pub trait AuditLog: Send + Sync {
    async fn write(&self, entry: AuditEntry) -> AuditResult<()>;
    async fn query(
        &self,
        category: Option<AuditCategory>,
        severity: Option<AuditSeverity>,
        limit: usize,
    ) -> Vec<AuditEntry>;
    async fn count(&self) -> usize;
}

/// In-memory audit log.
pub struct InMemoryAuditLog {
    entries: Arc<RwLock<Vec<AuditEntry>>>,
    max_entries: usize,
}

impl InMemoryAuditLog {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Arc::new(RwLock::new(Vec::new())),
            max_entries,
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(10000)
    }
}

#[async_trait::async_trait]
impl AuditLog for InMemoryAuditLog {
    async fn write(&self, entry: AuditEntry) -> AuditResult<()> {
        let mut entries = self.entries.write().await;
        entries.push(entry);

        // Trim if over limit
        if entries.len() > self.max_entries {
            let excess = entries.len() - self.max_entries;
            entries.drain(0..excess);
        }

        Ok(())
    }

    async fn query(
        &self,
        category: Option<AuditCategory>,
        severity: Option<AuditSeverity>,
        limit: usize,
    ) -> Vec<AuditEntry> {
        let entries = self.entries.read().await;
        entries
            .iter()
            .filter(|e| {
                if let Some(ref cat) = category {
                    if e.category != *cat {
                        return false;
                    }
                }
                if let Some(ref sev) = severity {
                    if e.severity != *sev {
                        return false;
                    }
                }
                true
            })
            .take(limit)
            .cloned()
            .collect()
    }

    async fn count(&self) -> usize {
        let entries = self.entries.read().await;
        entries.len()
    }
}

/// Audit logger that wraps an AuditLog implementation.
pub struct AuditLogger {
    log: Arc<dyn AuditLog>,
}

impl AuditLogger {
    pub fn new(log: Arc<dyn AuditLog>) -> Self {
        Self { log }
    }

    pub fn with_in_memory() -> Self {
        Self::new(Arc::new(InMemoryAuditLog::with_defaults()))
    }

    /// Log an authentication event.
    pub async fn auth(
        &self,
        action: impl Into<String>,
        actor: Option<String>,
        success: bool,
    ) -> AuditResult<()> {
        let entry = AuditEntry::new(AuditCategory::Authentication, AuditSeverity::Info, action)
            .with_success(success);
        let entry = if let Some(a) = actor {
            entry.with_actor(a)
        } else {
            entry
        };
        self.log.write(entry).await
    }

    /// Log an authorization event.
    pub async fn authz(
        &self,
        action: impl Into<String>,
        actor: String,
        target: String,
        success: bool,
    ) -> AuditResult<()> {
        let entry = AuditEntry::new(AuditCategory::Authorization, AuditSeverity::Warning, action)
            .with_actor(actor)
            .with_target(target)
            .with_success(success);
        self.log.write(entry).await
    }

    /// Log a data access event.
    pub async fn data_access(
        &self,
        action: impl Into<String>,
        actor: String,
        target: String,
    ) -> AuditResult<()> {
        let entry = AuditEntry::new(AuditCategory::DataAccess, AuditSeverity::Info, action)
            .with_actor(actor)
            .with_target(target);
        self.log.write(entry).await
    }

    /// Log a data modification event.
    pub async fn data_modification(
        &self,
        action: impl Into<String>,
        actor: String,
        target: String,
    ) -> AuditResult<()> {
        let entry = AuditEntry::new(AuditCategory::DataModification, AuditSeverity::Info, action)
            .with_actor(actor)
            .with_target(target);
        self.log.write(entry).await
    }

    /// Log a security event.
    pub async fn security(
        &self,
        action: impl Into<String>,
        severity: AuditSeverity,
        details: HashMap<String, String>,
    ) -> AuditResult<()> {
        let mut entry = AuditEntry::new(AuditCategory::Security, severity, action);
        entry.details = details;
        self.log.write(entry).await
    }

    /// Log a scan event.
    pub async fn scan(
        &self,
        action: impl Into<String>,
        actor: String,
        target: String,
        details: HashMap<String, String>,
    ) -> AuditResult<()> {
        let mut entry = AuditEntry::new(AuditCategory::Scan, AuditSeverity::Info, action)
            .with_actor(actor)
            .with_target(target);
        entry.details = details;
        self.log.write(entry).await
    }

    /// Query audit logs.
    pub async fn query(
        &self,
        category: Option<AuditCategory>,
        severity: Option<AuditSeverity>,
        limit: usize,
    ) -> Vec<AuditEntry> {
        self.log.query(category, severity, limit).await
    }

    /// Get total count.
    pub async fn count(&self) -> usize {
        self.log.count().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn audit_entry_creation() {
        let entry = AuditEntry::new(AuditCategory::Authentication, AuditSeverity::Info, "login")
            .with_actor("user1")
            .with_target("api")
            .with_ip("127.0.0.1")
            .with_success(true);

        assert_eq!(entry.category, AuditCategory::Authentication);
        assert_eq!(entry.severity, AuditSeverity::Info);
        assert_eq!(entry.action, "login");
        assert_eq!(entry.actor, Some("user1".to_string()));
        assert!(entry.success);
    }

    #[tokio::test]
    async fn in_memory_audit_log_write() {
        let log = InMemoryAuditLog::with_defaults();
        let entry = AuditEntry::new(AuditCategory::System, AuditSeverity::Info, "startup");
        log.write(entry).await.unwrap();
        assert_eq!(log.count().await, 1);
    }

    #[tokio::test]
    async fn in_memory_audit_log_query() {
        let log = InMemoryAuditLog::with_defaults();

        log.write(AuditEntry::new(
            AuditCategory::Authentication,
            AuditSeverity::Info,
            "login",
        ))
        .await
        .unwrap();
        log.write(AuditEntry::new(
            AuditCategory::Security,
            AuditSeverity::Critical,
            "attack",
        ))
        .await
        .unwrap();

        let auth_entries = log
            .query(Some(AuditCategory::Authentication), None, 10)
            .await;
        assert_eq!(auth_entries.len(), 1);

        let critical = log.query(None, Some(AuditSeverity::Critical), 10).await;
        assert_eq!(critical.len(), 1);
    }

    #[tokio::test]
    async fn audit_logger_auth() {
        let logger = AuditLogger::with_in_memory();
        logger
            .auth("login", Some("user1".to_string()), true)
            .await
            .unwrap();
        assert_eq!(logger.count().await, 1);
    }

    #[tokio::test]
    async fn audit_logger_security() {
        let logger = AuditLogger::with_in_memory();
        let mut details = HashMap::new();
        details.insert("reason".to_string(), "brute_force".to_string());
        logger
            .security("blocked_ip", AuditSeverity::Critical, details)
            .await
            .unwrap();
        assert_eq!(logger.count().await, 1);
    }

    #[tokio::test]
    async fn max_entries_trim() {
        let log = InMemoryAuditLog::new(5);
        for i in 0..10 {
            log.write(AuditEntry::new(
                AuditCategory::System,
                AuditSeverity::Info,
                format!("event_{}", i),
            ))
            .await
            .unwrap();
        }
        assert_eq!(log.count().await, 5);
    }
}
