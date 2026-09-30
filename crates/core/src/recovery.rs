use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum RecoveryError {
    #[error("Operation not found: {0}")]
    NotFound(String),
    #[error("Operation failed: {0}")]
    Failed(String),
    #[error("Recovery limit exceeded: {0}")]
    RecoveryLimitExceeded(String),
    #[error("State persistence error: {0}")]
    PersistenceError(String),
}

pub type RecoveryResult<T> = Result<T, RecoveryError>;

/// State of a long-running operation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum OperationState {
    Pending,
    Running,
    Paused,
    Completed,
    Failed,
    Recovering,
}

impl std::fmt::Display for OperationState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Running => write!(f, "running"),
            Self::Paused => write!(f, "paused"),
            Self::Completed => write!(f, "completed"),
            Self::Failed => write!(f, "failed"),
            Self::Recovering => write!(f, "recovering"),
        }
    }
}

/// Heartbeat for detecting alive operations.
#[derive(Debug, Clone)]
pub struct Heartbeat {
    pub timestamp: Instant,
    pub worker_id: String,
    pub metadata: HashMap<String, String>,
}

impl Heartbeat {
    pub fn new(worker_id: impl Into<String>) -> Self {
        Self {
            timestamp: Instant::now(),
            worker_id: worker_id.into(),
            metadata: HashMap::new(),
        }
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    pub fn age(&self) -> Duration {
        self.timestamp.elapsed()
    }

    pub fn is_stale(&self, max_age: Duration) -> bool {
        self.age() > max_age
    }
}

/// Persisted state of an operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationRecord {
    pub id: String,
    pub state: OperationState,
    pub created_at: String,
    pub updated_at: String,
    pub heartbeat: Option<HeartbeatRecord>,
    pub retry_count: u32,
    pub max_retries: u32,
    pub error: Option<String>,
    pub progress: f32,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRecord {
    pub timestamp: String,
    pub worker_id: String,
}

/// Failure recovery manager.
pub struct RecoveryManager {
    operations: Arc<RwLock<HashMap<String, OperationRecord>>>,
    dead_letter_queue: Arc<RwLock<Vec<OperationRecord>>>,
    heartbeat_timeout: Duration,
    max_retries: u32,
}

impl RecoveryManager {
    pub fn new(heartbeat_timeout: Duration, max_retries: u32) -> Self {
        Self {
            operations: Arc::new(RwLock::new(HashMap::new())),
            dead_letter_queue: Arc::new(RwLock::new(Vec::new())),
            heartbeat_timeout,
            max_retries,
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(Duration::from_secs(60), 3)
    }

    /// Register a new operation.
    pub async fn register(&self, id: impl Into<String>) {
        let id = id.into();
        let record = OperationRecord {
            id: id.clone(),
            state: OperationState::Pending,
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
            heartbeat: None,
            retry_count: 0,
            max_retries: self.max_retries,
            error: None,
            progress: 0.0,
            metadata: HashMap::new(),
        };

        let mut ops = self.operations.write().await;
        ops.insert(id, record);
    }

    /// Update operation state.
    pub async fn update_state(&self, id: &str, state: OperationState) -> RecoveryResult<()> {
        let mut ops = self.operations.write().await;
        let record = ops
            .get_mut(id)
            .ok_or_else(|| RecoveryError::NotFound(id.to_string()))?;

        record.state = state;
        record.updated_at = chrono::Utc::now().to_rfc3339();
        Ok(())
    }

    /// Update operation progress.
    pub async fn update_progress(&self, id: &str, progress: f32) -> RecoveryResult<()> {
        let mut ops = self.operations.write().await;
        let record = ops
            .get_mut(id)
            .ok_or_else(|| RecoveryError::NotFound(id.to_string()))?;

        record.progress = progress.clamp(0.0, 1.0);
        record.updated_at = chrono::Utc::now().to_rfc3339();
        Ok(())
    }

    /// Record heartbeat from worker.
    pub async fn heartbeat(&self, id: &str, worker_id: impl Into<String>) -> RecoveryResult<()> {
        let mut ops = self.operations.write().await;
        let record = ops
            .get_mut(id)
            .ok_or_else(|| RecoveryError::NotFound(id.to_string()))?;

        record.heartbeat = Some(HeartbeatRecord {
            timestamp: chrono::Utc::now().to_rfc3339(),
            worker_id: worker_id.into(),
        });
        record.updated_at = chrono::Utc::now().to_rfc3339();

        // If recovering, move back to running
        if record.state == OperationState::Recovering {
            record.state = OperationState::Running;
        }

        Ok(())
    }

    /// Check for stale operations (no heartbeat).
    pub async fn check_stale(&self) -> Vec<String> {
        let ops = self.operations.read().await;
        let mut stale = Vec::new();

        for (id, record) in ops.iter() {
            if record.state == OperationState::Running {
                if let Some(ref heartbeat) = record.heartbeat {
                    if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(&heartbeat.timestamp) {
                        let age = chrono::Utc::now() - ts.with_timezone(&chrono::Utc);
                        let timeout =
                            chrono::TimeDelta::from_std(self.heartbeat_timeout).unwrap_or_default();
                        if age > timeout {
                            stale.push(id.clone());
                        }
                    }
                }
            }
        }

        stale
    }

    /// Attempt to recover a stale operation.
    pub async fn recover(&self, id: &str) -> RecoveryResult<bool> {
        let mut ops = self.operations.write().await;
        let record = ops
            .get_mut(id)
            .ok_or_else(|| RecoveryError::NotFound(id.to_string()))?;

        if record.retry_count >= record.max_retries {
            // Move to dead letter queue
            record.state = OperationState::Failed;
            record.error = Some("Max retries exceeded".to_string());
            return Ok(false);
        }

        record.state = OperationState::Recovering;
        record.retry_count += 1;
        record.updated_at = chrono::Utc::now().to_rfc3339();

        Ok(true)
    }

    /// Mark operation as failed.
    pub async fn fail(&self, id: &str, error: impl Into<String>) -> RecoveryResult<()> {
        let mut ops = self.operations.write().await;
        let record = ops
            .get_mut(id)
            .ok_or_else(|| RecoveryError::NotFound(id.to_string()))?;

        record.state = OperationState::Failed;
        record.error = Some(error.into());
        record.updated_at = chrono::Utc::now().to_rfc3339();

        // Check if should go to dead letter queue
        if record.retry_count >= record.max_retries {
            let mut dlq = self.dead_letter_queue.write().await;
            dlq.push(record.clone());
        }

        Ok(())
    }

    /// Mark operation as completed.
    pub async fn complete(&self, id: &str) -> RecoveryResult<()> {
        let mut ops = self.operations.write().await;
        let record = ops
            .get_mut(id)
            .ok_or_else(|| RecoveryError::NotFound(id.to_string()))?;

        record.state = OperationState::Completed;
        record.progress = 1.0;
        record.updated_at = chrono::Utc::now().to_rfc3339();

        Ok(())
    }

    /// Get operation record.
    pub async fn get(&self, id: &str) -> RecoveryResult<OperationRecord> {
        let ops = self.operations.read().await;
        ops.get(id)
            .cloned()
            .ok_or_else(|| RecoveryError::NotFound(id.to_string()))
    }

    /// Get all operations.
    pub async fn list_all(&self) -> Vec<OperationRecord> {
        let ops = self.operations.read().await;
        ops.values().cloned().collect()
    }

    /// Get operations by state.
    pub async fn list_by_state(&self, state: OperationState) -> Vec<OperationRecord> {
        let ops = self.operations.read().await;
        ops.values().filter(|r| r.state == state).cloned().collect()
    }

    /// Get dead letter queue.
    pub async fn dead_letter_queue(&self) -> Vec<OperationRecord> {
        let dlq = self.dead_letter_queue.read().await;
        dlq.clone()
    }

    /// Retry a failed operation.
    pub async fn retry(&self, id: &str) -> RecoveryResult<()> {
        let mut ops = self.operations.write().await;
        let record = ops
            .get_mut(id)
            .ok_or_else(|| RecoveryError::NotFound(id.to_string()))?;

        if record.state != OperationState::Failed {
            return Err(RecoveryError::Failed(
                "Operation is not in failed state".to_string(),
            ));
        }

        if record.retry_count >= record.max_retries {
            return Err(RecoveryError::RecoveryLimitExceeded(
                "Max retries exceeded".to_string(),
            ));
        }

        record.state = OperationState::Recovering;
        record.retry_count += 1;
        record.error = None;
        record.updated_at = chrono::Utc::now().to_rfc3339();

        Ok(())
    }

    /// Get recovery stats.
    pub async fn stats(&self) -> RecoveryStats {
        let ops = self.operations.read().await;
        let dlq = self.dead_letter_queue.read().await;

        let mut stats = RecoveryStats::default();
        for record in ops.values() {
            match record.state {
                OperationState::Pending => stats.pending += 1,
                OperationState::Running => stats.running += 1,
                OperationState::Paused => stats.paused += 1,
                OperationState::Completed => stats.completed += 1,
                OperationState::Failed => stats.failed += 1,
                OperationState::Recovering => stats.recovering += 1,
            }
        }
        stats.dead_letter = dlq.len();

        stats
    }
}

/// Recovery statistics.
#[derive(Debug, Default, Clone)]
pub struct RecoveryStats {
    pub pending: usize,
    pub running: usize,
    pub paused: usize,
    pub completed: usize,
    pub failed: usize,
    pub recovering: usize,
    pub dead_letter: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn register_operation() {
        let manager = RecoveryManager::with_defaults();
        manager.register("op-1").await;

        let record = manager.get("op-1").await.unwrap();
        assert_eq!(record.state, OperationState::Pending);
    }

    #[tokio::test]
    async fn update_state() {
        let manager = RecoveryManager::with_defaults();
        manager.register("op-1").await;

        manager
            .update_state("op-1", OperationState::Running)
            .await
            .unwrap();
        let record = manager.get("op-1").await.unwrap();
        assert_eq!(record.state, OperationState::Running);
    }

    #[tokio::test]
    async fn heartbeat_updates() {
        let manager = RecoveryManager::with_defaults();
        manager.register("op-1").await;
        manager
            .update_state("op-1", OperationState::Running)
            .await
            .unwrap();

        manager.heartbeat("op-1", "worker-1").await.unwrap();
        let record = manager.get("op-1").await.unwrap();
        assert!(record.heartbeat.is_some());
    }

    #[tokio::test]
    async fn recovery_flow() {
        let manager = RecoveryManager::with_defaults();
        manager.register("op-1").await;
        manager
            .update_state("op-1", OperationState::Running)
            .await
            .unwrap();

        // Fail the operation
        manager.fail("op-1", "test error").await.unwrap();
        let record = manager.get("op-1").await.unwrap();
        assert_eq!(record.state, OperationState::Failed);

        // Retry
        manager.retry("op-1").await.unwrap();
        let record = manager.get("op-1").await.unwrap();
        assert_eq!(record.state, OperationState::Recovering);
    }

    #[tokio::test]
    async fn max_retries() {
        let manager = RecoveryManager::new(Duration::from_secs(60), 1);
        manager.register("op-1").await;

        manager.fail("op-1", "error 1").await.unwrap();
        manager.retry("op-1").await.unwrap();
        manager.fail("op-1", "error 2").await.unwrap();

        // Should be in dead letter queue
        let dlq = manager.dead_letter_queue().await;
        assert_eq!(dlq.len(), 1);
    }

    #[tokio::test]
    async fn list_by_state() {
        let manager = RecoveryManager::with_defaults();
        manager.register("op-1").await;
        manager.register("op-2").await;
        manager.register("op-3").await;

        manager
            .update_state("op-1", OperationState::Running)
            .await
            .unwrap();
        manager
            .update_state("op-2", OperationState::Running)
            .await
            .unwrap();

        let running = manager.list_by_state(OperationState::Running).await;
        assert_eq!(running.len(), 2);
    }

    #[tokio::test]
    async fn stats() {
        let manager = RecoveryManager::with_defaults();
        manager.register("op-1").await;
        manager.register("op-2").await;

        manager
            .update_state("op-1", OperationState::Running)
            .await
            .unwrap();

        let stats = manager.stats().await;
        assert_eq!(stats.pending, 1);
        assert_eq!(stats.running, 1);
    }
}
