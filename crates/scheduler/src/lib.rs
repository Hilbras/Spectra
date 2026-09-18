use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;

/// Marker type for job identifiers.
#[derive(Debug, Clone)]
pub struct JobId;

#[derive(Debug, Error)]
pub enum SchedulerError {
    #[error("Scheduler error: {0}")]
    Generic(String),
    #[error("Job not found: {0}")]
    JobNotFound(String),
    #[error("Queue error: {0}")]
    Queue(String),
}

pub type SchedulerResult<T> = Result<T, SchedulerError>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JobStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Retry,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub id: String,
    pub job_type: String,
    pub payload: serde_json::Value,
    pub status: JobStatus,
    pub priority: u32,
    pub max_retries: u32,
    pub retry_count: u32,
    pub created_at: String,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub last_error: Option<String>,
}

impl Job {
    pub fn builder() -> JobBuilder {
        JobBuilder::default()
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self.status, JobStatus::Completed | JobStatus::Failed)
    }

    pub fn can_retry(&self) -> bool {
        self.retry_count < self.max_retries
    }
}

impl Default for Job {
    fn default() -> Self {
        Self {
            id: String::new(),
            job_type: String::new(),
            payload: serde_json::Value::Null,
            status: JobStatus::Pending,
            priority: 100,
            max_retries: 3,
            retry_count: 0,
            created_at: chrono::Utc::now().to_rfc3339(),
            started_at: None,
            completed_at: None,
            last_error: None,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct JobBuilder {
    id: Option<String>,
    job_type: Option<String>,
    payload: Option<serde_json::Value>,
    priority: Option<u32>,
    max_retries: Option<u32>,
}

impl JobBuilder {
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    pub fn job_type(mut self, job_type: impl Into<String>) -> Self {
        self.job_type = Some(job_type.into());
        self
    }

    pub fn payload(mut self, payload: serde_json::Value) -> Self {
        self.payload = Some(payload);
        self
    }

    pub fn priority(mut self, priority: u32) -> Self {
        self.priority = Some(priority);
        self
    }

    pub fn max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = Some(max_retries);
        self
    }

    pub fn build(self) -> Job {
        Job {
            id: self.id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            job_type: self.job_type.unwrap_or_default(),
            payload: self.payload.unwrap_or(serde_json::Value::Null),
            status: JobStatus::Pending,
            priority: self.priority.unwrap_or(100),
            max_retries: self.max_retries.unwrap_or(3),
            retry_count: 0,
            created_at: chrono::Utc::now().to_rfc3339(),
            started_at: None,
            completed_at: None,
            last_error: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleConfig {
    pub max_concurrent_jobs: u32,
    pub poll_interval_ms: u64,
    pub retry_delay_ms: u64,
}

impl Default for ScheduleConfig {
    fn default() -> Self {
        Self {
            max_concurrent_jobs: 10,
            poll_interval_ms: 1000,
            retry_delay_ms: 5000,
        }
    }
}

#[async_trait::async_trait]
pub trait JobQueue: Send + Sync {
    async fn enqueue(&self, job: Job) -> SchedulerResult<()>;
    async fn dequeue(&self) -> SchedulerResult<Option<Job>>;
    async fn complete(&self, job_id: &str) -> SchedulerResult<()>;
    async fn fail(&self, job_id: &str, error: &str) -> SchedulerResult<()>;
    async fn retry(&self, job_id: &str) -> SchedulerResult<()>;
}

#[derive(Debug)]
struct QueuedJob {
    job: Job,
    enqueued_at: Instant,
    retry_after: Option<Instant>,
}

#[derive(Debug, Clone)]
pub struct InMemoryJobQueue {
    config: ScheduleConfig,
    inner: Arc<tokio::sync::Mutex<InMemoryQueueInner>>,
}

#[derive(Debug)]
struct InMemoryQueueInner {
    pending: VecDeque<QueuedJob>,
    running: std::collections::HashMap<String, QueuedJob>,
    completed: Vec<Job>,
    failed: Vec<Job>,
}

impl InMemoryJobQueue {
    pub fn new(config: ScheduleConfig) -> Self {
        Self {
            config,
            inner: Arc::new(tokio::sync::Mutex::new(InMemoryQueueInner {
                pending: VecDeque::new(),
                running: std::collections::HashMap::new(),
                completed: Vec::new(),
                failed: Vec::new(),
            })),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(ScheduleConfig::default())
    }

    pub async fn pending_count(&self) -> usize {
        self.inner.lock().await.pending.len()
    }

    pub async fn running_count(&self) -> usize {
        self.inner.lock().await.running.len()
    }

    pub async fn completed_count(&self) -> usize {
        self.inner.lock().await.completed.len()
    }

    pub async fn failed_count(&self) -> usize {
        self.inner.lock().await.failed.len()
    }

    pub async fn get_job(&self, job_id: &str) -> SchedulerResult<Option<Job>> {
        let inner = self.inner.lock().await;

        if let Some(qj) = inner.running.get(job_id) {
            return Ok(Some(qj.job.clone()));
        }
        for qj in &inner.pending {
            if qj.job.id == job_id {
                return Ok(Some(qj.job.clone()));
            }
        }
        for job in &inner.completed {
            if job.id == job_id {
                return Ok(Some(job.clone()));
            }
        }
        for job in &inner.failed {
            if job.id == job_id {
                return Ok(Some(job.clone()));
            }
        }
        Ok(None)
    }

    pub async fn cancel_job(&self, job_id: &str) -> SchedulerResult<bool> {
        let mut inner = self.inner.lock().await;

        if inner.running.remove(job_id).is_some() {
            return Ok(true);
        }
        if let Some(pos) = inner.pending.iter().position(|qj| qj.job.id == job_id) {
            inner.pending.remove(pos);
            return Ok(true);
        }
        Ok(false)
    }

    pub async fn stats(&self) -> QueueStats {
        let inner = self.inner.lock().await;
        QueueStats {
            pending: inner.pending.len(),
            running: inner.running.len(),
            completed: inner.completed.len(),
            failed: inner.failed.len(),
        }
    }

    /// Returns all pending jobs.
    pub async fn list_pending(&self) -> Vec<Job> {
        let inner = self.inner.lock().await;
        inner.pending.iter().map(|qj| qj.job.clone()).collect()
    }

    /// Returns all running jobs.
    pub async fn list_running(&self) -> Vec<Job> {
        let inner = self.inner.lock().await;
        inner.running.values().map(|qj| qj.job.clone()).collect()
    }

    /// Returns all completed jobs.
    pub async fn list_completed(&self) -> Vec<Job> {
        let inner = self.inner.lock().await;
        inner.completed.clone()
    }

    /// Returns all failed jobs.
    pub async fn list_failed(&self) -> Vec<Job> {
        let inner = self.inner.lock().await;
        inner.failed.clone()
    }

    /// Removes a job from any state (pending, running, completed, failed).
    pub async fn remove_job(&self, job_id: &str) -> SchedulerResult<bool> {
        let mut inner = self.inner.lock().await;

        if inner.running.remove(job_id).is_some() {
            return Ok(true);
        }
        if let Some(pos) = inner.pending.iter().position(|qj| qj.job.id == job_id) {
            inner.pending.remove(pos);
            return Ok(true);
        }
        if let Some(pos) = inner.completed.iter().position(|j| j.id == job_id) {
            inner.completed.remove(pos);
            return Ok(true);
        }
        if let Some(pos) = inner.failed.iter().position(|j| j.id == job_id) {
            inner.failed.remove(pos);
            return Ok(true);
        }
        Ok(false)
    }

    /// Returns total number of jobs across all states.
    pub async fn total_count(&self) -> usize {
        let inner = self.inner.lock().await;
        inner.pending.len() + inner.running.len() + inner.completed.len() + inner.failed.len()
    }

    /// Drains all pending jobs and returns them.
    pub async fn drain_pending(&self) -> Vec<Job> {
        let mut inner = self.inner.lock().await;
        inner.pending.drain(..).map(|qj| qj.job).collect()
    }

    fn sort_pending(pending: &mut VecDeque<QueuedJob>) {
        let mut jobs: Vec<QueuedJob> = pending.drain(..).collect();
        jobs.sort_by(|a, b| {
            a.job
                .priority
                .cmp(&b.job.priority)
                .then_with(|| a.enqueued_at.cmp(&b.enqueued_at))
        });
        *pending = jobs.into();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueStats {
    pub pending: usize,
    pub running: usize,
    pub completed: usize,
    pub failed: usize,
}

#[async_trait::async_trait]
impl JobQueue for InMemoryJobQueue {
    async fn enqueue(&self, job: Job) -> SchedulerResult<()> {
        let mut inner = self.inner.lock().await;
        inner.pending.push_back(QueuedJob {
            job,
            enqueued_at: Instant::now(),
            retry_after: None,
        });
        Self::sort_pending(&mut inner.pending);
        Ok(())
    }

    async fn dequeue(&self) -> SchedulerResult<Option<Job>> {
        let mut inner = self.inner.lock().await;
        let now = Instant::now();

        if inner.running.len() as u32 >= self.config.max_concurrent_jobs {
            return Ok(None);
        }

        let mut idx = None;
        for (i, qj) in inner.pending.iter().enumerate() {
            if let Some(retry_after) = qj.retry_after {
                if now < retry_after {
                    continue;
                }
            }
            idx = Some(i);
            break;
        }

        if let Some(i) = idx {
            let mut qj = inner.pending.remove(i).unwrap();
            qj.job.status = JobStatus::Running;
            qj.job.started_at = Some(chrono::Utc::now().to_rfc3339());
            let job = qj.job.clone();
            inner.running.insert(job.id.clone(), qj);
            Ok(Some(job))
        } else {
            Ok(None)
        }
    }

    async fn complete(&self, job_id: &str) -> SchedulerResult<()> {
        let mut inner = self.inner.lock().await;
        if let Some(mut qj) = inner.running.remove(job_id) {
            qj.job.status = JobStatus::Completed;
            qj.job.completed_at = Some(chrono::Utc::now().to_rfc3339());
            inner.completed.push(qj.job);
            Ok(())
        } else {
            Err(SchedulerError::JobNotFound(job_id.to_string()))
        }
    }

    async fn fail(&self, job_id: &str, error: &str) -> SchedulerResult<()> {
        let mut inner = self.inner.lock().await;
        if let Some(mut qj) = inner.running.remove(job_id) {
            qj.job.last_error = Some(error.to_string());
            if qj.job.can_retry() {
                qj.job.retry_count += 1;
                qj.job.status = JobStatus::Retry;
                qj.retry_after =
                    Some(Instant::now() + Duration::from_millis(self.config.retry_delay_ms));
                inner.pending.push_back(qj);
                Self::sort_pending(&mut inner.pending);
            } else {
                qj.job.status = JobStatus::Failed;
                inner.failed.push(qj.job);
            }
            Ok(())
        } else {
            Err(SchedulerError::JobNotFound(job_id.to_string()))
        }
    }

    async fn retry(&self, job_id: &str) -> SchedulerResult<()> {
        let mut inner = self.inner.lock().await;

        if let Some(mut qj) = inner.running.remove(job_id) {
            qj.job.retry_count += 1;
            qj.job.status = JobStatus::Pending;
            qj.retry_after = None;
            inner.pending.push_back(qj);
            Self::sort_pending(&mut inner.pending);
            return Ok(());
        }

        if let Some(pos) = inner.failed.iter().position(|j| j.id == job_id) {
            let mut job = inner.failed.remove(pos);
            job.retry_count += 1;
            job.status = JobStatus::Pending;
            inner.pending.push_back(QueuedJob {
                job,
                enqueued_at: Instant::now(),
                retry_after: None,
            });
            Self::sort_pending(&mut inner.pending);
            return Ok(());
        }

        Err(SchedulerError::JobNotFound(job_id.to_string()))
    }
}

impl Default for InMemoryJobQueue {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_job(priority: u32) -> Job {
        Job::builder()
            .id(uuid::Uuid::new_v4().to_string())
            .job_type("scan")
            .priority(priority)
            .build()
    }

    #[tokio::test]
    async fn enqueue_and_dequeue() {
        let queue = InMemoryJobQueue::with_defaults();
        let job = make_job(100);
        let id = job.id.clone();

        queue.enqueue(job).await.unwrap();
        assert_eq!(queue.pending_count().await, 1);

        let dequeued = queue.dequeue().await.unwrap().unwrap();
        assert_eq!(dequeued.id, id);
        assert_eq!(dequeued.status, JobStatus::Running);
        assert_eq!(queue.running_count().await, 1);
    }

    #[tokio::test]
    async fn priority_ordering() {
        let queue = InMemoryJobQueue::with_defaults();

        queue.enqueue(make_job(200)).await.unwrap();
        queue.enqueue(make_job(10)).await.unwrap();
        queue.enqueue(make_job(50)).await.unwrap();

        let first = queue.dequeue().await.unwrap().unwrap();
        assert_eq!(first.priority, 10);

        let second = queue.dequeue().await.unwrap().unwrap();
        assert_eq!(second.priority, 50);

        let third = queue.dequeue().await.unwrap().unwrap();
        assert_eq!(third.priority, 200);
    }

    #[tokio::test]
    async fn complete_job() {
        let queue = InMemoryJobQueue::with_defaults();
        let job = make_job(100);
        let id = job.id.clone();

        queue.enqueue(job).await.unwrap();
        queue.dequeue().await.unwrap();
        queue.complete(&id).await.unwrap();

        assert_eq!(queue.running_count().await, 0);
        assert_eq!(queue.completed_count().await, 1);
    }

    #[tokio::test]
    async fn fail_and_retry() {
        let config = ScheduleConfig {
            retry_delay_ms: 0,
            ..Default::default()
        };
        let queue = InMemoryJobQueue::new(config);
        let job = Job::builder()
            .id("job-1")
            .job_type("scan")
            .priority(100)
            .max_retries(2)
            .build();

        queue.enqueue(job).await.unwrap();
        queue.dequeue().await.unwrap();
        queue.fail("job-1", "timeout").await.unwrap();

        assert_eq!(queue.running_count().await, 0);
        assert_eq!(queue.pending_count().await, 1);

        queue.dequeue().await.unwrap();
        queue.fail("job-1", "error again").await.unwrap();

        assert_eq!(queue.pending_count().await, 1);

        queue.dequeue().await.unwrap();
        queue.fail("job-1", "final error").await.unwrap();

        assert_eq!(queue.failed_count().await, 1);
        assert_eq!(queue.pending_count().await, 0);
    }

    #[tokio::test]
    async fn cancel_running_job() {
        let queue = InMemoryJobQueue::with_defaults();
        let job = make_job(100);
        let id = job.id.clone();

        queue.enqueue(job).await.unwrap();
        queue.dequeue().await.unwrap();

        let cancelled = queue.cancel_job(&id).await.unwrap();
        assert!(cancelled);
        assert_eq!(queue.running_count().await, 0);
    }

    #[tokio::test]
    async fn cancel_pending_job() {
        let queue = InMemoryJobQueue::with_defaults();
        let job = make_job(100);
        let id = job.id.clone();

        queue.enqueue(job).await.unwrap();

        let cancelled = queue.cancel_job(&id).await.unwrap();
        assert!(cancelled);
        assert_eq!(queue.pending_count().await, 0);
    }

    #[tokio::test]
    async fn cancel_nonexistent_returns_false() {
        let queue = InMemoryJobQueue::with_defaults();
        let cancelled = queue.cancel_job("nope").await.unwrap();
        assert!(!cancelled);
    }

    #[tokio::test]
    async fn stats() {
        let queue = InMemoryJobQueue::with_defaults();

        queue.enqueue(make_job(100)).await.unwrap();
        queue.enqueue(make_job(100)).await.unwrap();
        queue.dequeue().await.unwrap();

        let stats = queue.stats().await;
        assert_eq!(stats.pending, 1);
        assert_eq!(stats.running, 1);
        assert_eq!(stats.completed, 0);
        assert_eq!(stats.failed, 0);
    }

    #[tokio::test]
    async fn max_concurrent_limit() {
        let config = ScheduleConfig {
            max_concurrent_jobs: 2,
            ..Default::default()
        };
        let queue = InMemoryJobQueue::new(config);

        queue.enqueue(make_job(100)).await.unwrap();
        queue.enqueue(make_job(100)).await.unwrap();
        queue.enqueue(make_job(100)).await.unwrap();

        let first = queue.dequeue().await.unwrap();
        assert!(first.is_some());
        let second = queue.dequeue().await.unwrap();
        assert!(second.is_some());
        let third = queue.dequeue().await.unwrap();
        assert!(third.is_none());
    }

    #[tokio::test]
    async fn retry_from_failed() {
        let config = ScheduleConfig {
            retry_delay_ms: 0,
            ..Default::default()
        };
        let queue = InMemoryJobQueue::new(config);
        let job = Job::builder()
            .id("job-retry")
            .job_type("scan")
            .priority(100)
            .max_retries(1)
            .build();

        queue.enqueue(job).await.unwrap();
        queue.dequeue().await.unwrap();

        // First fail: retry_count goes 0→1, still can_retry, so goes to pending
        queue.fail("job-retry", "error").await.unwrap();
        assert_eq!(queue.pending_count().await, 1);
        assert_eq!(queue.failed_count().await, 0);

        // Dequeue again (retry_count=1, max_retries=1 → can't retry anymore)
        queue.dequeue().await.unwrap();
        queue.fail("job-retry", "error again").await.unwrap();
        assert_eq!(queue.failed_count().await, 1);
        assert_eq!(queue.pending_count().await, 0);

        // Now retry from failed
        queue.retry("job-retry").await.unwrap();
        assert_eq!(queue.failed_count().await, 0);
        assert_eq!(queue.pending_count().await, 1);
    }

    #[tokio::test]
    async fn retry_nonexistent_fails() {
        let queue = InMemoryJobQueue::with_defaults();
        let result = queue.retry("nope").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn job_builder_defaults() {
        let job = Job::builder().id("test-1").build();
        assert_eq!(job.id, "test-1");
        assert_eq!(job.priority, 100);
        assert_eq!(job.max_retries, 3);
        assert_eq!(job.status, JobStatus::Pending);
    }

    #[tokio::test]
    async fn job_is_terminal() {
        let mut job = make_job(100);
        assert!(!job.is_terminal());

        job.status = JobStatus::Completed;
        assert!(job.is_terminal());

        job.status = JobStatus::Failed;
        assert!(job.is_terminal());
    }

    #[tokio::test]
    async fn dequeue_empty_queue() {
        let queue = InMemoryJobQueue::with_defaults();
        let result = queue.dequeue().await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn complete_nonexistent_fails() {
        let queue = InMemoryJobQueue::with_defaults();
        let result = queue.complete("nope").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn list_pending_jobs() {
        let queue = InMemoryJobQueue::with_defaults();
        queue.enqueue(make_job(100)).await.unwrap();
        queue.enqueue(make_job(50)).await.unwrap();

        let pending = queue.list_pending().await;
        assert_eq!(pending.len(), 2);
    }

    #[tokio::test]
    async fn list_running_jobs() {
        let queue = InMemoryJobQueue::with_defaults();
        queue.enqueue(make_job(100)).await.unwrap();
        queue.enqueue(make_job(50)).await.unwrap();
        queue.dequeue().await.unwrap();

        let running = queue.list_running().await;
        assert_eq!(running.len(), 1);
        assert_eq!(running[0].status, JobStatus::Running);
    }

    #[tokio::test]
    async fn list_completed_jobs() {
        let queue = InMemoryJobQueue::with_defaults();
        let job = make_job(100);
        let id = job.id.clone();
        queue.enqueue(job).await.unwrap();
        queue.dequeue().await.unwrap();
        queue.complete(&id).await.unwrap();

        let completed = queue.list_completed().await;
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].id, id);
    }

    #[tokio::test]
    async fn list_failed_jobs() {
        let config = ScheduleConfig {
            retry_delay_ms: 0,
            ..Default::default()
        };
        let queue = InMemoryJobQueue::new(config);
        let job = Job::builder()
            .id("fail-1")
            .job_type("scan")
            .max_retries(0)
            .build();
        queue.enqueue(job).await.unwrap();
        queue.dequeue().await.unwrap();
        queue.fail("fail-1", "error").await.unwrap();

        let failed = queue.list_failed().await;
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].id, "fail-1");
    }

    #[tokio::test]
    async fn remove_pending_job() {
        let queue = InMemoryJobQueue::with_defaults();
        let job = make_job(100);
        let id = job.id.clone();
        queue.enqueue(job).await.unwrap();

        let removed = queue.remove_job(&id).await.unwrap();
        assert!(removed);
        assert_eq!(queue.pending_count().await, 0);
    }

    #[tokio::test]
    async fn remove_running_job() {
        let queue = InMemoryJobQueue::with_defaults();
        let job = make_job(100);
        let id = job.id.clone();
        queue.enqueue(job).await.unwrap();
        queue.dequeue().await.unwrap();

        let removed = queue.remove_job(&id).await.unwrap();
        assert!(removed);
        assert_eq!(queue.running_count().await, 0);
    }

    #[tokio::test]
    async fn remove_nonexistent_returns_false() {
        let queue = InMemoryJobQueue::with_defaults();
        let removed = queue.remove_job("nope").await.unwrap();
        assert!(!removed);
    }

    #[tokio::test]
    async fn total_count() {
        let queue = InMemoryJobQueue::with_defaults();
        assert_eq!(queue.total_count().await, 0);

        queue.enqueue(make_job(100)).await.unwrap();
        queue.enqueue(make_job(50)).await.unwrap();
        assert_eq!(queue.total_count().await, 2);

        queue.dequeue().await.unwrap();
        assert_eq!(queue.total_count().await, 2);
    }

    #[tokio::test]
    async fn drain_pending() {
        let queue = InMemoryJobQueue::with_defaults();
        queue.enqueue(make_job(100)).await.unwrap();
        queue.enqueue(make_job(50)).await.unwrap();
        assert_eq!(queue.pending_count().await, 2);

        let drained = queue.drain_pending().await;
        assert_eq!(drained.len(), 2);
        assert_eq!(queue.pending_count().await, 0);
    }

    #[tokio::test]
    async fn get_job_any_state() {
        let queue = InMemoryJobQueue::with_defaults();

        let pending = make_job(100);
        let pending_id = pending.id.clone();
        queue.enqueue(pending).await.unwrap();

        let running = make_job(50);
        let running_id = running.id.clone();
        queue.enqueue(running).await.unwrap();
        queue.dequeue().await.unwrap();

        let found_pending = queue.get_job(&pending_id).await.unwrap();
        assert!(found_pending.is_some());

        let found_running = queue.get_job(&running_id).await.unwrap();
        assert!(found_running.is_some());

        let not_found = queue.get_job("nope").await.unwrap();
        assert!(not_found.is_none());
    }
}
