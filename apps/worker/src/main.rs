use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info};

#[derive(Debug, Clone)]
struct WorkerInfo {
    id: String,
    hostname: String,
    version: String,
}

impl WorkerInfo {
    fn new() -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            hostname: hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "unknown".to_string()),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

#[derive(Debug, Default)]
struct WorkerMetrics {
    jobs_processed: AtomicU64,
    jobs_succeeded: AtomicU64,
    jobs_failed: AtomicU64,
    uptime_seconds: AtomicU64,
    last_heartbeat: std::sync::Mutex<Option<String>>,
}

impl WorkerMetrics {
    fn new() -> Self {
        Self::default()
    }

    #[allow(dead_code)]
    fn record_processed(&self) {
        self.jobs_processed.fetch_add(1, Ordering::Relaxed);
    }

    #[allow(dead_code)]
    fn record_success(&self) {
        self.jobs_succeeded.fetch_add(1, Ordering::Relaxed);
    }

    #[allow(dead_code)]
    fn record_failure(&self) {
        self.jobs_failed.fetch_add(1, Ordering::Relaxed);
    }

    fn update_uptime(&self, start: Instant) {
        self.uptime_seconds
            .store(start.elapsed().as_secs(), Ordering::Relaxed);
    }

    fn update_heartbeat(&self) {
        let now = chrono::Utc::now().to_rfc3339();
        *self.last_heartbeat.lock().unwrap() = Some(now);
    }

    fn summary(&self) -> WorkerMetricsSummary {
        WorkerMetricsSummary {
            jobs_processed: self.jobs_processed.load(Ordering::Relaxed),
            jobs_succeeded: self.jobs_succeeded.load(Ordering::Relaxed),
            jobs_failed: self.jobs_failed.load(Ordering::Relaxed),
            uptime_seconds: self.uptime_seconds.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct WorkerMetricsSummary {
    jobs_processed: u64,
    jobs_succeeded: u64,
    jobs_failed: u64,
    uptime_seconds: u64,
}

struct Worker {
    info: WorkerInfo,
    metrics: WorkerMetrics,
    running: Arc<AtomicBool>,
    heartbeat_interval: Duration,
    metrics_interval: Duration,
}

impl Worker {
    fn new(running: Arc<AtomicBool>) -> Self {
        Self {
            info: WorkerInfo::new(),
            metrics: WorkerMetrics::new(),
            running,
            heartbeat_interval: Duration::from_secs(30),
            metrics_interval: Duration::from_secs(60),
        }
    }

    fn with_heartbeat_interval(mut self, interval: Duration) -> Self {
        self.heartbeat_interval = interval;
        self
    }

    fn with_metrics_interval(mut self, interval: Duration) -> Self {
        self.metrics_interval = interval;
        self
    }

    async fn run(&self, _config: spectra_config::Config) {
        let start = Instant::now();
        let mut heartbeat_timer = tokio::time::interval(self.heartbeat_interval);
        let mut metrics_timer = tokio::time::interval(self.metrics_interval);
        let mut job_poll_timer = tokio::time::interval(Duration::from_secs(1));

        info!(
            worker_id = %self.info.id,
            hostname = %self.info.hostname,
            version = %self.info.version,
            "Spectra worker started"
        );

        while self.running.load(Ordering::SeqCst) {
            tokio::select! {
                _ = heartbeat_timer.tick() => {
                    self.metrics.update_heartbeat();
                    debug!(
                        worker_id = %self.info.id,
                        "Heartbeat sent"
                    );
                }
                _ = metrics_timer.tick() => {
                    self.metrics.update_uptime(start);
                    let summary = self.metrics.summary();
                    info!(
                        worker_id = %self.info.id,
                        processed = summary.jobs_processed,
                        succeeded = summary.jobs_succeeded,
                        failed = summary.jobs_failed,
                        uptime_secs = summary.uptime_seconds,
                        "Worker metrics"
                    );
                }
                _ = job_poll_timer.tick() => {
                    if !self.running.load(Ordering::SeqCst) {
                        break;
                    }
                    // In a real implementation, this would dequeue from the scheduler
                    // and process jobs. For now we just poll.
                }
            }
        }

        self.metrics.update_uptime(start);
        let summary = self.metrics.summary();
        info!(
            worker_id = %self.info.id,
            processed = summary.jobs_processed,
            succeeded = summary.jobs_succeeded,
            failed = summary.jobs_failed,
            uptime_secs = summary.uptime_seconds,
            "Worker shutting down"
        );
    }

    #[allow(dead_code)]
    fn id(&self) -> &str {
        &self.info.id
    }

    #[allow(dead_code)]
    fn hostname(&self) -> &str {
        &self.info.hostname
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = spectra_config::Config::load().unwrap_or_default();

    spectra_telemetry::init_logging(&config);

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        info!("Received shutdown signal");
        r.store(false, Ordering::SeqCst);
    })?;

    let worker = Worker::new(running.clone())
        .with_heartbeat_interval(Duration::from_secs(30))
        .with_metrics_interval(Duration::from_secs(60));

    worker.run(config).await;

    spectra_telemetry::shutdown_telemetry();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_info_creation() {
        let info = WorkerInfo::new();
        assert!(!info.id.is_empty());
        assert!(!info.hostname.is_empty());
        assert!(!info.version.is_empty());
    }

    #[test]
    fn worker_metrics_initial() {
        let metrics = WorkerMetrics::new();
        let summary = metrics.summary();
        assert_eq!(summary.jobs_processed, 0);
        assert_eq!(summary.jobs_succeeded, 0);
        assert_eq!(summary.jobs_failed, 0);
        assert_eq!(summary.uptime_seconds, 0);
    }

    #[test]
    fn worker_metrics_record() {
        let metrics = WorkerMetrics::new();
        metrics.record_processed();
        metrics.record_processed();
        metrics.record_success();
        metrics.record_failure();

        let summary = metrics.summary();
        assert_eq!(summary.jobs_processed, 2);
        assert_eq!(summary.jobs_succeeded, 1);
        assert_eq!(summary.jobs_failed, 1);
    }

    #[test]
    fn worker_metrics_uptime() {
        let metrics = WorkerMetrics::new();
        let start = Instant::now() - Duration::from_secs(42);
        metrics.update_uptime(start);
        let summary = metrics.summary();
        assert!(summary.uptime_seconds >= 41);
    }

    #[test]
    fn worker_metrics_heartbeat() {
        let metrics = WorkerMetrics::new();
        assert!(metrics.last_heartbeat.lock().unwrap().is_none());

        metrics.update_heartbeat();
        assert!(metrics.last_heartbeat.lock().unwrap().is_some());
    }

    #[test]
    fn worker_creation() {
        let running = Arc::new(AtomicBool::new(true));
        let worker = Worker::new(running);
        assert!(!worker.id().is_empty());
        assert!(!worker.hostname().is_empty());
    }

    #[test]
    fn worker_builder() {
        let running = Arc::new(AtomicBool::new(true));
        let worker = Worker::new(running)
            .with_heartbeat_interval(Duration::from_secs(10))
            .with_metrics_interval(Duration::from_secs(30));

        assert_eq!(worker.heartbeat_interval, Duration::from_secs(10));
        assert_eq!(worker.metrics_interval, Duration::from_secs(30));
    }

    #[test]
    fn metrics_summary_clone() {
        let metrics = WorkerMetrics::new();
        metrics.record_processed();
        metrics.record_success();

        let summary = metrics.summary();
        let cloned = summary.clone();
        assert_eq!(cloned.jobs_processed, 1);
        assert_eq!(cloned.jobs_succeeded, 1);
    }

    #[test]
    fn worker_shutdown() {
        let running = Arc::new(AtomicBool::new(true));
        let _worker = Worker::new(running.clone());

        assert!(running.load(Ordering::SeqCst));
        running.store(false, Ordering::SeqCst);
        assert!(!running.load(Ordering::SeqCst));
    }

    #[test]
    fn metrics_atomic_operations() {
        let metrics = WorkerMetrics::new();

        // Test atomic increments
        for _ in 0..100 {
            metrics.record_processed();
        }
        for _ in 0..50 {
            metrics.record_success();
        }
        for _ in 0..25 {
            metrics.record_failure();
        }

        let summary = metrics.summary();
        assert_eq!(summary.jobs_processed, 100);
        assert_eq!(summary.jobs_succeeded, 50);
        assert_eq!(summary.jobs_failed, 25);
    }

    #[test]
    fn worker_info_clone() {
        let info = WorkerInfo::new();
        let cloned = info.clone();
        assert_eq!(info.id, cloned.id);
        assert_eq!(info.hostname, cloned.hostname);
        assert_eq!(info.version, cloned.version);
    }

    #[test]
    fn worker_metrics_summary_serialize() {
        let metrics = WorkerMetrics::new();
        metrics.record_processed();

        let summary = metrics.summary();
        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("jobs_processed"));
        assert!(json.contains("1"));
    }

    #[tokio::test]
    async fn worker_run_shutdown() {
        let running = Arc::new(AtomicBool::new(true));
        let worker = Worker::new(running.clone())
            .with_heartbeat_interval(Duration::from_millis(10))
            .with_metrics_interval(Duration::from_millis(10));

        // Shutdown after a short delay
        let r = running.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            r.store(false, Ordering::SeqCst);
        });

        let config = spectra_config::Config::default();
        worker.run(config).await;

        // If we get here, the worker shut down gracefully
        let summary = worker.metrics.summary();
        assert!(summary.uptime_seconds < 5);
    }
}
