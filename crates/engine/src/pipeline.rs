use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tokio::time::timeout;

use crate::EngineResult;

// =============================================================================
// Execution Context
// =============================================================================

/// Context passed to every execution step.
#[derive(Debug, Clone)]
pub struct ExecutionContext {
    pub scan_id: String,
    pub target_id: String,
    pub target_value: String,
    pub timeout: Duration,
    pub max_retries: u32,
    pub metadata: HashMap<String, serde_json::Value>,
    pub cancel_token: Arc<AtomicBool>,
    pub started_at: Instant,
}

impl ExecutionContext {
    pub fn new(
        scan_id: impl Into<String>,
        target_id: impl Into<String>,
        target_value: impl Into<String>,
    ) -> Self {
        Self {
            scan_id: scan_id.into(),
            target_id: target_id.into(),
            target_value: target_value.into(),
            timeout: Duration::from_secs(300),
            max_retries: 3,
            metadata: HashMap::new(),
            cancel_token: Arc::new(AtomicBool::new(false)),
            started_at: Instant::now(),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel_token.load(Ordering::Relaxed)
    }

    pub fn cancel(&self) {
        self.cancel_token.store(true, Ordering::Relaxed);
    }
}

// =============================================================================
// Execution Plan
// =============================================================================

/// A plan that defines the steps to execute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionPlan {
    pub name: String,
    pub steps: Vec<ExecutionStep>,
    pub policy: ExecutionPolicy,
}

impl ExecutionPlan {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            steps: Vec::new(),
            policy: ExecutionPolicy::default(),
        }
    }

    pub fn with_step(mut self, step: ExecutionStep) -> Self {
        self.steps.push(step);
        self
    }

    pub fn with_policy(mut self, policy: ExecutionPolicy) -> Self {
        self.policy = policy;
        self
    }
}

/// A single step in an execution plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionStep {
    pub name: String,
    pub step_type: StepType,
    pub timeout: Option<Duration>,
    pub retry_count: Option<u32>,
    pub depends_on: Vec<String>,
    pub required: bool,
}

impl ExecutionStep {
    pub fn new(name: impl Into<String>, step_type: StepType) -> Self {
        Self {
            name: name.into(),
            step_type,
            timeout: None,
            retry_count: None,
            depends_on: Vec::new(),
            required: true,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn with_retries(mut self, count: u32) -> Self {
        self.retry_count = Some(count);
        self
    }

    pub fn depends_on(mut self, step_name: impl Into<String>) -> Self {
        self.depends_on.push(step_name.into());
        self
    }

    pub fn optional(mut self) -> Self {
        self.required = false;
        self
    }
}

/// Types of execution steps.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StepType {
    Discovery,
    Crawling,
    Fingerprinting,
    Scanning,
    Observation,
    Detection,
    Verification,
    Correlation,
    Reporting,
    Custom(String),
}

impl std::fmt::Display for StepType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Discovery => write!(f, "discovery"),
            Self::Crawling => write!(f, "crawling"),
            Self::Fingerprinting => write!(f, "fingerprinting"),
            Self::Scanning => write!(f, "scanning"),
            Self::Observation => write!(f, "observation"),
            Self::Detection => write!(f, "detection"),
            Self::Verification => write!(f, "verification"),
            Self::Correlation => write!(f, "correlation"),
            Self::Reporting => write!(f, "reporting"),
            Self::Custom(name) => write!(f, "{}", name),
        }
    }
}

// =============================================================================
// Execution Policy
// =============================================================================

/// Policy that controls how execution behaves.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionPolicy {
    pub max_concurrency: u32,
    pub fail_fast: bool,
    pub skip_optional_on_failure: bool,
    pub collect_metrics: bool,
    pub emit_events: bool,
}

impl Default for ExecutionPolicy {
    fn default() -> Self {
        Self {
            max_concurrency: 1,
            fail_fast: true,
            skip_optional_on_failure: true,
            collect_metrics: true,
            emit_events: true,
        }
    }
}

// =============================================================================
// Execution State
// =============================================================================

/// Current state of an execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionState {
    pub status: ExecutionStatus,
    pub current_step: Option<String>,
    pub completed_steps: Vec<String>,
    pub failed_steps: Vec<String>,
    pub skipped_steps: Vec<String>,
    pub step_results: HashMap<String, StepResult>,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub errors: Vec<String>,
}

impl ExecutionState {
    pub fn new() -> Self {
        Self {
            status: ExecutionStatus::Pending,
            current_step: None,
            completed_steps: Vec::new(),
            failed_steps: Vec::new(),
            skipped_steps: Vec::new(),
            step_results: HashMap::new(),
            started_at: None,
            completed_at: None,
            errors: Vec::new(),
        }
    }

    pub fn mark_started(&mut self) {
        self.status = ExecutionStatus::Running;
        self.started_at = Some(chrono::Utc::now().to_rfc3339());
    }

    pub fn mark_step_running(&mut self, step_name: &str) {
        self.current_step = Some(step_name.to_string());
    }

    pub fn mark_step_completed(&mut self, step_name: &str, result: StepResult) {
        self.completed_steps.push(step_name.to_string());
        self.step_results.insert(step_name.to_string(), result);
        self.current_step = None;
    }

    pub fn mark_step_failed(&mut self, step_name: &str, error: String) {
        self.failed_steps.push(step_name.to_string());
        self.errors.push(format!("{}: {}", step_name, error));
        self.current_step = None;
    }

    pub fn mark_step_skipped(&mut self, step_name: &str) {
        self.skipped_steps.push(step_name.to_string());
        self.current_step = None;
    }

    pub fn mark_completed(&mut self) {
        self.status = ExecutionStatus::Completed;
        self.completed_at = Some(chrono::Utc::now().to_rfc3339());
    }

    pub fn mark_failed(&mut self) {
        self.status = ExecutionStatus::Failed;
        self.completed_at = Some(chrono::Utc::now().to_rfc3339());
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self.status,
            ExecutionStatus::Completed | ExecutionStatus::Failed | ExecutionStatus::Cancelled
        )
    }
}

impl Default for ExecutionState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExecutionStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl std::fmt::Display for ExecutionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Running => write!(f, "running"),
            Self::Completed => write!(f, "completed"),
            Self::Failed => write!(f, "failed"),
            Self::Cancelled => write!(f, "cancelled"),
        }
    }
}

// =============================================================================
// Execution Result
// =============================================================================

/// Result of a single step execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResult {
    pub step_name: String,
    pub status: StepStatus,
    pub duration_ms: u64,
    pub output: Option<serde_json::Value>,
    pub error: Option<String>,
    pub metrics: StepMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StepStatus {
    Success,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StepMetrics {
    pub items_processed: u64,
    pub items_created: u64,
    pub items_updated: u64,
    pub items_deleted: u64,
    pub bytes_processed: u64,
}

/// Overall execution result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub plan_name: String,
    pub status: ExecutionStatus,
    pub state: ExecutionState,
    pub total_duration_ms: u64,
    pub steps_executed: usize,
    pub steps_succeeded: usize,
    pub steps_failed: usize,
    pub steps_skipped: usize,
}

// =============================================================================
// Pipeline Executor
// =============================================================================

/// Trait for executing a single step in a pipeline.
#[async_trait::async_trait]
pub trait PipelineStep: Send + Sync {
    /// Returns the name of this step.
    fn name(&self) -> &str;

    /// Returns the type of this step.
    fn step_type(&self) -> StepType;

    /// Executes this step and returns a result.
    async fn execute(&self, context: &ExecutionContext) -> EngineResult<StepResult>;
}

/// Executes an execution plan with proper dependency resolution and error handling.
pub struct PipelineExecutor {
    steps: Vec<Arc<dyn PipelineStep>>,
    state: ExecutionState,
}

impl PipelineExecutor {
    pub fn new() -> Self {
        Self {
            steps: Vec::new(),
            state: ExecutionState::new(),
        }
    }

    pub fn register_step(&mut self, step: Arc<dyn PipelineStep>) {
        self.steps.push(step);
    }

    pub fn state(&self) -> &ExecutionState {
        &self.state
    }

    pub async fn execute(
        &mut self,
        plan: &ExecutionPlan,
        context: &ExecutionContext,
    ) -> EngineResult<ExecutionResult> {
        self.state = ExecutionState::new();
        self.state.mark_started();

        let start = Instant::now();

        for step_plan in &plan.steps {
            if context.is_cancelled() {
                self.state.mark_failed();
                self.state.errors.push("Cancelled by user".to_string());
                break;
            }

            // Check dependencies
            let deps_met = step_plan
                .depends_on
                .iter()
                .all(|dep| self.state.completed_steps.contains(dep));

            if !deps_met {
                if step_plan.required {
                    self.state
                        .mark_step_failed(&step_plan.name, "Dependencies not met".to_string());
                    if plan.policy.fail_fast {
                        break;
                    }
                    continue;
                } else {
                    self.state.mark_step_skipped(&step_plan.name);
                    continue;
                }
            }

            // Find the step implementation
            let step_impl = self.steps.iter().find(|s| s.name() == step_plan.name);
            let step_impl = match step_impl {
                Some(s) => s.clone(),
                None => {
                    if step_plan.required {
                        self.state
                            .mark_step_failed(&step_plan.name, "Step not found".to_string());
                        if plan.policy.fail_fast {
                            break;
                        }
                    } else {
                        self.state.mark_step_skipped(&step_plan.name);
                    }
                    continue;
                }
            };

            self.state.mark_step_running(&step_plan.name);

            let step_timeout = step_plan.timeout.unwrap_or(context.timeout);
            let retries = step_plan.retry_count.unwrap_or(context.max_retries);

            let mut last_error = None;
            for attempt in 0..=retries {
                if context.is_cancelled() {
                    break;
                }

                match timeout(step_timeout, step_impl.execute(context)).await {
                    Ok(Ok(result)) => {
                        self.state.mark_step_completed(&step_plan.name, result);
                        last_error = None;
                        break;
                    }
                    Ok(Err(e)) => {
                        last_error = Some(e.to_string());
                        if attempt < retries {
                            tokio::time::sleep(Duration::from_millis(100 * (attempt + 1) as u64))
                                .await;
                        }
                    }
                    Err(_) => {
                        last_error = Some(format!("Step timed out after {:?}", step_timeout));
                        if attempt < retries {
                            tokio::time::sleep(Duration::from_millis(100 * (attempt + 1) as u64))
                                .await;
                        }
                    }
                }
            }

            if let Some(error) = last_error {
                self.state.mark_step_failed(&step_plan.name, error);
                if step_plan.required && plan.policy.fail_fast {
                    break;
                }
            }
        }

        let total_duration = start.elapsed().as_millis() as u64;

        if self.state.failed_steps.is_empty() && !context.is_cancelled() {
            self.state.mark_completed();
        } else if !context.is_cancelled() {
            self.state.mark_failed();
        } else {
            self.state.status = ExecutionStatus::Cancelled;
        }

        Ok(ExecutionResult {
            plan_name: plan.name.clone(),
            status: self.state.status.clone(),
            state: self.state.clone(),
            total_duration_ms: total_duration,
            steps_executed: self.state.completed_steps.len() + self.state.failed_steps.len(),
            steps_succeeded: self.state.completed_steps.len(),
            steps_failed: self.state.failed_steps.len(),
            steps_skipped: self.state.skipped_steps.len(),
        })
    }
}

impl Default for PipelineExecutor {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Shared State
// =============================================================================

/// Thread-safe shared state accessible by all pipeline steps.
pub struct SharedState {
    inner: RwLock<HashMap<String, serde_json::Value>>,
}

impl SharedState {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    pub async fn get(&self, key: &str) -> Option<serde_json::Value> {
        let map = self.inner.read().await;
        map.get(key).cloned()
    }

    pub async fn set(&self, key: impl Into<String>, value: serde_json::Value) {
        let mut map = self.inner.write().await;
        map.insert(key.into(), value);
    }

    pub async fn has(&self, key: &str) -> bool {
        let map = self.inner.read().await;
        map.contains_key(key)
    }
}

impl Default for SharedState {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EngineError;
    use std::sync::atomic::AtomicU32;

    struct DummyStep {
        name: String,
        counter: Arc<AtomicU32>,
    }

    impl DummyStep {
        fn new(name: &str, counter: Arc<AtomicU32>) -> Self {
            Self {
                name: name.to_string(),
                counter,
            }
        }
    }

    #[async_trait::async_trait]
    impl PipelineStep for DummyStep {
        fn name(&self) -> &str {
            &self.name
        }

        fn step_type(&self) -> StepType {
            StepType::Custom("dummy".to_string())
        }

        async fn execute(&self, _context: &ExecutionContext) -> EngineResult<StepResult> {
            self.counter.fetch_add(1, Ordering::SeqCst);
            Ok(StepResult {
                step_name: self.name.clone(),
                status: StepStatus::Success,
                duration_ms: 10,
                output: None,
                error: None,
                metrics: StepMetrics::default(),
            })
        }
    }

    struct FailingStep {
        name: String,
    }

    #[async_trait::async_trait]
    impl PipelineStep for FailingStep {
        fn name(&self) -> &str {
            &self.name
        }

        fn step_type(&self) -> StepType {
            StepType::Custom("failing".to_string())
        }

        async fn execute(&self, _context: &ExecutionContext) -> EngineResult<StepResult> {
            Err(EngineError::Generic("intentional failure".to_string()))
        }
    }

    #[test]
    fn execution_context_creation() {
        let ctx = ExecutionContext::new("scan-1", "target-1", "example.com");
        assert_eq!(ctx.scan_id, "scan-1");
        assert!(!ctx.is_cancelled());
    }

    #[test]
    fn execution_context_cancel() {
        let ctx = ExecutionContext::new("scan-1", "target-1", "example.com");
        ctx.cancel();
        assert!(ctx.is_cancelled());
    }

    #[test]
    fn execution_plan_construction() {
        let plan = ExecutionPlan::new("test-plan")
            .with_step(ExecutionStep::new("step-1", StepType::Discovery))
            .with_step(ExecutionStep::new("step-2", StepType::Scanning).depends_on("step-1"));

        assert_eq!(plan.steps.len(), 2);
        assert_eq!(plan.steps[1].depends_on, vec!["step-1"]);
    }

    #[test]
    fn execution_state_lifecycle() {
        let mut state = ExecutionState::new();
        assert_eq!(state.status, ExecutionStatus::Pending);

        state.mark_started();
        assert_eq!(state.status, ExecutionStatus::Running);

        state.mark_step_running("step-1");
        assert_eq!(state.current_step.as_deref(), Some("step-1"));

        state.mark_step_completed(
            "step-1",
            StepResult {
                step_name: "step-1".into(),
                status: StepStatus::Success,
                duration_ms: 100,
                output: None,
                error: None,
                metrics: StepMetrics::default(),
            },
        );
        assert!(state.completed_steps.contains(&"step-1".to_string()));

        state.mark_completed();
        assert_eq!(state.status, ExecutionStatus::Completed);
        assert!(state.is_terminal());
    }

    #[test]
    fn shared_state_operations() {
        let state = SharedState::new();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            assert!(!state.has("key").await);
            state.set("key", serde_json::json!("value")).await;
            assert!(state.has("key").await);
            assert_eq!(state.get("key").await, Some(serde_json::json!("value")));
        });
    }

    #[tokio::test]
    async fn pipeline_executor_success() {
        let counter = Arc::new(AtomicU32::new(0));
        let mut executor = PipelineExecutor::new();
        executor.register_step(Arc::new(DummyStep::new("step-1", counter.clone())));
        executor.register_step(Arc::new(DummyStep::new("step-2", counter.clone())));

        let plan = ExecutionPlan::new("test")
            .with_step(ExecutionStep::new("step-1", StepType::Discovery))
            .with_step(ExecutionStep::new("step-2", StepType::Scanning));

        let context = ExecutionContext::new("scan-1", "target-1", "example.com");
        let result = executor.execute(&plan, &context).await.unwrap();

        assert_eq!(result.status, ExecutionStatus::Completed);
        assert_eq!(result.steps_succeeded, 2);
        assert_eq!(result.steps_failed, 0);
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn pipeline_executor_fail_fast() {
        let mut executor = PipelineExecutor::new();
        executor.register_step(Arc::new(FailingStep {
            name: "step-1".into(),
        }));
        executor.register_step(Arc::new(DummyStep::new(
            "step-2",
            Arc::new(AtomicU32::new(0)),
        )));

        let plan = ExecutionPlan::new("test")
            .with_step(ExecutionStep::new("step-1", StepType::Discovery))
            .with_step(ExecutionStep::new("step-2", StepType::Scanning))
            .with_policy(ExecutionPolicy {
                fail_fast: true,
                ..Default::default()
            });

        let context = ExecutionContext::new("scan-1", "target-1", "example.com");
        let result = executor.execute(&plan, &context).await.unwrap();

        assert_eq!(result.status, ExecutionStatus::Failed);
        assert_eq!(result.steps_failed, 1);
        assert_eq!(result.steps_succeeded, 0);
    }

    #[tokio::test]
    async fn pipeline_executor_optional_step_failure() {
        let mut executor = PipelineExecutor::new();
        executor.register_step(Arc::new(FailingStep {
            name: "step-1".into(),
        }));
        executor.register_step(Arc::new(DummyStep::new(
            "step-2",
            Arc::new(AtomicU32::new(0)),
        )));

        let plan = ExecutionPlan::new("test")
            .with_step(ExecutionStep::new("step-1", StepType::Discovery).optional())
            .with_step(ExecutionStep::new("step-2", StepType::Scanning))
            .with_policy(ExecutionPolicy {
                fail_fast: false,
                skip_optional_on_failure: true,
                ..Default::default()
            });

        let context = ExecutionContext::new("scan-1", "target-1", "example.com");
        let result = executor.execute(&plan, &context).await.unwrap();

        // step-1 fails (optional) but step-2 should still run
        assert_eq!(result.steps_failed, 1);
    }

    #[tokio::test]
    async fn pipeline_executor_cancel() {
        let mut executor = PipelineExecutor::new();
        executor.register_step(Arc::new(DummyStep::new(
            "step-1",
            Arc::new(AtomicU32::new(0)),
        )));

        let plan =
            ExecutionPlan::new("test").with_step(ExecutionStep::new("step-1", StepType::Discovery));

        let context = ExecutionContext::new("scan-1", "target-1", "example.com");
        context.cancel();

        let result = executor.execute(&plan, &context).await.unwrap();
        assert_eq!(result.status, ExecutionStatus::Cancelled);
    }

    #[tokio::test]
    async fn pipeline_dependency_not_met() {
        let mut executor = PipelineExecutor::new();
        executor.register_step(Arc::new(DummyStep::new(
            "step-2",
            Arc::new(AtomicU32::new(0)),
        )));

        let plan = ExecutionPlan::new("test")
            .with_step(ExecutionStep::new("step-2", StepType::Scanning).depends_on("step-1"));

        let context = ExecutionContext::new("scan-1", "target-1", "example.com");
        let result = executor.execute(&plan, &context).await.unwrap();

        assert_eq!(result.steps_failed, 1);
    }
}
