use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("Sandbox initialization failed: {0}")]
    InitFailed(String),
    #[error("Execution limit exceeded: {0}")]
    LimitExceeded(String),
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    #[error("Timeout after {0}ms")]
    Timeout(u64),
    #[error("Process error: {0}")]
    ProcessError(String),
    #[error("Policy violation: {0}")]
    PolicyViolation(String),
}

pub type SandboxResult<T> = Result<T, SandboxError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub max_memory_bytes: u64,
    pub max_cpu_time_ms: u64,
    pub max_disk_bytes: u64,
    pub max_network_connections: u32,
    pub allowed_hosts: Vec<String>,
    pub blocked_hosts: Vec<String>,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_memory_bytes: 256 * 1024 * 1024,
            max_cpu_time_ms: 30000,
            max_disk_bytes: 1024 * 1024 * 1024,
            max_network_connections: 10,
            allowed_hosts: vec![],
            blocked_hosts: vec![],
        }
    }
}

impl ResourceLimits {
    pub fn strict() -> Self {
        Self {
            max_memory_bytes: 64 * 1024 * 1024,
            max_cpu_time_ms: 5000,
            max_disk_bytes: 10 * 1024 * 1024,
            max_network_connections: 0,
            allowed_hosts: vec![],
            blocked_hosts: vec!["*".into()],
        }
    }

    pub fn permissive() -> Self {
        Self {
            max_memory_bytes: 1024 * 1024 * 1024,
            max_cpu_time_ms: 120000,
            max_disk_bytes: 10 * 1024 * 1024 * 1024,
            max_network_connections: 100,
            allowed_hosts: vec!["*".into()],
            blocked_hosts: vec![],
        }
    }

    pub fn is_host_allowed(&self, host: &str) -> bool {
        if self.blocked_hosts.contains(&"*".to_string()) {
            return false;
        }
        if self.blocked_hosts.iter().any(|h| h == host) {
            return false;
        }
        if self.allowed_hosts.is_empty() {
            return true;
        }
        self.allowed_hosts.iter().any(|h| h == host || h == "*")
    }

    pub fn memory_mb(&self) -> u64 {
        self.max_memory_bytes / (1024 * 1024)
    }

    pub fn cpu_seconds(&self) -> u64 {
        self.max_cpu_time_ms / 1000
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
    pub memory_used_bytes: u64,
}

impl ExecutionResult {
    pub fn success(&self) -> bool {
        self.exit_code == 0
    }
}

#[async_trait::async_trait]
pub trait Sandbox: Send + Sync {
    async fn execute(
        &self,
        command: &str,
        args: &[String],
        limits: &ResourceLimits,
    ) -> SandboxResult<ExecutionResult>;
    async fn cleanup(&self) -> SandboxResult<()>;
}

pub struct LocalSandbox {
    working_dir: Option<String>,
}

impl Default for LocalSandbox {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalSandbox {
    pub fn new() -> Self {
        Self { working_dir: None }
    }

    pub fn with_working_dir(dir: impl Into<String>) -> Self {
        Self {
            working_dir: Some(dir.into()),
        }
    }
}

#[async_trait::async_trait]
impl Sandbox for LocalSandbox {
    async fn execute(
        &self,
        command: &str,
        args: &[String],
        limits: &ResourceLimits,
    ) -> SandboxResult<ExecutionResult> {
        let start = std::time::Instant::now();

        let mut cmd = tokio::process::Command::new(command);
        cmd.args(args);

        if let Some(ref dir) = self.working_dir {
            cmd.current_dir(dir);
        }

        cmd.kill_on_drop(true);

        let output = cmd
            .output()
            .await
            .map_err(|e| SandboxError::ProcessError(e.to_string()))?;

        let duration_ms = start.elapsed().as_millis() as u64;

        if duration_ms > limits.max_cpu_time_ms {
            return Err(SandboxError::Timeout(limits.max_cpu_time_ms));
        }

        Ok(ExecutionResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            duration_ms,
            memory_used_bytes: 0,
        })
    }

    async fn cleanup(&self) -> SandboxResult<()> {
        Ok(())
    }
}

/// Audit log entry for sandbox executions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub command: String,
    pub args: Vec<String>,
    pub exit_code: i32,
    pub duration_ms: u64,
    pub memory_used_bytes: u64,
    pub executed_at: String,
    pub policy_applied: String,
}

/// Sandbox metrics tracking.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SandboxMetrics {
    pub total_executions: u64,
    pub successful_executions: u64,
    pub failed_executions: u64,
    pub timeout_count: u64,
    pub policy_violations: u64,
    pub total_duration_ms: u64,
    pub total_memory_bytes: u64,
}

impl SandboxMetrics {
    pub fn average_duration_ms(&self) -> f64 {
        if self.total_executions == 0 {
            0.0
        } else {
            self.total_duration_ms as f64 / self.total_executions as f64
        }
    }

    pub fn average_memory_bytes(&self) -> f64 {
        if self.total_executions == 0 {
            0.0
        } else {
            self.total_memory_bytes as f64 / self.total_executions as f64
        }
    }

    pub fn success_rate(&self) -> f64 {
        if self.total_executions == 0 {
            0.0
        } else {
            self.successful_executions as f64 / self.total_executions as f64
        }
    }
}

/// Sandbox policy for execution control.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxPolicy {
    pub name: String,
    pub max_executions_per_minute: u32,
    pub allowed_commands: Vec<String>,
    pub blocked_commands: Vec<String>,
    pub require_resource_limits: bool,
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        Self {
            name: "default".into(),
            max_executions_per_minute: 60,
            allowed_commands: Vec::new(),
            blocked_commands: Vec::new(),
            require_resource_limits: true,
        }
    }
}

impl SandboxPolicy {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Default::default()
        }
    }

    pub fn with_max_executions_per_minute(mut self, max: u32) -> Self {
        self.max_executions_per_minute = max;
        self
    }

    pub fn with_allowed_command(mut self, cmd: impl Into<String>) -> Self {
        self.allowed_commands.push(cmd.into());
        self
    }

    pub fn with_blocked_command(mut self, cmd: impl Into<String>) -> Self {
        self.blocked_commands.push(cmd.into());
        self
    }

    pub fn is_command_allowed(&self, command: &str) -> bool {
        if self.blocked_commands.contains(&command.to_string()) {
            return false;
        }
        if self.allowed_commands.is_empty() {
            return true;
        }
        self.allowed_commands.contains(&command.to_string())
    }

    /// Create a restrictive policy for untrusted code.
    pub fn restrictive() -> Self {
        Self::new("restrictive")
            .with_max_executions_per_minute(10)
            .with_allowed_command("echo")
            .with_allowed_command("cat")
            .with_allowed_command("ls")
    }

    /// Create a permissive policy for trusted code.
    pub fn permissive() -> Self {
        Self::new("permissive").with_max_executions_per_minute(1000)
    }
}

/// Auditing sandbox wrapper that logs all executions.
pub struct AuditingSandbox {
    inner: Arc<dyn Sandbox>,
    policy: SandboxPolicy,
    audit_log: tokio::sync::Mutex<Vec<AuditEntry>>,
    metrics: tokio::sync::Mutex<SandboxMetrics>,
}

impl AuditingSandbox {
    pub fn new(sandbox: Arc<dyn Sandbox>, policy: SandboxPolicy) -> Self {
        Self {
            inner: sandbox,
            policy,
            audit_log: tokio::sync::Mutex::new(Vec::new()),
            metrics: tokio::sync::Mutex::new(SandboxMetrics::default()),
        }
    }

    pub async fn execute_with_audit(
        &self,
        command: &str,
        args: &[String],
        limits: &ResourceLimits,
    ) -> SandboxResult<ExecutionResult> {
        // Check policy
        if !self.policy.is_command_allowed(command) {
            let mut metrics = self.metrics.lock().await;
            metrics.policy_violations += 1;
            return Err(SandboxError::PolicyViolation(format!(
                "Command '{}' is not allowed by policy '{}'",
                command, self.policy.name
            )));
        }

        let result = self.inner.execute(command, args, limits).await;

        let entry = AuditEntry {
            command: command.to_string(),
            args: args.to_vec(),
            exit_code: result.as_ref().map(|r| r.exit_code).unwrap_or(-1),
            duration_ms: result.as_ref().map(|r| r.duration_ms).unwrap_or(0),
            memory_used_bytes: result.as_ref().map(|r| r.memory_used_bytes).unwrap_or(0),
            executed_at: chrono::Utc::now().to_rfc3339(),
            policy_applied: self.policy.name.clone(),
        };

        let mut audit = self.audit_log.lock().await;
        audit.push(entry);

        let mut metrics = self.metrics.lock().await;
        metrics.total_executions += 1;
        if let Ok(ref r) = result {
            metrics.total_duration_ms += r.duration_ms;
            metrics.total_memory_bytes += r.memory_used_bytes;
            if r.success() {
                metrics.successful_executions += 1;
            } else {
                metrics.failed_executions += 1;
            }
        } else {
            metrics.failed_executions += 1;
            if let Err(SandboxError::Timeout(_)) = &result {
                metrics.timeout_count += 1;
            }
        }

        result
    }

    pub async fn audit_log(&self) -> Vec<AuditEntry> {
        self.audit_log.lock().await.clone()
    }

    pub async fn metrics(&self) -> SandboxMetrics {
        self.metrics.lock().await.clone()
    }

    pub fn policy(&self) -> &SandboxPolicy {
        &self.policy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_limits() {
        let limits = ResourceLimits::default();
        assert_eq!(limits.max_memory_bytes, 256 * 1024 * 1024);
        assert_eq!(limits.max_cpu_time_ms, 30000);
        assert_eq!(limits.max_network_connections, 10);
        assert!(limits.allowed_hosts.is_empty());
    }

    #[test]
    fn strict_limits() {
        let limits = ResourceLimits::strict();
        assert_eq!(limits.max_memory_bytes, 64 * 1024 * 1024);
        assert_eq!(limits.max_cpu_time_ms, 5000);
        assert_eq!(limits.max_network_connections, 0);
        assert!(!limits.is_host_allowed("example.com"));
    }

    #[test]
    fn permissive_limits() {
        let limits = ResourceLimits::permissive();
        assert_eq!(limits.max_memory_bytes, 1024 * 1024 * 1024);
        assert!(limits.is_host_allowed("example.com"));
    }

    #[test]
    fn host_allowed_default() {
        let limits = ResourceLimits::default();
        assert!(limits.is_host_allowed("example.com"));
        assert!(limits.is_host_allowed("localhost"));
    }

    #[test]
    fn host_blocked() {
        let limits = ResourceLimits {
            blocked_hosts: vec!["evil.com".into()],
            ..Default::default()
        };
        assert!(!limits.is_host_allowed("evil.com"));
        assert!(limits.is_host_allowed("good.com"));
    }

    #[test]
    fn host_allowlist() {
        let limits = ResourceLimits {
            allowed_hosts: vec!["safe.com".into()],
            ..Default::default()
        };
        assert!(limits.is_host_allowed("safe.com"));
        assert!(!limits.is_host_allowed("other.com"));
    }

    #[test]
    fn host_wildcard_block() {
        let limits = ResourceLimits {
            blocked_hosts: vec!["*".into()],
            ..Default::default()
        };
        assert!(!limits.is_host_allowed("anything.com"));
    }

    #[test]
    fn execution_result_success() {
        let result = ExecutionResult {
            exit_code: 0,
            stdout: "ok".into(),
            stderr: String::new(),
            duration_ms: 100,
            memory_used_bytes: 0,
        };
        assert!(result.success());

        let result = ExecutionResult {
            exit_code: 1,
            stdout: String::new(),
            stderr: "error".into(),
            duration_ms: 50,
            memory_used_bytes: 0,
        };
        assert!(!result.success());
    }

    #[test]
    fn limits_conversion() {
        let limits = ResourceLimits {
            max_memory_bytes: 512 * 1024 * 1024,
            max_cpu_time_ms: 15000,
            ..Default::default()
        };
        assert_eq!(limits.memory_mb(), 512);
        assert_eq!(limits.cpu_seconds(), 15);
    }

    #[tokio::test]
    async fn local_sandbox_execute_echo() {
        let sandbox = LocalSandbox::new();
        let limits = ResourceLimits::permissive();
        let result = sandbox
            .execute("echo", &["hello".into()], &limits)
            .await
            .unwrap();
        assert!(result.success());
        assert_eq!(result.stdout.trim(), "hello");
    }

    #[tokio::test]
    async fn local_sandbox_execute_fails() {
        let sandbox = LocalSandbox::new();
        let limits = ResourceLimits::permissive();
        let result = sandbox.execute("false", &[], &limits).await.unwrap();
        assert!(!result.success());
    }

    #[tokio::test]
    async fn local_sandbox_cleanup() {
        let sandbox = LocalSandbox::new();
        assert!(sandbox.cleanup().await.is_ok());
    }

    #[tokio::test]
    async fn local_sandbox_with_workdir() {
        let sandbox = LocalSandbox::with_working_dir("/tmp");
        let limits = ResourceLimits::permissive();
        let result = sandbox.execute("pwd", &[], &limits).await.unwrap();
        assert!(result.success());
        assert_eq!(result.stdout.trim(), "/tmp");
    }

    #[tokio::test]
    async fn local_sandbox_nonexistent_command() {
        let sandbox = LocalSandbox::new();
        let limits = ResourceLimits::permissive();
        let result = sandbox
            .execute("nonexistent_command_xyz", &[], &limits)
            .await;
        assert!(result.is_err());
    }

    // Sandbox policy tests
    #[test]
    fn policy_default() {
        let policy = SandboxPolicy::default();
        assert_eq!(policy.name, "default");
        assert_eq!(policy.max_executions_per_minute, 60);
        assert!(policy.is_command_allowed("anything"));
    }

    #[test]
    fn policy_restrictive() {
        let policy = SandboxPolicy::restrictive();
        assert!(policy.is_command_allowed("echo"));
        assert!(policy.is_command_allowed("ls"));
        assert!(!policy.is_command_allowed("rm"));
        assert_eq!(policy.max_executions_per_minute, 10);
    }

    #[test]
    fn policy_permissive() {
        let policy = SandboxPolicy::permissive();
        assert!(policy.is_command_allowed("anything"));
        assert_eq!(policy.max_executions_per_minute, 1000);
    }

    #[test]
    fn policy_blocked_command() {
        let policy = SandboxPolicy::new("test")
            .with_blocked_command("rm")
            .with_blocked_command("sudo");

        assert!(!policy.is_command_allowed("rm"));
        assert!(!policy.is_command_allowed("sudo"));
        assert!(policy.is_command_allowed("echo"));
    }

    #[test]
    fn policy_allowed_command() {
        let policy = SandboxPolicy::new("test")
            .with_allowed_command("echo")
            .with_allowed_command("ls");

        assert!(policy.is_command_allowed("echo"));
        assert!(policy.is_command_allowed("ls"));
        assert!(!policy.is_command_allowed("rm"));
    }

    // Metrics tests
    #[test]
    fn metrics_default() {
        let metrics = SandboxMetrics::default();
        assert_eq!(metrics.total_executions, 0);
        assert_eq!(metrics.average_duration_ms(), 0.0);
        assert_eq!(metrics.success_rate(), 0.0);
    }

    #[test]
    fn metrics_calculations() {
        let metrics = SandboxMetrics {
            total_executions: 10,
            successful_executions: 8,
            failed_executions: 2,
            timeout_count: 1,
            policy_violations: 0,
            total_duration_ms: 5000,
            total_memory_bytes: 10 * 1024 * 1024,
        };

        assert!((metrics.average_duration_ms() - 500.0).abs() < 0.001);
        assert!((metrics.success_rate() - 0.8).abs() < 0.001);
        assert!((metrics.average_memory_bytes() - 1024.0 * 1024.0).abs() < 0.001);
    }

    // Auditing sandbox tests
    #[tokio::test]
    async fn auditing_sandbox_execute() {
        let sandbox = Arc::new(LocalSandbox::new());
        let policy = SandboxPolicy::permissive();
        let auditing = AuditingSandbox::new(sandbox, policy);

        let limits = ResourceLimits::permissive();
        let result = auditing
            .execute_with_audit("echo", &["test".into()], &limits)
            .await
            .unwrap();

        assert!(result.success());
        assert_eq!(result.stdout.trim(), "test");

        let log = auditing.audit_log().await;
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].command, "echo");

        let metrics = auditing.metrics().await;
        assert_eq!(metrics.total_executions, 1);
        assert_eq!(metrics.successful_executions, 1);
    }

    #[tokio::test]
    async fn auditing_sandbox_policy_violation() {
        let sandbox = Arc::new(LocalSandbox::new());
        let policy = SandboxPolicy::new("test").with_blocked_command("rm");
        let auditing = AuditingSandbox::new(sandbox, policy);

        let limits = ResourceLimits::permissive();
        let result = auditing
            .execute_with_audit("rm", &["-rf".into()], &limits)
            .await;

        assert!(result.is_err());
        let metrics = auditing.metrics().await;
        assert_eq!(metrics.policy_violations, 1);
        assert_eq!(metrics.total_executions, 0);
    }

    #[tokio::test]
    async fn auditing_sandbox_multiple_executions() {
        let sandbox = Arc::new(LocalSandbox::new());
        let policy = SandboxPolicy::permissive();
        let auditing = AuditingSandbox::new(sandbox, policy);

        let limits = ResourceLimits::permissive();
        for i in 0..5 {
            auditing
                .execute_with_audit("echo", &[i.to_string()], &limits)
                .await
                .unwrap();
        }

        let log = auditing.audit_log().await;
        assert_eq!(log.len(), 5);

        let metrics = auditing.metrics().await;
        assert_eq!(metrics.total_executions, 5);
        assert_eq!(metrics.successful_executions, 5);
    }

    #[tokio::test]
    async fn auditing_sandbox_failed_execution() {
        let sandbox = Arc::new(LocalSandbox::new());
        let policy = SandboxPolicy::permissive();
        let auditing = AuditingSandbox::new(sandbox, policy);

        let limits = ResourceLimits::permissive();
        let result = auditing.execute_with_audit("false", &[], &limits).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().success());

        let metrics = auditing.metrics().await;
        assert_eq!(metrics.total_executions, 1);
        assert_eq!(metrics.failed_executions, 1);
    }

    #[tokio::test]
    async fn auditing_sandbox_nonexistent_command() {
        let sandbox = Arc::new(LocalSandbox::new());
        let policy = SandboxPolicy::permissive();
        let auditing = AuditingSandbox::new(sandbox, policy);

        let limits = ResourceLimits::permissive();
        let result = auditing
            .execute_with_audit("nonexistent_xyz", &[], &limits)
            .await;
        assert!(result.is_err());

        let metrics = auditing.metrics().await;
        assert_eq!(metrics.total_executions, 1);
        assert_eq!(metrics.failed_executions, 1);
    }
}
