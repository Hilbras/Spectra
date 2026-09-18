use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PluginError {
    #[error("Plugin not found: {0}")]
    NotFound(String),
    #[error("Plugin load error: {0}")]
    LoadError(String),
    #[error("Plugin execution error: {0}")]
    ExecutionError(String),
    #[error("Plugin already registered: {0}")]
    AlreadyRegistered(String),
    #[error("Plugin capability not supported: {0}")]
    CapabilityNotSupported(String),
    #[error("Sandbox error: {0}")]
    Sandbox(#[from] spectra_sandbox::SandboxError),
}

pub type PluginResult<T> = Result<T, PluginError>;

/// Capabilities a plugin can declare.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum PluginCapability {
    Scanner,
    Transformer,
    Enricher,
    Notifier,
    Reporter,
    Custom(String),
}

impl std::fmt::Display for PluginCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Scanner => write!(f, "Scanner"),
            Self::Transformer => write!(f, "Transformer"),
            Self::Enricher => write!(f, "Enricher"),
            Self::Notifier => write!(f, "Notifier"),
            Self::Reporter => write!(f, "Reporter"),
            Self::Custom(s) => write!(f, "Custom: {}", s),
        }
    }
}

/// Health status of a plugin.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PluginHealth {
    Healthy,
    Degraded { reason: String },
    Unhealthy { reason: String },
}

impl std::fmt::Display for PluginHealth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Healthy => write!(f, "Healthy"),
            Self::Degraded { reason } => write!(f, "Degraded: {}", reason),
            Self::Unhealthy { reason } => write!(f, "Unhealthy: {}", reason),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub entry_point: String,
    pub permissions: Vec<String>,
    pub dependencies: Vec<String>,
    pub capabilities: Vec<PluginCapability>,
}

impl PluginManifest {
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            description: String::new(),
            author: String::new(),
            entry_point: String::new(),
            permissions: Vec::new(),
            dependencies: Vec::new(),
            capabilities: Vec::new(),
        }
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    pub fn with_author(mut self, author: impl Into<String>) -> Self {
        self.author = author.into();
        self
    }

    pub fn with_permission(mut self, perm: impl Into<String>) -> Self {
        self.permissions.push(perm.into());
        self
    }

    pub fn with_capability(mut self, cap: PluginCapability) -> Self {
        self.capabilities.push(cap);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PluginState {
    Unloaded,
    Loaded,
    Running,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInfo {
    pub manifest: PluginManifest,
    pub state: PluginState,
}

#[async_trait::async_trait]
pub trait Plugin: Send + Sync {
    fn info(&self) -> PluginInfo;
    async fn initialize(&mut self) -> PluginResult<()>;
    async fn execute(&self, input: serde_json::Value) -> PluginResult<serde_json::Value>;
    async fn shutdown(&self) -> PluginResult<()>;
    /// Check plugin health.
    async fn health_check(&self) -> PluginHealth {
        PluginHealth::Healthy
    }
}

pub struct PluginManager {
    plugins: Vec<Box<dyn Plugin>>,
    index: HashMap<String, usize>,
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginManager {
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
            index: HashMap::new(),
        }
    }

    pub fn register(&mut self, plugin: Box<dyn Plugin>) -> PluginResult<()> {
        let name = plugin.info().manifest.name.clone();
        if self.index.contains_key(&name) {
            return Err(PluginError::AlreadyRegistered(name));
        }
        let idx = self.plugins.len();
        self.plugins.push(plugin);
        self.index.insert(name, idx);
        Ok(())
    }

    pub fn list_plugins(&self) -> Vec<PluginInfo> {
        self.plugins.iter().map(|p| p.info()).collect()
    }

    pub fn get_plugin(&self, name: &str) -> Option<&dyn Plugin> {
        self.index.get(name).map(|&idx| self.plugins[idx].as_ref())
    }

    pub fn plugin_count(&self) -> usize {
        self.plugins.len()
    }

    pub fn plugin_names(&self) -> Vec<String> {
        self.plugins
            .iter()
            .map(|p| p.info().manifest.name)
            .collect()
    }

    pub async fn initialize_all(&mut self) -> PluginResult<()> {
        for plugin in &mut self.plugins {
            plugin.initialize().await?;
        }
        Ok(())
    }

    pub async fn shutdown_all(&self) -> PluginResult<()> {
        for plugin in &self.plugins {
            plugin.shutdown().await?;
        }
        Ok(())
    }

    pub async fn execute_on(
        &self,
        name: &str,
        input: serde_json::Value,
    ) -> PluginResult<serde_json::Value> {
        let plugin = self
            .get_plugin(name)
            .ok_or_else(|| PluginError::NotFound(name.to_string()))?;
        plugin.execute(input).await
    }

    /// Health check all plugins.
    pub async fn health_check_all(&self) -> Vec<(String, PluginHealth)> {
        let mut results = Vec::new();
        for plugin in &self.plugins {
            let name = plugin.info().manifest.name.clone();
            let health = plugin.health_check().await;
            results.push((name, health));
        }
        results
    }

    /// Get plugins by capability.
    pub fn plugins_with_capability(&self, cap: &PluginCapability) -> Vec<&dyn Plugin> {
        self.plugins
            .iter()
            .filter(|p| p.info().manifest.capabilities.contains(cap))
            .map(|p| p.as_ref())
            .collect()
    }

    /// Remove a plugin by name.
    pub fn remove(&mut self, name: &str) -> PluginResult<Box<dyn Plugin>> {
        let idx = self
            .index
            .remove(name)
            .ok_or_else(|| PluginError::NotFound(name.to_string()))?;
        let plugin = self.plugins.remove(idx);
        // Rebuild index
        self.index.clear();
        for (i, p) in self.plugins.iter().enumerate() {
            self.index.insert(p.info().manifest.name.clone(), i);
        }
        Ok(plugin)
    }
}

pub struct EchoPlugin;

#[async_trait::async_trait]
impl Plugin for EchoPlugin {
    fn info(&self) -> PluginInfo {
        PluginInfo {
            manifest: PluginManifest::new("echo", "1.0.0")
                .with_description("Echo plugin for testing"),
            state: PluginState::Loaded,
        }
    }

    async fn initialize(&mut self) -> PluginResult<()> {
        Ok(())
    }

    async fn execute(&self, input: serde_json::Value) -> PluginResult<serde_json::Value> {
        Ok(input)
    }

    async fn shutdown(&self) -> PluginResult<()> {
        Ok(())
    }
}

pub struct TransformPlugin {
    manifest: PluginManifest,
}

impl TransformPlugin {
    pub fn new() -> Self {
        Self {
            manifest: PluginManifest::new("transform", "1.0.0")
                .with_description("Transforms input by uppercasing string values"),
        }
    }
}

impl Default for TransformPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Plugin for TransformPlugin {
    fn info(&self) -> PluginInfo {
        PluginInfo {
            manifest: self.manifest.clone(),
            state: PluginState::Loaded,
        }
    }

    async fn initialize(&mut self) -> PluginResult<()> {
        Ok(())
    }

    async fn execute(&self, input: serde_json::Value) -> PluginResult<serde_json::Value> {
        match input {
            serde_json::Value::String(s) => Ok(serde_json::Value::String(s.to_uppercase())),
            serde_json::Value::Object(map) => {
                let transformed: serde_json::Map<String, serde_json::Value> = map
                    .into_iter()
                    .map(|(k, v)| {
                        let val = match v {
                            serde_json::Value::String(s) => {
                                serde_json::Value::String(s.to_uppercase())
                            }
                            other => other,
                        };
                        (k, val)
                    })
                    .collect();
                Ok(serde_json::Value::Object(transformed))
            }
            other => Ok(other),
        }
    }

    async fn shutdown(&self) -> PluginResult<()> {
        Ok(())
    }
}

/// A counter plugin that tracks execution count.
pub struct CounterPlugin {
    manifest: PluginManifest,
    count: std::sync::atomic::AtomicU32,
}

impl CounterPlugin {
    pub fn new() -> Self {
        Self {
            manifest: PluginManifest::new("counter", "1.0.0")
                .with_description("Counts executions")
                .with_capability(PluginCapability::Enricher),
            count: std::sync::atomic::AtomicU32::new(0),
        }
    }

    pub fn count(&self) -> u32 {
        self.count.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl Default for CounterPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Plugin for CounterPlugin {
    fn info(&self) -> PluginInfo {
        PluginInfo {
            manifest: self.manifest.clone(),
            state: PluginState::Loaded,
        }
    }

    async fn initialize(&mut self) -> PluginResult<()> {
        Ok(())
    }

    async fn execute(&self, input: serde_json::Value) -> PluginResult<serde_json::Value> {
        let c = self
            .count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        Ok(serde_json::json!({
            "count": c,
            "input": input,
        }))
    }

    async fn shutdown(&self) -> PluginResult<()> {
        Ok(())
    }
}

/// An aggregator plugin that collects inputs.
pub struct AggregatorPlugin {
    manifest: PluginManifest,
    items: std::sync::Mutex<Vec<serde_json::Value>>,
}

impl AggregatorPlugin {
    pub fn new() -> Self {
        Self {
            manifest: PluginManifest::new("aggregator", "1.0.0")
                .with_description("Aggregates inputs into a list")
                .with_capability(PluginCapability::Transformer),
            items: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub fn items(&self) -> Vec<serde_json::Value> {
        self.items.lock().unwrap().clone()
    }
}

impl Default for AggregatorPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Plugin for AggregatorPlugin {
    fn info(&self) -> PluginInfo {
        PluginInfo {
            manifest: self.manifest.clone(),
            state: PluginState::Loaded,
        }
    }

    async fn initialize(&mut self) -> PluginResult<()> {
        Ok(())
    }

    async fn execute(&self, input: serde_json::Value) -> PluginResult<serde_json::Value> {
        self.items.lock().unwrap().push(input.clone());
        let items = self.items.lock().unwrap().clone();
        Ok(serde_json::json!({
            "total": items.len(),
            "items": items,
        }))
    }

    async fn shutdown(&self) -> PluginResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn echo_plugin() {
        let mut plugin = EchoPlugin;
        plugin.initialize().await.unwrap();

        let input = serde_json::json!({"key": "value"});
        let output = plugin.execute(input.clone()).await.unwrap();
        assert_eq!(output, input);

        plugin.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn transform_plugin_string() {
        let mut plugin = TransformPlugin::new();
        plugin.initialize().await.unwrap();

        let input = serde_json::Value::String("hello".into());
        let output = plugin.execute(input).await.unwrap();
        assert_eq!(output, serde_json::Value::String("HELLO".into()));
    }

    #[tokio::test]
    async fn transform_plugin_object() {
        let mut plugin = TransformPlugin::new();
        plugin.initialize().await.unwrap();

        let input = serde_json::json!({"name": "test", "count": 42});
        let output = plugin.execute(input).await.unwrap();
        assert_eq!(output["name"], "TEST");
        assert_eq!(output["count"], 42);
    }

    #[tokio::test]
    async fn transform_plugin_passthrough() {
        let mut plugin = TransformPlugin::new();
        plugin.initialize().await.unwrap();

        let input = serde_json::json!(42);
        let output = plugin.execute(input.clone()).await.unwrap();
        assert_eq!(output, input);
    }

    #[tokio::test]
    async fn plugin_manager_register_and_list() {
        let mut manager = PluginManager::new();
        manager.register(Box::new(EchoPlugin)).unwrap();
        manager.register(Box::new(TransformPlugin::new())).unwrap();

        assert_eq!(manager.plugin_count(), 2);
        let names = manager.plugin_names();
        assert!(names.contains(&"echo".to_string()));
        assert!(names.contains(&"transform".to_string()));
    }

    #[tokio::test]
    async fn plugin_manager_duplicate_registration() {
        let mut manager = PluginManager::new();
        manager.register(Box::new(EchoPlugin)).unwrap();
        let result = manager.register(Box::new(EchoPlugin));
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn plugin_manager_get_plugin() {
        let mut manager = PluginManager::new();
        manager.register(Box::new(EchoPlugin)).unwrap();

        assert!(manager.get_plugin("echo").is_some());
        assert!(manager.get_plugin("nonexistent").is_none());
    }

    #[tokio::test]
    async fn plugin_manager_execute_on() {
        let mut manager = PluginManager::new();
        manager.register(Box::new(EchoPlugin)).unwrap();

        let input = serde_json::json!({"test": true});
        let output = manager.execute_on("echo", input.clone()).await.unwrap();
        assert_eq!(output, input);
    }

    #[tokio::test]
    async fn plugin_manager_execute_not_found() {
        let manager = PluginManager::new();
        let result = manager.execute_on("nope", serde_json::json!(null)).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn plugin_manager_initialize_and_shutdown() {
        let mut manager = PluginManager::new();
        manager.register(Box::new(EchoPlugin)).unwrap();
        manager.register(Box::new(TransformPlugin::new())).unwrap();

        manager.initialize_all().await.unwrap();
        manager.shutdown_all().await.unwrap();
    }

    #[test]
    fn manifest_builder() {
        let manifest = PluginManifest::new("test", "0.1.0")
            .with_description("A test plugin")
            .with_author("tester")
            .with_permission("network")
            .with_permission("filesystem")
            .with_capability(PluginCapability::Scanner);

        assert_eq!(manifest.name, "test");
        assert_eq!(manifest.version, "0.1.0");
        assert_eq!(manifest.description, "A test plugin");
        assert_eq!(manifest.author, "tester");
        assert_eq!(manifest.permissions.len(), 2);
        assert_eq!(manifest.capabilities.len(), 1);
    }

    #[test]
    fn plugin_info_display() {
        let plugin = EchoPlugin;
        let info = plugin.info();
        assert_eq!(info.manifest.name, "echo");
        assert_eq!(info.state, PluginState::Loaded);
    }

    #[test]
    fn capability_display() {
        assert_eq!(PluginCapability::Scanner.to_string(), "Scanner");
        assert_eq!(
            PluginCapability::Custom("test".into()).to_string(),
            "Custom: test"
        );
    }

    #[test]
    fn health_display() {
        assert_eq!(PluginHealth::Healthy.to_string(), "Healthy");
        assert_eq!(
            PluginHealth::Degraded {
                reason: "slow".into()
            }
            .to_string(),
            "Degraded: slow"
        );
    }

    #[tokio::test]
    async fn health_check_default() {
        let plugin = EchoPlugin;
        assert_eq!(plugin.health_check().await, PluginHealth::Healthy);
    }

    #[tokio::test]
    async fn counter_plugin() {
        let plugin = CounterPlugin::new();
        assert_eq!(plugin.count(), 0);

        let output = plugin.execute(serde_json::json!("test")).await.unwrap();
        assert_eq!(output["count"], 1);

        let output = plugin.execute(serde_json::json!("test2")).await.unwrap();
        assert_eq!(output["count"], 2);

        assert_eq!(plugin.count(), 2);
    }

    #[tokio::test]
    async fn aggregator_plugin() {
        let plugin = AggregatorPlugin::new();
        assert!(plugin.items().is_empty());

        let output = plugin.execute(serde_json::json!("a")).await.unwrap();
        assert_eq!(output["total"], 1);

        let output = plugin.execute(serde_json::json!("b")).await.unwrap();
        assert_eq!(output["total"], 2);

        assert_eq!(plugin.items().len(), 2);
    }

    #[tokio::test]
    async fn plugin_manager_health_check_all() {
        let mut manager = PluginManager::new();
        manager.register(Box::new(EchoPlugin)).unwrap();
        manager.register(Box::new(TransformPlugin::new())).unwrap();

        let results = manager.health_check_all().await;
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|(_, h)| h == &PluginHealth::Healthy));
    }

    #[tokio::test]
    async fn plugins_with_capability() {
        let mut manager = PluginManager::new();
        manager.register(Box::new(EchoPlugin)).unwrap();
        manager.register(Box::new(CounterPlugin::new())).unwrap();
        manager.register(Box::new(AggregatorPlugin::new())).unwrap();

        let enrichers = manager.plugins_with_capability(&PluginCapability::Enricher);
        assert_eq!(enrichers.len(), 1);

        let transformers = manager.plugins_with_capability(&PluginCapability::Transformer);
        assert_eq!(transformers.len(), 1);
    }

    #[tokio::test]
    async fn remove_plugin() {
        let mut manager = PluginManager::new();
        manager.register(Box::new(EchoPlugin)).unwrap();
        assert_eq!(manager.plugin_count(), 1);

        let removed = manager.remove("echo").unwrap();
        assert_eq!(removed.info().manifest.name, "echo");
        assert_eq!(manager.plugin_count(), 0);
        assert!(manager.get_plugin("echo").is_none());
    }

    #[tokio::test]
    async fn remove_nonexistent_plugin() {
        let mut manager = PluginManager::new();
        assert!(manager.remove("nope").is_err());
    }
}
