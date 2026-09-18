# Plugin Development

Spectra supports plugins via the `Plugin` trait. Plugins extend the platform with custom scanners, transformers, enrichers, notifiers, and reporters.

## Plugin Interface

```rust
use async_trait::async_trait;
use spectra_plugins::{Plugin, PluginInfo, PluginManifest, PluginCapability, PluginResult};

pub struct MyPlugin;

#[async_trait]
impl Plugin for MyPlugin {
    fn info(&self) -> PluginInfo {
        PluginInfo {
            manifest: PluginManifest::new("my-plugin", "0.1.0")
                .with_description("Does something useful")
                .with_author("your-name")
                .with_permission("network")
                .with_capability(PluginCapability::Scanner),
            state: spectra_plugins::PluginState::Loaded,
        }
    }

    async fn initialize(&mut self) -> PluginResult<()> {
        // Setup resources, validate config, etc.
        Ok(())
    }

    async fn execute(&self, input: serde_json::Value) -> PluginResult<serde_json::Value> {
        // Process the input and return results
        let target = input["target"].as_str().unwrap_or("unknown");
        Ok(serde_json::json!({
            "plugin": "my-plugin",
            "target": target,
            "results": []
        }))
    }

    async fn shutdown(&self) -> PluginResult<()> {
        // Cleanup resources
        Ok(())
    }
}
```

## Plugin Capabilities

| Capability | Purpose |
|------------|---------|
| `Scanner` | Vulnerability scanning |
| `Transformer` | Transform input data |
| `Enricher` | Enrich data with additional info |
| `Notifier` | Send notifications |
| `Reporter` | Generate reports |
| `Custom(String)` | Custom capability |

## Plugin Manager

```rust
use spectra_plugins::PluginManager;

let mut manager = PluginManager::new();

// Register plugins
manager.register(Box::new(MyPlugin)).unwrap();

// Initialize all
manager.initialize_all().await.unwrap();

// Execute a plugin
let result = manager.execute_on("my-plugin", serde_json::json!({
    "target": "example.com"
})).await.unwrap();

// Health check
let health = manager.health_check_all().await;

// Find plugins by capability
let scanners = manager.plugins_with_capability(&PluginCapability::Scanner);

// Remove a plugin
manager.remove("my-plugin").unwrap();

// Shutdown all
manager.shutdown_all().await.unwrap();
```

## Built-in Plugins

| Plugin | Capability | Description |
|--------|------------|-------------|
| `EchoPlugin` | Custom | Echoes input back (testing) |
| `TransformPlugin` | Transformer | Uppercases strings, passes through objects |
| `CounterPlugin` | Enricher | Counts executions |
| `AggregatorPlugin` | Transformer | Collects inputs into a list |

## Health Checks

Plugins can implement health checks:

```rust
use spectra_plugins::PluginHealth;

#[async_trait]
impl Plugin for MyPlugin {
    // ... other methods ...

    async fn health_check(&self) -> PluginHealth {
        // Check plugin health
        if self.is_healthy() {
            PluginHealth::Healthy
        } else {
            PluginHealth::Degraded {
                reason: "connection pool exhausted".into(),
            }
        }
    }
}
```

Health statuses:
- `Healthy` — operating normally
- `Degraded { reason }` — operational but impaired
- `Unhealthy` — not operational

## Sandbox Execution

Plugins run in a sandboxed environment with configurable resource limits:

```rust
use spectra_sandbox::{ResourceLimits, SandboxPolicy};

// Strict limits for untrusted plugins
let limits = ResourceLimits::strict();
// 64MB memory, 5s CPU, 10MB disk, no network

// Permissive limits for trusted plugins
let limits = ResourceLimits::permissive();
// 1GB memory, 120s CPU, 10GB disk, full network

// Custom policy
let policy = SandboxPolicy::new("my-policy")
    .with_max_executions_per_minute(30)
    .with_allowed_command("nmap")
    .with_blocked_command("rm");
```

## Plugin Lifecycle

```
Register → Initialize → [Execute]* → Shutdown
              ↓              ↓
         Health Check    Audit Log
```

1. **Register** — Add plugin to manager
2. **Initialize** — Setup resources, validate config
3. **Execute** — Process inputs (may be called many times)
4. **Health Check** — Periodic health verification
5. **Shutdown** — Cleanup and release resources

All executions are logged in the audit trail with command, duration, exit code, and policy applied.

## Example: Custom Scanner Plugin

```rust
use async_trait::async_trait;
use spectra_plugins::{Plugin, PluginInfo, PluginManifest, PluginCapability, PluginResult};

struct CustomScanner {
    findings: std::sync::Mutex<Vec<serde_json::Value>>,
}

impl CustomScanner {
    fn new() -> Self {
        Self {
            findings: std::sync::Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl Plugin for CustomScanner {
    fn info(&self) -> PluginInfo {
        PluginInfo {
            manifest: PluginManifest::new("custom-scanner", "0.1.0")
                .with_description("Custom vulnerability scanner")
                .with_capability(PluginCapability::Scanner)
                .with_permission("network"),
            state: spectra_plugins::PluginState::Loaded,
        }
    }

    async fn initialize(&mut self) -> PluginResult<()> {
        Ok(())
    }

    async fn execute(&self, input: serde_json::Value) -> PluginResult<serde_json::Value> {
        let url = input["url"].as_str().unwrap_or("");

        // Your scanning logic here
        let findings = vec![];

        Ok(serde_json::json!({
            "scanner": "custom-scanner",
            "url": url,
            "findings": findings,
            "scan_time_ms": 0
        }))
    }

    async fn shutdown(&self) -> PluginResult<()> {
        Ok(())
    }
}

// Register and use
let mut manager = PluginManager::new();
manager.register(Box::new(CustomScanner::new())).unwrap();
```

## Security Considerations

- Plugins run with the permissions declared in their manifest
- The sandbox enforces resource limits (memory, CPU, disk, network)
- All plugin executions are audit-logged
- Host allow/block lists control network access
- Use `ResourceLimits::strict()` for untrusted plugins
- Never grant more permissions than needed
