# Configuration Reference

Spectra uses TOML configuration with environment variable overrides.

## Configuration File Locations

Spectra searches for `spectra.toml` in:

1. Current directory (`./spectra.toml`)
2. Home directory (`~/.config/spectra/spectra.toml`)
3. System directory (`/etc/spectra/spectra.toml`)

## Full Configuration

```toml
# API Server Configuration
[api]
host = "127.0.0.1"        # Bind address
port = 8080                # Listen port
cors_origins = ["*"]       # CORS allowed origins
max_request_size = 10485760  # 10MB

# Database Configuration
[database]
url = "postgres://localhost/spectra"
max_connections = 10
connection_timeout_secs = 30
idle_timeout_secs = 600

# Redis Configuration
[redis]
url = "redis://localhost:6379"
max_connections = 10
connection_timeout_secs = 5

# Object Storage Configuration
[storage]
backend = "local"          # local, s3, gcs
local_path = "./storage"

# Storage - S3 Backend
[storage.s3]
bucket = "spectra-storage"
region = "us-east-1"
endpoint = ""              # For S3-compatible storage

# Network Configuration
[network]
dns_servers = ["8.8.8.8", "8.8.4.4"]
timeout_ms = 5000
max_concurrent = 100
proxy = ""                 # HTTP proxy URL

# Crawler Configuration
[crawler]
max_depth = 3
max_pages = 10000
concurrent_requests = 10
delay_ms = 100
respect_robots = true
user_agent = "Spectra/0.1.0"

# Scanner Configuration
[scanner]
max_concurrent = 10
timeout_secs = 300
max_retries = 3
retry_delay_ms = 1000

# Scheduler Configuration
[scheduler]
max_concurrent_jobs = 10
poll_interval_ms = 1000
retry_delay_ms = 5000
job_timeout_secs = 600

# Verification Configuration
[verification]
auto_verify = true
min_confidence = 0.5
require_evidence = false

# Evidence Configuration
[evidence]
storage_path = "./evidence"
max_size_bytes = 10485760  # 10MB
retention_days = 90
redact_sensitive = true

# Plugin Configuration
[plugins]
enabled = true
sandbox_enabled = true
max_plugins = 100

# Sandbox Configuration
[sandbox]
max_memory_bytes = 268435456  # 256MB
max_cpu_time_ms = 30000       # 30s
max_disk_bytes = 1073741824   # 1GB
max_network_connections = 10

# Telemetry Configuration
[telemetry]
enabled = true
service_name = "spectra"
otlp_endpoint = ""           # OpenTelemetry collector endpoint
log_level = "info"           # trace, debug, info, warn, error

# Logging Configuration
[logging]
level = "info"
format = "pretty"            # pretty, json, compact
file = ""                    # Log file path (empty = stdout)
```

## Environment Variables

All configuration values can be overridden with environment variables.

### Naming Convention

```text
SPECTRA_<SECTION>__<KEY>
```

Double underscore (`__`) separates section from key.

### Examples

```bash
# API Configuration
SPECTRA_API__HOST=0.0.0.0
SPECTRA_API__PORT=9090

# Database Configuration
SPECTRA_DATABASE__URL=postgres://user:pass@host/db

# Redis Configuration
SPECTRA_REDIS__URL=redis://localhost:6379

# Network Configuration
SPECTRA_NETWORK__TIMEOUT_MS=10000

# Logging
SPECTRA_LOGGING__LEVEL=debug
```

### Nested Values

```bash
# S3 Storage
SPECTRA_STORAGE__BACKEND=s3
SPECTRA_STORAGE__S3__BUCKET=my-bucket
SPECTRA_STORAGE__S3__REGION=us-west-2
```

## Configuration Precedence

1. Command-line arguments (highest)
2. Environment variables
3. Local config file (`./spectra.toml`)
4. User config file (`~/.config/spectra/spectra.toml`)
5. System config file (`/etc/spectra/spectra.toml`)
6. Default values (lowest)

## Sensitive Values

Never commit sensitive values to version control:

- Database passwords
- API keys
- AWS credentials
- Encryption keys

Use environment variables or encrypted configuration files.

## Validation

Spectra validates configuration on startup:

- Required fields must be present
- Types must match
- URLs must be valid
- Ports must be in valid range
- Paths must exist (for file-based config)

Invalid configuration causes startup failure with clear error messages.
