# Configuration Reference

Spectra uses TOML configuration with environment variable overrides.

## Config File Locations

Spectra searches for `spectra.toml` in order:

1. `./spectra.toml` (current directory)
2. `~/.config/spectra/spectra.toml` (user)
3. `/etc/spectra/spectra.toml` (system)

## Full Configuration

```toml
# Server
[server]
host = "0.0.0.0"          # Bind address
port = 8080                # Listen port
workers = 4                # Tokio worker threads

# PostgreSQL Database
[database]
url = "postgresql://localhost/spectra"
max_connections = 20       # Connection pool max
min_connections = 5        # Connection pool min

# Object Storage
[storage]
storage_type = "local"     # "local" or "s3"
path = "./storage"         # Local storage path

[storage.s3]
bucket = "spectra-storage"
region = "us-east-1"
endpoint = ""              # For S3-compatible (MinIO, etc.)
access_key = ""            # Or use AWS_ACCESS_KEY_ID env
secret_key = ""            # Or use AWS_SECRET_ACCESS_KEY env

# Full-Text Search
[search]
url = "http://localhost:9200"
index_prefix = "spectra"

# Job Queue
[queue]
queue_type = "redis"       # "redis" or "in-memory"
url = "redis://localhost:6379"

# Scanner
[scanner]
max_concurrent = 10        # Max concurrent scans
default_timeout = 300      # Scan timeout in seconds
rate_limit_per_second = 50 # Requests per second per target

# Crawler
[crawler]
max_depth = 10             # Max crawl depth from seed
max_pages = 10000          # Max pages per crawl
concurrent_requests = 10   # Parallel HTTP requests
respect_robots = true      # Honor robots.txt
user_agent = "Spectra/0.1.1"

# AI Analysis
[ai]
provider = "openai"        # AI provider
model = "gpt-4"            # Model name
api_key_env = "SPECTRA_AI_API_KEY"  # Env var with API key
enabled = false            # Enable AI features

# Telemetry (OpenTelemetry)
[telemetry]
enabled = true
endpoint = "http://localhost:4317"  # OTLP collector

# Worker
[worker]
heartbeat_interval = 10    # Seconds between heartbeats
job_timeout = 600          # Max job runtime in seconds
max_retries = 3            # Max retry attempts

# Logging
[logging]
level = "info"             # trace, debug, info, warn, error
format = "text"            # "text" or "json"
```

## Environment Variables

All config values can be overridden with environment variables:

### Naming Convention

```
SPECTRA_<SECTION>__<KEY>
```

Double underscore (`__`) separates section from key.

### Examples

```bash
# Server
SPECTRA_SERVER__HOST=0.0.0.0
SPECTRA_SERVER__PORT=9090

# Database
SPECTRA_DATABASE__URL=postgresql://user:pass@host/db

# Storage
SPECTRA_STORAGE__STORAGE_TYPE=s3
SPECTRA_STORAGE__S3__BUCKET=my-bucket

# Scanner
SPECTRA_SCANNER__MAX_CONCURRENT=20
SPECTRA_SCANNER__RATE_LIMIT_PER_SECOND=100

# Crawler
SPECTRA_CRAWLER__MAX_DEPTH=5
SPECTRA_CRAWLER__RESPECT_ROBOTS=false

# Logging
SPECTRA_LOGGING__LEVEL=debug
SPECTRA_LOGGING__FORMAT=json

# AI
SPECTRA_AI__ENABLED=true
SPECTRA_AI__PROVIDER=openai
```

## Configuration Precedence

Values are resolved in order (highest wins):

1. Command-line arguments
2. Environment variables
3. `./spectra.toml`
4. `~/.config/spectra/spectra.toml`
5. `/etc/spectra/spectra.toml`
6. Compiled defaults

## Sensitive Values

Never commit these to version control:

- Database passwords
- API keys (`ai.api_key_env` points to an env var, not the key itself)
- AWS/S3 credentials
- Encryption keys

Use environment variables or encrypted config files for secrets.

## Validation

Spectra validates configuration on startup:

- Required fields must be present
- Types must match (port must be u16, etc.)
- URLs must be parseable
- Port numbers must be in 1–65535
- Paths are checked when applicable

Invalid config causes a clear startup error:

```
Error: Configuration error: invalid value for port: 99999
```

## Per-Environment Configs

Use environment variables for per-deployment overrides:

```bash
# Development
SPECTRA_LOGGING__LEVEL=debug
SPECTRA_SCANNER__MAX_CONCURRENT=2

# Production
SPECTRA_LOGGING__LEVEL=warn
SPECTRA_SCANNER__MAX_CONCURRENT=20
SPECTRA_DATABASE__URL=postgresql://prod-host/spectra
```
