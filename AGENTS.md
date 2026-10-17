# Spectra — AGENTS.md

This file describes how to build, test, run, and extend the Spectra repository.
It is a working document: update it when the layout, commands, or env vars change.

## Repo layout

```
/home/gin/work/Hilbras/Spectra
├── Cargo.toml            # workspace root: 27 members (19 crates + 3 apps)
├── migrations/           # SQL migrations, applied at startup via `run_migrations`
├── crates/               # library crates (storage, scheduler, engine, auth, ...)
│   ├── storage/          # DB abstraction: PostgresDatabase, JobRepository (pg_repos.rs)
│   ├── scheduler/        # JobQueue trait + InMemoryJobQueue + PostgresJobQueue (pg_queue.rs)
│   └── ...
├── apps/
│   ├── api/              # spectra-api (axum HTTP server)
│   ├── cli/              # spectra-cli
│   └── worker/           # spectra-worker (job consumer)
├── scripts/start.sh      # build + start api + worker (release binaries)
├── docker-compose.yml    # postgres:16 + redis + api + worker
├── Dockerfile
└── target/               # build output (gitignored)
```

## Build / test commands (run from repo root)

```
cargo build --workspace              # debug build of everything
cargo build --release --workspace    # release build (used by scripts/start.sh)
cargo test --workspace               # full test suite
cargo test -p spectra-api            # single crate
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check           # formatting check
cargo fmt --all                      # apply formatting
```

Per-crate shortcuts that matter day-to-day:

```
cargo build -p spectra-api
cargo build -p spectra-worker
cargo build -p spectra-scheduler
cargo build -p spectra-storage
```

## Environment variables

| Var | Meaning | Default |
|-----|---------|---------|
| `SPECTRA_DATABASE_URL` | PostgreSQL connection URL (sqlx format) | unset → in-memory mode |
| `SPECTRA_PORT` | API server port | 8080 |
| `SPECTRA_ADMIN_PASSWORD` | Initial admin password | random if unset |
| `SPECTRA_JWT_SECRET` | JWT signing secret (>= 32 bytes) | required |
| `SPECTRA_REDIS_URL` | Redis URL | unset |
| `SPECTRA_LOG_LEVEL` | tracing log level | info |

The API reads `SPECTRA_DATABASE_URL` at startup in `apps/api/src/main.rs`. When set, it connects to Postgres, runs `migrations/`, and persists scan jobs via `JobRepository`. When unset, it falls back to in-memory state.

The worker reads the same `SPECTRA_DATABASE_URL`. When set it uses `PostgresJobQueue` (backed by the `scan_jobs` table) so API and worker share a durable queue; when unset it uses `InMemoryJobQueue`.

## Running the services

### Local binaries (scripts/start.sh)
```
chmod +x scripts/start.sh
./scripts/start.sh start    # builds release binaries if needed, starts api + worker
./scripts/start.sh status
./scripts/start.sh stop
```
API listens on `http://0.0.0.0:8080`; health at `/api/v1/health`. Logs go to `logs/`, PIDs to `.pids/`.

### Docker Compose
```
docker compose up -d          # postgres + redis + api + worker
docker compose logs -f api
docker compose down
```
The compose file requires `POSTGRES_PASSWORD` and `SPECTRA_JWT_SECRET` to be set (it fails with a clear message otherwise). Postgres is exposed on `5432`, API on `8080`.

## Migrations

Migration files live in `migrations/` and are applied in name order at startup by
`PostgresDatabase::run_migrations("migrations")`. Each file is applied inside its
own transaction and recorded in `schema_migrations` with an md5 checksum, so a
re-run is a no-op and a checksum mismatch on an already-applied migration is an
error. Add new numbered files for schema changes; do not edit applied files.

## Postgres-backed pieces (current state)

- `crates/storage/src/pg_repos.rs` — `JobRepository for PostgresDatabase` (create/get/list/update/delete/list_pending/list_by_status on `scan_jobs`).
- `crates/scheduler/src/pg_queue.rs` — `PostgresJobQueue` implementing `spectra_scheduler::JobQueue` (enqueue/dequeue/complete/fail/retry on `scan_jobs`, claimed with `FOR UPDATE SKIP LOCKED`).
- `apps/api/src/main.rs` — wires `PostgresDatabase` into `AppState`, pings it in health check, writes `JobRecord` on POST /scans.
- `apps/worker/src/main.rs` — uses `PostgresJobQueue` when `SPECTRA_DATABASE_URL` is set, else `InMemoryJobQueue`.

## Conventions

- No `chrono`/`sqlx` direct imports in app crates unless they are workspace deps declared in that crate's `Cargo.toml`.
- `unsafe_code = "forbid"` at workspace level; clippy `pedantic`/`nursery` are `allow` but CI runs `-D warnings`.
- Default to no comments; match existing idioms.
- All state is in-memory today except what Postgres persists (jobs). Auth `UserStore` stays in-memory (out of scope).
