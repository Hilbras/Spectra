# Postgres End-to-End Verification (Manual)

Local port 5432 is occupied and no `psql` client is available in this
environment, so the API/worker-vs-Postgres e2e cannot be run here. Follow these
steps against a reachable Postgres instance.

## Prerequisites

- A running Postgres 16+ instance reachable over TCP
- `psql` client (or any SQL client) to verify schema/data
- The `SPECTRA_DATABASE_URL` env var set to the instance (sqlx format)
- `SPECTRA_JWT_SECRET` set (>= 32 bytes) for the API

## 1. Start Postgres (docker-compose)

```bash
export POSTGRES_PASSWORD=<strong-password>
export SPECTRA_JWT_SECRET=<32+ random bytes>
docker compose up -d postgres redis
```

Postgres is exposed on `localhost:5432`.

## 2. Point the API and worker at Postgres

```bash
export SPECTRA_DATABASE_URL="postgres://spectra:<password>@localhost:5432/spectra?sslmode=disable"
```

When `SPECTRA_DATABASE_URL` is set, `PostgresDatabase` connects, runs
`migrations/` (001–007), and persists scan jobs. The worker uses
`PostgresJobQueue` (backed by `scan_jobs`), so API and worker share a durable
queue.

## 3. Build and start the services

```bash
cargo build --release --workspace
./scripts/start.sh start
./scripts/start.sh status
```

API listens on `http://0.0.0.0:8080`; health at `/api/v1/health`.

## 4. E2E flow

Create a scan via the API:

```bash
curl -s -X POST http://localhost:8080/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target_id":"<uuid>","scanner":"directory","config":{}}' \
  | jq .
```

Note the returned scan `id`. Then:

- **GET /scans** — the scan should appear in the list (reads `list_all()` from Postgres)
- **GET /scans/:id** — the scan should return full detail (reads `get()` from Postgres)

Restart the API:

```bash
./scripts/start.sh stop
./scripts/start.sh start
```

Re-query **GET /scans** and **GET /scans/:id**. Both should still return the scan,
proving it was read from durable Postgres storage, not the in-memory map (which
is cleared on restart).

## 5. Verify directly in Postgres

```bash
psql "$SPECTRA_DATABASE_URL" -c "SELECT id, status, payload->>'target_id' AS target_id, created_at FROM scan_jobs ORDER BY created_at DESC LIMIT 5;"
```

## Known limitation of the fallback read path

`JobRecord` (the Postgres row) does not persist engine metrics
(`network_asset_count`, `crawl_page_count`, `technology_count`,
`total_findings`, `findings_by_severity`, `observations_recorded`,
`evidence_collected`, `scan_duration_ms`, `errors`). When `GET /scans/:id`
falls back to Postgres, those fields are reported as zero/defaults and
`errors` contains only `JobRecord.error`. This is a documented compromise for
the durable read path; full detail remains available via the in-memory map
before a restart.
