use async_trait::async_trait;
use chrono::Utc;
use serde_json::Value;
use spectra_core::{Id, SpectraError};
use sqlx::types::Uuid;

use crate::pg::{pg_row_to_row, PostgresDatabase};
use crate::repositories::{JobRecord, JobRepository, ScanRecord};
use crate::{Row, StorageResult};

fn row_to_job_record(row: Row) -> StorageResult<JobRecord> {
    let id: Id<JobRecord> = row
        .get_by_name::<String>("id")?
        .parse()
        .map_err(|e| SpectraError::Storage(format!("Invalid job id: {e}")))?;

    let scan_id: Id<ScanRecord> = row
        .get_by_name::<String>("scan_id")?
        .parse()
        .map_err(|e| SpectraError::Storage(format!("Invalid scan id: {e}")))?;

    let job_type: String = row.get_by_name("job_type")?;
    let status: String = row.get_by_name("status")?;
    let priority: u32 = row.get_by_name::<i64>("priority")? as u32;
    let payload: Value = row.get_by_name("payload")?;
    let result: Option<Value> = row.get_by_name("result")?;
    let error: Option<String> = row.get_by_name("error_message")?;
    let attempts: u32 = row.get_by_name::<i64>("attempts")? as u32;
    let max_attempts: u32 = row.get_by_name::<i64>("max_retries")? as u32;
    let worker_id: Option<String> = row.get_by_name("worker_id")?;
    let queued_at: String = row.get_by_name("created_at")?;
    let started_at: Option<String> = row.get_by_name("started_at")?;
    let completed_at: Option<String> = row.get_by_name("completed_at")?;

    Ok(JobRecord {
        id,
        scan_id,
        job_type,
        status,
        priority,
        payload,
        result,
        error,
        attempts,
        max_attempts,
        worker_id,
        queued_at,
        started_at,
        completed_at,
    })
}

fn parse_timestamp(s: &str) -> StorageResult<chrono::DateTime<Utc>> {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| SpectraError::Storage(format!("Invalid timestamp: {e}")))
}

#[async_trait]
impl JobRepository for PostgresDatabase {
    async fn create(&self, job: &JobRecord) -> StorageResult<JobRecord> {
        let id = job.id.as_uuid();
        let scan_id = job.scan_id.as_uuid();
        let worker_id = job
            .worker_id
            .as_deref()
            .and_then(|s| Uuid::parse_str(s).ok());

        let queued_at = parse_timestamp(&job.queued_at)?;
        let started_at = job.started_at.as_deref().map(parse_timestamp).transpose()?;
        let completed_at = job
            .completed_at
            .as_deref()
            .map(parse_timestamp)
            .transpose()?;

        let row = sqlx::query(
            r#"
            INSERT INTO scan_jobs (
                id, scan_id, worker_id, job_type, status, priority,
                payload, result, error_message, attempts, max_retries,
                started_at, completed_at, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $14)
            RETURNING id, scan_id, worker_id, job_type, status, priority,
                      payload, result, error_message, attempts, max_retries,
                      started_at, completed_at, created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(scan_id)
        .bind(worker_id)
        .bind(&job.job_type)
        .bind(&job.status)
        .bind(job.priority as i32)
        .bind(&job.payload)
        .bind(&job.result)
        .bind(&job.error)
        .bind(job.attempts as i32)
        .bind(job.max_attempts as i32)
        .bind(started_at)
        .bind(completed_at)
        .bind(queued_at)
        .fetch_one(self.pool())
        .await
        .map_err(|e| SpectraError::Storage(format!("Insert scan_jobs failed: {e}")))?;

        let row = pg_row_to_row(row)?;
        row_to_job_record(row)
    }

    async fn get(&self, id: &Id<JobRecord>) -> StorageResult<Option<JobRecord>> {
        let row = sqlx::query(
            "SELECT id, scan_id, worker_id, job_type, status, priority, payload, result, \
             error_message, attempts, max_retries, started_at, completed_at, created_at, \
             updated_at FROM scan_jobs WHERE id = $1",
        )
        .bind(id.as_uuid())
        .fetch_optional(self.pool())
        .await
        .map_err(|e| SpectraError::Storage(format!("Get scan_jobs failed: {e}")))?;

        match row {
            Some(pg_row) => {
                let row = pg_row_to_row(pg_row)?;
                Ok(Some(row_to_job_record(row)?))
            }
            None => Ok(None),
        }
    }

    async fn list_all(&self) -> StorageResult<Vec<JobRecord>> {
        let rows = sqlx::query(
            "SELECT id, scan_id, worker_id, job_type, status, priority, payload, result, \
             error_message, attempts, max_retries, started_at, completed_at, created_at, \
             updated_at FROM scan_jobs ORDER BY created_at",
        )
        .fetch_all(self.pool())
        .await
        .map_err(|e| SpectraError::Storage(format!("List all scan_jobs failed: {e}")))?;

        rows.into_iter()
            .map(pg_row_to_row)
            .collect::<StorageResult<Vec<Row>>>()?
            .into_iter()
            .map(row_to_job_record)
            .collect()
    }

    async fn list_by_scan(&self, scan_id: &Id<ScanRecord>) -> StorageResult<Vec<JobRecord>> {
        let rows = sqlx::query(
            "SELECT id, scan_id, worker_id, job_type, status, priority, payload, result, \
             error_message, attempts, max_retries, started_at, completed_at, created_at, \
             updated_at FROM scan_jobs WHERE scan_id = $1 ORDER BY created_at",
        )
        .bind(scan_id.as_uuid())
        .fetch_all(self.pool())
        .await
        .map_err(|e| SpectraError::Storage(format!("List scan_jobs by scan failed: {e}")))?;

        rows.into_iter()
            .map(pg_row_to_row)
            .collect::<StorageResult<Vec<Row>>>()?
            .into_iter()
            .map(row_to_job_record)
            .collect()
    }

    async fn update(&self, job: &JobRecord) -> StorageResult<()> {
        let id = job.id.as_uuid();
        let worker_id = job
            .worker_id
            .as_deref()
            .and_then(|s| Uuid::parse_str(s).ok());

        let started_at = job.started_at.as_deref().map(parse_timestamp).transpose()?;
        let completed_at = job
            .completed_at
            .as_deref()
            .map(parse_timestamp)
            .transpose()?;

        let result = sqlx::query(
            "UPDATE scan_jobs SET worker_id = $1, job_type = $2, status = $3, priority = $4, \
             payload = $5, result = $6, error_message = $7, attempts = $8, max_retries = $9, \
             started_at = $10, completed_at = $11, updated_at = NOW() \
             WHERE id = $12",
        )
        .bind(worker_id)
        .bind(&job.job_type)
        .bind(&job.status)
        .bind(job.priority as i32)
        .bind(&job.payload)
        .bind(&job.result)
        .bind(&job.error)
        .bind(job.attempts as i32)
        .bind(job.max_attempts as i32)
        .bind(started_at)
        .bind(completed_at)
        .bind(id)
        .execute(self.pool())
        .await
        .map_err(|e| SpectraError::Storage(format!("Update scan_jobs failed: {e}")))?;

        if result.rows_affected() == 0 {
            return Err(SpectraError::Storage(format!(
                "Job {} not found for update",
                job.id
            )));
        }

        Ok(())
    }

    async fn delete(&self, id: &Id<JobRecord>) -> StorageResult<()> {
        let result = sqlx::query("DELETE FROM scan_jobs WHERE id = $1")
            .bind(id.as_uuid())
            .execute(self.pool())
            .await
            .map_err(|e| SpectraError::Storage(format!("Delete scan_jobs failed: {e}")))?;

        if result.rows_affected() == 0 {
            return Err(SpectraError::Storage(format!(
                "Job {} not found for delete",
                id
            )));
        }

        Ok(())
    }

    async fn list_pending(&self) -> StorageResult<Vec<JobRecord>> {
        let rows = sqlx::query(
            "SELECT id, scan_id, worker_id, job_type, status, priority, payload, result, \
             error_message, attempts, max_retries, started_at, completed_at, created_at, \
             updated_at FROM scan_jobs WHERE status = 'queued' ORDER BY priority ASC, created_at ASC",
        )
        .fetch_all(self.pool())
        .await
        .map_err(|e| SpectraError::Storage(format!("List pending scan_jobs failed: {e}")))?;

        rows.into_iter()
            .map(pg_row_to_row)
            .collect::<StorageResult<Vec<Row>>>()?
            .into_iter()
            .map(row_to_job_record)
            .collect()
    }

    async fn list_by_status(&self, status: &str) -> StorageResult<Vec<JobRecord>> {
        let rows = sqlx::query(
            "SELECT id, scan_id, worker_id, job_type, status, priority, payload, result, \
             error_message, attempts, max_retries, started_at, completed_at, created_at, \
             updated_at FROM scan_jobs WHERE status = $1 ORDER BY priority ASC, created_at ASC",
        )
        .bind(status)
        .fetch_all(self.pool())
        .await
        .map_err(|e| SpectraError::Storage(format!("List scan_jobs by status failed: {e}")))?;

        rows.into_iter()
            .map(pg_row_to_row)
            .collect::<StorageResult<Vec<Row>>>()?
            .into_iter()
            .map(row_to_job_record)
            .collect()
    }
}
