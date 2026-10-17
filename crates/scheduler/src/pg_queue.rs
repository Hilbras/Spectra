use crate::{Job, JobQueue, JobStatus, SchedulerError, SchedulerResult};
use async_trait::async_trait;
use chrono::Utc;
use spectra_storage::pg::PostgresDatabase;
use sqlx::Row;
use std::sync::Arc;
use uuid::Uuid;

const STATUS_PENDING: &str = "pending";
const STATUS_RUNNING: &str = "running";
const STATUS_COMPLETED: &str = "completed";
const STATUS_FAILED: &str = "failed";
const STATUS_RETRY: &str = "retry";

/// A PostgreSQL-backed [`JobQueue`] backed by the `scan_jobs` table.
///
/// Jobs are claimed atomically with `UPDATE ... RETURNING ... FOR UPDATE SKIP
/// LOCKED`, so multiple workers can poll the same table without being handed the
/// same job twice.
pub struct PostgresJobQueue {
    db: Arc<PostgresDatabase>,
}

impl PostgresJobQueue {
    pub fn new(db: Arc<PostgresDatabase>) -> Self {
        Self { db }
    }

    fn pool(&self) -> &sqlx::postgres::PgPool {
        self.db.pool()
    }
}

fn str_to_job_status(status: &str) -> JobStatus {
    match status {
        STATUS_RUNNING => JobStatus::Running,
        STATUS_COMPLETED => JobStatus::Completed,
        STATUS_FAILED => JobStatus::Failed,
        STATUS_RETRY => JobStatus::Retry,
        _ => JobStatus::Pending,
    }
}

fn row_to_job(row: sqlx::postgres::PgRow) -> SchedulerResult<Job> {
    let id: uuid::Uuid = row.get("id");
    let job_type: String = row.get("job_type");
    let payload: serde_json::Value = row.get("payload");
    let status: JobStatus = str_to_job_status(&row.get::<String, _>("status"));
    let priority: u32 = row.get::<i64, _>("priority") as u32;
    let max_retries: u32 = row.get::<i32, _>("max_retries") as u32;
    let retry_count: u32 = row.get::<i32, _>("attempts") as u32;
    let last_error: Option<String> = row.get("error_message");
    let created_at: Option<String> = row
        .get::<Option<chrono::DateTime<Utc>>, _>("created_at")
        .map(|dt| dt.to_rfc3339());
    let started_at: Option<String> = row
        .get::<Option<chrono::DateTime<Utc>>, _>("started_at")
        .map(|dt| dt.to_rfc3339());
    let completed_at: Option<String> = row
        .get::<Option<chrono::DateTime<Utc>>, _>("completed_at")
        .map(|dt| dt.to_rfc3339());

    Ok(Job {
        id: id.to_string(),
        job_type,
        payload,
        status,
        priority,
        max_retries,
        retry_count,
        created_at: created_at.unwrap_or_else(|| Utc::now().to_rfc3339()),
        started_at,
        completed_at,
        last_error,
    })
}

#[async_trait]
impl JobQueue for PostgresJobQueue {
    async fn enqueue(&self, job: Job) -> SchedulerResult<()> {
        let id = Uuid::parse_str(&job.id)
            .map_err(|e| SchedulerError::Queue(format!("Invalid job id {}: {e}", job.id)))?;

        sqlx::query(
            r#"
            INSERT INTO scan_jobs (
                id, scan_id, job_type, status, priority, payload,
                max_retries, attempts, error_message, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
            "#,
        )
        .bind(id)
        .bind(id) // scan_id: no parent scan in the standalone queue; self-reference.
        .bind(&job.job_type)
        .bind(STATUS_PENDING)
        .bind(job.priority as i32)
        .bind(&job.payload)
        .bind(job.max_retries as i32)
        .bind(0i32)
        .bind(&job.last_error)
        .execute(self.pool())
        .await
        .map_err(|e| SchedulerError::Queue(format!("Enqueue failed: {e}")))?;

        Ok(())
    }

    async fn dequeue(&self) -> SchedulerResult<Option<Job>> {
        let row = sqlx::query(
            r#"
            UPDATE scan_jobs
            SET status = $1, started_at = NOW(), updated_at = NOW()
            WHERE id = (
                SELECT id FROM scan_jobs
                WHERE status = $2
                ORDER BY priority ASC, created_at ASC
                LIMIT 1
                FOR UPDATE SKIP LOCKED
            )
            RETURNING id, scan_id, job_type, status, priority, payload, result, \
                      error_message, attempts, max_retries, started_at, \
                      completed_at, created_at, updated_at
            "#,
        )
        .bind(STATUS_RUNNING)
        .bind(STATUS_PENDING)
        .fetch_optional(self.pool())
        .await
        .map_err(|e| SchedulerError::Queue(format!("Dequeue failed: {e}")))?;

        match row {
            Some(r) => Ok(Some(row_to_job(r)?)),
            None => Ok(None),
        }
    }

    async fn complete(&self, job_id: &str) -> SchedulerResult<()> {
        let id = uuid::Uuid::parse_str(job_id)
            .map_err(|e| SchedulerError::Queue(format!("Invalid job id {job_id}: {e}")))?;

        let result = sqlx::query(
            "UPDATE scan_jobs SET status = $1, completed_at = NOW(), updated_at = NOW() \
             WHERE id = $2",
        )
        .bind(STATUS_COMPLETED)
        .bind(id)
        .execute(self.pool())
        .await
        .map_err(|e| SchedulerError::Queue(format!("Complete failed: {e}")))?;

        if result.rows_affected() == 0 {
            return Err(SchedulerError::JobNotFound(job_id.to_string()));
        }

        Ok(())
    }

    async fn fail(&self, job_id: &str, error: &str) -> SchedulerResult<()> {
        let id = uuid::Uuid::parse_str(job_id)
            .map_err(|e| SchedulerError::Queue(format!("Invalid job id {job_id}: {e}")))?;

        let current = sqlx::query("SELECT attempts, max_retries FROM scan_jobs WHERE id = $1")
            .bind(id)
            .fetch_optional(self.pool())
            .await
            .map_err(|e| SchedulerError::Queue(format!("Fetch job for fail failed: {e}")))?;

        let Some(row) = current else {
            return Err(SchedulerError::JobNotFound(job_id.to_string()));
        };
        let attempts: i32 = row.get("attempts");
        let max_retries: i32 = row.get("max_retries");

        if attempts < max_retries {
            sqlx::query(
                "UPDATE scan_jobs SET status = $1, attempts = $2, error_message = $3, \
                 started_at = NULL, updated_at = NOW() WHERE id = $4",
            )
            .bind(STATUS_PENDING)
            .bind(attempts + 1)
            .bind(error)
            .bind(id)
            .execute(self.pool())
            .await
            .map_err(|e| SchedulerError::Queue(format!("Requeue failed: {e}")))?;
        } else {
            sqlx::query(
                "UPDATE scan_jobs SET status = $1, attempts = $2, error_message = $3, \
                 completed_at = NOW(), updated_at = NOW() WHERE id = $4",
            )
            .bind(STATUS_FAILED)
            .bind(attempts + 1)
            .bind(error)
            .bind(id)
            .execute(self.pool())
            .await
            .map_err(|e| SchedulerError::Queue(format!("Fail failed: {e}")))?;
        }

        Ok(())
    }

    async fn retry(&self, job_id: &str) -> SchedulerResult<()> {
        let id = uuid::Uuid::parse_str(job_id)
            .map_err(|e| SchedulerError::Queue(format!("Invalid job id {job_id}: {e}")))?;

        let result = sqlx::query(
            "UPDATE scan_jobs SET status = $1, attempts = attempts + 1, \
             error_message = NULL, started_at = NULL, completed_at = NULL, \
             updated_at = NOW() WHERE id = $2 AND status IN ($3, $4)",
        )
        .bind(STATUS_PENDING)
        .bind(id)
        .bind(STATUS_FAILED)
        .bind(STATUS_RETRY)
        .execute(self.pool())
        .await
        .map_err(|e| SchedulerError::Queue(format!("Retry failed: {e}")))?;

        if result.rows_affected() == 0 {
            return Err(SchedulerError::JobNotFound(job_id.to_string()));
        }

        Ok(())
    }
}
