use async_trait::async_trait;
use serde_json::Value;
use spectra_core::SpectraError;
use sqlx::postgres::{PgPool, PgPoolOptions, PgRow};
use sqlx::{Column, Postgres, Transaction as PgTransaction, TypeInfo};
use std::time::Duration;

use crate::{Database, Row, StorageResult, Transaction};

mod row_ext {
    pub use sqlx::Row;
}

/// PostgreSQL-backed database implementation.
pub struct PostgresDatabase {
    pool: PgPool,
}

impl PostgresDatabase {
    /// Creates a new PostgreSQL database from a connection URL.
    pub async fn new(database_url: &str) -> StorageResult<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .acquire_timeout(Duration::from_secs(30))
            .idle_timeout(Duration::from_secs(600))
            .connect(database_url)
            .await
            .map_err(|e| {
                SpectraError::Storage(format!("Failed to connect to PostgreSQL: {}", e))
            })?;

        Ok(Self { pool })
    }

    /// Creates a new PostgreSQL database with custom pool settings.
    pub async fn with_pool(database_url: &str, max_connections: u32) -> StorageResult<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(Duration::from_secs(30))
            .connect(database_url)
            .await
            .map_err(|e| {
                SpectraError::Storage(format!("Failed to connect to PostgreSQL: {}", e))
            })?;

        Ok(Self { pool })
    }

    /// Returns a reference to the connection pool.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Tests the database connection.
    pub async fn ping(&self) -> StorageResult<()> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map_err(|e| SpectraError::Storage(format!("Database ping failed: {}", e)))?;
        Ok(())
    }

    /// Runs database migrations from a directory, applying only what is missing.
    ///
    /// Idempotent: each applied migration is recorded in `schema_migrations` with a
    /// checksum, so a second run is a no-op rather than a failure. Each file is
    /// applied inside its own transaction, so a migration that fails part-way
    /// leaves nothing behind and is not recorded.
    ///
    /// The whole file is sent as one `raw_sql`, not split on `;`. `001_initial.sql`
    /// contains `$$ ... $$` function bodies whose own semicolons would break a naive
    /// split, and PostgreSQL's parser handles them correctly.
    ///
    /// A checksum mismatch on an already-applied migration is an error rather than a
    /// skip. Editing a migration that has run somewhere is how environments diverge
    /// permanently, and the quiet version of that bug is a schema that matches no
    /// code path.
    pub async fn run_migrations(&self, migrations_dir: &str) -> StorageResult<MigrationReport> {
        let path = std::path::Path::new(migrations_dir);
        if !path.is_dir() {
            return Err(SpectraError::Storage(format!(
                "Migrations directory not found or not a directory: {}",
                migrations_dir
            )));
        }

        let mut entries: Vec<_> = std::fs::read_dir(path)
            .map_err(|e| {
                SpectraError::Storage(format!(
                    "Could not read migrations directory {migrations_dir}: {e}"
                ))
            })?
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|ext| ext == "sql")
                    .unwrap_or(false)
            })
            .collect();

        // Sort by file name: the numeric prefix is the intended order.
        entries.sort_by_key(|e| e.file_name());

        self.ensure_migrations_table().await?;

        let mut report = MigrationReport::default();

        for entry in entries {
            let file_name = entry.file_name().to_string_lossy().to_string();
            let version = file_name.trim_end_matches(".sql").to_string();

            let sql = std::fs::read_to_string(entry.path()).map_err(|e| {
                SpectraError::Storage(format!("Could not read migration {file_name}: {e}"))
            })?;

            let checksum = self.md5(&sql).await?;
            let applied: Option<String> =
                sqlx::query_scalar("SELECT checksum FROM schema_migrations WHERE version = $1")
                    .bind(&version)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(|e| {
                        SpectraError::Storage(format!(
                            "Could not read migration state for {version}: {e}"
                        ))
                    })?;

            if let Some(recorded) = applied {
                if recorded != checksum {
                    return Err(SpectraError::Storage(format!(
                        "Migration {version} has already been applied but its contents \
                         have changed (recorded checksum {recorded}, current {checksum}). \
                         Applied migrations are immutable: add a new migration instead."
                    )));
                }
                report.already_applied.push(version);
                continue;
            }

            let mut tx = self.pool.begin().await.map_err(|e| {
                SpectraError::Storage(format!("Could not begin transaction for {version}: {e}"))
            })?;

            sqlx::raw_sql(&sql).execute(&mut *tx).await.map_err(|e| {
                SpectraError::Storage(format!("Failed to execute migration {version}: {e}"))
            })?;

            sqlx::query("INSERT INTO schema_migrations (version, checksum) VALUES ($1, $2)")
                .bind(&version)
                .bind(&checksum)
                .execute(&mut *tx)
                .await
                .map_err(|e| {
                    SpectraError::Storage(format!(
                        "Could not record migration {version} as applied: {e}"
                    ))
                })?;

            tx.commit().await.map_err(|e| {
                SpectraError::Storage(format!("Could not commit migration {version}: {e}"))
            })?;

            report.applied.push(version);
        }

        Ok(report)
    }

    /// Creates the bookkeeping table, if it is not already there.
    async fn ensure_migrations_table(&self) -> StorageResult<()> {
        sqlx::raw_sql(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                 version    TEXT PRIMARY KEY,
                 checksum   TEXT NOT NULL,
                 applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
             )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| {
            SpectraError::Storage(format!("Could not create schema_migrations table: {e}"))
        })?;
        Ok(())
    }

    /// A checksum of the migration text, computed by the database.
    ///
    /// Uses PostgreSQL's `md5` rather than a Rust hash so no new dependency is
    /// needed and the checksum is stable across builds and platforms.
    /// `std`'s `DefaultHasher` is explicitly not stable across Rust releases, which
    /// would make a persisted checksum meaningless.
    async fn md5(&self, text: &str) -> StorageResult<String> {
        sqlx::query_scalar("SELECT md5($1)")
            .bind(text)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| SpectraError::Storage(format!("Could not checksum migration: {e}")))
    }

    /// Drops every table, including `schema_migrations`.
    ///
    /// This is the rollback strategy. The migrations are forward-only and are not
    /// paired with down-migrations: authoring six of those would mean six more SQL
    /// files that are never exercised against real data, and a wrong `DROP` is worse
    /// than no `DROP`. Recreating the schema from the migration set is the operation
    /// that is actually verifiable, and it is what this performs.
    pub async fn drop_schema(&self) -> StorageResult<u64> {
        let rows = self
            .query(
                "SELECT tablename FROM pg_tables WHERE schemaname = 'public'",
                &[],
            )
            .await?;

        let mut dropped = 0u64;
        for row in rows {
            let table: String = row.get_by_name("tablename")?;
            // Quoted, so a table name needing mixed case cannot become a syntax
            // error or, worse, a different table.
            dropped += self
                .execute(&format!("DROP TABLE IF EXISTS \"{table}\" CASCADE"), &[])
                .await?;
        }
        Ok(dropped)
    }
}

/// What a call to [`PostgresDatabase::run_migrations`] did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MigrationReport {
    /// Migrations applied by this call, in the order they were applied.
    pub applied: Vec<String>,
    /// Migrations that were already recorded as applied, and therefore skipped.
    pub already_applied: Vec<String>,
}

impl MigrationReport {
    /// True when the call changed nothing.
    pub fn is_noop(&self) -> bool {
        self.applied.is_empty()
    }
}

/// Convert a driver row into a [`Row`], or fail.
///
/// The distinction this makes is the whole point of the function, and it is the one
/// the previous version got wrong. `try_get::<Option<T>>` returns `Ok(None)` when the
/// column really is SQL `NULL`, and `Err(_)` when the value cannot be decoded as `T`
/// — a wrong type, a truncated value, a renamed column. The old code collapsed both
/// into `Null` with `.unwrap_or(None)`.
///
/// That converts a schema mismatch into plausible wrong data: a query against a
/// renamed column returns NULL for it instead of saying so, and the caller reads a
/// default. The first live instance was `pg_tables.tablename`, whose type is `NAME`
/// and which the type match did not handle, so it silently became `Null`.
///
/// A `NULL` column is data. A column that could not be read is an error, and is
/// reported as one.
///
/// Types not listed are an error too, rather than `Null`. A new PostgreSQL type
/// appearing in a query should stop the caller from silently losing the column; the
/// fix is to teach this function about it, which is a deliberate act.
pub(crate) fn pg_row_to_row(pg_row: PgRow) -> StorageResult<Row> {
    use row_ext::Row as _;

    let mut columns = Vec::new();
    let mut values = Vec::new();

    for (idx, column) in pg_row.columns().iter().enumerate() {
        let name = column.name().to_string();
        let type_name = column.type_info().name().to_string();

        let value: Value = match type_name.as_str() {
            "BOOL" => match pg_row.try_get::<Option<bool>, _>(idx) {
                Ok(Some(v)) => Value::Bool(v),
                Ok(None) => Value::Null,
                Err(e) => return Err(decode_error(&name, &type_name, &e)),
            },
            "INT2" | "INT4" | "INT8" => match pg_row.try_get::<Option<i64>, _>(idx) {
                Ok(Some(v)) => Value::Number(v.into()),
                Ok(None) => Value::Null,
                Err(e) => return Err(decode_error(&name, &type_name, &e)),
            },
            "FLOAT4" | "FLOAT8" => match pg_row.try_get::<Option<f64>, _>(idx) {
                Ok(Some(v)) => {
                    // A NaN or infinity has no JSON representation. Reporting NULL
                    // would be the same silent substitution this function exists to
                    // prevent, so it is an error.
                    match serde_json::Number::from_f64(v) {
                        Some(n) => Value::Number(n),
                        None => {
                            return Err(SpectraError::Storage(format!(
                                "Column `{name}` ({type_name}) holds {v}, which has no JSON \
                                 representation"
                            )))
                        }
                    }
                }
                Ok(None) => Value::Null,
                Err(e) => return Err(decode_error(&name, &type_name, &e)),
            },
            // `NAME` is PostgreSQL's internal identifier type, used by catalogs and
            // by anything declared `VARCHAR(n)` without an explicit length in some
            // paths. Its absence from this list is what made `tablename` decode as
            // NULL.
            "TEXT" | "VARCHAR" | "BPCHAR" | "NAME" | "CHAR" => {
                match pg_row.try_get::<Option<String>, _>(idx) {
                    Ok(Some(v)) => Value::String(v),
                    Ok(None) => Value::Null,
                    Err(e) => return Err(decode_error(&name, &type_name, &e)),
                }
            }
            "JSON" | "JSONB" => match pg_row.try_get::<Option<Value>, _>(idx) {
                Ok(Some(v)) => v,
                Ok(None) => Value::Null,
                Err(e) => return Err(decode_error(&name, &type_name, &e)),
            },
            "UUID" => match pg_row.try_get::<Option<sqlx::types::Uuid>, _>(idx) {
                Ok(Some(v)) => Value::String(v.to_string()),
                Ok(None) => Value::Null,
                Err(e) => return Err(decode_error(&name, &type_name, &e)),
            },
            "BYTEA" => match pg_row.try_get::<Option<Vec<u8>>, _>(idx) {
                Ok(Some(bytes)) => {
                    Value::String(bytes.iter().map(|b| format!("{b:02x}")).collect::<String>())
                }
                Ok(None) => Value::Null,
                Err(e) => return Err(decode_error(&name, &type_name, &e)),
            },
            "TIMESTAMPTZ" | "TIMESTAMP" => {
                match pg_row.try_get::<Option<chrono::DateTime<chrono::Utc>>, _>(idx) {
                    Ok(Some(t)) => Value::String(t.to_rfc3339()),
                    Ok(None) => Value::Null,
                    Err(e) => return Err(decode_error(&name, &type_name, &e)),
                }
            }
            "DATE" => match pg_row.try_get::<Option<chrono::NaiveDate>, _>(idx) {
                Ok(Some(d)) => Value::String(d.to_string()),
                Ok(None) => Value::Null,
                Err(e) => return Err(decode_error(&name, &type_name, &e)),
            },
            other => {
                return Err(SpectraError::Storage(format!(
                    "Column `{name}` has PostgreSQL type `{other}`, which this row decoder \
                     does not handle. Teaching it that type is a deliberate change; it is \
                     not reported as NULL, because NULL is indistinguishable from a value \
                     that was never read."
                )))
            }
        };

        columns.push(name);
        values.push(value);
    }

    Ok(Row::new(columns, values))
}

/// A decode failure, naming the column, its type, and the driver's reason.
fn decode_error(column: &str, type_name: &str, cause: &sqlx::Error) -> SpectraError {
    SpectraError::Storage(format!(
        "Could not read column `{column}` as {type_name}: {cause}. This is a schema or \
         query mismatch, not a missing value -- a genuinely NULL column decodes to NULL."
    ))
}

#[async_trait]
impl Database for PostgresDatabase {
    async fn execute(&self, query: &str, params: &[Value]) -> StorageResult<u64> {
        let result = build_query(query, params)
            .execute(&self.pool)
            .await
            .map_err(|e| SpectraError::Storage(format!("Execute failed: {}", e)))?;

        Ok(result.rows_affected())
    }

    async fn query(&self, query: &str, params: &[Value]) -> StorageResult<Vec<Row>> {
        let rows = build_query(query, params)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| SpectraError::Storage(format!("Query failed: {}", e)))?;

        rows.into_iter().map(pg_row_to_row).collect()
    }

    async fn query_one(&self, query: &str, params: &[Value]) -> StorageResult<Option<Row>> {
        let row = build_query(query, params)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SpectraError::Storage(format!("Query failed: {}", e)))?;

        row.map(pg_row_to_row).transpose()
    }

    async fn query_scalar(&self, query: &str, params: &[Value]) -> StorageResult<Option<Value>> {
        let row = self.query_one(query, params).await?;
        match row {
            Some(r) if !r.is_empty() => r.get::<Value>(0).map(Some),
            _ => Ok(None),
        }
    }

    async fn begin(&self) -> StorageResult<Box<dyn Transaction>> {
        let tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SpectraError::Storage(format!("Begin transaction failed: {}", e)))?;

        Ok(Box::new(PostgresTransaction { tx }))
    }
}

/// PostgreSQL transaction implementation.
pub struct PostgresTransaction {
    tx: PgTransaction<'static, Postgres>,
}

#[async_trait]
impl Transaction for PostgresTransaction {
    async fn execute(&mut self, query: &str, params: &[Value]) -> StorageResult<u64> {
        let result = build_query(query, params)
            .execute(&mut *self.tx)
            .await
            .map_err(|e| SpectraError::Storage(format!("Transaction execute failed: {}", e)))?;

        Ok(result.rows_affected())
    }

    async fn query(&mut self, query: &str, params: &[Value]) -> StorageResult<Vec<Row>> {
        let rows = build_query(query, params)
            .fetch_all(&mut *self.tx)
            .await
            .map_err(|e| SpectraError::Storage(format!("Transaction query failed: {}", e)))?;

        rows.into_iter().map(pg_row_to_row).collect()
    }

    async fn commit(self: Box<Self>) -> StorageResult<()> {
        self.tx
            .commit()
            .await
            .map_err(|e| SpectraError::Storage(format!("Transaction commit failed: {}", e)))?;
        Ok(())
    }

    async fn rollback(self: Box<Self>) -> StorageResult<()> {
        self.tx
            .rollback()
            .await
            .map_err(|e| SpectraError::Storage(format!("Transaction rollback failed: {}", e)))?;
        Ok(())
    }
}

fn build_query<'a>(
    query: &'a str,
    params: &[Value],
) -> sqlx::query::Query<'a, Postgres, sqlx::postgres::PgArguments> {
    let mut q = sqlx::query(query);
    for param in params {
        q = bind_json_param(q, param);
    }
    q
}

fn bind_json_param<'a>(
    q: sqlx::query::Query<'a, Postgres, sqlx::postgres::PgArguments>,
    param: &Value,
) -> sqlx::query::Query<'a, Postgres, sqlx::postgres::PgArguments> {
    match param {
        Value::Null => q.bind(None::<String>),
        Value::Bool(b) => q.bind(*b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                q.bind(i)
            } else if let Some(f) = n.as_f64() {
                q.bind(f)
            } else {
                q.bind(n.to_string())
            }
        }
        Value::String(s) => q.bind(s.clone()),
        Value::Array(_) | Value::Object(_) => q.bind(param.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pg_row_conversion() {
        let columns = vec!["id".into(), "name".into(), "active".into()];
        let values = vec![
            Value::String("test-id".into()),
            Value::String("Test Name".into()),
            Value::Bool(true),
        ];
        let row = Row::new(columns, values);

        let id: String = row.get_by_name("id").unwrap();
        assert_eq!(id, "test-id");

        let name: String = row.get_by_name("name").unwrap();
        assert_eq!(name, "Test Name");

        let active: bool = row.get_by_name("active").unwrap();
        assert!(active);
    }

    #[test]
    fn row_out_of_bounds() {
        let row = Row::new(vec!["id".into()], vec![Value::Null]);
        let result: StorageResult<String> = row.get(5);
        assert!(result.is_err());
    }

    #[test]
    fn row_column_not_found() {
        let row = Row::new(vec!["id".into()], vec![Value::Null]);
        let result: StorageResult<String> = row.get_by_name("nonexistent");
        assert!(result.is_err());
    }
}
