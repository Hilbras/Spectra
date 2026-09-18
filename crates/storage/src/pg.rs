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

    /// Runs database migrations from a directory.
    pub async fn run_migrations(&self, migrations_dir: &str) -> StorageResult<()> {
        let path = std::path::Path::new(migrations_dir);
        if !path.exists() {
            return Err(SpectraError::Storage(format!(
                "Migrations directory not found: {}",
                migrations_dir
            )));
        }

        let mut entries: Vec<_> = std::fs::read_dir(path)
            .map_err(|e| SpectraError::Storage(e.to_string()))?
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|ext| ext == "sql")
                    .unwrap_or(false)
            })
            .collect();

        entries.sort_by_key(|e| e.file_name());

        for entry in entries {
            let sql = std::fs::read_to_string(entry.path())
                .map_err(|e| SpectraError::Storage(e.to_string()))?;

            sqlx::query(&sql).execute(&self.pool).await.map_err(|e| {
                SpectraError::Storage(format!(
                    "Failed to execute migration {}: {}",
                    entry.path().display(),
                    e
                ))
            })?;
        }

        Ok(())
    }
}

fn pg_row_to_row(pg_row: PgRow) -> Row {
    use row_ext::Row as _;

    let mut columns = Vec::new();
    let mut values = Vec::new();

    for (idx, column) in pg_row.columns().iter().enumerate() {
        columns.push(column.name().to_string());

        let value: Value = match column.type_info().name() {
            "bool" => {
                let v: Option<bool> = pg_row.try_get(idx).unwrap_or(None);
                v.map(Value::Bool).unwrap_or(Value::Null)
            }
            "int4" | "int8" => {
                let v: Option<i64> = pg_row.try_get(idx).unwrap_or(None);
                v.map(|n| Value::Number(n.into())).unwrap_or(Value::Null)
            }
            "float4" | "float8" => {
                let v: Option<f64> = pg_row.try_get(idx).unwrap_or(None);
                v.and_then(serde_json::Number::from_f64)
                    .map(Value::Number)
                    .unwrap_or(Value::Null)
            }
            "text" | "varchar" | "bpchar" => {
                let v: Option<String> = pg_row.try_get(idx).unwrap_or(None);
                v.map(Value::String).unwrap_or(Value::Null)
            }
            "jsonb" | "json" => {
                let v: Option<Value> = pg_row.try_get(idx).unwrap_or(None);
                v.unwrap_or(Value::Null)
            }
            "uuid" => {
                let v: Option<sqlx::types::Uuid> = pg_row.try_get(idx).unwrap_or(None);
                v.map(|u| Value::String(u.to_string()))
                    .unwrap_or(Value::Null)
            }
            "bytea" => {
                let v: Option<Vec<u8>> = pg_row.try_get(idx).unwrap_or(None);
                v.map(|bytes| {
                    let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
                    Value::String(hex)
                })
                .unwrap_or(Value::Null)
            }
            "timestamptz" | "timestamp" => {
                let v: Option<chrono::DateTime<chrono::Utc>> = pg_row.try_get(idx).unwrap_or(None);
                v.map(|t| Value::String(t.to_rfc3339()))
                    .unwrap_or(Value::Null)
            }
            _ => Value::Null,
        };

        values.push(value);
    }

    Row::new(columns, values)
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

        Ok(rows.into_iter().map(pg_row_to_row).collect())
    }

    async fn query_one(&self, query: &str, params: &[Value]) -> StorageResult<Option<Row>> {
        let row = build_query(query, params)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| SpectraError::Storage(format!("Query failed: {}", e)))?;

        Ok(row.map(pg_row_to_row))
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

        Ok(rows.into_iter().map(pg_row_to_row).collect())
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
