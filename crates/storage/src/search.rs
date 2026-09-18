use async_trait::async_trait;
use serde_json::Value;
use spectra_core::SpectraError;
use sqlx::postgres::PgPool;
use sqlx::Row as SqlxRow;

use crate::{SearchIndex, SearchResult, StorageResult};

/// PostgreSQL-backed search index using built-in full-text search.
pub struct PostgresSearchIndex {
    pool: PgPool,
}

impl PostgresSearchIndex {
    /// Creates a new PostgreSQL search index.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Initializes the search infrastructure (creates tables and functions).
    pub async fn initialize(&self) -> StorageResult<()> {
        sqlx::raw_sql(
            r#"
            CREATE TABLE IF NOT EXISTS search_documents (
                id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                index_name VARCHAR(255) NOT NULL,
                document_id VARCHAR(255) NOT NULL,
                document JSONB NOT NULL,
                search_vector tsvector,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                UNIQUE(index_name, document_id)
            );

            CREATE INDEX IF NOT EXISTS idx_search_documents_index ON search_documents(index_name);
            CREATE INDEX IF NOT EXISTS idx_search_documents_id ON search_documents(index_name, document_id);
            CREATE INDEX IF NOT EXISTS idx_search_documents_vector ON search_documents USING gin(search_vector);

            CREATE OR REPLACE FUNCTION update_search_vector()
            RETURNS trigger AS $$
            BEGIN
                NEW.search_vector := to_tsvector('english', COALESCE(NEW.document::text, ''));
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql;

            DROP TRIGGER IF EXISTS trg_search_vector ON search_documents;
            CREATE TRIGGER trg_search_vector
                BEFORE INSERT OR UPDATE ON search_documents
                FOR EACH ROW
                EXECUTE FUNCTION update_search_vector();
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SpectraError::Storage(format!("Failed to initialize search index: {}", e)))?;

        Ok(())
    }
}

#[async_trait]
impl SearchIndex for PostgresSearchIndex {
    async fn index(&self, index: &str, id: &str, document: Value) -> StorageResult<()> {
        sqlx::query(
            r#"
            INSERT INTO search_documents (index_name, document_id, document, updated_at)
            VALUES ($1, $2, $3, NOW())
            ON CONFLICT (index_name, document_id)
            DO UPDATE SET document = $3, updated_at = NOW()
            "#,
        )
        .bind(index)
        .bind(id)
        .bind(document)
        .execute(&self.pool)
        .await
        .map_err(|e| SpectraError::Storage(format!("Index failed: {}", e)))?;

        Ok(())
    }

    async fn search(
        &self,
        index: &str,
        query: &str,
        limit: usize,
    ) -> StorageResult<Vec<SearchResult>> {
        let rows = sqlx::query(
            r#"
            SELECT document_id, document,
                   ts_rank_cd(search_vector, plainto_tsquery('english', $2)) as rank
            FROM search_documents
            WHERE index_name = $1
              AND search_vector @@ plainto_tsquery('english', $2)
            ORDER BY rank DESC
            LIMIT $3
            "#,
        )
        .bind(index)
        .bind(query)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| SpectraError::Storage(format!("Search failed: {}", e)))?;

        let mut results = Vec::new();
        for row in rows {
            let id: String = row
                .try_get("document_id")
                .map_err(|e| SpectraError::Storage(e.to_string()))?;
            let document: Value = row
                .try_get("document")
                .map_err(|e| SpectraError::Storage(e.to_string()))?;
            let score: f64 = row
                .try_get::<Option<f64>, _>("rank")
                .unwrap_or(None)
                .unwrap_or(0.0);

            results.push(SearchResult {
                id,
                score,
                document,
            });
        }

        Ok(results)
    }

    async fn delete(&self, index: &str, id: &str) -> StorageResult<()> {
        sqlx::query(
            r#"
            DELETE FROM search_documents
            WHERE index_name = $1 AND document_id = $2
            "#,
        )
        .bind(index)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(|e| SpectraError::Storage(format!("Delete failed: {}", e)))?;

        Ok(())
    }

    async fn bulk_index(&self, index: &str, documents: Vec<(String, Value)>) -> StorageResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| SpectraError::Storage(format!("Begin transaction failed: {}", e)))?;

        for (id, document) in documents {
            sqlx::query(
                r#"
                INSERT INTO search_documents (index_name, document_id, document, updated_at)
                VALUES ($1, $2, $3, NOW())
                ON CONFLICT (index_name, document_id)
                DO UPDATE SET document = $3, updated_at = NOW()
                "#,
            )
            .bind(index)
            .bind(&id)
            .bind(document)
            .execute(&mut *tx)
            .await
            .map_err(|e| SpectraError::Storage(format!("Bulk index failed for {}: {}", id, e)))?;
        }

        tx.commit()
            .await
            .map_err(|e| SpectraError::Storage(format!("Commit failed: {}", e)))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_result_creation() {
        let result = SearchResult {
            id: "test-id".into(),
            score: 0.95,
            document: serde_json::json!({"title": "Test"}),
        };

        assert_eq!(result.id, "test-id");
        assert!((result.score - 0.95).abs() < f64::EPSILON);
    }
}
