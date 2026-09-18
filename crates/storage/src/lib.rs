pub mod pg;
pub mod search;

use async_trait::async_trait;
use serde_json::Value;
use spectra_core::SpectraError;

/// Result type for storage operations.
pub type StorageResult<T> = Result<T, SpectraError>;

/// Object storage trait for storing and retrieving binary data.
#[async_trait]
pub trait Storage: Send + Sync {
    /// Stores data at the given key.
    async fn put(&self, key: &str, data: Vec<u8>, content_type: &str) -> StorageResult<()>;

    /// Retrieves data by key.
    async fn get(&self, key: &str) -> StorageResult<Option<Vec<u8>>>;

    /// Deletes data at the given key.
    async fn delete(&self, key: &str) -> StorageResult<()>;

    /// Lists all keys with the given prefix.
    async fn list(&self, prefix: &str) -> StorageResult<Vec<String>>;

    /// Checks if a key exists.
    async fn exists(&self, key: &str) -> StorageResult<bool>;

    /// Generates a presigned URL for temporary access.
    async fn presign(&self, key: &str, expiry_secs: u64) -> StorageResult<String>;
}

/// Database trait for structured data operations.
#[async_trait]
pub trait Database: Send + Sync {
    /// Executes a query that doesn't return rows.
    async fn execute(&self, query: &str, params: &[Value]) -> StorageResult<u64>;

    /// Executes a query that returns rows.
    async fn query(&self, query: &str, params: &[Value]) -> StorageResult<Vec<Row>>;

    /// Executes a query that returns a single row.
    async fn query_one(&self, query: &str, params: &[Value]) -> StorageResult<Option<Row>>;

    /// Executes a query that returns a single value.
    async fn query_scalar(&self, query: &str, params: &[Value]) -> StorageResult<Option<Value>>;

    /// Begins a database transaction.
    async fn begin(&self) -> StorageResult<Box<dyn Transaction>>;
}

/// A database row.
#[derive(Debug, Clone)]
pub struct Row {
    columns: Vec<String>,
    values: Vec<Value>,
}

impl Row {
    /// Creates a new row.
    pub fn new(columns: Vec<String>, values: Vec<Value>) -> Self {
        Self { columns, values }
    }

    /// Gets a column value by index.
    pub fn get<T: serde::de::DeserializeOwned>(&self, index: usize) -> StorageResult<T> {
        let value = self.values.get(index).ok_or_else(|| {
            SpectraError::Storage(format!("Column index {} out of bounds", index))
        })?;
        serde_json::from_value(value.clone()).map_err(|e| SpectraError::Storage(e.to_string()))
    }

    /// Gets a column value by name.
    pub fn get_by_name<T: serde::de::DeserializeOwned>(&self, name: &str) -> StorageResult<T> {
        let index = self
            .columns
            .iter()
            .position(|c| c == name)
            .ok_or_else(|| SpectraError::Storage(format!("Column '{}' not found", name)))?;
        self.get(index)
    }

    /// Returns the number of columns.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Returns true if the row has no columns.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

/// Database transaction trait.
#[async_trait]
pub trait Transaction: Send + Sync {
    /// Executes a query that doesn't return rows.
    async fn execute(&mut self, query: &str, params: &[Value]) -> StorageResult<u64>;

    /// Executes a query that returns rows.
    async fn query(&mut self, query: &str, params: &[Value]) -> StorageResult<Vec<Row>>;

    /// Commits the transaction.
    async fn commit(self: Box<Self>) -> StorageResult<()>;

    /// Rolls back the transaction.
    async fn rollback(self: Box<Self>) -> StorageResult<()>;
}

/// Search index trait for full-text search operations.
#[async_trait]
pub trait SearchIndex: Send + Sync {
    /// Indexes a document.
    async fn index(&self, index: &str, id: &str, document: Value) -> StorageResult<()>;

    /// Searches the index.
    async fn search(
        &self,
        index: &str,
        query: &str,
        limit: usize,
    ) -> StorageResult<Vec<SearchResult>>;

    /// Deletes a document from the index.
    async fn delete(&self, index: &str, id: &str) -> StorageResult<()>;

    /// Bulk indexes multiple documents.
    async fn bulk_index(&self, index: &str, documents: Vec<(String, Value)>) -> StorageResult<()>;
}

/// A search result.
#[derive(Debug, Clone)]
pub struct SearchResult {
    pub id: String,
    pub score: f64,
    pub document: Value,
}

/// Local filesystem storage implementation.
pub struct LocalStorage {
    base_path: std::path::PathBuf,
}

impl LocalStorage {
    /// Creates a new local storage instance.
    pub fn new(base_path: impl AsRef<std::path::Path>) -> Self {
        Self {
            base_path: base_path.as_ref().to_path_buf(),
        }
    }
}

#[async_trait]
impl Storage for LocalStorage {
    async fn put(&self, key: &str, data: Vec<u8>, _content_type: &str) -> StorageResult<()> {
        let path = self.base_path.join(key);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| SpectraError::Storage(e.to_string()))?;
        }
        std::fs::write(&path, data).map_err(|e| SpectraError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn get(&self, key: &str) -> StorageResult<Option<Vec<u8>>> {
        let path = self.base_path.join(key);
        if path.exists() {
            let data = std::fs::read(&path).map_err(|e| SpectraError::Storage(e.to_string()))?;
            Ok(Some(data))
        } else {
            Ok(None)
        }
    }

    async fn delete(&self, key: &str) -> StorageResult<()> {
        let path = self.base_path.join(key);
        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| SpectraError::Storage(e.to_string()))?;
        }
        Ok(())
    }

    async fn list(&self, prefix: &str) -> StorageResult<Vec<String>> {
        let mut keys = Vec::new();
        let prefix_path = self.base_path.join(prefix);

        if prefix_path.exists() {
            self.list_recursive(&prefix_path, prefix, &mut keys)?;
        }

        Ok(keys)
    }

    async fn exists(&self, key: &str) -> StorageResult<bool> {
        let path = self.base_path.join(key);
        Ok(path.exists())
    }

    async fn presign(&self, _key: &str, _expiry_secs: u64) -> StorageResult<String> {
        Err(SpectraError::Storage(
            "Presign not supported for local storage".to_string(),
        ))
    }
}

impl LocalStorage {
    #[allow(clippy::only_used_in_recursion)]
    fn list_recursive(
        &self,
        dir: &std::path::Path,
        _prefix: &str,
        keys: &mut Vec<String>,
    ) -> StorageResult<()> {
        if dir.is_dir() {
            for entry in std::fs::read_dir(dir).map_err(|e| SpectraError::Storage(e.to_string()))? {
                let entry = entry.map_err(|e| SpectraError::Storage(e.to_string()))?;
                let path = entry.path();
                let relative = path
                    .strip_prefix(&self.base_path)
                    .map_err(|e| SpectraError::Storage(e.to_string()))?;

                if path.is_dir() {
                    self.list_recursive(&path, _prefix, keys)?;
                } else if let Some(key) = relative.to_str() {
                    keys.push(key.to_string());
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn local_storage_operations() {
        let temp_dir = TempDir::new().unwrap();
        let storage = LocalStorage::new(temp_dir.path());

        // Put and get
        storage
            .put("test/file.txt", b"hello world".to_vec(), "text/plain")
            .await
            .unwrap();
        let data = storage.get("test/file.txt").await.unwrap();
        assert_eq!(data, Some(b"hello world".to_vec()));

        // Exists
        assert!(storage.exists("test/file.txt").await.unwrap());
        assert!(!storage.exists("nonexistent.txt").await.unwrap());

        // List
        let keys = storage.list("test/").await.unwrap();
        assert_eq!(keys.len(), 1);

        // Delete
        storage.delete("test/file.txt").await.unwrap();
        assert!(!storage.exists("test/file.txt").await.unwrap());
    }
}
