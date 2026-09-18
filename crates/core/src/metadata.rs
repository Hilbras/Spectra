use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Generic metadata container for extensible entity properties.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Metadata(HashMap<String, serde_json::Value>);

impl Metadata {
    /// Creates empty metadata.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Gets a value by key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.0.get(key)
    }

    /// Sets a value.
    pub fn insert(&mut self, key: impl Into<String>, value: serde_json::Value) {
        self.0.insert(key.into(), value);
    }

    /// Removes a value.
    pub fn remove(&mut self, key: &str) -> Option<serde_json::Value> {
        self.0.remove(key)
    }

    /// Returns true if the metadata contains the given key.
    #[must_use]
    pub fn contains_key(&self, key: &str) -> bool {
        self.0.contains_key(key)
    }

    /// Returns the number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if the metadata is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns an iterator over the entries.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &serde_json::Value)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v))
    }
}

impl From<HashMap<String, serde_json::Value>> for Metadata {
    fn from(map: HashMap<String, serde_json::Value>) -> Self {
        Self(map)
    }
}

#[allow(clippy::implicit_hasher)]
impl From<Metadata> for HashMap<String, serde_json::Value> {
    fn from(metadata: Metadata) -> Self {
        metadata.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_operations() {
        let mut meta = Metadata::new();
        assert!(meta.is_empty());

        meta.insert("key1", serde_json::json!("value1"));
        meta.insert("key2", serde_json::json!(42));

        assert_eq!(meta.len(), 2);
        assert_eq!(meta.get("key1"), Some(&serde_json::json!("value1")));
        assert!(meta.contains_key("key2"));

        meta.remove("key1");
        assert_eq!(meta.len(), 1);
    }
}
