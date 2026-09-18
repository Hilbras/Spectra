use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Timestamps for an entity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Timestamp {
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Timestamp {
    /// Creates a new timestamp with the current time.
    #[must_use]
    pub fn now() -> Self {
        let now = Utc::now();
        Self {
            created_at: now,
            updated_at: now,
        }
    }

    /// Updates the `updated_at` timestamp to now.
    pub fn touch(&mut self) {
        self.updated_at = Utc::now();
    }
}

impl Default for Timestamp {
    fn default() -> Self {
        Self::now()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_creation() {
        let ts = Timestamp::now();
        assert_eq!(ts.created_at, ts.updated_at);
    }

    #[test]
    fn timestamp_touch() {
        let mut ts = Timestamp::now();
        let original = ts.created_at;
        ts.touch();
        assert_eq!(ts.created_at, original);
        assert!(ts.updated_at >= original);
    }
}
