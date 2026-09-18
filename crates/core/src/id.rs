use serde::{Deserialize, Serialize};
use std::fmt;
use std::marker::PhantomData;
use uuid::Uuid;

/// Typed identifier wrapper.
///
/// Uses a phantom type parameter to prevent mixing IDs of different entity types
/// at compile time while maintaining zero-cost abstraction.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Id<T>(Uuid, #[serde(skip)] PhantomData<T>);

impl<T> Id<T> {
    /// Creates a new random ID.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4(), PhantomData)
    }

    /// Creates an ID from an existing UUID.
    #[must_use]
    pub const fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid, PhantomData)
    }

    /// Returns the inner UUID.
    #[must_use]
    pub const fn as_uuid(&self) -> Uuid {
        self.0
    }

    /// Returns the ID as a string.
    #[must_use]
    pub fn as_str(&self) -> String {
        self.0.to_string()
    }
}

impl<T> Default for Id<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> fmt::Debug for Id<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Id({})", self.0)
    }
}

impl<T> fmt::Display for Id<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<T> std::str::FromStr for Id<T> {
    type Err = uuid::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(Self::from_uuid(Uuid::parse_str(s)?))
    }
}

impl<T> PartialEq<Uuid> for Id<T> {
    fn eq(&self, other: &Uuid) -> bool {
        self.0 == *other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct User;

    #[derive(Debug)]
    struct Project;

    #[test]
    fn id_creation() {
        let id = Id::<User>::new();
        assert!(!id.as_uuid().is_nil());
    }

    #[test]
    fn id_display() {
        let id = Id::<User>::new();
        let s = id.to_string();
        assert_eq!(s.len(), 36); // UUID v4 string length
    }

    #[test]
    fn id_from_str() {
        let id = Id::<User>::new();
        let s = id.to_string();
        let parsed: Id<User> = s.parse().unwrap();
        assert_eq!(id.as_uuid(), parsed.as_uuid());
    }

    #[test]
    fn different_types_different_ids() {
        let user_id = Id::<User>::new();
        let project_id = Id::<Project>::new();
        // This would be a compile error if we tried to compare them directly:
        // assert_eq!(user_id, project_id);
        assert_ne!(user_id.as_uuid(), project_id.as_uuid());
    }
}
