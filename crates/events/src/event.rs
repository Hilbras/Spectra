use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use spectra_core::Id;

/// Unique identifier for an event.
pub type EventId = Id<Event>;

/// Source that emitted the event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventSource {
    System,
    User { user_id: String },
    Worker { worker_id: String },
    Plugin { plugin_id: String },
    Scheduler,
}

/// Classification of events.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EventType {
    // Target events
    TargetCreated,
    TargetUpdated,
    TargetDeleted,

    // Scan events
    ScanStarted,
    ScanProgress,
    ScanCompleted,
    ScanFailed,
    ScanCancelled,

    // Finding events
    FindingCreated,
    FindingUpdated,
    FindingVerified,

    // Asset events
    AssetDiscovered,
    AssetUpdated,

    // Worker events
    WorkerRegistered,
    WorkerHeartbeat,
    WorkerOffline,

    // Plugin events
    PluginLoaded,
    PluginUnloaded,
    PluginError,

    // Job events
    JobQueued,
    JobAssigned,
    JobCompleted,
    JobFailed,

    // System events
    SystemHealth,
    SystemError,

    // Custom event
    Custom(String),
}

/// Event payload containing the actual data.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum EventPayload {
    // Target events
    TargetCreated {
        target_id: String,
        project_id: String,
        name: String,
    },
    TargetUpdated {
        target_id: String,
    },
    TargetDeleted {
        target_id: String,
    },

    // Scan events
    ScanStarted {
        scan_id: String,
        target_id: String,
    },
    ScanProgress {
        scan_id: String,
        progress: f64,
        message: String,
    },
    ScanCompleted {
        scan_id: String,
    },
    ScanFailed {
        scan_id: String,
        error: String,
    },
    ScanCancelled {
        scan_id: String,
    },

    // Finding events
    FindingCreated {
        finding_id: String,
        scan_id: Option<String>,
        severity: String,
    },
    FindingUpdated {
        finding_id: String,
    },
    FindingVerified {
        finding_id: String,
        verified: bool,
    },

    // Asset events
    AssetDiscovered {
        asset_id: String,
        target_id: String,
        asset_type: String,
    },
    AssetUpdated {
        asset_id: String,
    },

    // Worker events
    WorkerRegistered {
        worker_id: String,
        hostname: String,
    },
    WorkerHeartbeat {
        worker_id: String,
    },
    WorkerOffline {
        worker_id: String,
    },

    // Plugin events
    PluginLoaded {
        plugin_id: String,
        name: String,
    },
    PluginUnloaded {
        plugin_id: String,
    },
    PluginError {
        plugin_id: String,
        error: String,
    },

    // Job events
    JobQueued {
        job_id: String,
        job_type: String,
    },
    JobAssigned {
        job_id: String,
        worker_id: String,
    },
    JobCompleted {
        job_id: String,
    },
    JobFailed {
        job_id: String,
        error: String,
    },

    // System events
    SystemHealth {
        status: String,
    },
    SystemError {
        error: String,
    },

    // Custom event
    Custom {
        event_type: String,
        data: serde_json::Value,
    },
}

/// An event in the Spectra system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: EventId,
    pub event_type: EventType,
    pub source: EventSource,
    pub payload: EventPayload,
    pub metadata: serde_json::Value,
    pub timestamp: DateTime<Utc>,
}

impl Event {
    /// Creates a new event.
    #[must_use]
    pub fn new(event_type: EventType, source: EventSource, payload: EventPayload) -> Self {
        Self {
            id: EventId::new(),
            event_type,
            source,
            payload,
            metadata: serde_json::Value::Null,
            timestamp: Utc::now(),
        }
    }

    /// Creates an event with metadata.
    #[must_use]
    pub fn with_metadata(
        event_type: EventType,
        source: EventSource,
        payload: EventPayload,
        metadata: serde_json::Value,
    ) -> Self {
        Self {
            id: EventId::new(),
            event_type,
            source,
            payload,
            metadata,
            timestamp: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_creation() {
        let event = Event::new(
            EventType::TargetCreated,
            EventSource::System,
            EventPayload::TargetCreated {
                target_id: "test".to_string(),
                project_id: "proj".to_string(),
                name: "example.com".to_string(),
            },
        );

        assert_eq!(event.event_type, EventType::TargetCreated);
        assert!(event.metadata.is_null());
    }

    #[test]
    fn event_with_metadata() {
        let meta = serde_json::json!({"key": "value"});
        let event = Event::with_metadata(
            EventType::ScanStarted,
            EventSource::Worker {
                worker_id: "w1".into(),
            },
            EventPayload::ScanStarted {
                scan_id: "s1".into(),
                target_id: "t1".into(),
            },
            meta.clone(),
        );

        assert_eq!(event.event_type, EventType::ScanStarted);
        assert_eq!(event.metadata, meta);
        if let EventSource::Worker { worker_id } = &event.source {
            assert_eq!(worker_id, "w1");
        } else {
            panic!("Expected Worker source");
        }
    }

    #[test]
    fn event_source_variants() {
        let sources = vec![
            EventSource::System,
            EventSource::User {
                user_id: "u1".into(),
            },
            EventSource::Worker {
                worker_id: "w1".into(),
            },
            EventSource::Plugin {
                plugin_id: "p1".into(),
            },
            EventSource::Scheduler,
        ];
        assert_eq!(sources.len(), 5);
    }

    #[test]
    fn event_type_display() {
        assert_eq!(EventType::ScanStarted, EventType::ScanStarted);
        assert_ne!(EventType::ScanStarted, EventType::ScanCompleted);
    }

    #[test]
    fn event_type_hash() {
        let mut set = std::collections::HashSet::new();
        set.insert(EventType::TargetCreated);
        set.insert(EventType::TargetCreated);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn event_type_custom() {
        let t1 = EventType::Custom("test1".into());
        let t2 = EventType::Custom("test2".into());
        assert_ne!(t1, t2);
        assert_eq!(t1, EventType::Custom("test1".into()));
    }

    #[test]
    fn event_payload_serialization() {
        let payload = EventPayload::ScanProgress {
            scan_id: "s1".into(),
            progress: 0.5,
            message: "halfway".into(),
        };
        let json = serde_json::to_string(&payload).unwrap();
        let back: EventPayload = serde_json::from_str(&json).unwrap();
        if let EventPayload::ScanProgress { progress, .. } = back {
            assert!((progress - 0.5).abs() < 0.001);
        } else {
            panic!("Wrong variant");
        }
    }
}
