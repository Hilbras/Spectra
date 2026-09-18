use crate::event::Event;
use async_trait::async_trait;

/// Trait for handling events.
#[async_trait]
pub trait EventHandler: Send + Sync {
    /// Returns the event types this handler is interested in.
    fn event_types(&self) -> Vec<crate::event::EventType>;

    /// Handles an event.
    async fn handle(&self, event: &Event) -> spectra_core::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Event, EventPayload, EventSource, EventType};
    use std::sync::Arc;

    struct TestHandler;

    #[async_trait]
    impl EventHandler for TestHandler {
        fn event_types(&self) -> Vec<EventType> {
            vec![EventType::TargetCreated]
        }

        async fn handle(&self, _event: &Event) -> spectra_core::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn handler_receives_event() {
        let handler = Arc::new(TestHandler);
        let event = Event::new(
            EventType::TargetCreated,
            EventSource::System,
            EventPayload::TargetCreated {
                target_id: "test".to_string(),
                project_id: "proj".to_string(),
                name: "example.com".to_string(),
            },
        );

        assert!(handler.handle(&event).await.is_ok());
    }
}
