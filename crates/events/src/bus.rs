use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{debug, warn};

use crate::event::Event;
use crate::handler::EventHandler;

type HandlerList = Vec<Arc<dyn EventHandler>>;
type HandlerMap = HashMap<String, HandlerList>;

/// In-process event bus using broadcast channels.
pub struct EventBus {
    sender: broadcast::Sender<Event>,
    handlers: Arc<tokio::sync::RwLock<HandlerMap>>,
}

impl EventBus {
    /// Creates a new event bus with the given channel capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self {
            sender,
            handlers: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }

    /// Publishes an event to all subscribers.
    pub fn publish(&self, event: Event) {
        debug!(event_id = %event.id, event_type = ?event.event_type, "Publishing event");
        if self.sender.send(event).is_err() {
            warn!("No active subscribers for event");
        }
    }

    /// Subscribes to events. Returns a receiver that will get all events.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.sender.subscribe()
    }

    /// Registers a handler for specific event types.
    pub async fn register_handler(&self, name: String, handler: Arc<dyn EventHandler>) {
        let mut handlers = self.handlers.write().await;
        handlers.entry(name).or_default().push(handler);
    }

    /// Dispatches events to registered handlers.
    pub fn dispatch_events(&self) {
        let mut receiver = self.sender.subscribe();
        let handlers = self.handlers.clone();

        tokio::spawn(async move {
            while let Ok(event) = receiver.recv().await {
                let handlers = handlers.read().await;
                for (name, handler_list) in handlers.iter() {
                    for handler in handler_list {
                        if handler.event_types().contains(&event.event_type) {
                            if let Err(e) = handler.handle(&event).await {
                                warn!(
                                    handler = name.as_str(),
                                    error = %e,
                                    "Handler failed to process event"
                                );
                            }
                        }
                    }
                }
            }
        });
    }
}

impl Clone for EventBus {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            handlers: self.handlers.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{EventPayload, EventSource, EventType};
    use crate::handler::EventHandler;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountHandler {
        count: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl EventHandler for CountHandler {
        fn event_types(&self) -> Vec<EventType> {
            vec![EventType::ScanStarted]
        }

        async fn handle(&self, _event: &Event) -> spectra_core::Result<()> {
            self.count.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    #[tokio::test]
    async fn publish_and_subscribe() {
        let bus = EventBus::new(10);
        let mut receiver = bus.subscribe();

        let event = Event::new(
            EventType::TargetCreated,
            EventSource::System,
            EventPayload::TargetCreated {
                target_id: "test".to_string(),
                project_id: "proj".to_string(),
                name: "example.com".to_string(),
            },
        );

        bus.publish(event.clone());

        let received = receiver.recv().await.unwrap();
        assert_eq!(received.event_type, EventType::TargetCreated);
    }

    #[tokio::test]
    async fn multiple_subscribers() {
        let bus = EventBus::new(10);
        let mut rx1 = bus.subscribe();
        let mut rx2 = bus.subscribe();

        let event = Event::new(
            EventType::ScanStarted,
            EventSource::System,
            EventPayload::ScanStarted {
                scan_id: "s1".into(),
                target_id: "t1".into(),
            },
        );

        bus.publish(event);

        let r1 = rx1.recv().await.unwrap();
        let r2 = rx2.recv().await.unwrap();
        assert_eq!(r1.event_type, r2.event_type);
    }

    #[tokio::test]
    async fn bus_clone_shares_events() {
        let bus1 = EventBus::new(10);
        let bus2 = bus1.clone();
        let mut rx = bus2.subscribe();

        let event = Event::new(
            EventType::ScanCompleted,
            EventSource::System,
            EventPayload::ScanCompleted {
                scan_id: "s1".into(),
            },
        );

        bus1.publish(event);
        let received = rx.recv().await.unwrap();
        assert_eq!(received.event_type, EventType::ScanCompleted);
    }

    #[tokio::test]
    async fn handler_registration_and_dispatch() {
        let bus = EventBus::new(10);
        let handler = Arc::new(CountHandler {
            count: AtomicUsize::new(0),
        });

        bus.register_handler("counter".into(), handler.clone())
            .await;
        bus.dispatch_events();

        let event = Event::new(
            EventType::ScanStarted,
            EventSource::System,
            EventPayload::ScanStarted {
                scan_id: "s1".into(),
                target_id: "t1".into(),
            },
        );

        bus.publish(event);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(handler.count.load(Ordering::Relaxed) > 0);
    }

    #[tokio::test]
    async fn publish_no_subscribers() {
        let bus = EventBus::new(10);
        let event = Event::new(
            EventType::SystemHealth,
            EventSource::System,
            EventPayload::SystemHealth {
                status: "ok".into(),
            },
        );
        bus.publish(event);
    }

    #[tokio::test]
    async fn multiple_events_ordering() {
        let bus = EventBus::new(10);
        let mut rx = bus.subscribe();

        for i in 0..5 {
            bus.publish(Event::new(
                EventType::ScanProgress,
                EventSource::System,
                EventPayload::ScanProgress {
                    scan_id: "s1".into(),
                    progress: i as f64 / 5.0,
                    message: format!("step {}", i),
                },
            ));
        }

        for i in 0..5 {
            let received = rx.recv().await.unwrap();
            if let EventPayload::ScanProgress { progress, .. } = received.payload {
                assert!((progress - i as f64 / 5.0).abs() < 0.001);
            } else {
                panic!("Wrong payload variant");
            }
        }
    }
}
