/*
Copyright 2025  The Hyperlight Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

use std::cell::RefCell;
use std::collections::HashMap;

use serde_json::{Value, json, to_string_pretty};
use tracing::Subscriber;
use tracing_core::event::Event;
use tracing_core::metadata::Metadata;
use tracing_core::span::{Attributes, Current, Id, Record};
use tracing_core::{Level, LevelFilter};
use tracing_serde::AsSerde;

#[derive(Debug, Clone)]
pub struct TracingSubscriber {}

thread_local!(
    static SPAN_METADATA: RefCell<HashMap<u64, &'static Metadata<'static>>> =
        RefCell::new(HashMap::new());
    static SPANS: RefCell<HashMap<u64, Value>> = RefCell::new(HashMap::new());
    static EVENTS: RefCell<Vec<Value>> = const { RefCell::new(Vec::new()) };
    static LEVEL_FILTER: RefCell<LevelFilter> = const { RefCell::new(LevelFilter::OFF) };
    static NEXT_ID: RefCell<u64> = const { RefCell::new(1) };
    static SPAN_STACK: RefCell<Vec<Id>> = const { RefCell::new(Vec::new()) };
);

impl TracingSubscriber {
    pub fn new(trace_level: Level) -> Self {
        LEVEL_FILTER.with(|level_filter| *level_filter.borrow_mut() = trace_level.into());
        Self {}
    }

    pub fn get_span_metadata(&self, id: u64) -> &'static Metadata<'static> {
        SPAN_METADATA.with(
            |span_metadata: &RefCell<HashMap<u64, &Metadata<'static>>>| -> &Metadata<'static> {
                span_metadata
                    .borrow()
                    .get(&id)
                    .unwrap_or_else(|| panic!("Failed to get span metadata ID {}", id))
            },
        )
    }

    pub fn get_span(&self, id: u64) -> Value {
        SPANS.with(|spans| {
            spans
                .borrow()
                .get(&id)
                .unwrap_or_else(|| panic!("Failed to get span ID {}", id))
                .clone()
        })
    }

    pub fn get_events(&self) -> Vec<Value> {
        EVENTS.with(|events| events.borrow().clone())
    }

    pub fn test_trace_records<F: Fn(&HashMap<u64, Value>, &Vec<Value>)>(&self, f: F) {
        SPANS.with(|spans| {
            EVENTS.with(|events| {
                f(&spans.borrow().clone(), &events.borrow().clone());
                events.borrow_mut().clear();
            });
        });
    }

    pub fn clear(&self) {
        SPANS.with(|spans| spans.borrow_mut().clear());
        EVENTS.with(|events| events.borrow_mut().clear());
        SPAN_STACK.with(|span_stack| span_stack.borrow_mut().clear());
        SPAN_METADATA.with(|span_metadata| span_metadata.borrow_mut().clear());
        NEXT_ID.with(|next_id| *next_id.borrow_mut() = 1);
    }
}

impl Subscriber for TracingSubscriber {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        LEVEL_FILTER.with(|level_filter| metadata.level() <= &*level_filter.borrow())
    }

    fn new_span(&self, span_attributes: &Attributes<'_>) -> Id {
        let span_id = NEXT_ID.with(|next_id| {
            let id = *next_id.borrow();
            *next_id.borrow_mut() += 1;
            id
        });
        let id = Id::from_u64(span_id);
        let json = json!({
        "span": {
            "id": id.as_serde(),
            "attributes": span_attributes.as_serde(),

        }});
        println!(
            "Thread {:?} {}",
            std::thread::current().id(),
            to_string_pretty(&json).expect("Failed to pretty print json")
        );
        SPANS.with(|spans| {
            spans.borrow_mut().insert(span_id, json);
        });
        let metadata = span_attributes.metadata();
        SPAN_METADATA.with(|span_metadata| {
            span_metadata.borrow_mut().insert(span_id, metadata);
        });
        id
    }

    fn record(&self, id: &Id, values: &Record<'_>) {
        let span_id = id.into_u64();
        SPANS.with(|spans| {
            let mut map = spans.borrow_mut();
            let entry = &mut *map
                .get_mut(&span_id)
                .unwrap_or_else(|| panic!("Failed to get span with ID {}", id.into_u64()));
            let json_object = entry
                .as_object_mut()
                .unwrap_or_else(|| panic!("Span entry is not an object {}", id.into_u64()));
            let mut json_values = json!(values.as_serde());
            println!(
                "Thread {:?} span {} values: {}",
                std::thread::current().id(),
                &span_id,
                to_string_pretty(&json_values).expect("Failed to pretty print json")
            );
            let json_values = json_values
                .as_object_mut()
                .expect("Record is not an object");
            json_object
                .get_mut("span")
                .expect("span not found in json")
                .as_object_mut()
                .expect("span was not an object")
                .get_mut("attributes")
                .expect("attributes not found in json")
                .as_object_mut()
                .expect("attributes was not an object")
                .append(json_values);
            println!(
                "Thread {:?} Updated Span {} values: {}",
                std::thread::current().id(),
                &span_id,
                to_string_pretty(&json_object).expect("Failed to pretty print json")
            );
        });
    }

    fn event(&self, event: &Event<'_>) {
        let json = json!({
            "event": event.as_serde(),
        });
        println!(
            "Thread {:?} {}",
            std::thread::current().id(),
            to_string_pretty(&json).expect("Failed to pretty print json")
        );
        EVENTS.with(|events| {
            events.borrow_mut().push(json);
        });
    }

    fn current_span(&self) -> Current {
        SPAN_STACK.with(|span_stack| {
            let stack = span_stack.borrow();
            if stack.is_empty() {
                return Current::none();
            }
            let id = stack.last().expect("Failed to get last span from stack");
            let map = SPAN_METADATA.with(|span_metadata| span_metadata.borrow().clone());
            let metadata = *map
                .get(&id.into_u64())
                .unwrap_or_else(|| panic!("Failed to get span metadata ID {}", id.into_u64()));
            Current::new(id.clone(), metadata)
        })
    }

    fn enter(&self, span: &Id) {
        println!(
            "Thread {:?} Entered Span {}",
            std::thread::current().id(),
            span.into_u64()
        );
        SPAN_STACK.with(|span_stack| {
            let mut stack = span_stack.borrow_mut();
            stack.push(span.clone());
        });
    }

    fn exit(&self, span: &Id) {
        println!(
            "Thread {:?} Exited Span {}",
            std::thread::current().id(),
            span.into_u64()
        );
        SPAN_STACK.with(|span_stack| {
            let mut stack = span_stack.borrow_mut();
            let popped = stack.pop();
            assert_eq!(popped, Some(span.clone()));
        });
    }

    // We are not interested in this method for testing

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}
}

#[cfg(test)]
mod tests {
    use std::thread;

    use serde_json::Value;
    use tracing::Level;

    use super::*;

    #[test]
    fn test_tracing_subscriber_new() {
        let subscriber = TracingSubscriber::new(Level::INFO);

        // Verify the subscriber is created successfully
        assert!(format!("{:?}", subscriber).contains("TracingSubscriber"));

        // Clean up
        subscriber.clear();
    }

    #[test]
    fn test_get_events_empty() {
        let subscriber = TracingSubscriber::new(Level::DEBUG);

        // Initially, events should be empty
        let events = subscriber.get_events();
        assert!(events.is_empty());

        subscriber.clear();
    }

    #[test]
    fn test_clear_functionality() {
        let subscriber = TracingSubscriber::new(Level::DEBUG);

        // Clear should not panic even when nothing exists
        subscriber.clear();

        // Events should be empty after clear
        let events_after_clear = subscriber.get_events();
        assert!(events_after_clear.is_empty());
    }

    #[test]
    fn test_get_span_panic_conditions() {
        let subscriber = TracingSubscriber::new(Level::INFO);

        // Test that getting non-existent span panics
        let result = std::panic::catch_unwind(|| {
            subscriber.get_span(999);
        });
        assert!(result.is_err());

        subscriber.clear();
    }

    #[test]
    fn test_get_span_metadata_panic_conditions() {
        let subscriber = TracingSubscriber::new(Level::INFO);

        // Test that getting non-existent span metadata panics
        let result = std::panic::catch_unwind(|| {
            subscriber.get_span_metadata(999);
        });
        assert!(result.is_err());

        subscriber.clear();
    }

    #[test]
    fn test_test_trace_records_empty() {
        let subscriber = TracingSubscriber::new(Level::INFO);

        // Use test_trace_records to inspect empty data
        use std::cell::RefCell;
        use std::rc::Rc;

        let spans_received = Rc::new(RefCell::new(None::<std::collections::HashMap<u64, Value>>));
        let events_received = Rc::new(RefCell::new(None::<Vec<Value>>));

        let spans_clone = spans_received.clone();
        let events_clone = events_received.clone();

        subscriber.test_trace_records(move |spans, events| {
            *spans_clone.borrow_mut() = Some(spans.clone());
            *events_clone.borrow_mut() = Some(events.clone());
        });

        // Verify we received the data
        let spans = spans_received.borrow().as_ref().unwrap().clone();
        let events = events_received.borrow().as_ref().unwrap().clone();

        // Should have no spans initially
        assert!(spans.is_empty());

        // Events should be empty
        assert!(events.is_empty());

        subscriber.clear();
    }

    #[test]
    fn test_thread_local_isolation_basic() {
        let subscriber = TracingSubscriber::new(Level::INFO);

        // Get initial events in main thread
        let main_events = subscriber.get_events();
        assert!(main_events.is_empty());

        // Spawn a thread and test isolation
        let handle = thread::spawn(move || {
            let thread_subscriber = TracingSubscriber::new(Level::INFO);
            let thread_events = thread_subscriber.get_events();
            assert!(thread_events.is_empty());
            thread_subscriber.clear();
        });

        handle.join().unwrap();

        // Main thread should still have empty events
        let main_events_after = subscriber.get_events();
        assert!(main_events_after.is_empty());

        subscriber.clear();
    }

    #[test]
    fn test_multiple_level_configurations() {
        // Test different level configurations
        let trace_subscriber = TracingSubscriber::new(Level::TRACE);
        let debug_subscriber = TracingSubscriber::new(Level::DEBUG);
        let info_subscriber = TracingSubscriber::new(Level::INFO);
        let warn_subscriber = TracingSubscriber::new(Level::WARN);
        let error_subscriber = TracingSubscriber::new(Level::ERROR);

        // All should be created successfully
        assert!(format!("{:?}", trace_subscriber).contains("TracingSubscriber"));
        assert!(format!("{:?}", debug_subscriber).contains("TracingSubscriber"));
        assert!(format!("{:?}", info_subscriber).contains("TracingSubscriber"));
        assert!(format!("{:?}", warn_subscriber).contains("TracingSubscriber"));
        assert!(format!("{:?}", error_subscriber).contains("TracingSubscriber"));

        // Clean up all subscribers
        trace_subscriber.clear();
        debug_subscriber.clear();
        info_subscriber.clear();
        warn_subscriber.clear();
        error_subscriber.clear();
    }

    #[test]
    fn test_consecutive_clears() {
        let subscriber = TracingSubscriber::new(Level::INFO);

        // Multiple consecutive clears should not panic
        subscriber.clear();
        subscriber.clear();
        subscriber.clear();

        // Events should still be empty
        let events = subscriber.get_events();
        assert!(events.is_empty());
    }

    #[test]
    fn test_new_with_all_log_levels() {
        // Test creating subscriber with each log level
        let levels = [
            Level::ERROR,
            Level::WARN,
            Level::INFO,
            Level::DEBUG,
            Level::TRACE,
        ];

        for level in levels {
            let subscriber = TracingSubscriber::new(level);

            // Should create successfully
            assert!(format!("{:?}", subscriber).contains("TracingSubscriber"));

            // Should have empty events initially
            assert!(subscriber.get_events().is_empty());

            subscriber.clear();
        }
    }
}
