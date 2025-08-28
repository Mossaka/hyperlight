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
use std::sync::Once;
use std::thread::current;

use log::{Level, LevelFilter, Log, Metadata, Record, set_logger, set_max_level};
use once_cell::sync::Lazy;
use tracing_log::LogTracer;

pub static LOGGER: Logger = Logger {};
static LOG_TRACER: Lazy<LogTracer> = Lazy::new(LogTracer::new);
static INITLOGGER: Once = Once::new();
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct LogCall {
    pub level: Level,
    pub args: String,
    pub target: String,
    pub line: Option<u32>,
    pub file: Option<String>,
    pub module_path: Option<String>,
}

thread_local!(
    static LOGCALLS: RefCell<Vec<LogCall>> = const { RefCell::new(Vec::<LogCall>::new()) };
    static LOGGER_MAX_LEVEL: RefCell<LevelFilter> = const { RefCell::new(LevelFilter::Off) };
);

pub struct Logger {}

impl Logger {
    pub fn initialize_test_logger() {
        INITLOGGER.call_once(|| {
            // In tests, the logger might already be set by another component,
            // so we should ignore the error if it fails
            if set_logger(&LOGGER).is_ok() {
                set_max_level(log::LevelFilter::Trace);
            }
        });
    }

    pub fn initialize_log_tracer() {
        INITLOGGER.call_once(|| {
            // In tests, the logger might already be set by another component,
            // so we should ignore the error if it fails
            if set_logger(&*LOG_TRACER).is_ok() {
                set_max_level(log::LevelFilter::Trace);
            }
        });
    }

    pub fn num_log_calls(&self) -> usize {
        LOGCALLS.with(|log_calls| log_calls.borrow().len())
    }
    pub fn get_log_call(&self, idx: usize) -> Option<LogCall> {
        LOGCALLS.with(|log_calls| log_calls.borrow().get(idx).cloned())
    }

    pub fn clear_log_calls(&self) {
        LOGCALLS.with(|log_calls| log_calls.borrow_mut().clear());
    }

    pub fn test_log_records<F: Fn(&Vec<LogCall>)>(&self, f: F) {
        LOGCALLS.with(|log_calls| f(&log_calls.borrow()));
        self.clear_log_calls();
    }

    pub fn set_max_level(&self, level: LevelFilter) {
        LOGGER_MAX_LEVEL.with(|max_level| {
            *max_level.borrow_mut() = level;
        });
    }
}

impl Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        LOGGER_MAX_LEVEL.with(|max_level| metadata.level() <= *max_level.borrow())
    }
    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        LOGCALLS.with(|log_calls| {
            if record.target().contains("hyperlight_guest") {
                println!("Thread {:?} {:?}", current().id(), record);
                println!("Thread {:?} {:?}", current().id(), record.metadata());
            }
            log_calls.borrow_mut().push(LogCall {
                level: record.level(),
                args: format!("{}", record.args()),
                target: record.target().to_string(),
                line: record.line(),
                file: match record.file() {
                    None => record.file_static().map(|file| file.to_string()),
                    Some(file) => Some(file.to_string()),
                },
                module_path: match record.module_path() {
                    None => record
                        .module_path_static()
                        .map(|module_path| module_path.to_string()),
                    Some(module_path) => Some(module_path.to_string()),
                },
            })
        });

        println!("Thread {:?} {:?}", current().id(), record);
    }

    fn flush(&self) {}
}

#[cfg(test)]
mod tests {
    use log::{Level, LevelFilter};

    use super::*;

    #[test]
    fn test_logger_initialization() {
        // Note: We can't test initialization directly because once a logger is set,
        // it can't be changed in the same process. We just test that this doesn't panic.
        Logger::initialize_test_logger();
        // If we reach here, initialization succeeded or was already done
        assert!(log::max_level() >= log::LevelFilter::Off);
    }

    #[test]
    fn test_log_call_creation_and_equality() {
        let log_call1 = LogCall {
            level: Level::Info,
            args: "test message".to_string(),
            target: "test_target".to_string(),
            line: Some(42),
            file: Some("test.rs".to_string()),
            module_path: Some("test::module".to_string()),
        };

        let log_call2 = LogCall {
            level: Level::Info,
            args: "test message".to_string(),
            target: "test_target".to_string(),
            line: Some(42),
            file: Some("test.rs".to_string()),
            module_path: Some("test::module".to_string()),
        };

        assert_eq!(log_call1, log_call2);
        assert_eq!(log_call1.clone(), log_call1);
    }

    #[test]
    fn test_logger_set_and_respect_max_level() {
        let logger = Logger {};
        logger.clear_log_calls();

        // Set max level to Info
        logger.set_max_level(LevelFilter::Info);

        let info_metadata = log::MetadataBuilder::new()
            .level(Level::Info)
            .target("test")
            .build();

        let debug_metadata = log::MetadataBuilder::new()
            .level(Level::Debug)
            .target("test")
            .build();

        let error_metadata = log::MetadataBuilder::new()
            .level(Level::Error)
            .target("test")
            .build();

        // Info and Error should be enabled, Debug should not
        assert!(logger.enabled(&info_metadata));
        assert!(logger.enabled(&error_metadata));
        assert!(!logger.enabled(&debug_metadata));
    }

    #[test]
    fn test_logger_set_max_level_trace() {
        let logger = Logger {};
        logger.set_max_level(LevelFilter::Trace);

        let trace_metadata = log::MetadataBuilder::new()
            .level(Level::Trace)
            .target("test")
            .build();

        assert!(logger.enabled(&trace_metadata));
    }

    #[test]
    fn test_logger_set_max_level_off() {
        let logger = Logger {};
        logger.set_max_level(LevelFilter::Off);

        let error_metadata = log::MetadataBuilder::new()
            .level(Level::Error)
            .target("test")
            .build();

        assert!(!logger.enabled(&error_metadata));
    }

    #[test]
    fn test_clear_log_calls() {
        let logger = Logger {};
        logger.clear_log_calls();

        assert_eq!(logger.num_log_calls(), 0);

        // Log a test message
        logger.set_max_level(LevelFilter::Trace);
        let record = log::Record::builder()
            .level(Level::Info)
            .args(format_args!("test message"))
            .target("test")
            .build();

        logger.log(&record);
        assert_eq!(logger.num_log_calls(), 1);

        logger.clear_log_calls();
        assert_eq!(logger.num_log_calls(), 0);
    }

    #[test]
    fn test_get_log_call_with_valid_index() {
        let logger = Logger {};
        logger.clear_log_calls();
        logger.set_max_level(LevelFilter::Trace);

        let record = log::Record::builder()
            .level(Level::Warn)
            .args(format_args!("warning message"))
            .target("test_target")
            .line(Some(123))
            .file(Some("warning.rs"))
            .module_path(Some("test::warning"))
            .build();

        logger.log(&record);

        let log_call = logger.get_log_call(0);
        assert!(log_call.is_some());

        let call = log_call.unwrap();
        assert_eq!(call.level, Level::Warn);
        assert_eq!(call.args, "warning message");
        assert_eq!(call.target, "test_target");
        assert_eq!(call.line, Some(123));
        assert_eq!(call.file, Some("warning.rs".to_string()));
        assert_eq!(call.module_path, Some("test::warning".to_string()));
    }

    #[test]
    fn test_get_log_call_with_invalid_index() {
        let logger = Logger {};
        logger.clear_log_calls();

        assert!(logger.get_log_call(0).is_none());
        assert!(logger.get_log_call(100).is_none());
    }

    #[test]
    fn test_log_call_count_tracking() {
        let logger = Logger {};
        logger.clear_log_calls();
        logger.set_max_level(LevelFilter::Trace);

        assert_eq!(logger.num_log_calls(), 0);

        let record1 = log::Record::builder()
            .level(Level::Info)
            .args(format_args!("first"))
            .target("test")
            .build();

        let record2 = log::Record::builder()
            .level(Level::Error)
            .args(format_args!("second"))
            .target("test")
            .build();

        logger.log(&record1);
        assert_eq!(logger.num_log_calls(), 1);

        logger.log(&record2);
        assert_eq!(logger.num_log_calls(), 2);
    }

    #[test]
    fn test_log_filtering_by_level() {
        let logger = Logger {};
        logger.clear_log_calls();
        logger.set_max_level(LevelFilter::Warn);

        let warn_record = log::Record::builder()
            .level(Level::Warn)
            .args(format_args!("warning"))
            .target("test")
            .build();

        let debug_record = log::Record::builder()
            .level(Level::Debug)
            .args(format_args!("debug"))
            .target("test")
            .build();

        logger.log(&warn_record);
        logger.log(&debug_record);

        // Only the warning should be logged due to level filtering
        assert_eq!(logger.num_log_calls(), 1);

        let logged_call = logger.get_log_call(0).unwrap();
        assert_eq!(logged_call.args, "warning");
        assert_eq!(logged_call.level, Level::Warn);
    }

    #[test]
    fn test_test_log_records_function() {
        let logger = Logger {};
        logger.clear_log_calls();
        logger.set_max_level(LevelFilter::Trace);

        let record = log::Record::builder()
            .level(Level::Debug)
            .args(format_args!("debug test"))
            .target("test")
            .build();

        logger.log(&record);
        assert_eq!(logger.num_log_calls(), 1);

        // Test the test_log_records function
        logger.test_log_records(|calls| {
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].args, "debug test");
            assert_eq!(calls[0].level, Level::Debug);
        });

        // After test_log_records, calls should be cleared
        assert_eq!(logger.num_log_calls(), 0);
    }

    #[test]
    fn test_log_with_optional_fields_none() {
        let logger = Logger {};
        logger.clear_log_calls();
        logger.set_max_level(LevelFilter::Trace);

        let record = log::Record::builder()
            .level(Level::Trace)
            .args(format_args!("minimal record"))
            .target("test")
            .build();

        logger.log(&record);

        let logged_call = logger.get_log_call(0).unwrap();
        assert_eq!(logged_call.level, Level::Trace);
        assert_eq!(logged_call.args, "minimal record");
        assert_eq!(logged_call.target, "test");
        assert_eq!(logged_call.line, None);
        assert_eq!(logged_call.file, None);
        assert_eq!(logged_call.module_path, None);
    }

    #[test]
    fn test_multiple_threads_independence() {
        // This tests the thread_local nature of the logger storage
        let logger = Logger {};
        logger.clear_log_calls();
        logger.set_max_level(LevelFilter::Trace);

        let record = log::Record::builder()
            .level(Level::Info)
            .args(format_args!("main thread"))
            .target("test")
            .build();

        logger.log(&record);
        assert_eq!(logger.num_log_calls(), 1);

        // The log calls should be thread-local, so they're independent per thread
        let handle = std::thread::spawn(move || {
            let thread_logger = Logger {};
            // This should be 0 in the new thread due to thread_local storage
            assert_eq!(thread_logger.num_log_calls(), 0);
        });

        handle.join().unwrap();

        // Back in main thread, we should still have our log call
        assert_eq!(logger.num_log_calls(), 1);
    }

    #[test]
    fn test_flush_does_nothing() {
        let logger = Logger {};
        // flush should not panic and should do nothing
        logger.flush();
    }

    #[test]
    fn test_hyperlight_guest_target_special_handling() {
        let logger = Logger {};
        logger.clear_log_calls();
        logger.set_max_level(LevelFilter::Trace);

        // Test that hyperlight_guest target gets special handling (more prints)
        let guest_record = log::Record::builder()
            .level(Level::Info)
            .args(format_args!("guest message"))
            .target("hyperlight_guest_module")
            .build();

        let regular_record = log::Record::builder()
            .level(Level::Info)
            .args(format_args!("regular message"))
            .target("regular_target")
            .build();

        // Both should be logged, but guest target gets special print handling
        logger.log(&guest_record);
        logger.log(&regular_record);

        assert_eq!(logger.num_log_calls(), 2);

        let guest_call = logger.get_log_call(0).unwrap();
        let regular_call = logger.get_log_call(1).unwrap();

        assert_eq!(guest_call.target, "hyperlight_guest_module");
        assert_eq!(regular_call.target, "regular_target");
    }
}
