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
#![allow(static_mut_refs)]
// this is a non threadsafe logger for testing purposes, to test the log messages emitted by the guest.
// it will only log messages from the hyperlight_guest target. It will not log messages from other targets.
// this target is only used when handling an outb log request from the guest, so this logger will only capture those messages.

use std::sync::Once;
use std::thread::current;

use log::{Level, Log, Metadata, Record, set_logger, set_max_level};

pub static LOGGER: SimpleLogger = SimpleLogger {};
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

static mut LOGCALLS: Vec<LogCall> = Vec::<LogCall>::new();
static mut NUMBER_OF_ENABLED_CALLS: usize = 0;

pub struct SimpleLogger {}

impl SimpleLogger {
    pub fn initialize_test_logger() {
        INITLOGGER.call_once(|| {
            // In tests, the logger might already be set by another component,
            // so we should ignore the error if it fails
            if set_logger(&LOGGER).is_ok() {
                set_max_level(log::LevelFilter::Trace);
            }
        });
    }

    pub fn num_enabled_calls(&self) -> usize {
        unsafe { NUMBER_OF_ENABLED_CALLS }
    }

    pub fn num_log_calls(&self) -> usize {
        unsafe { LOGCALLS.len() }
    }
    pub fn get_log_call(&self, idx: usize) -> Option<LogCall> {
        unsafe { LOGCALLS.get(idx).cloned() }
    }

    pub fn clear_log_calls(&self) {
        unsafe {
            LOGCALLS.clear();
            NUMBER_OF_ENABLED_CALLS = 0;
        }
    }

    pub fn test_log_records<F: Fn(&Vec<LogCall>)>(&self, f: F) {
        unsafe {
            // this logger is only used for testing so unsafe is fine here
            #[allow(static_mut_refs)]
            f(&LOGCALLS);
        };
        self.clear_log_calls();
    }
}

impl Log for SimpleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        // This allows us to count the actual number of messages that have been logged by the guest
        // because the guest derives its log level from the host log level then the number times that enabled is called for
        // the "hyperlight_guest" target will be the same as the number of messages logged by the guest.
        // In other words this function should always return true for the "hyperlight_guest" target.
        unsafe {
            if metadata.target() == "hyperlight_guest" {
                NUMBER_OF_ENABLED_CALLS += 1;
            }
            metadata.target() == "hyperlight_guest" && metadata.level() <= log::max_level()
        }
    }
    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        unsafe {
            LOGCALLS.push(LogCall {
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
            });
        };

        println!("Thread {:?} {:?}", current().id(), record);
    }

    fn flush(&self) {}
}

#[cfg(test)]
mod tests {
    use log::Level;

    use super::*;

    #[test]
    fn test_simple_logger_initialization() {
        // Note: We can't test initialization directly because once a logger is set,
        // it can't be changed in the same process. But we can test that this doesn't panic.
        // The initialization uses Once::call_once, so multiple calls are safe.
        SimpleLogger::initialize_test_logger();
        SimpleLogger::initialize_test_logger(); // Should be safe to call multiple times
        // If we reach here, initialization succeeded or was already done
        assert!(log::max_level() >= log::LevelFilter::Off);
    }

    #[test]
    fn test_log_call_creation_and_equality() {
        let log_call1 = LogCall {
            level: Level::Info,
            args: "test message".to_string(),
            target: "hyperlight_guest".to_string(),
            line: Some(42),
            file: Some("test.rs".to_string()),
            module_path: Some("test::module".to_string()),
        };

        let log_call2 = LogCall {
            level: Level::Info,
            args: "test message".to_string(),
            target: "hyperlight_guest".to_string(),
            line: Some(42),
            file: Some("test.rs".to_string()),
            module_path: Some("test::module".to_string()),
        };

        assert_eq!(log_call1, log_call2);
        assert_eq!(log_call1.clone(), log_call1);
    }

    #[test]
    fn test_log_call_debug_formatting() {
        let log_call = LogCall {
            level: Level::Error,
            args: "error message".to_string(),
            target: "hyperlight_guest".to_string(),
            line: None,
            file: None,
            module_path: None,
        };

        let debug_str = format!("{:?}", log_call);
        assert!(debug_str.contains("Error"));
        assert!(debug_str.contains("error message"));
        assert!(debug_str.contains("hyperlight_guest"));
    }

    #[test]
    fn test_logger_enabled_hyperlight_guest_target() {
        let logger = SimpleLogger {};
        let metadata = log::MetadataBuilder::new()
            .level(Level::Info)
            .target("hyperlight_guest")
            .build();

        logger.clear_log_calls();
        let initial_count = logger.num_enabled_calls();

        assert!(logger.enabled(&metadata));
        assert_eq!(logger.num_enabled_calls(), initial_count + 1);
    }

    #[test]
    fn test_logger_not_enabled_for_other_targets() {
        let logger = SimpleLogger {};
        let metadata = log::MetadataBuilder::new()
            .level(Level::Info)
            .target("other_target")
            .build();

        logger.clear_log_calls();
        let initial_count = logger.num_enabled_calls();

        assert!(!logger.enabled(&metadata));
        assert_eq!(logger.num_enabled_calls(), initial_count);
    }

    #[test]
    fn test_logger_respects_log_level() {
        let logger = SimpleLogger {};

        // Test that it respects max log level
        let trace_metadata = log::MetadataBuilder::new()
            .level(Level::Trace)
            .target("hyperlight_guest")
            .build();

        let error_metadata = log::MetadataBuilder::new()
            .level(Level::Error)
            .target("hyperlight_guest")
            .build();

        // Both should be enabled since we set max level to Trace in initialize_test_logger
        assert!(logger.enabled(&trace_metadata));
        assert!(logger.enabled(&error_metadata));
    }

    #[test]
    fn test_clear_log_calls() {
        let logger = SimpleLogger {};
        logger.clear_log_calls();

        assert_eq!(logger.num_log_calls(), 0);
        assert_eq!(logger.num_enabled_calls(), 0);

        // Trigger some enabled calls
        let metadata = log::MetadataBuilder::new()
            .level(Level::Info)
            .target("hyperlight_guest")
            .build();
        logger.enabled(&metadata);
        logger.enabled(&metadata);

        assert_eq!(logger.num_enabled_calls(), 2);

        logger.clear_log_calls();
        assert_eq!(logger.num_enabled_calls(), 0);
    }

    #[test]
    fn test_get_log_call_with_valid_index() {
        let logger = SimpleLogger {};
        logger.clear_log_calls();

        // Initialize the logger to set proper log level
        SimpleLogger::initialize_test_logger();

        // Create a test record and log it
        let record = log::Record::builder()
            .level(Level::Warn)
            .args(format_args!("test warning"))
            .target("hyperlight_guest")
            .line(Some(100))
            .file(Some("test.rs"))
            .module_path(Some("test::path"))
            .build();

        logger.log(&record);

        let log_call = logger.get_log_call(0);
        assert!(log_call.is_some());

        let call = log_call.unwrap();
        assert_eq!(call.level, Level::Warn);
        assert_eq!(call.args, "test warning");
        assert_eq!(call.target, "hyperlight_guest");
        assert_eq!(call.line, Some(100));
        assert_eq!(call.file, Some("test.rs".to_string()));
        assert_eq!(call.module_path, Some("test::path".to_string()));
    }

    #[test]
    fn test_get_log_call_with_invalid_index() {
        let logger = SimpleLogger {};
        logger.clear_log_calls();

        assert!(logger.get_log_call(0).is_none());
        assert!(logger.get_log_call(100).is_none());
    }

    #[test]
    fn test_log_call_count_tracking() {
        let logger = SimpleLogger {};
        logger.clear_log_calls();

        // Initialize the logger to set proper log level
        SimpleLogger::initialize_test_logger();

        assert_eq!(logger.num_log_calls(), 0);

        // Log multiple records
        let record1 = log::Record::builder()
            .level(Level::Info)
            .args(format_args!("first message"))
            .target("hyperlight_guest")
            .build();

        let record2 = log::Record::builder()
            .level(Level::Error)
            .args(format_args!("second message"))
            .target("hyperlight_guest")
            .build();

        logger.log(&record1);
        assert_eq!(logger.num_log_calls(), 1);

        logger.log(&record2);
        assert_eq!(logger.num_log_calls(), 2);
    }

    #[test]
    fn test_log_filtering_by_target() {
        let logger = SimpleLogger {};
        logger.clear_log_calls();

        // Initialize the logger to set proper log level
        SimpleLogger::initialize_test_logger();

        // Log message with hyperlight_guest target (should be logged)
        let guest_record = log::Record::builder()
            .level(Level::Info)
            .args(format_args!("guest message"))
            .target("hyperlight_guest")
            .build();

        // Log message with different target (should be filtered out)
        let other_record = log::Record::builder()
            .level(Level::Info)
            .args(format_args!("other message"))
            .target("other_target")
            .build();

        logger.log(&guest_record);
        logger.log(&other_record);

        // Only the hyperlight_guest message should be logged
        assert_eq!(logger.num_log_calls(), 1);

        let logged_call = logger.get_log_call(0).unwrap();
        assert_eq!(logged_call.args, "guest message");
        assert_eq!(logged_call.target, "hyperlight_guest");
    }

    #[test]
    fn test_test_log_records_function() {
        let logger = SimpleLogger {};
        logger.clear_log_calls();

        // Initialize the logger to set proper log level
        SimpleLogger::initialize_test_logger();

        // Log a test message
        let record = log::Record::builder()
            .level(Level::Debug)
            .args(format_args!("debug test"))
            .target("hyperlight_guest")
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
        let logger = SimpleLogger {};
        logger.clear_log_calls();

        // Initialize the logger to set proper log level
        SimpleLogger::initialize_test_logger();

        let record = log::Record::builder()
            .level(Level::Trace)
            .args(format_args!("minimal record"))
            .target("hyperlight_guest")
            .build();

        logger.log(&record);

        let logged_call = logger.get_log_call(0).unwrap();
        assert_eq!(logged_call.level, Level::Trace);
        assert_eq!(logged_call.args, "minimal record");
        assert_eq!(logged_call.target, "hyperlight_guest");
        assert_eq!(logged_call.line, None);
        assert_eq!(logged_call.file, None);
        assert_eq!(logged_call.module_path, None);
    }

    #[test]
    fn test_flush_does_nothing() {
        let logger = SimpleLogger {};
        // flush should not panic and should do nothing
        logger.flush();
    }
}
