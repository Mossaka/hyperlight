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

#[cfg(mshv2)]
extern crate mshv_ioctls2 as mshv_ioctls;

#[cfg(mshv3)]
extern crate mshv_ioctls3 as mshv_ioctls;

use std::array::TryFromSliceError;
use std::cell::{BorrowError, BorrowMutError};
use std::convert::Infallible;
use std::error::Error;
use std::num::TryFromIntError;
use std::string::FromUtf8Error;
use std::sync::{MutexGuard, PoisonError};
use std::time::SystemTimeError;

#[cfg(target_os = "windows")]
use crossbeam_channel::{RecvError, SendError};
use flatbuffers::InvalidFlatbuffer;
use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterValue, ReturnValue};
use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use thiserror::Error;

#[cfg(target_os = "windows")]
use crate::hypervisor::wrappers::HandleWrapper;
use crate::mem::memory_region::MemoryRegionFlags;
use crate::mem::ptr::RawPtr;

/// The error type for Hyperlight operations
#[derive(Error, Debug)]
pub enum HyperlightError {
    /// Anyhow error
    #[error("Anyhow Error was returned: {0}")]
    AnyhowError(#[from] anyhow::Error),
    /// Memory access out of bounds
    #[error("Offset: {0} out of bounds, Max is: {1}")]
    BoundsCheckFailed(u64, usize),

    /// Checked Add Overflow
    #[error("Couldn't add offset to base address. Offset: {0}, Base Address: {1}")]
    CheckedAddOverflow(u64, u64),

    /// Cross beam channel receive error
    #[error("{0:?}")]
    #[cfg(target_os = "windows")]
    CrossBeamReceiveError(#[from] RecvError),

    /// Cross beam channel send error
    #[error("{0:?}")]
    #[cfg(target_os = "windows")]
    CrossBeamSendError(#[from] SendError<HandleWrapper>),

    /// CString conversion error
    #[error("Error converting CString {0:?}")]
    CStringConversionError(#[from] std::ffi::NulError),

    /// A disallowed syscall was caught
    #[error("Seccomp filter trapped on disallowed syscall (check STDERR for offending syscall)")]
    #[cfg(all(feature = "seccomp", target_os = "linux"))]
    DisallowedSyscall,

    /// A generic error with a message
    #[error("{0}")]
    Error(String),

    /// Execution violation
    #[error("Non-executable address {0:#x} tried to be executed")]
    ExecutionAccessViolation(u64),

    /// Guest execution was cancelled by the host
    #[error("Execution was cancelled by the host.")]
    ExecutionCanceledByHost(),

    /// Accessing the value of a flatbuffer parameter failed
    #[error("Failed to get a value from flat buffer parameter")]
    FailedToGetValueFromParameter(),

    ///Field Name not found in decoded GuestLogData
    #[error("Field Name {0} not found in decoded GuestLogData")]
    FieldIsMissingInGuestLogData(String),

    /// Guest aborted during outb
    #[error("Guest aborted: {0} {1}")]
    GuestAborted(u8, String),

    /// Guest call resulted in error in guest
    #[error("Guest error occurred {0:?}: {1}")]
    GuestError(ErrorCode, String),

    /// An attempt to cancel guest execution failed because it is hanging on a host function call
    #[error("Guest execution hung on the execution of a host function call")]
    GuestExecutionHungOnHostFunctionCall(),

    /// Guest call already in progress
    #[error("Guest call is already in progress")]
    GuestFunctionCallAlreadyInProgress(),

    /// The given type is not supported by the guest interface.
    #[error("Unsupported type: {0}")]
    GuestInterfaceUnsupportedType(String),

    /// The guest offset is invalid.
    #[error("The guest offset {0} is invalid.")]
    GuestOffsetIsInvalid(usize),

    /// A Host function was called by the guest but it was not registered.
    #[error("HostFunction {0} was not found")]
    HostFunctionNotFound(String),

    /// Reading Writing or Seeking data failed.
    #[error("Reading Writing or Seeking data failed {0:?}")]
    IOError(#[from] std::io::Error),

    /// Failed to convert to Integer
    #[error("Failed To Convert Size to usize")]
    IntConversionFailure(#[from] TryFromIntError),

    /// The flatbuffer is invalid
    #[error("The flatbuffer is invalid")]
    InvalidFlatBuffer(#[from] InvalidFlatbuffer),

    /// Conversion of str to Json failed
    #[error("Conversion of str data to json failed")]
    JsonConversionFailure(#[from] serde_json::Error),

    /// KVM Error Occurred
    #[error("KVM Error {0:?}")]
    #[cfg(kvm)]
    KVMError(#[from] kvm_ioctls::Error),

    /// An attempt to get a lock from a Mutex failed.
    #[error("Unable to lock resource")]
    LockAttemptFailed(String),

    /// Memory Access Violation at the given address. The access type and memory region flags are provided.
    #[error("Memory Access Violation at address {0:#x} of type {1}, but memory is marked as {2}")]
    MemoryAccessViolation(u64, MemoryRegionFlags, MemoryRegionFlags),

    /// Memory Allocation Failed.
    #[error("Memory Allocation Failed with OS Error {0:?}.")]
    MemoryAllocationFailed(Option<i32>),

    /// Memory Protection Failed
    #[error("Memory Protection Failed with OS Error {0:?}.")]
    MemoryProtectionFailed(Option<i32>),

    /// The memory request exceeds the maximum size allowed
    #[error("Memory requested {0} exceeds maximum size allowed {1}")]
    MemoryRequestTooBig(usize, usize),

    /// Metric Not Found.
    #[error("Metric Not Found {0:?}.")]
    MetricNotFound(&'static str),

    /// mmap Failed.
    #[error("mmap failed with os error {0:?}")]
    MmapFailed(Option<i32>),

    /// mprotect Failed.
    #[error("mprotect failed with os error {0:?}")]
    MprotectFailed(Option<i32>),

    /// mshv Error Occurred
    #[error("mshv Error {0:?}")]
    #[cfg(mshv)]
    MSHVError(#[from] mshv_ioctls::MshvError),

    /// No Hypervisor was found for Sandbox.
    #[error("No Hypervisor was found for Sandbox")]
    NoHypervisorFound(),

    /// Restore_state called with no valid snapshot
    #[error("Restore_state called with no valid snapshot")]
    NoMemorySnapshot,

    /// Failed to get value from parameter value
    #[error("Failed To Convert Parameter Value {0:?} to {1:?}")]
    ParameterValueConversionFailure(ParameterValue, &'static str),

    /// a failure occurred processing a PE file
    #[error("Failure processing PE File {0:?}")]
    PEFileProcessingFailure(#[from] goblin::error::Error),

    /// Raw pointer is less than base address
    #[error("Raw pointer ({0:?}) was less than the base address ({1})")]
    RawPointerLessThanBaseAddress(RawPtr, u64),

    /// RefCell borrow failed
    #[error("RefCell borrow failed")]
    RefCellBorrowFailed(#[from] BorrowError),

    /// RefCell mut borrow failed
    #[error("RefCell mut borrow failed")]
    RefCellMutBorrowFailed(#[from] BorrowMutError),

    /// Failed to get value from return value
    #[error("Failed To Convert Return Value {0:?} to {1:?}")]
    ReturnValueConversionFailure(ReturnValue, &'static str),

    /// Stack overflow detected in guest
    #[error("Stack overflow detected")]
    StackOverflow(),

    /// a backend error occurred with seccomp filters
    #[error("Backend Error with Seccomp Filter {0:?}")]
    #[cfg(all(feature = "seccomp", target_os = "linux"))]
    SeccompFilterBackendError(#[from] seccompiler::BackendError),

    /// an error occurred with seccomp filters
    #[error("Error with Seccomp Filter {0:?}")]
    #[cfg(all(feature = "seccomp", target_os = "linux"))]
    SeccompFilterError(#[from] seccompiler::Error),

    /// Tried to restore snapshot to a sandbox that is not the same as the one the snapshot was taken from
    #[error("Snapshot was taken from a different sandbox")]
    SnapshotSandboxMismatch,

    /// SystemTimeError
    #[error("SystemTimeError {0:?}")]
    SystemTimeError(#[from] SystemTimeError),

    /// Error occurred when translating guest address
    #[error("An error occurred when translating guest address: {0:?}")]
    #[cfg(gdb)]
    TranslateGuestAddress(u64),

    /// Error occurred converting a slice to an array
    #[error("TryFromSliceError {0:?}")]
    TryFromSliceError(#[from] TryFromSliceError),

    /// A function was called with an incorrect number of arguments
    #[error("The number of arguments to the function is wrong: got {0:?} expected {1:?}")]
    UnexpectedNoOfArguments(usize, usize),

    /// The parameter value type is unexpected
    #[error("The parameter value type is unexpected got {0:?} expected {1:?}")]
    UnexpectedParameterValueType(ParameterValue, String),

    /// The return value type is unexpected
    #[error("The return value type is unexpected got {0:?} expected {1:?}")]
    UnexpectedReturnValueType(ReturnValue, String),

    /// Slice conversion to UTF8 failed
    #[error("String Conversion of UTF8 data to str failed")]
    UTF8StringConversionFailure(#[from] FromUtf8Error),

    /// The capacity of the vector is incorrect
    #[error(
        "The capacity of the vector is incorrect. Capacity: {0}, Length: {1}, FlatBuffer Size: {2}"
    )]
    VectorCapacityIncorrect(usize, usize, i32),

    /// vmm sys Error Occurred
    #[error("vmm sys Error {0:?}")]
    #[cfg(target_os = "linux")]
    VmmSysError(vmm_sys_util::errno::Error),

    /// Windows Error
    #[cfg(target_os = "windows")]
    #[error("Windows API Error Result {0:?}")]
    WindowsAPIError(#[from] windows_result::Error),
}

impl From<Infallible> for HyperlightError {
    fn from(_: Infallible) -> Self {
        "Impossible as this is an infallible error".into()
    }
}

impl From<&str> for HyperlightError {
    fn from(s: &str) -> Self {
        HyperlightError::Error(s.to_string())
    }
}

impl<T> From<PoisonError<MutexGuard<'_, T>>> for HyperlightError {
    // Implemented this way rather than passing the error as a source to LockAttemptFailed as that would require
    // Box<dyn Error + Send + Sync> which is not easy to implement for PoisonError<MutexGuard<'_, T>>
    // This is a good enough solution and allows use to use the ? operator on lock() calls
    fn from(e: PoisonError<MutexGuard<'_, T>>) -> Self {
        let source = match e.source() {
            Some(s) => s.to_string(),
            None => String::from(""),
        };
        HyperlightError::LockAttemptFailed(source)
    }
}

/// Creates a `HyperlightError::Error` from a string literal or format string
#[macro_export]
macro_rules! new_error {
    ($msg:literal $(,)?) => {{
        let __args = std::format_args!($msg);
        let __err_msg = match __args.as_str() {
            Some(msg) => String::from(msg),
            None => std::format!($msg),
        };
        $crate::HyperlightError::Error(__err_msg)
    }};
    ($fmtstr:expr, $($arg:tt)*) => {{
           let __err_msg = std::format!($fmtstr, $($arg)*);
           $crate::error::HyperlightError::Error(__err_msg)
    }};
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterValue, ReturnValue};
    use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;

    use super::*;
    use crate::mem::memory_region::MemoryRegionFlags;
    use crate::mem::ptr::RawPtr;

    #[test]
    fn test_bounds_check_failed_error() {
        let error = HyperlightError::BoundsCheckFailed(100, 50);
        assert_eq!(
            format!("{}", error),
            "Offset: 100 out of bounds, Max is: 50"
        );
    }

    #[test]
    fn test_checked_add_overflow_error() {
        let error = HyperlightError::CheckedAddOverflow(0xFFFFFFFFFFFFFFFF, 1);
        assert_eq!(
            format!("{}", error),
            "Couldn't add offset to base address. Offset: 18446744073709551615, Base Address: 1"
        );
    }

    #[test]
    fn test_execution_access_violation_error() {
        let error = HyperlightError::ExecutionAccessViolation(0x1000);
        assert_eq!(
            format!("{}", error),
            "Non-executable address 0x1000 tried to be executed"
        );
    }

    #[test]
    fn test_execution_canceled_by_host_error() {
        let error = HyperlightError::ExecutionCanceledByHost();
        assert_eq!(format!("{}", error), "Execution was cancelled by the host.");
    }

    #[test]
    fn test_guest_aborted_error() {
        let error = HyperlightError::GuestAborted(1, "Test abort message".to_string());
        assert_eq!(format!("{}", error), "Guest aborted: 1 Test abort message");
    }

    #[test]
    fn test_guest_error() {
        let error = HyperlightError::GuestError(
            ErrorCode::GuestFunctionNotFound,
            "Test guest error".to_string(),
        );
        assert_eq!(
            format!("{}", error),
            "Guest error occurred GuestFunctionNotFound: Test guest error"
        );
    }

    #[test]
    fn test_host_function_not_found_error() {
        let error = HyperlightError::HostFunctionNotFound("test_function".to_string());
        assert_eq!(
            format!("{}", error),
            "HostFunction test_function was not found"
        );
    }

    #[test]
    fn test_guest_offset_invalid_error() {
        let error = HyperlightError::GuestOffsetIsInvalid(12345);
        assert_eq!(format!("{}", error), "The guest offset 12345 is invalid.");
    }

    #[test]
    fn test_memory_access_violation_error() {
        let error = HyperlightError::MemoryAccessViolation(
            0x1000,
            MemoryRegionFlags::READ,
            MemoryRegionFlags::WRITE,
        );
        assert!(format!("{}", error).contains("Memory Access Violation at address 0x1000"));
    }

    #[test]
    fn test_memory_allocation_failed_error() {
        let error = HyperlightError::MemoryAllocationFailed(Some(12));
        assert_eq!(
            format!("{}", error),
            "Memory Allocation Failed with OS Error Some(12)."
        );

        let error_none = HyperlightError::MemoryAllocationFailed(None);
        assert_eq!(
            format!("{}", error_none),
            "Memory Allocation Failed with OS Error None."
        );
    }

    #[test]
    fn test_memory_protection_failed_error() {
        let error = HyperlightError::MemoryProtectionFailed(Some(13));
        assert_eq!(
            format!("{}", error),
            "Memory Protection Failed with OS Error Some(13)."
        );
    }

    #[test]
    fn test_memory_request_too_big_error() {
        let error = HyperlightError::MemoryRequestTooBig(1024, 512);
        assert_eq!(
            format!("{}", error),
            "Memory requested 1024 exceeds maximum size allowed 512"
        );
    }

    #[test]
    fn test_stack_overflow_error() {
        let error = HyperlightError::StackOverflow();
        assert_eq!(format!("{}", error), "Stack overflow detected");
    }

    #[test]
    fn test_no_hypervisor_found_error() {
        let error = HyperlightError::NoHypervisorFound();
        assert_eq!(format!("{}", error), "No Hypervisor was found for Sandbox");
    }

    #[test]
    fn test_no_memory_snapshot_error() {
        let error = HyperlightError::NoMemorySnapshot;
        assert_eq!(
            format!("{}", error),
            "Restore_state called with no valid snapshot"
        );
    }

    #[test]
    fn test_snapshot_sandbox_mismatch_error() {
        let error = HyperlightError::SnapshotSandboxMismatch;
        assert_eq!(
            format!("{}", error),
            "Snapshot was taken from a different sandbox"
        );
    }

    #[test]
    fn test_unexpected_no_of_arguments_error() {
        let error = HyperlightError::UnexpectedNoOfArguments(3, 2);
        assert_eq!(
            format!("{}", error),
            "The number of arguments to the function is wrong: got 3 expected 2"
        );
    }

    #[test]
    fn test_vector_capacity_incorrect_error() {
        let error = HyperlightError::VectorCapacityIncorrect(100, 50, 200);
        assert_eq!(
            format!("{}", error),
            "The capacity of the vector is incorrect. Capacity: 100, Length: 50, FlatBuffer Size: 200"
        );
    }

    #[test]
    fn test_parameter_value_conversion_failure_error() {
        let param = ParameterValue::Int(42);
        let error = HyperlightError::ParameterValueConversionFailure(param, "String");
        assert!(format!("{}", error).contains("Failed To Convert Parameter Value"));
    }

    #[test]
    fn test_return_value_conversion_failure_error() {
        let ret_val = ReturnValue::Int(42);
        let error = HyperlightError::ReturnValueConversionFailure(ret_val, "String");
        assert!(format!("{}", error).contains("Failed To Convert Return Value"));
    }

    #[test]
    fn test_raw_pointer_less_than_base_address_error() {
        let raw_ptr = RawPtr::from(0x1000u64);
        let error = HyperlightError::RawPointerLessThanBaseAddress(raw_ptr, 0x2000);
        assert!(format!("{}", error).contains("Raw pointer"));
        assert!(format!("{}", error).contains("was less than the base address"));
    }

    #[test]
    fn test_guest_interface_unsupported_type_error() {
        let error = HyperlightError::GuestInterfaceUnsupportedType("CustomType".to_string());
        assert_eq!(format!("{}", error), "Unsupported type: CustomType");
    }

    #[test]
    fn test_unexpected_parameter_value_type_error() {
        let param = ParameterValue::Int(42);
        let error =
            HyperlightError::UnexpectedParameterValueType(param, "Expected String".to_string());
        assert!(format!("{}", error).contains("The parameter value type is unexpected"));
    }

    #[test]
    fn test_unexpected_return_value_type_error() {
        let ret_val = ReturnValue::Int(42);
        let error =
            HyperlightError::UnexpectedReturnValueType(ret_val, "Expected String".to_string());
        assert!(format!("{}", error).contains("The return value type is unexpected"));
    }

    #[test]
    fn test_generic_error_from_str() {
        let error: HyperlightError = "Test error message".into();
        assert_eq!(format!("{}", error), "Test error message");
    }

    #[test]
    fn test_generic_error_from_string() {
        let error = HyperlightError::Error("Test error".to_string());
        assert_eq!(format!("{}", error), "Test error");
    }

    #[test]
    fn test_mutex_poison_error_conversion() {
        // Create a mutex and poison it
        let mutex = Arc::new(Mutex::new(42));
        let mutex_clone = Arc::clone(&mutex);

        // Spawn a thread that panics while holding the mutex
        let handle = std::thread::spawn(move || {
            let _guard = mutex_clone.lock().unwrap();
            panic!("This will poison the mutex");
        });

        // Wait for the thread to finish (and panic)
        let _ = handle.join();

        // Now try to lock the poisoned mutex and convert the error
        let lock_result = mutex.lock();
        assert!(lock_result.is_err());

        let hyperlight_error: HyperlightError = lock_result.unwrap_err().into();
        match hyperlight_error {
            HyperlightError::LockAttemptFailed(_) => {
                // Test passes
            }
            _ => panic!("Expected LockAttemptFailed error"),
        }
    }

    #[test]
    fn test_failed_to_get_value_from_parameter_error() {
        let error = HyperlightError::FailedToGetValueFromParameter();
        assert_eq!(
            format!("{}", error),
            "Failed to get a value from flat buffer parameter"
        );
    }

    #[test]
    fn test_field_missing_in_guest_log_data_error() {
        let error = HyperlightError::FieldIsMissingInGuestLogData("test_field".to_string());
        assert_eq!(
            format!("{}", error),
            "Field Name test_field not found in decoded GuestLogData"
        );
    }

    #[test]
    fn test_guest_function_call_already_in_progress_error() {
        let error = HyperlightError::GuestFunctionCallAlreadyInProgress();
        assert_eq!(format!("{}", error), "Guest call is already in progress");
    }

    #[test]
    fn test_guest_execution_hung_on_host_function_call_error() {
        let error = HyperlightError::GuestExecutionHungOnHostFunctionCall();
        assert_eq!(
            format!("{}", error),
            "Guest execution hung on the execution of a host function call"
        );
    }

    #[test]
    fn test_lock_attempt_failed_error() {
        let error = HyperlightError::LockAttemptFailed("test lock failure".to_string());
        assert_eq!(format!("{}", error), "Unable to lock resource");
    }

    #[test]
    fn test_metric_not_found_error() {
        let error = HyperlightError::MetricNotFound("test_metric");
        assert_eq!(format!("{}", error), "Metric Not Found \"test_metric\".");
    }

    #[test]
    fn test_mmap_failed_error() {
        let error = HyperlightError::MmapFailed(Some(42));
        assert_eq!(format!("{}", error), "mmap failed with os error Some(42)");

        let error_none = HyperlightError::MmapFailed(None);
        assert_eq!(format!("{}", error_none), "mmap failed with os error None");
    }

    #[test]
    fn test_mprotect_failed_error() {
        let error = HyperlightError::MprotectFailed(Some(42));
        assert_eq!(
            format!("{}", error),
            "mprotect failed with os error Some(42)"
        );

        let error_none = HyperlightError::MprotectFailed(None);
        assert_eq!(
            format!("{}", error_none),
            "mprotect failed with os error None"
        );
    }

    #[test]
    fn test_new_error_macro_simple() {
        let error = new_error!("Simple error message");
        match error {
            HyperlightError::Error(msg) => assert_eq!(msg, "Simple error message"),
            _ => panic!("Expected Error variant"),
        }
    }

    #[test]
    fn test_new_error_macro_formatted() {
        let error = new_error!("Formatted error: {} {}", "test", 42);
        match error {
            HyperlightError::Error(msg) => assert_eq!(msg, "Formatted error: test 42"),
            _ => panic!("Expected Error variant"),
        }
    }

    #[test]
    fn test_from_infallible() {
        // This test is a bit artificial since Infallible can never actually be constructed,
        // but we can test the conversion function exists and compiles
        fn test_conversion(inf: std::convert::Infallible) -> HyperlightError {
            inf.into()
        }

        // The function compiles, which is what we're testing
        // We can't actually call it since Infallible can't be constructed
    }
}
