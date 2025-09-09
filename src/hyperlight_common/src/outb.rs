/*
Copyright 2025 The Hyperlight Authors.

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

use core::convert::TryFrom;

use anyhow::{Error, anyhow};

/// Exception codes for the x86 architecture.
/// These are helpful to identify the type of exception that occurred
/// together with OutBAction::Abort.
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum Exception {
    DivideByZero = 0,
    Debug = 1,
    NonMaskableInterrupt = 2,
    Breakpoint = 3,
    Overflow = 4,
    BoundRangeExceeded = 5,
    InvalidOpcode = 6,
    DeviceNotAvailable = 7,
    DoubleFault = 8,
    CoprocessorSegmentOverrun = 9,
    InvalidTSS = 10,
    SegmentNotPresent = 11,
    StackSegmentFault = 12,
    GeneralProtectionFault = 13,
    PageFault = 14,
    Reserved = 15,
    X87FloatingPointException = 16,
    AlignmentCheck = 17,
    MachineCheck = 18,
    SIMDFloatingPointException = 19,
    VirtualizationException = 20,
    SecurityException = 30,
    NoException = 0xFF,
}

impl TryFrom<u8> for Exception {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        use Exception::*;
        let exception = match value {
            0 => DivideByZero,
            1 => Debug,
            2 => NonMaskableInterrupt,
            3 => Breakpoint,
            4 => Overflow,
            5 => BoundRangeExceeded,
            6 => InvalidOpcode,
            7 => DeviceNotAvailable,
            8 => DoubleFault,
            9 => CoprocessorSegmentOverrun,
            10 => InvalidTSS,
            11 => SegmentNotPresent,
            12 => StackSegmentFault,
            13 => GeneralProtectionFault,
            14 => PageFault,
            15 => Reserved,
            16 => X87FloatingPointException,
            17 => AlignmentCheck,
            18 => MachineCheck,
            19 => SIMDFloatingPointException,
            20 => VirtualizationException,
            30 => SecurityException,
            0x7F => NoException,
            _ => return Err(anyhow!("Unknown exception code: {:#x}", value)),
        };

        Ok(exception)
    }
}

/// Supported actions when issuing an OUTB actions by Hyperlight.
/// - Log: for logging,
/// - CallFunction: makes a call to a host function,
/// - Abort: aborts the execution of the guest,
/// - DebugPrint: prints a message to the host
/// - TraceRecordStack: records the stack trace of the guest
/// - TraceMemoryAlloc: records memory allocation events
/// - TraceMemoryFree: records memory deallocation events
/// - TraceRecord: records a trace event in the guest
#[derive(Debug)]
pub enum OutBAction {
    Log = 99,
    CallFunction = 101,
    Abort = 102,
    DebugPrint = 103,
    #[cfg(feature = "unwind_guest")]
    TraceRecordStack = 104,
    #[cfg(feature = "mem_profile")]
    TraceMemoryAlloc = 105,
    #[cfg(feature = "mem_profile")]
    TraceMemoryFree = 106,
    #[cfg(feature = "trace_guest")]
    TraceRecord = 107,
}

impl TryFrom<u16> for OutBAction {
    type Error = anyhow::Error;
    fn try_from(val: u16) -> anyhow::Result<Self> {
        match val {
            99 => Ok(OutBAction::Log),
            101 => Ok(OutBAction::CallFunction),
            102 => Ok(OutBAction::Abort),
            103 => Ok(OutBAction::DebugPrint),
            #[cfg(feature = "unwind_guest")]
            104 => Ok(OutBAction::TraceRecordStack),
            #[cfg(feature = "mem_profile")]
            105 => Ok(OutBAction::TraceMemoryAlloc),
            #[cfg(feature = "mem_profile")]
            106 => Ok(OutBAction::TraceMemoryFree),
            #[cfg(feature = "trace_guest")]
            107 => Ok(OutBAction::TraceRecord),
            _ => Err(anyhow::anyhow!("Invalid OutBAction value: {}", val)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    #[test]
    fn test_exception_try_from_valid_values() {
        // Test all valid exception codes
        assert!(matches!(Exception::try_from(0), Ok(Exception::DivideByZero)));
        assert!(matches!(Exception::try_from(1), Ok(Exception::Debug)));
        assert!(matches!(Exception::try_from(2), Ok(Exception::NonMaskableInterrupt)));
        assert!(matches!(Exception::try_from(3), Ok(Exception::Breakpoint)));
        assert!(matches!(Exception::try_from(4), Ok(Exception::Overflow)));
        assert!(matches!(Exception::try_from(5), Ok(Exception::BoundRangeExceeded)));
        assert!(matches!(Exception::try_from(6), Ok(Exception::InvalidOpcode)));
        assert!(matches!(Exception::try_from(7), Ok(Exception::DeviceNotAvailable)));
        assert!(matches!(Exception::try_from(8), Ok(Exception::DoubleFault)));
        assert!(matches!(Exception::try_from(9), Ok(Exception::CoprocessorSegmentOverrun)));
        assert!(matches!(Exception::try_from(10), Ok(Exception::InvalidTSS)));
        assert!(matches!(Exception::try_from(11), Ok(Exception::SegmentNotPresent)));
        assert!(matches!(Exception::try_from(12), Ok(Exception::StackSegmentFault)));
        assert!(matches!(Exception::try_from(13), Ok(Exception::GeneralProtectionFault)));
        assert!(matches!(Exception::try_from(14), Ok(Exception::PageFault)));
        assert!(matches!(Exception::try_from(15), Ok(Exception::Reserved)));
        assert!(matches!(Exception::try_from(16), Ok(Exception::X87FloatingPointException)));
        assert!(matches!(Exception::try_from(17), Ok(Exception::AlignmentCheck)));
        assert!(matches!(Exception::try_from(18), Ok(Exception::MachineCheck)));
        assert!(matches!(Exception::try_from(19), Ok(Exception::SIMDFloatingPointException)));
        assert!(matches!(Exception::try_from(20), Ok(Exception::VirtualizationException)));
        assert!(matches!(Exception::try_from(30), Ok(Exception::SecurityException)));
        assert!(matches!(Exception::try_from(0x7F), Ok(Exception::NoException)));
    }

    #[test]
    fn test_exception_try_from_invalid_values() {
        // Test various invalid values
        assert!(Exception::try_from(21).is_err());
        assert!(Exception::try_from(29).is_err());
        assert!(Exception::try_from(31).is_err());
        assert!(Exception::try_from(50).is_err());
        assert!(Exception::try_from(100).is_err());
        assert!(Exception::try_from(0xFE).is_err());
        assert!(Exception::try_from(0x80).is_err());
        
        // Check that error messages contain the invalid value
        let result = Exception::try_from(99);
        assert!(result.is_err());
        let error_msg = format!("{}", result.unwrap_err());
        assert!(error_msg.contains("99") || error_msg.contains("0x63"));
    }

    #[test]
    fn test_exception_debug_clone_copy() {
        let exception = Exception::DivideByZero;
        
        // Test Debug trait
        let debug_str = format!("{:?}", exception);
        assert_eq!(debug_str, "DivideByZero");
        
        // Test Clone trait
        let cloned = exception.clone();
        assert!(matches!(cloned, Exception::DivideByZero));
        
        // Test Copy trait (implicit through assignment)
        let copied = exception;
        assert!(matches!(copied, Exception::DivideByZero));
        assert!(matches!(exception, Exception::DivideByZero)); // Original still accessible
    }

    #[test]
    fn test_exception_repr_values() {
        // Verify that the enum values match expected u8 representations
        assert_eq!(Exception::DivideByZero as u8, 0);
        assert_eq!(Exception::Debug as u8, 1);
        assert_eq!(Exception::GeneralProtectionFault as u8, 13);
        assert_eq!(Exception::PageFault as u8, 14);
        assert_eq!(Exception::SecurityException as u8, 30);
        assert_eq!(Exception::NoException as u8, 0xFF);
    }

    #[test]
    fn test_outb_action_try_from_valid_values() {
        // Test all valid OutBAction codes
        assert!(matches!(OutBAction::try_from(99), Ok(OutBAction::Log)));
        assert!(matches!(OutBAction::try_from(101), Ok(OutBAction::CallFunction)));
        assert!(matches!(OutBAction::try_from(102), Ok(OutBAction::Abort)));
        assert!(matches!(OutBAction::try_from(103), Ok(OutBAction::DebugPrint)));
        
        // Test feature-gated actions if enabled
        #[cfg(feature = "unwind_guest")]
        assert!(matches!(OutBAction::try_from(104), Ok(OutBAction::TraceRecordStack)));
        
        #[cfg(feature = "mem_profile")]
        {
            assert!(matches!(OutBAction::try_from(105), Ok(OutBAction::TraceMemoryAlloc)));
            assert!(matches!(OutBAction::try_from(106), Ok(OutBAction::TraceMemoryFree)));
        }
        
        #[cfg(feature = "trace_guest")]
        assert!(matches!(OutBAction::try_from(107), Ok(OutBAction::TraceRecord)));
    }

    #[test]
    fn test_outb_action_try_from_invalid_values() {
        // Test various invalid values
        assert!(OutBAction::try_from(0).is_err());
        assert!(OutBAction::try_from(50).is_err());
        assert!(OutBAction::try_from(98).is_err());
        assert!(OutBAction::try_from(100).is_err());
        assert!(OutBAction::try_from(200).is_err());
        assert!(OutBAction::try_from(1000).is_err());
        assert!(OutBAction::try_from(u16::MAX).is_err());
        
        // Check that error messages contain the invalid value
        let result = OutBAction::try_from(42);
        assert!(result.is_err());
        let error_msg = format!("{}", result.unwrap_err());
        assert!(error_msg.contains("42"));
    }

    #[test]
    fn test_outb_action_feature_gated_values() {
        // Test that feature-gated values return appropriate results
        #[cfg(not(feature = "unwind_guest"))]
        assert!(OutBAction::try_from(104).is_err());
        
        #[cfg(not(feature = "mem_profile"))]
        {
            assert!(OutBAction::try_from(105).is_err());
            assert!(OutBAction::try_from(106).is_err());
        }
        
        #[cfg(not(feature = "trace_guest"))]
        assert!(OutBAction::try_from(107).is_err());
    }

    #[test]
    fn test_outb_action_repr_values() {
        // Verify that the enum values match expected u16 representations
        assert_eq!(OutBAction::Log as u16, 99);
        assert_eq!(OutBAction::CallFunction as u16, 101);
        assert_eq!(OutBAction::Abort as u16, 102);
        assert_eq!(OutBAction::DebugPrint as u16, 103);
        
        #[cfg(feature = "unwind_guest")]
        assert_eq!(OutBAction::TraceRecordStack as u16, 104);
        
        #[cfg(feature = "mem_profile")]
        {
            assert_eq!(OutBAction::TraceMemoryAlloc as u16, 105);
            assert_eq!(OutBAction::TraceMemoryFree as u16, 106);
        }
        
        #[cfg(feature = "trace_guest")]
        assert_eq!(OutBAction::TraceRecord as u16, 107);
    }

    #[test]
    fn test_exception_boundary_cases() {
        // Test boundary cases and edge values
        assert!(Exception::try_from(0xFF).is_err()); // Should be 0x7F for NoException
        assert!(matches!(Exception::try_from(0x7F), Ok(Exception::NoException)));
        
        // Test gaps in the enum
        assert!(Exception::try_from(22).is_err()); // Gap between VirtualizationException and SecurityException
        assert!(Exception::try_from(28).is_err()); // Gap before SecurityException
        assert!(Exception::try_from(31).is_err()); // After SecurityException
    }

    #[test]
    fn test_outb_action_boundary_cases() {
        // Test boundary cases around valid ranges
        assert!(OutBAction::try_from(98).is_err());  // Just before Log
        assert!(OutBAction::try_from(108).is_err()); // Just after the last possible action
        
        // Test values between valid actions
        assert!(OutBAction::try_from(100).is_err()); // Between Log (99) and CallFunction (101)
    }

    #[test]
    fn test_error_types() {
        // Verify error types are correct anyhow::Error instances
        let exception_error = Exception::try_from(255).unwrap_err();
        let exception_error_str = format!("{}", exception_error);
        assert!(exception_error_str.contains("Unknown exception code"));
        
        let outb_error = OutBAction::try_from(255).unwrap_err();
        let outb_error_str = format!("{}", outb_error);
        assert!(outb_error_str.contains("Invalid OutBAction value"));
    }
}
