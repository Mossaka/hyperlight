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

extern crate flatbuffers;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use anyhow::{Error, Result};
use flatbuffers::size_prefixed_root;
#[cfg(feature = "tracing")]
use tracing::{Span, instrument};

use crate::flatbuffers::hyperlight::generated::{
    ErrorCode as FbErrorCode, GuestError as FbGuestError, GuestErrorArgs,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[repr(C)]
/// `ErrorCode` represents an error that occurred in the Hyperlight Guest.
pub enum ErrorCode {
    NoError = 0,
    UnsupportedParameterType = 2,
    GuestFunctionNameNotProvided = 3,
    GuestFunctionNotFound = 4,
    GuestFunctionIncorrecNoOfParameters = 5,
    GispatchFunctionPointerNotSet = 6,
    OutbError = 7,
    UnknownError = 8,
    StackOverflow = 9,
    GsCheckFailed = 10,
    TooManyGuestFunctions = 11,
    FailureInDlmalloc = 12,
    MallocFailed = 13,
    GuestFunctionParameterTypeMismatch = 14,
    GuestError = 15,
    ArrayLengthParamIsMissing = 16,
}

impl From<ErrorCode> for FbErrorCode {
    fn from(error_code: ErrorCode) -> Self {
        match error_code {
            ErrorCode::NoError => Self::NoError,
            ErrorCode::UnsupportedParameterType => Self::UnsupportedParameterType,
            ErrorCode::GuestFunctionNameNotProvided => Self::GuestFunctionNameNotProvided,
            ErrorCode::GuestFunctionNotFound => Self::GuestFunctionNotFound,
            ErrorCode::GuestFunctionIncorrecNoOfParameters => {
                Self::GuestFunctionIncorrecNoOfParameters
            }
            ErrorCode::GispatchFunctionPointerNotSet => Self::GispatchFunctionPointerNotSet,
            ErrorCode::OutbError => Self::OutbError,
            ErrorCode::UnknownError => Self::UnknownError,
            ErrorCode::StackOverflow => Self::StackOverflow,
            ErrorCode::GsCheckFailed => Self::GsCheckFailed,
            ErrorCode::TooManyGuestFunctions => Self::TooManyGuestFunctions,
            ErrorCode::FailureInDlmalloc => Self::FailureInDlmalloc,
            ErrorCode::MallocFailed => Self::MallocFailed,
            ErrorCode::GuestFunctionParameterTypeMismatch => {
                Self::GuestFunctionParameterTypeMismatch
            }
            ErrorCode::GuestError => Self::GuestError,
            ErrorCode::ArrayLengthParamIsMissing => Self::ArrayLengthParamIsMissing,
        }
    }
}

impl From<FbErrorCode> for ErrorCode {
    fn from(error_code: FbErrorCode) -> Self {
        match error_code {
            FbErrorCode::NoError => Self::NoError,
            FbErrorCode::UnsupportedParameterType => Self::UnsupportedParameterType,
            FbErrorCode::GuestFunctionNameNotProvided => Self::GuestFunctionNameNotProvided,
            FbErrorCode::GuestFunctionNotFound => Self::GuestFunctionNotFound,
            FbErrorCode::GuestFunctionIncorrecNoOfParameters => {
                Self::GuestFunctionIncorrecNoOfParameters
            }
            FbErrorCode::GispatchFunctionPointerNotSet => Self::GispatchFunctionPointerNotSet,
            FbErrorCode::OutbError => Self::OutbError,
            FbErrorCode::StackOverflow => Self::StackOverflow,
            FbErrorCode::GsCheckFailed => Self::GsCheckFailed,
            FbErrorCode::TooManyGuestFunctions => Self::TooManyGuestFunctions,
            FbErrorCode::FailureInDlmalloc => Self::FailureInDlmalloc,
            FbErrorCode::MallocFailed => Self::MallocFailed,
            FbErrorCode::GuestFunctionParameterTypeMismatch => {
                Self::GuestFunctionParameterTypeMismatch
            }
            FbErrorCode::GuestError => Self::GuestError,
            FbErrorCode::ArrayLengthParamIsMissing => Self::ArrayLengthParamIsMissing,
            _ => Self::UnknownError,
        }
    }
}

impl From<u64> for ErrorCode {
    fn from(error_code: u64) -> Self {
        match error_code {
            0 => Self::NoError,
            2 => Self::UnsupportedParameterType,
            3 => Self::GuestFunctionNameNotProvided,
            4 => Self::GuestFunctionNotFound,
            5 => Self::GuestFunctionIncorrecNoOfParameters,
            6 => Self::GispatchFunctionPointerNotSet,
            7 => Self::OutbError,
            8 => Self::UnknownError,
            9 => Self::StackOverflow,
            10 => Self::GsCheckFailed,
            11 => Self::TooManyGuestFunctions,
            12 => Self::FailureInDlmalloc,
            13 => Self::MallocFailed,
            14 => Self::GuestFunctionParameterTypeMismatch,
            15 => Self::GuestError,
            16 => Self::ArrayLengthParamIsMissing,
            _ => Self::UnknownError,
        }
    }
}

impl From<ErrorCode> for u64 {
    fn from(error_code: ErrorCode) -> Self {
        match error_code {
            ErrorCode::NoError => 0,
            ErrorCode::UnsupportedParameterType => 2,
            ErrorCode::GuestFunctionNameNotProvided => 3,
            ErrorCode::GuestFunctionNotFound => 4,
            ErrorCode::GuestFunctionIncorrecNoOfParameters => 5,
            ErrorCode::GispatchFunctionPointerNotSet => 6,
            ErrorCode::OutbError => 7,
            ErrorCode::UnknownError => 8,
            ErrorCode::StackOverflow => 9,
            ErrorCode::GsCheckFailed => 10,
            ErrorCode::TooManyGuestFunctions => 11,
            ErrorCode::FailureInDlmalloc => 12,
            ErrorCode::MallocFailed => 13,
            ErrorCode::GuestFunctionParameterTypeMismatch => 14,
            ErrorCode::GuestError => 15,
            ErrorCode::ArrayLengthParamIsMissing => 16,
        }
    }
}

impl From<ErrorCode> for String {
    fn from(error_code: ErrorCode) -> Self {
        match error_code {
            ErrorCode::NoError => "NoError".to_string(),
            ErrorCode::UnsupportedParameterType => "UnsupportedParameterType".to_string(),
            ErrorCode::GuestFunctionNameNotProvided => "GuestFunctionNameNotProvided".to_string(),
            ErrorCode::GuestFunctionNotFound => "GuestFunctionNotFound".to_string(),
            ErrorCode::GuestFunctionIncorrecNoOfParameters => {
                "GuestFunctionIncorrecNoOfParameters".to_string()
            }
            ErrorCode::GispatchFunctionPointerNotSet => "GispatchFunctionPointerNotSet".to_string(),
            ErrorCode::OutbError => "OutbError".to_string(),
            ErrorCode::UnknownError => "UnknownError".to_string(),
            ErrorCode::StackOverflow => "StackOverflow".to_string(),
            ErrorCode::GsCheckFailed => "GsCheckFailed".to_string(),
            ErrorCode::TooManyGuestFunctions => "TooManyGuestFunctions".to_string(),
            ErrorCode::FailureInDlmalloc => "FailureInDlmalloc".to_string(),
            ErrorCode::MallocFailed => "MallocFailed".to_string(),
            ErrorCode::GuestFunctionParameterTypeMismatch => {
                "GuestFunctionParameterTypeMismatch".to_string()
            }
            ErrorCode::GuestError => "GuestError".to_string(),
            ErrorCode::ArrayLengthParamIsMissing => "ArrayLengthParamIsMissing".to_string(),
        }
    }
}

/// `GuestError` represents an error that occurred in the Hyperlight Guest.
#[derive(Debug, Clone)]
pub struct GuestError {
    /// The error code.
    pub code: ErrorCode,
    /// The error message.
    pub message: String,
}

impl GuestError {
    #[cfg_attr(feature = "tracing", instrument(skip_all, parent = Span::current(), level= "Trace"))]
    pub fn new(code: ErrorCode, message: String) -> Self {
        Self { code, message }
    }
}

impl TryFrom<&[u8]> for GuestError {
    type Error = Error;
    fn try_from(value: &[u8]) -> Result<Self> {
        let guest_error_fb = size_prefixed_root::<FbGuestError>(value)
            .map_err(|e| anyhow::anyhow!("Error while reading GuestError: {:?}", e))?;
        let code = guest_error_fb.code();
        let message = match guest_error_fb.message() {
            Some(message) => message.to_string(),
            None => String::new(),
        };
        Ok(Self {
            code: code.into(),
            message,
        })
    }
}

impl TryFrom<&GuestError> for Vec<u8> {
    type Error = Error;
    #[cfg_attr(feature = "tracing", instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace"))]
    fn try_from(value: &GuestError) -> Result<Vec<u8>> {
        let mut builder = flatbuffers::FlatBufferBuilder::new();
        let message = builder.create_string(&value.message);

        let guest_error_fb = FbGuestError::create(
            &mut builder,
            &GuestErrorArgs {
                code: value.code.into(),
                message: Some(message),
            },
        );
        builder.finish_size_prefixed(guest_error_fb, None);
        let res = builder.finished_data().to_vec();

        Ok(res)
    }
}

impl Default for GuestError {
    #[cfg_attr(feature = "tracing", instrument(parent = Span::current(), level= "Trace"))]
    fn default() -> Self {
        Self {
            code: ErrorCode::NoError,
            message: String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::String;
    use alloc::{format, vec};

    use super::*;
    use crate::flatbuffers::hyperlight::generated::ErrorCode as FbErrorCode;

    #[test]
    fn test_error_code_enum_basic() {
        // Test equality and copy
        assert_eq!(ErrorCode::NoError, ErrorCode::NoError);
        assert_ne!(ErrorCode::NoError, ErrorCode::UnknownError);

        // Test debug
        let debug_str = format!("{:?}", ErrorCode::GuestError);
        assert_eq!(debug_str, "GuestError");

        // Test clone
        let original = ErrorCode::StackOverflow;
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn test_error_code_from_u64() {
        assert_eq!(ErrorCode::from(0u64), ErrorCode::NoError);
        assert_eq!(ErrorCode::from(2u64), ErrorCode::UnsupportedParameterType);
        assert_eq!(
            ErrorCode::from(3u64),
            ErrorCode::GuestFunctionNameNotProvided
        );
        assert_eq!(ErrorCode::from(4u64), ErrorCode::GuestFunctionNotFound);
        assert_eq!(
            ErrorCode::from(5u64),
            ErrorCode::GuestFunctionIncorrecNoOfParameters
        );
        assert_eq!(
            ErrorCode::from(6u64),
            ErrorCode::GispatchFunctionPointerNotSet
        );
        assert_eq!(ErrorCode::from(7u64), ErrorCode::OutbError);
        assert_eq!(ErrorCode::from(8u64), ErrorCode::UnknownError);
        assert_eq!(ErrorCode::from(9u64), ErrorCode::StackOverflow);
        assert_eq!(ErrorCode::from(10u64), ErrorCode::GsCheckFailed);
        assert_eq!(ErrorCode::from(11u64), ErrorCode::TooManyGuestFunctions);
        assert_eq!(ErrorCode::from(12u64), ErrorCode::FailureInDlmalloc);
        assert_eq!(ErrorCode::from(13u64), ErrorCode::MallocFailed);
        assert_eq!(
            ErrorCode::from(14u64),
            ErrorCode::GuestFunctionParameterTypeMismatch
        );
        assert_eq!(ErrorCode::from(15u64), ErrorCode::GuestError);
        assert_eq!(ErrorCode::from(16u64), ErrorCode::ArrayLengthParamIsMissing);
    }

    #[test]
    fn test_error_code_from_u64_unknown() {
        // Test unknown error codes
        assert_eq!(ErrorCode::from(1u64), ErrorCode::UnknownError);
        assert_eq!(ErrorCode::from(100u64), ErrorCode::UnknownError);
        assert_eq!(ErrorCode::from(9999u64), ErrorCode::UnknownError);
    }

    #[test]
    fn test_error_code_to_u64() {
        assert_eq!(u64::from(ErrorCode::NoError), 0);
        assert_eq!(u64::from(ErrorCode::UnsupportedParameterType), 2);
        assert_eq!(u64::from(ErrorCode::GuestFunctionNameNotProvided), 3);
        assert_eq!(u64::from(ErrorCode::GuestFunctionNotFound), 4);
        assert_eq!(u64::from(ErrorCode::GuestFunctionIncorrecNoOfParameters), 5);
        assert_eq!(u64::from(ErrorCode::GispatchFunctionPointerNotSet), 6);
        assert_eq!(u64::from(ErrorCode::OutbError), 7);
        assert_eq!(u64::from(ErrorCode::UnknownError), 8);
        assert_eq!(u64::from(ErrorCode::StackOverflow), 9);
        assert_eq!(u64::from(ErrorCode::GsCheckFailed), 10);
        assert_eq!(u64::from(ErrorCode::TooManyGuestFunctions), 11);
        assert_eq!(u64::from(ErrorCode::FailureInDlmalloc), 12);
        assert_eq!(u64::from(ErrorCode::MallocFailed), 13);
        assert_eq!(u64::from(ErrorCode::GuestFunctionParameterTypeMismatch), 14);
        assert_eq!(u64::from(ErrorCode::GuestError), 15);
        assert_eq!(u64::from(ErrorCode::ArrayLengthParamIsMissing), 16);
    }

    #[test]
    fn test_error_code_to_string() {
        assert_eq!(String::from(ErrorCode::NoError), "NoError");
        assert_eq!(
            String::from(ErrorCode::UnsupportedParameterType),
            "UnsupportedParameterType"
        );
        assert_eq!(
            String::from(ErrorCode::GuestFunctionNameNotProvided),
            "GuestFunctionNameNotProvided"
        );
        assert_eq!(
            String::from(ErrorCode::GuestFunctionNotFound),
            "GuestFunctionNotFound"
        );
        assert_eq!(
            String::from(ErrorCode::GuestFunctionIncorrecNoOfParameters),
            "GuestFunctionIncorrecNoOfParameters"
        );
        assert_eq!(
            String::from(ErrorCode::GispatchFunctionPointerNotSet),
            "GispatchFunctionPointerNotSet"
        );
        assert_eq!(String::from(ErrorCode::OutbError), "OutbError");
        assert_eq!(String::from(ErrorCode::UnknownError), "UnknownError");
        assert_eq!(String::from(ErrorCode::StackOverflow), "StackOverflow");
        assert_eq!(String::from(ErrorCode::GsCheckFailed), "GsCheckFailed");
        assert_eq!(
            String::from(ErrorCode::TooManyGuestFunctions),
            "TooManyGuestFunctions"
        );
        assert_eq!(
            String::from(ErrorCode::FailureInDlmalloc),
            "FailureInDlmalloc"
        );
        assert_eq!(String::from(ErrorCode::MallocFailed), "MallocFailed");
        assert_eq!(
            String::from(ErrorCode::GuestFunctionParameterTypeMismatch),
            "GuestFunctionParameterTypeMismatch"
        );
        assert_eq!(String::from(ErrorCode::GuestError), "GuestError");
        assert_eq!(
            String::from(ErrorCode::ArrayLengthParamIsMissing),
            "ArrayLengthParamIsMissing"
        );
    }

    #[test]
    fn test_error_code_from_fb_error_code() {
        assert_eq!(ErrorCode::from(FbErrorCode::NoError), ErrorCode::NoError);
        assert_eq!(
            ErrorCode::from(FbErrorCode::UnsupportedParameterType),
            ErrorCode::UnsupportedParameterType
        );
        assert_eq!(
            ErrorCode::from(FbErrorCode::GuestFunctionNameNotProvided),
            ErrorCode::GuestFunctionNameNotProvided
        );
        assert_eq!(
            ErrorCode::from(FbErrorCode::GuestFunctionNotFound),
            ErrorCode::GuestFunctionNotFound
        );
        assert_eq!(
            ErrorCode::from(FbErrorCode::GuestFunctionIncorrecNoOfParameters),
            ErrorCode::GuestFunctionIncorrecNoOfParameters
        );
        assert_eq!(
            ErrorCode::from(FbErrorCode::GispatchFunctionPointerNotSet),
            ErrorCode::GispatchFunctionPointerNotSet
        );
        assert_eq!(
            ErrorCode::from(FbErrorCode::OutbError),
            ErrorCode::OutbError
        );
        assert_eq!(
            ErrorCode::from(FbErrorCode::StackOverflow),
            ErrorCode::StackOverflow
        );
        assert_eq!(
            ErrorCode::from(FbErrorCode::GsCheckFailed),
            ErrorCode::GsCheckFailed
        );
        assert_eq!(
            ErrorCode::from(FbErrorCode::TooManyGuestFunctions),
            ErrorCode::TooManyGuestFunctions
        );
        assert_eq!(
            ErrorCode::from(FbErrorCode::FailureInDlmalloc),
            ErrorCode::FailureInDlmalloc
        );
        assert_eq!(
            ErrorCode::from(FbErrorCode::MallocFailed),
            ErrorCode::MallocFailed
        );
        assert_eq!(
            ErrorCode::from(FbErrorCode::GuestFunctionParameterTypeMismatch),
            ErrorCode::GuestFunctionParameterTypeMismatch
        );
        assert_eq!(
            ErrorCode::from(FbErrorCode::GuestError),
            ErrorCode::GuestError
        );
        assert_eq!(
            ErrorCode::from(FbErrorCode::ArrayLengthParamIsMissing),
            ErrorCode::ArrayLengthParamIsMissing
        );
    }

    #[test]
    fn test_error_code_to_fb_error_code() {
        assert_eq!(FbErrorCode::from(ErrorCode::NoError), FbErrorCode::NoError);
        assert_eq!(
            FbErrorCode::from(ErrorCode::UnsupportedParameterType),
            FbErrorCode::UnsupportedParameterType
        );
        assert_eq!(
            FbErrorCode::from(ErrorCode::GuestFunctionNameNotProvided),
            FbErrorCode::GuestFunctionNameNotProvided
        );
        assert_eq!(
            FbErrorCode::from(ErrorCode::GuestFunctionNotFound),
            FbErrorCode::GuestFunctionNotFound
        );
        assert_eq!(
            FbErrorCode::from(ErrorCode::GuestFunctionIncorrecNoOfParameters),
            FbErrorCode::GuestFunctionIncorrecNoOfParameters
        );
        assert_eq!(
            FbErrorCode::from(ErrorCode::GispatchFunctionPointerNotSet),
            FbErrorCode::GispatchFunctionPointerNotSet
        );
        assert_eq!(
            FbErrorCode::from(ErrorCode::OutbError),
            FbErrorCode::OutbError
        );
        assert_eq!(
            FbErrorCode::from(ErrorCode::UnknownError),
            FbErrorCode::UnknownError
        );
        assert_eq!(
            FbErrorCode::from(ErrorCode::StackOverflow),
            FbErrorCode::StackOverflow
        );
        assert_eq!(
            FbErrorCode::from(ErrorCode::GsCheckFailed),
            FbErrorCode::GsCheckFailed
        );
        assert_eq!(
            FbErrorCode::from(ErrorCode::TooManyGuestFunctions),
            FbErrorCode::TooManyGuestFunctions
        );
        assert_eq!(
            FbErrorCode::from(ErrorCode::FailureInDlmalloc),
            FbErrorCode::FailureInDlmalloc
        );
        assert_eq!(
            FbErrorCode::from(ErrorCode::MallocFailed),
            FbErrorCode::MallocFailed
        );
        assert_eq!(
            FbErrorCode::from(ErrorCode::GuestFunctionParameterTypeMismatch),
            FbErrorCode::GuestFunctionParameterTypeMismatch
        );
        assert_eq!(
            FbErrorCode::from(ErrorCode::GuestError),
            FbErrorCode::GuestError
        );
        assert_eq!(
            FbErrorCode::from(ErrorCode::ArrayLengthParamIsMissing),
            FbErrorCode::ArrayLengthParamIsMissing
        );
    }

    #[test]
    fn test_guest_error_new() {
        let guest_error = GuestError::new(
            ErrorCode::GuestFunctionNotFound,
            "Function 'hello_world' not found".to_string(),
        );

        assert_eq!(guest_error.code, ErrorCode::GuestFunctionNotFound);
        assert_eq!(guest_error.message, "Function 'hello_world' not found");
    }

    #[test]
    fn test_guest_error_default() {
        let guest_error = GuestError::default();

        assert_eq!(guest_error.code, ErrorCode::NoError);
        assert_eq!(guest_error.message, "");
    }

    #[test]
    fn test_guest_error_debug_and_clone() {
        let original = GuestError::new(
            ErrorCode::StackOverflow,
            "Stack overflow detected".to_string(),
        );

        let cloned = original.clone();
        assert_eq!(cloned.code, original.code);
        assert_eq!(cloned.message, original.message);

        let debug_str = format!("{:?}", original);
        assert!(debug_str.contains("StackOverflow"));
        assert!(debug_str.contains("Stack overflow detected"));
    }

    #[test]
    fn test_guest_error_serialization_roundtrip() {
        let original = GuestError::new(
            ErrorCode::MallocFailed,
            "Memory allocation failed for size 1024".to_string(),
        );

        // Serialize to bytes
        let serialized: Vec<u8> = (&original).try_into().unwrap();

        // Deserialize from bytes
        let deserialized = GuestError::try_from(serialized.as_slice()).unwrap();

        assert_eq!(deserialized.code, original.code);
        assert_eq!(deserialized.message, original.message);
    }

    #[test]
    fn test_guest_error_serialization_empty_message() {
        let original = GuestError::new(ErrorCode::NoError, String::new());

        let serialized: Vec<u8> = (&original).try_into().unwrap();
        let deserialized = GuestError::try_from(serialized.as_slice()).unwrap();

        assert_eq!(deserialized.code, ErrorCode::NoError);
        assert_eq!(deserialized.message, "");
    }

    #[test]
    fn test_guest_error_serialization_special_characters() {
        let original = GuestError::new(
            ErrorCode::GuestError,
            "Error with special chars: !@#$%^&*()_+{}[]\\|;:'\",.<>?/~` and unicode: 🦀❤️"
                .to_string(),
        );

        let serialized: Vec<u8> = (&original).try_into().unwrap();
        let deserialized = GuestError::try_from(serialized.as_slice()).unwrap();

        assert_eq!(deserialized.code, ErrorCode::GuestError);
        assert_eq!(
            deserialized.message,
            "Error with special chars: !@#$%^&*()_+{}[]\\|;:'\",.<>?/~` and unicode: 🦀❤️"
        );
    }

    #[test]
    fn test_guest_error_serialization_all_error_codes() {
        let all_error_codes = vec![
            ErrorCode::NoError,
            ErrorCode::UnsupportedParameterType,
            ErrorCode::GuestFunctionNameNotProvided,
            ErrorCode::GuestFunctionNotFound,
            ErrorCode::GuestFunctionIncorrecNoOfParameters,
            ErrorCode::GispatchFunctionPointerNotSet,
            ErrorCode::OutbError,
            ErrorCode::UnknownError,
            ErrorCode::StackOverflow,
            ErrorCode::GsCheckFailed,
            ErrorCode::TooManyGuestFunctions,
            ErrorCode::FailureInDlmalloc,
            ErrorCode::MallocFailed,
            ErrorCode::GuestFunctionParameterTypeMismatch,
            ErrorCode::GuestError,
            ErrorCode::ArrayLengthParamIsMissing,
        ];

        for (i, error_code) in all_error_codes.iter().enumerate() {
            let original =
                GuestError::new(*error_code, format!("Test message for error code {}", i));

            let serialized: Vec<u8> = (&original).try_into().unwrap();
            let deserialized = GuestError::try_from(serialized.as_slice()).unwrap();

            assert_eq!(deserialized.code, *error_code);
            assert_eq!(
                deserialized.message,
                format!("Test message for error code {}", i)
            );
        }
    }

    #[test]
    fn test_guest_error_deserialization_corrupted_data() {
        let corrupted_data = vec![0xFF, 0x00, 0x42, 0x13, 0x37];
        let result = GuestError::try_from(corrupted_data.as_slice());

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Error while reading GuestError"));
    }

    #[test]
    fn test_guest_error_long_message() {
        let long_message = "x".repeat(10000); // 10k character message
        let original = GuestError::new(ErrorCode::GuestError, long_message.clone());

        let serialized: Vec<u8> = (&original).try_into().unwrap();
        let deserialized = GuestError::try_from(serialized.as_slice()).unwrap();

        assert_eq!(deserialized.code, ErrorCode::GuestError);
        assert_eq!(deserialized.message, long_message);
        assert_eq!(deserialized.message.len(), 10000);
    }

    #[test]
    fn test_error_code_bidirectional_conversion_u64() {
        let all_error_codes = vec![
            ErrorCode::NoError,
            ErrorCode::UnsupportedParameterType,
            ErrorCode::GuestFunctionNameNotProvided,
            ErrorCode::GuestFunctionNotFound,
            ErrorCode::GuestFunctionIncorrecNoOfParameters,
            ErrorCode::GispatchFunctionPointerNotSet,
            ErrorCode::OutbError,
            ErrorCode::UnknownError,
            ErrorCode::StackOverflow,
            ErrorCode::GsCheckFailed,
            ErrorCode::TooManyGuestFunctions,
            ErrorCode::FailureInDlmalloc,
            ErrorCode::MallocFailed,
            ErrorCode::GuestFunctionParameterTypeMismatch,
            ErrorCode::GuestError,
            ErrorCode::ArrayLengthParamIsMissing,
        ];

        for error_code in all_error_codes {
            let as_u64 = u64::from(error_code);
            let back_to_enum = ErrorCode::from(as_u64);
            assert_eq!(error_code, back_to_enum);
        }
    }

    #[test]
    fn test_error_code_bidirectional_conversion_fb() {
        let all_error_codes = vec![
            ErrorCode::NoError,
            ErrorCode::UnsupportedParameterType,
            ErrorCode::GuestFunctionNameNotProvided,
            ErrorCode::GuestFunctionNotFound,
            ErrorCode::GuestFunctionIncorrecNoOfParameters,
            ErrorCode::GispatchFunctionPointerNotSet,
            ErrorCode::OutbError,
            ErrorCode::UnknownError,
            ErrorCode::StackOverflow,
            ErrorCode::GsCheckFailed,
            ErrorCode::TooManyGuestFunctions,
            ErrorCode::FailureInDlmalloc,
            ErrorCode::MallocFailed,
            ErrorCode::GuestFunctionParameterTypeMismatch,
            ErrorCode::GuestError,
            ErrorCode::ArrayLengthParamIsMissing,
        ];

        for error_code in all_error_codes {
            let as_fb = FbErrorCode::from(error_code);
            let back_to_enum = ErrorCode::from(as_fb);
            assert_eq!(error_code, back_to_enum);
        }
    }
}
