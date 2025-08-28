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

use alloc::vec::Vec;

use flatbuffers::FlatBufferBuilder;

use crate::flatbuffer_wrappers::function_types::ParameterValue;
use crate::flatbuffers::hyperlight::generated::{
    FunctionCallResult as FbFunctionCallResult, FunctionCallResultArgs as FbFunctionCallResultArgs,
    ReturnValue as FbReturnValue, hlbool as Fbhlbool, hlboolArgs as FbhlboolArgs,
    hldouble as Fbhldouble, hldoubleArgs as FbhldoubleArgs, hlfloat as Fbhlfloat,
    hlfloatArgs as FbhlfloatArgs, hlint as Fbhlint, hlintArgs as FbhlintArgs, hllong as Fbhllong,
    hllongArgs as FbhllongArgs, hlsizeprefixedbuffer as Fbhlsizeprefixedbuffer,
    hlsizeprefixedbufferArgs as FbhlsizeprefixedbufferArgs, hlstring as Fbhlstring,
    hlstringArgs as FbhlstringArgs, hluint as Fbhluint, hluintArgs as FbhluintArgs,
    hlulong as Fbhlulong, hlulongArgs as FbhlulongArgs, hlvoid as Fbhlvoid,
    hlvoidArgs as FbhlvoidArgs,
};

/// Flatbuffer-encodes the given value
pub fn get_flatbuffer_result<T: FlatbufferSerializable>(val: T) -> Vec<u8> {
    let mut builder = FlatBufferBuilder::new();
    let res = &T::serialize(&val, &mut builder);
    let result_offset = FbFunctionCallResult::create(&mut builder, res);

    builder.finish_size_prefixed(result_offset, None);

    builder.finished_data().to_vec()
}

pub trait FlatbufferSerializable {
    fn serialize(&self, builder: &mut FlatBufferBuilder) -> FbFunctionCallResultArgs;
}

// Implementations for basic types below

impl FlatbufferSerializable for () {
    fn serialize(&self, builder: &mut FlatBufferBuilder) -> FbFunctionCallResultArgs {
        FbFunctionCallResultArgs {
            return_value: Some(Fbhlvoid::create(builder, &FbhlvoidArgs {}).as_union_value()),
            return_value_type: FbReturnValue::hlvoid,
        }
    }
}

impl FlatbufferSerializable for &str {
    fn serialize(&self, builder: &mut FlatBufferBuilder) -> FbFunctionCallResultArgs {
        let string_offset = builder.create_string(self);
        FbFunctionCallResultArgs {
            return_value: Some(
                Fbhlstring::create(
                    builder,
                    &FbhlstringArgs {
                        value: Some(string_offset),
                    },
                )
                .as_union_value(),
            ),
            return_value_type: FbReturnValue::hlstring,
        }
    }
}

impl FlatbufferSerializable for &[u8] {
    fn serialize(&self, builder: &mut FlatBufferBuilder) -> FbFunctionCallResultArgs {
        let vec_offset = builder.create_vector(self);
        FbFunctionCallResultArgs {
            return_value: Some(
                Fbhlsizeprefixedbuffer::create(
                    builder,
                    &FbhlsizeprefixedbufferArgs {
                        size: self.len() as i32,
                        value: Some(vec_offset),
                    },
                )
                .as_union_value(),
            ),
            return_value_type: FbReturnValue::hlsizeprefixedbuffer,
        }
    }
}

impl FlatbufferSerializable for f32 {
    fn serialize(&self, builder: &mut FlatBufferBuilder) -> FbFunctionCallResultArgs {
        FbFunctionCallResultArgs {
            return_value: Some(
                Fbhlfloat::create(builder, &FbhlfloatArgs { value: *self }).as_union_value(),
            ),
            return_value_type: FbReturnValue::hlfloat,
        }
    }
}

impl FlatbufferSerializable for f64 {
    fn serialize(&self, builder: &mut FlatBufferBuilder) -> FbFunctionCallResultArgs {
        FbFunctionCallResultArgs {
            return_value: Some(
                Fbhldouble::create(builder, &FbhldoubleArgs { value: *self }).as_union_value(),
            ),
            return_value_type: FbReturnValue::hldouble,
        }
    }
}

impl FlatbufferSerializable for i32 {
    fn serialize(&self, builder: &mut FlatBufferBuilder) -> FbFunctionCallResultArgs {
        FbFunctionCallResultArgs {
            return_value: Some(
                Fbhlint::create(builder, &FbhlintArgs { value: *self }).as_union_value(),
            ),
            return_value_type: FbReturnValue::hlint,
        }
    }
}

impl FlatbufferSerializable for i64 {
    fn serialize(&self, builder: &mut FlatBufferBuilder) -> FbFunctionCallResultArgs {
        FbFunctionCallResultArgs {
            return_value: Some(
                Fbhllong::create(builder, &FbhllongArgs { value: *self }).as_union_value(),
            ),
            return_value_type: FbReturnValue::hllong,
        }
    }
}

impl FlatbufferSerializable for u32 {
    fn serialize(&self, builder: &mut FlatBufferBuilder) -> FbFunctionCallResultArgs {
        FbFunctionCallResultArgs {
            return_value: Some(
                Fbhluint::create(builder, &FbhluintArgs { value: *self }).as_union_value(),
            ),
            return_value_type: FbReturnValue::hluint,
        }
    }
}

impl FlatbufferSerializable for u64 {
    fn serialize(&self, builder: &mut FlatBufferBuilder) -> FbFunctionCallResultArgs {
        FbFunctionCallResultArgs {
            return_value: Some(
                Fbhlulong::create(builder, &FbhlulongArgs { value: *self }).as_union_value(),
            ),
            return_value_type: FbReturnValue::hlulong,
        }
    }
}

impl FlatbufferSerializable for bool {
    fn serialize(&self, builder: &mut FlatBufferBuilder) -> FbFunctionCallResultArgs {
        FbFunctionCallResultArgs {
            return_value: Some(
                Fbhlbool::create(builder, &FbhlboolArgs { value: *self }).as_union_value(),
            ),
            return_value_type: FbReturnValue::hlbool,
        }
    }
}

/// Estimates the required buffer capacity for encoding a FunctionCall with the given parameters.
/// This helps avoid reallocation during FlatBuffer encoding when passing large slices and strings.
///
/// The function aims to be lightweight and fast and run in O(1) as long as the number of parameters is limited
/// (which it is since hyperlight only currently supports up to 12).
///
/// Note: This estimates the capacity needed for the inner vec inside a FlatBufferBuilder. It does not
/// necessarily match the size of the final encoded buffer. The estimation always rounds up to the
/// nearest power of two to match FlatBufferBuilder's allocation strategy.
///
/// The estimations are numbers used are empirically derived based on the tests below and vaguely based
/// on https://flatbuffers.dev/internals/ and https://github.com/dvidelabs/flatcc/blob/f064cefb2034d1e7407407ce32a6085c322212a7/doc/binary-format.md#flatbuffers-binary-format
#[inline] // allow cross-crate inlining (for hyperlight-host calls)
pub fn estimate_flatbuffer_capacity(function_name: &str, args: &[ParameterValue]) -> usize {
    let mut estimated_capacity = 20;

    // Function name overhead
    estimated_capacity += function_name.len() + 12;

    // Parameters vector overhead
    estimated_capacity += 12 + args.len() * 6;

    // Per-parameter overhead
    for arg in args {
        estimated_capacity += 16; // Base parameter structure
        estimated_capacity += match arg {
            ParameterValue::String(s) => s.len() + 20,
            ParameterValue::VecBytes(v) => v.len() + 20,
            ParameterValue::Int(_) | ParameterValue::UInt(_) => 16,
            ParameterValue::Long(_) | ParameterValue::ULong(_) => 20,
            ParameterValue::Float(_) => 16,
            ParameterValue::Double(_) => 20,
            ParameterValue::Bool(_) => 12,
        };
    }

    // match how vec grows
    estimated_capacity.next_power_of_two()
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;
    use crate::flatbuffer_wrappers::function_call::{FunctionCall, FunctionCallType};
    use crate::flatbuffer_wrappers::function_types::{ParameterValue, ReturnType};

    // Tests for get_flatbuffer_result function and FlatbufferSerializable trait implementations

    #[test]
    fn test_get_flatbuffer_result_void() {
        let result = get_flatbuffer_result(());

        // Should produce valid flatbuffer data
        assert!(!result.is_empty());
        assert!(result.len() > 4); // Size prefix + flatbuffer content

        // Verify the flatbuffer format - first 4 bytes are size prefix
        let size = u32::from_le_bytes([result[0], result[1], result[2], result[3]]) as usize;
        assert_eq!(size, result.len() - 4);
    }

    #[test]
    fn test_get_flatbuffer_result_string() {
        let test_string = "Hello, World!";
        let result = get_flatbuffer_result(test_string);

        // Should produce valid flatbuffer data
        assert!(!result.is_empty());
        assert!(result.len() > test_string.len()); // Should be larger due to flatbuffer overhead

        // Verify size prefix
        let size = u32::from_le_bytes([result[0], result[1], result[2], result[3]]) as usize;
        assert_eq!(size, result.len() - 4);
    }

    #[test]
    fn test_get_flatbuffer_result_byte_slice() {
        let test_bytes: &[u8] = &[0x01, 0x02, 0x03, 0x04, 0x05];
        let result = get_flatbuffer_result(test_bytes);

        // Should produce valid flatbuffer data
        assert!(!result.is_empty());
        assert!(result.len() > test_bytes.len());

        // Verify size prefix
        let size = u32::from_le_bytes([result[0], result[1], result[2], result[3]]) as usize;
        assert_eq!(size, result.len() - 4);
    }

    #[test]
    fn test_get_flatbuffer_result_numeric_types() {
        // Test all numeric types
        let f32_result = get_flatbuffer_result(42.5f32);
        let f64_result = get_flatbuffer_result(123.456789f64);
        let i32_result = get_flatbuffer_result(-12345i32);
        let i64_result = get_flatbuffer_result(-987654321i64);
        let u32_result = get_flatbuffer_result(4294967295u32);
        let u64_result = get_flatbuffer_result(18446744073709551615u64);
        let bool_result = get_flatbuffer_result(true);

        // All should produce valid data
        for result in [
            &f32_result,
            &f64_result,
            &i32_result,
            &i64_result,
            &u32_result,
            &u64_result,
            &bool_result,
        ] {
            assert!(!result.is_empty());
            let size = u32::from_le_bytes([result[0], result[1], result[2], result[3]]) as usize;
            assert_eq!(size, result.len() - 4);
        }
    }

    #[test]
    fn test_flatbuffer_serializable_void() {
        let mut builder = FlatBufferBuilder::new();
        let args = ().serialize(&mut builder);

        assert_eq!(args.return_value_type, FbReturnValue::hlvoid);
        assert!(args.return_value.is_some());
    }

    #[test]
    fn test_flatbuffer_serializable_string() {
        let test_str = "Test string for serialization";
        let mut builder = FlatBufferBuilder::new();
        let args = test_str.serialize(&mut builder);

        assert_eq!(args.return_value_type, FbReturnValue::hlstring);
        assert!(args.return_value.is_some());
    }

    #[test]
    fn test_flatbuffer_serializable_byte_slice() {
        let test_bytes: &[u8] = &[0x10, 0x20, 0x30, 0x40, 0x50];
        let mut builder = FlatBufferBuilder::new();
        let args = test_bytes.serialize(&mut builder);

        assert_eq!(args.return_value_type, FbReturnValue::hlsizeprefixedbuffer);
        assert!(args.return_value.is_some());
    }

    #[test]
    fn test_flatbuffer_serializable_f32() {
        let test_val = 3.14159f32;
        let mut builder = FlatBufferBuilder::new();
        let args = test_val.serialize(&mut builder);

        assert_eq!(args.return_value_type, FbReturnValue::hlfloat);
        assert!(args.return_value.is_some());
    }

    #[test]
    fn test_flatbuffer_serializable_f64() {
        let test_val = 2.718281828459045f64;
        let mut builder = FlatBufferBuilder::new();
        let args = test_val.serialize(&mut builder);

        assert_eq!(args.return_value_type, FbReturnValue::hldouble);
        assert!(args.return_value.is_some());
    }

    #[test]
    fn test_flatbuffer_serializable_i32() {
        let test_val = -2147483648i32;
        let mut builder = FlatBufferBuilder::new();
        let args = test_val.serialize(&mut builder);

        assert_eq!(args.return_value_type, FbReturnValue::hlint);
        assert!(args.return_value.is_some());
    }

    #[test]
    fn test_flatbuffer_serializable_i64() {
        let test_val = -9223372036854775808i64;
        let mut builder = FlatBufferBuilder::new();
        let args = test_val.serialize(&mut builder);

        assert_eq!(args.return_value_type, FbReturnValue::hllong);
        assert!(args.return_value.is_some());
    }

    #[test]
    fn test_flatbuffer_serializable_u32() {
        let test_val = 4294967295u32;
        let mut builder = FlatBufferBuilder::new();
        let args = test_val.serialize(&mut builder);

        assert_eq!(args.return_value_type, FbReturnValue::hluint);
        assert!(args.return_value.is_some());
    }

    #[test]
    fn test_flatbuffer_serializable_u64() {
        let test_val = 18446744073709551615u64;
        let mut builder = FlatBufferBuilder::new();
        let args = test_val.serialize(&mut builder);

        assert_eq!(args.return_value_type, FbReturnValue::hlulong);
        assert!(args.return_value.is_some());
    }

    #[test]
    fn test_flatbuffer_serializable_bool() {
        for test_val in [true, false] {
            let mut builder = FlatBufferBuilder::new();
            let args = test_val.serialize(&mut builder);

            assert_eq!(args.return_value_type, FbReturnValue::hlbool);
            assert!(args.return_value.is_some());
        }
    }

    #[test]
    fn test_get_flatbuffer_result_empty_string() {
        let empty_str = "";
        let result = get_flatbuffer_result(empty_str);

        assert!(!result.is_empty());
        let size = u32::from_le_bytes([result[0], result[1], result[2], result[3]]) as usize;
        assert_eq!(size, result.len() - 4);
    }

    #[test]
    fn test_get_flatbuffer_result_empty_byte_slice() {
        let empty_bytes: &[u8] = &[];
        let result = get_flatbuffer_result(empty_bytes);

        assert!(!result.is_empty());
        let size = u32::from_le_bytes([result[0], result[1], result[2], result[3]]) as usize;
        assert_eq!(size, result.len() - 4);
    }

    #[test]
    fn test_get_flatbuffer_result_extreme_values() {
        // Test extreme values for each type
        let results = vec![
            get_flatbuffer_result(f32::MIN),
            get_flatbuffer_result(f32::MAX),
            get_flatbuffer_result(f32::INFINITY),
            get_flatbuffer_result(f32::NEG_INFINITY),
            get_flatbuffer_result(f64::MIN),
            get_flatbuffer_result(f64::MAX),
            get_flatbuffer_result(i32::MIN),
            get_flatbuffer_result(i32::MAX),
            get_flatbuffer_result(i64::MIN),
            get_flatbuffer_result(i64::MAX),
            get_flatbuffer_result(u32::MIN),
            get_flatbuffer_result(u32::MAX),
            get_flatbuffer_result(u64::MIN),
            get_flatbuffer_result(u64::MAX),
        ];

        // All should produce valid flatbuffer data
        for result in &results {
            assert!(!result.is_empty());
            let size = u32::from_le_bytes([result[0], result[1], result[2], result[3]]) as usize;
            assert_eq!(size, result.len() - 4);
        }
    }

    #[test]
    fn test_get_flatbuffer_result_large_string() {
        let large_string = "x".repeat(10000);
        let result = get_flatbuffer_result(large_string.as_str());

        assert!(!result.is_empty());
        assert!(result.len() > 10000); // Should include string data plus overhead

        let size = u32::from_le_bytes([result[0], result[1], result[2], result[3]]) as usize;
        assert_eq!(size, result.len() - 4);
    }

    #[test]
    fn test_get_flatbuffer_result_large_byte_array() {
        let large_array = vec![0x42u8; 50000];
        let result = get_flatbuffer_result(large_array.as_slice());

        assert!(!result.is_empty());
        assert!(result.len() > 50000); // Should include data plus overhead

        let size = u32::from_le_bytes([result[0], result[1], result[2], result[3]]) as usize;
        assert_eq!(size, result.len() - 4);
    }

    #[test]
    fn test_get_flatbuffer_result_unicode_string() {
        let unicode_str = "Hello 🦀 Rust! 你好世界 🚀";
        let result = get_flatbuffer_result(unicode_str);

        assert!(!result.is_empty());
        // Unicode strings are larger in bytes than character count
        assert!(result.len() > unicode_str.chars().count());

        let size = u32::from_le_bytes([result[0], result[1], result[2], result[3]]) as usize;
        assert_eq!(size, result.len() - 4);
    }

    #[test]
    fn test_get_flatbuffer_result_consistency() {
        // Multiple calls with same data should produce identical results
        let test_data = "consistency test";
        let result1 = get_flatbuffer_result(test_data);
        let result2 = get_flatbuffer_result(test_data);

        assert_eq!(result1, result2);
    }

    #[test]
    fn test_flatbuffer_serializable_trait_coverage() {
        // Ensure all implementations work correctly with their builders
        let mut builder = FlatBufferBuilder::new();

        // Test all trait implementations
        let void_result = ().serialize(&mut builder);
        let string_result = "test".serialize(&mut builder);
        let bytes_result: &[u8] = &[1u8, 2, 3];
        let bytes_result = bytes_result.serialize(&mut builder);
        let f32_result = 1.23f32.serialize(&mut builder);
        let f64_result = 4.56789f64.serialize(&mut builder);
        let i32_result = (-42i32).serialize(&mut builder);
        let i64_result = (-999i64).serialize(&mut builder);
        let u32_result = 42u32.serialize(&mut builder);
        let u64_result = 999u64.serialize(&mut builder);
        let bool_result = true.serialize(&mut builder);

        // All should have valid return value types and values
        let results = [
            (void_result, FbReturnValue::hlvoid),
            (string_result, FbReturnValue::hlstring),
            (bytes_result, FbReturnValue::hlsizeprefixedbuffer),
            (f32_result, FbReturnValue::hlfloat),
            (f64_result, FbReturnValue::hldouble),
            (i32_result, FbReturnValue::hlint),
            (i64_result, FbReturnValue::hllong),
            (u32_result, FbReturnValue::hluint),
            (u64_result, FbReturnValue::hlulong),
            (bool_result, FbReturnValue::hlbool),
        ];

        for (args, expected_type) in results {
            assert_eq!(args.return_value_type, expected_type);
            assert!(args.return_value.is_some());
        }
    }

    // Capacity estimation tests (existing tests)

    /// Helper function to check that estimation is within reasonable bounds (±25%)
    fn assert_estimation_accuracy(
        function_name: &str,
        args: Vec<ParameterValue>,
        call_type: FunctionCallType,
        return_type: ReturnType,
    ) {
        let estimated = estimate_flatbuffer_capacity(function_name, &args);

        let fc = FunctionCall::new(
            function_name.to_string(),
            Some(args),
            call_type.clone(),
            return_type,
        );
        // Important that this FlatBufferBuilder is created with capacity 0 so it grows to its needed capacity
        let mut builder = FlatBufferBuilder::new();
        let _buffer = fc.encode(&mut builder);
        let actual = builder.collapse().0.capacity();

        let lower_bound = (actual as f64 * 0.75) as usize;
        let upper_bound = (actual as f64 * 1.25) as usize;

        assert!(
            estimated >= lower_bound && estimated <= upper_bound,
            "Estimation {} outside bounds [{}, {}] for actual size {} (function: {}, call_type: {:?}, return_type: {:?})",
            estimated,
            lower_bound,
            upper_bound,
            actual,
            function_name,
            call_type,
            return_type
        );
    }

    #[test]
    fn test_estimate_no_parameters() {
        assert_estimation_accuracy(
            "simple_function",
            vec![],
            FunctionCallType::Guest,
            ReturnType::Void,
        );
    }

    #[test]
    fn test_estimate_single_int_parameter() {
        assert_estimation_accuracy(
            "add_one",
            vec![ParameterValue::Int(42)],
            FunctionCallType::Guest,
            ReturnType::Int,
        );
    }

    #[test]
    fn test_estimate_multiple_scalar_parameters() {
        assert_estimation_accuracy(
            "calculate",
            vec![
                ParameterValue::Int(10),
                ParameterValue::UInt(20),
                ParameterValue::Long(30),
                ParameterValue::ULong(40),
                ParameterValue::Float(1.5),
                ParameterValue::Double(2.5),
                ParameterValue::Bool(true),
            ],
            FunctionCallType::Guest,
            ReturnType::Double,
        );
    }

    #[test]
    fn test_estimate_string_parameters() {
        assert_estimation_accuracy(
            "process_strings",
            vec![
                ParameterValue::String("hello".to_string()),
                ParameterValue::String("world".to_string()),
                ParameterValue::String("this is a longer string for testing".to_string()),
            ],
            FunctionCallType::Host,
            ReturnType::String,
        );
    }

    #[test]
    fn test_estimate_very_long_string() {
        let long_string = "a".repeat(1000);
        assert_estimation_accuracy(
            "process_long_string",
            vec![ParameterValue::String(long_string)],
            FunctionCallType::Guest,
            ReturnType::String,
        );
    }

    #[test]
    fn test_estimate_vector_parameters() {
        assert_estimation_accuracy(
            "process_vectors",
            vec![
                ParameterValue::VecBytes(vec![1, 2, 3, 4, 5]),
                ParameterValue::VecBytes(vec![]),
                ParameterValue::VecBytes(vec![0; 100]),
            ],
            FunctionCallType::Host,
            ReturnType::VecBytes,
        );
    }

    #[test]
    fn test_estimate_mixed_parameters() {
        assert_estimation_accuracy(
            "complex_function",
            vec![
                ParameterValue::String("test".to_string()),
                ParameterValue::Int(42),
                ParameterValue::VecBytes(vec![1, 2, 3, 4, 5]),
                ParameterValue::Bool(true),
                ParameterValue::Double(553.14159),
                ParameterValue::String("another string".to_string()),
                ParameterValue::Long(9223372036854775807),
            ],
            FunctionCallType::Guest,
            ReturnType::VecBytes,
        );
    }

    #[test]
    fn test_estimate_large_function_name() {
        let long_name = "very_long_function_name_that_exceeds_normal_lengths_for_testing_purposes";
        assert_estimation_accuracy(
            long_name,
            vec![ParameterValue::Int(1)],
            FunctionCallType::Host,
            ReturnType::Long,
        );
    }

    #[test]
    fn test_estimate_large_vector() {
        let large_vector = vec![42u8; 10000];
        assert_estimation_accuracy(
            "process_large_data",
            vec![ParameterValue::VecBytes(large_vector)],
            FunctionCallType::Guest,
            ReturnType::Bool,
        );
    }

    #[test]
    fn test_estimate_all_parameter_types() {
        assert_estimation_accuracy(
            "comprehensive_test",
            vec![
                ParameterValue::Int(i32::MIN),
                ParameterValue::UInt(u32::MAX),
                ParameterValue::Long(i64::MIN),
                ParameterValue::ULong(u64::MAX),
                ParameterValue::Float(f32::MIN),
                ParameterValue::Double(f64::MAX),
                ParameterValue::Bool(false),
                ParameterValue::String("test string".to_string()),
                ParameterValue::VecBytes(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
            ],
            FunctionCallType::Host,
            ReturnType::ULong,
        );
    }

    #[test]
    fn test_different_function_call_types() {
        assert_estimation_accuracy(
            "guest_function",
            vec![ParameterValue::String("guest call".to_string())],
            FunctionCallType::Guest,
            ReturnType::String,
        );

        assert_estimation_accuracy(
            "host_function",
            vec![ParameterValue::String("host call".to_string())],
            FunctionCallType::Host,
            ReturnType::String,
        );
    }

    #[test]
    fn test_different_return_types() {
        let args = vec![
            ParameterValue::Int(42),
            ParameterValue::String("test".to_string()),
        ];

        let void_est = estimate_flatbuffer_capacity("test_void", &args);
        let int_est = estimate_flatbuffer_capacity("test_int", &args);
        let string_est = estimate_flatbuffer_capacity("test_string", &args);

        assert!((void_est as i32 - int_est as i32).abs() < 10);
        assert!((int_est as i32 - string_est as i32).abs() < 10);

        assert_estimation_accuracy(
            "test_void",
            args.clone(),
            FunctionCallType::Guest,
            ReturnType::Void,
        );
        assert_estimation_accuracy(
            "test_int",
            args.clone(),
            FunctionCallType::Guest,
            ReturnType::Int,
        );
        assert_estimation_accuracy(
            "test_string",
            args,
            FunctionCallType::Guest,
            ReturnType::String,
        );
    }

    #[test]
    fn test_estimate_many_large_vectors_and_strings() {
        assert_estimation_accuracy(
            "process_bulk_data",
            vec![
                ParameterValue::String("Large string data: ".to_string() + &"x".repeat(2000)),
                ParameterValue::VecBytes(vec![1u8; 5000]),
                ParameterValue::String(
                    "Another large string with lots of content ".to_string() + &"y".repeat(3000),
                ),
                ParameterValue::VecBytes(vec![255u8; 7500]),
                ParameterValue::String(
                    "Third massive string parameter ".to_string() + &"z".repeat(1500),
                ),
                ParameterValue::VecBytes(vec![128u8; 10000]),
                ParameterValue::Int(42),
                ParameterValue::String("Final large string ".to_string() + &"a".repeat(4000)),
                ParameterValue::VecBytes(vec![64u8; 2500]),
                ParameterValue::Bool(true),
            ],
            FunctionCallType::Host,
            ReturnType::VecBytes,
        );
    }

    #[test]
    fn test_estimate_twenty_parameters() {
        assert_estimation_accuracy(
            "function_with_many_parameters",
            vec![
                ParameterValue::Int(1),
                ParameterValue::String("param2".to_string()),
                ParameterValue::Bool(true),
                ParameterValue::Float(3213.14),
                ParameterValue::VecBytes(vec![1, 2, 3]),
                ParameterValue::Long(1000000),
                ParameterValue::Double(322.718),
                ParameterValue::UInt(42),
                ParameterValue::String("param9".to_string()),
                ParameterValue::Bool(false),
                ParameterValue::ULong(9999999999),
                ParameterValue::VecBytes(vec![4, 5, 6, 7, 8]),
                ParameterValue::Int(-100),
                ParameterValue::Float(1.414),
                ParameterValue::String("param15".to_string()),
                ParameterValue::Double(1.732),
                ParameterValue::Bool(true),
                ParameterValue::VecBytes(vec![9, 10]),
                ParameterValue::Long(-5000000),
                ParameterValue::UInt(12345),
            ],
            FunctionCallType::Guest,
            ReturnType::Int,
        );
    }

    #[test]
    fn test_estimate_megabyte_parameters() {
        assert_estimation_accuracy(
            "process_megabyte_data",
            vec![
                ParameterValue::String("MB String 1: ".to_string() + &"x".repeat(1_048_576)), // 1MB string
                ParameterValue::VecBytes(vec![42u8; 2_097_152]), // 2MB vector
                ParameterValue::String("MB String 2: ".to_string() + &"y".repeat(1_572_864)), // 1.5MB string
                ParameterValue::VecBytes(vec![128u8; 3_145_728]), // 3MB vector
                ParameterValue::String("MB String 3: ".to_string() + &"z".repeat(2_097_152)), // 2MB string
            ],
            FunctionCallType::Host,
            ReturnType::VecBytes,
        );
    }
}
