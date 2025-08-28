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

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use anyhow::{Error, Result, bail};
use flatbuffers::{FlatBufferBuilder, WIPOffset, size_prefixed_root};
#[cfg(feature = "tracing")]
use tracing::{Span, instrument};

use super::function_types::{ParameterValue, ReturnType};
use crate::flatbuffers::hyperlight::generated::{
    FunctionCall as FbFunctionCall, FunctionCallArgs as FbFunctionCallArgs,
    FunctionCallType as FbFunctionCallType, Parameter, ParameterArgs,
    ParameterValue as FbParameterValue, hlbool, hlboolArgs, hldouble, hldoubleArgs, hlfloat,
    hlfloatArgs, hlint, hlintArgs, hllong, hllongArgs, hlstring, hlstringArgs, hluint, hluintArgs,
    hlulong, hlulongArgs, hlvecbytes, hlvecbytesArgs,
};

/// The type of function call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FunctionCallType {
    /// The function call is to a guest function.
    Guest,
    /// The function call is to a host function.
    Host,
}

/// `Functioncall` represents a call to a function in the guest or host.
#[derive(Clone, Debug)]
pub struct FunctionCall {
    /// The function name
    pub function_name: String,
    /// The parameters for the function call.
    pub parameters: Option<Vec<ParameterValue>>,
    function_call_type: FunctionCallType,
    /// The return type of the function call
    pub expected_return_type: ReturnType,
}

impl FunctionCall {
    #[cfg_attr(feature = "tracing", instrument(skip_all, parent = Span::current(), level= "Trace"))]
    pub fn new(
        function_name: String,
        parameters: Option<Vec<ParameterValue>>,
        function_call_type: FunctionCallType,
        expected_return_type: ReturnType,
    ) -> Self {
        Self {
            function_name,
            parameters,
            function_call_type,
            expected_return_type,
        }
    }

    /// The type of the function call.
    pub fn function_call_type(&self) -> FunctionCallType {
        self.function_call_type.clone()
    }

    /// Encodes self into the given builder and returns the encoded data.
    ///
    /// # Notes
    ///
    /// The builder should not be reused after a call to encode, since this function
    /// does not reset the state of the builder. If you want to reuse the builder,
    /// you'll need to reset it first.
    pub fn encode<'a>(&self, builder: &'a mut FlatBufferBuilder) -> &'a [u8] {
        let function_name = builder.create_string(&self.function_name);

        let function_call_type = match self.function_call_type {
            FunctionCallType::Guest => FbFunctionCallType::guest,
            FunctionCallType::Host => FbFunctionCallType::host,
        };

        let expected_return_type = self.expected_return_type.into();

        let parameters = match &self.parameters {
            Some(p) if !p.is_empty() => {
                let parameter_offsets: Vec<WIPOffset<Parameter>> = p
                    .iter()
                    .map(|param| match param {
                        ParameterValue::Int(i) => {
                            let hlint = hlint::create(builder, &hlintArgs { value: *i });
                            Parameter::create(
                                builder,
                                &ParameterArgs {
                                    value_type: FbParameterValue::hlint,
                                    value: Some(hlint.as_union_value()),
                                },
                            )
                        }
                        ParameterValue::UInt(ui) => {
                            let hluint = hluint::create(builder, &hluintArgs { value: *ui });
                            Parameter::create(
                                builder,
                                &ParameterArgs {
                                    value_type: FbParameterValue::hluint,
                                    value: Some(hluint.as_union_value()),
                                },
                            )
                        }
                        ParameterValue::Long(l) => {
                            let hllong = hllong::create(builder, &hllongArgs { value: *l });
                            Parameter::create(
                                builder,
                                &ParameterArgs {
                                    value_type: FbParameterValue::hllong,
                                    value: Some(hllong.as_union_value()),
                                },
                            )
                        }
                        ParameterValue::ULong(ul) => {
                            let hlulong = hlulong::create(builder, &hlulongArgs { value: *ul });
                            Parameter::create(
                                builder,
                                &ParameterArgs {
                                    value_type: FbParameterValue::hlulong,
                                    value: Some(hlulong.as_union_value()),
                                },
                            )
                        }
                        ParameterValue::Float(f) => {
                            let hlfloat = hlfloat::create(builder, &hlfloatArgs { value: *f });
                            Parameter::create(
                                builder,
                                &ParameterArgs {
                                    value_type: FbParameterValue::hlfloat,
                                    value: Some(hlfloat.as_union_value()),
                                },
                            )
                        }
                        ParameterValue::Double(d) => {
                            let hldouble = hldouble::create(builder, &hldoubleArgs { value: *d });
                            Parameter::create(
                                builder,
                                &ParameterArgs {
                                    value_type: FbParameterValue::hldouble,
                                    value: Some(hldouble.as_union_value()),
                                },
                            )
                        }
                        ParameterValue::Bool(b) => {
                            let hlbool = hlbool::create(builder, &hlboolArgs { value: *b });
                            Parameter::create(
                                builder,
                                &ParameterArgs {
                                    value_type: FbParameterValue::hlbool,
                                    value: Some(hlbool.as_union_value()),
                                },
                            )
                        }
                        ParameterValue::String(s) => {
                            let val = builder.create_string(s.as_str());
                            let hlstring =
                                hlstring::create(builder, &hlstringArgs { value: Some(val) });
                            Parameter::create(
                                builder,
                                &ParameterArgs {
                                    value_type: FbParameterValue::hlstring,
                                    value: Some(hlstring.as_union_value()),
                                },
                            )
                        }
                        ParameterValue::VecBytes(v) => {
                            let vec_bytes = builder.create_vector(v);
                            let hlvecbytes = hlvecbytes::create(
                                builder,
                                &hlvecbytesArgs {
                                    value: Some(vec_bytes),
                                },
                            );
                            Parameter::create(
                                builder,
                                &ParameterArgs {
                                    value_type: FbParameterValue::hlvecbytes,
                                    value: Some(hlvecbytes.as_union_value()),
                                },
                            )
                        }
                    })
                    .collect();
                Some(builder.create_vector(&parameter_offsets))
            }
            _ => None,
        };

        let function_call = FbFunctionCall::create(
            builder,
            &FbFunctionCallArgs {
                function_name: Some(function_name),
                parameters,
                function_call_type,
                expected_return_type,
            },
        );
        builder.finish_size_prefixed(function_call, None);
        builder.finished_data()
    }
}

#[cfg_attr(feature = "tracing", instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace"))]
pub fn validate_guest_function_call_buffer(function_call_buffer: &[u8]) -> Result<()> {
    let guest_function_call_fb = size_prefixed_root::<FbFunctionCall>(function_call_buffer)
        .map_err(|e| anyhow::anyhow!("Error reading function call buffer: {:?}", e))?;
    match guest_function_call_fb.function_call_type() {
        FbFunctionCallType::guest => Ok(()),
        other => {
            bail!("Invalid function call type: {:?}", other);
        }
    }
}

#[cfg_attr(feature = "tracing", instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace"))]
pub fn validate_host_function_call_buffer(function_call_buffer: &[u8]) -> Result<()> {
    let host_function_call_fb = size_prefixed_root::<FbFunctionCall>(function_call_buffer)
        .map_err(|e| anyhow::anyhow!("Error reading function call buffer: {:?}", e))?;
    match host_function_call_fb.function_call_type() {
        FbFunctionCallType::host => Ok(()),
        other => {
            bail!("Invalid function call type: {:?}", other);
        }
    }
}

impl TryFrom<&[u8]> for FunctionCall {
    type Error = Error;
    #[cfg_attr(feature = "tracing", instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace"))]
    fn try_from(value: &[u8]) -> Result<Self> {
        let function_call_fb = size_prefixed_root::<FbFunctionCall>(value)
            .map_err(|e| anyhow::anyhow!("Error reading function call buffer: {:?}", e))?;
        let function_name = function_call_fb.function_name();
        let function_call_type = match function_call_fb.function_call_type() {
            FbFunctionCallType::guest => FunctionCallType::Guest,
            FbFunctionCallType::host => FunctionCallType::Host,
            other => {
                bail!("Invalid function call type: {:?}", other);
            }
        };
        let expected_return_type = function_call_fb.expected_return_type().try_into()?;

        let parameters = function_call_fb
            .parameters()
            .map(|v| {
                v.iter()
                    .map(|p| p.try_into())
                    .collect::<Result<Vec<ParameterValue>>>()
            })
            .transpose()?;

        Ok(Self {
            function_name: function_name.to_string(),
            parameters,
            function_call_type,
            expected_return_type,
        })
    }
}

#[cfg(test)]
mod tests {
    use alloc::{format, vec};

    use super::*;
    use crate::flatbuffer_wrappers::function_types::ReturnType;

    #[test]
    fn read_from_flatbuffer() -> Result<()> {
        let mut builder = FlatBufferBuilder::new();
        let test_data = FunctionCall::new(
            "PrintTwelveArgs".to_string(),
            Some(vec![
                ParameterValue::String("1".to_string()),
                ParameterValue::Int(2),
                ParameterValue::Long(3),
                ParameterValue::String("4".to_string()),
                ParameterValue::String("5".to_string()),
                ParameterValue::Bool(true),
                ParameterValue::Bool(false),
                ParameterValue::UInt(8),
                ParameterValue::ULong(9),
                ParameterValue::Int(10),
                ParameterValue::Float(3.123),
                ParameterValue::Double(0.01),
            ]),
            FunctionCallType::Guest,
            ReturnType::Int,
        )
        .encode(&mut builder);

        let function_call = FunctionCall::try_from(test_data)?;
        assert_eq!(function_call.function_name, "PrintTwelveArgs");
        assert!(function_call.parameters.is_some());
        let parameters = function_call.parameters.unwrap();
        assert_eq!(parameters.len(), 12);
        let expected_parameters = vec![
            ParameterValue::String("1".to_string()),
            ParameterValue::Int(2),
            ParameterValue::Long(3),
            ParameterValue::String("4".to_string()),
            ParameterValue::String("5".to_string()),
            ParameterValue::Bool(true),
            ParameterValue::Bool(false),
            ParameterValue::UInt(8),
            ParameterValue::ULong(9),
            ParameterValue::Int(10),
            ParameterValue::Float(3.123),
            ParameterValue::Double(0.01),
        ];
        assert!(expected_parameters == parameters);
        assert_eq!(function_call.function_call_type, FunctionCallType::Guest);

        Ok(())
    }

    #[test]
    fn test_function_call_type_enum() {
        assert_eq!(FunctionCallType::Guest, FunctionCallType::Guest);
        assert_eq!(FunctionCallType::Host, FunctionCallType::Host);
        assert_ne!(FunctionCallType::Guest, FunctionCallType::Host);

        // Test clone and debug
        let guest_type = FunctionCallType::Guest.clone();
        assert_eq!(guest_type, FunctionCallType::Guest);
        let debug_str = format!("{:?}", FunctionCallType::Host);
        assert_eq!(debug_str, "Host");
    }

    #[test]
    fn test_function_call_new() {
        let function_call = FunctionCall::new(
            "test_function".to_string(),
            Some(vec![ParameterValue::Int(42)]),
            FunctionCallType::Guest,
            ReturnType::String,
        );

        assert_eq!(function_call.function_name, "test_function");
        assert!(function_call.parameters.is_some());
        assert_eq!(function_call.parameters.as_ref().unwrap().len(), 1);
        assert_eq!(function_call.function_call_type(), FunctionCallType::Guest);
        assert_eq!(function_call.expected_return_type, ReturnType::String);
    }

    #[test]
    fn test_function_call_new_with_no_parameters() {
        let function_call = FunctionCall::new(
            "no_params".to_string(),
            None,
            FunctionCallType::Host,
            ReturnType::Void,
        );

        assert_eq!(function_call.function_name, "no_params");
        assert!(function_call.parameters.is_none());
        assert_eq!(function_call.function_call_type(), FunctionCallType::Host);
        assert_eq!(function_call.expected_return_type, ReturnType::Void);
    }

    #[test]
    fn test_function_call_type_accessor() {
        let function_call = FunctionCall::new(
            "test".to_string(),
            None,
            FunctionCallType::Guest,
            ReturnType::Int,
        );

        assert_eq!(function_call.function_call_type(), FunctionCallType::Guest);
    }

    #[test]
    fn test_encode_with_empty_parameters() {
        let mut builder = FlatBufferBuilder::new();
        let function_call = FunctionCall::new(
            "empty_params".to_string(),
            Some(vec![]), // Empty vector
            FunctionCallType::Host,
            ReturnType::Bool,
        );

        let encoded = function_call.encode(&mut builder);
        let decoded = FunctionCall::try_from(encoded).unwrap();

        assert_eq!(decoded.function_name, "empty_params");
        assert!(decoded.parameters.is_none());
        assert_eq!(decoded.function_call_type(), FunctionCallType::Host);
        assert_eq!(decoded.expected_return_type, ReturnType::Bool);
    }

    #[test]
    fn test_encode_single_parameter_types() {
        // Test Int parameter
        let mut builder = FlatBufferBuilder::new();
        let function_call = FunctionCall::new(
            "int_param".to_string(),
            Some(vec![ParameterValue::Int(-123)]),
            FunctionCallType::Guest,
            ReturnType::Int,
        );
        let encoded = function_call.encode(&mut builder);
        let decoded = FunctionCall::try_from(encoded).unwrap();
        assert_eq!(decoded.parameters.unwrap()[0], ParameterValue::Int(-123));

        // Test UInt parameter
        let mut builder2 = FlatBufferBuilder::new();
        let function_call2 = FunctionCall::new(
            "uint_param".to_string(),
            Some(vec![ParameterValue::UInt(456)]),
            FunctionCallType::Guest,
            ReturnType::UInt,
        );
        let encoded2 = function_call2.encode(&mut builder2);
        let decoded2 = FunctionCall::try_from(encoded2).unwrap();
        assert_eq!(decoded2.parameters.unwrap()[0], ParameterValue::UInt(456));

        // Test Long parameter
        let mut builder3 = FlatBufferBuilder::new();
        let function_call3 = FunctionCall::new(
            "long_param".to_string(),
            Some(vec![ParameterValue::Long(-9876543210)]),
            FunctionCallType::Guest,
            ReturnType::Long,
        );
        let encoded3 = function_call3.encode(&mut builder3);
        let decoded3 = FunctionCall::try_from(encoded3).unwrap();
        assert_eq!(
            decoded3.parameters.unwrap()[0],
            ParameterValue::Long(-9876543210)
        );

        // Test ULong parameter
        let mut builder4 = FlatBufferBuilder::new();
        let function_call4 = FunctionCall::new(
            "ulong_param".to_string(),
            Some(vec![ParameterValue::ULong(18446744073709551615)]),
            FunctionCallType::Guest,
            ReturnType::ULong,
        );
        let encoded4 = function_call4.encode(&mut builder4);
        let decoded4 = FunctionCall::try_from(encoded4).unwrap();
        assert_eq!(
            decoded4.parameters.unwrap()[0],
            ParameterValue::ULong(18446744073709551615)
        );
    }

    #[test]
    fn test_encode_float_and_double_parameters() {
        // Test Float parameter
        let mut builder = FlatBufferBuilder::new();
        let function_call = FunctionCall::new(
            "float_param".to_string(),
            Some(vec![ParameterValue::Float(3.14159)]),
            FunctionCallType::Guest,
            ReturnType::Float,
        );
        let encoded = function_call.encode(&mut builder);
        let decoded = FunctionCall::try_from(encoded).unwrap();
        if let ParameterValue::Float(f) = &decoded.parameters.unwrap()[0] {
            assert!((f - 3.14159).abs() < 0.00001);
        } else {
            panic!("Expected Float parameter");
        }

        // Test Double parameter
        let mut builder2 = FlatBufferBuilder::new();
        let function_call2 = FunctionCall::new(
            "double_param".to_string(),
            Some(vec![ParameterValue::Double(2.718281828459045)]),
            FunctionCallType::Guest,
            ReturnType::Double,
        );
        let encoded2 = function_call2.encode(&mut builder2);
        let decoded2 = FunctionCall::try_from(encoded2).unwrap();
        assert_eq!(
            decoded2.parameters.unwrap()[0],
            ParameterValue::Double(2.718281828459045)
        );
    }

    #[test]
    fn test_encode_string_and_bool_parameters() {
        // Test String parameter
        let mut builder = FlatBufferBuilder::new();
        let function_call = FunctionCall::new(
            "string_param".to_string(),
            Some(vec![ParameterValue::String("Hello, World! 🦀".to_string())]),
            FunctionCallType::Host,
            ReturnType::String,
        );
        let encoded = function_call.encode(&mut builder);
        let decoded = FunctionCall::try_from(encoded).unwrap();
        assert_eq!(
            decoded.parameters.unwrap()[0],
            ParameterValue::String("Hello, World! 🦀".to_string())
        );

        // Test Bool parameter (true)
        let mut builder2 = FlatBufferBuilder::new();
        let function_call2 = FunctionCall::new(
            "bool_true".to_string(),
            Some(vec![ParameterValue::Bool(true)]),
            FunctionCallType::Host,
            ReturnType::Bool,
        );
        let encoded2 = function_call2.encode(&mut builder2);
        let decoded2 = FunctionCall::try_from(encoded2).unwrap();
        assert_eq!(decoded2.parameters.unwrap()[0], ParameterValue::Bool(true));

        // Test Bool parameter (false)
        let mut builder3 = FlatBufferBuilder::new();
        let function_call3 = FunctionCall::new(
            "bool_false".to_string(),
            Some(vec![ParameterValue::Bool(false)]),
            FunctionCallType::Host,
            ReturnType::Bool,
        );
        let encoded3 = function_call3.encode(&mut builder3);
        let decoded3 = FunctionCall::try_from(encoded3).unwrap();
        assert_eq!(decoded3.parameters.unwrap()[0], ParameterValue::Bool(false));
    }

    #[test]
    fn test_encode_vecbytes_parameter() {
        let mut builder = FlatBufferBuilder::new();
        let test_bytes = vec![0x00, 0xFF, 0x42, 0x13, 0x37, 0xDE, 0xAD, 0xBE, 0xEF];
        let function_call = FunctionCall::new(
            "vecbytes_param".to_string(),
            Some(vec![ParameterValue::VecBytes(test_bytes.clone())]),
            FunctionCallType::Guest,
            ReturnType::VecBytes,
        );
        let encoded = function_call.encode(&mut builder);
        let decoded = FunctionCall::try_from(encoded).unwrap();
        assert_eq!(
            decoded.parameters.unwrap()[0],
            ParameterValue::VecBytes(test_bytes)
        );
    }

    #[test]
    fn test_encode_mixed_parameters() {
        let mut builder = FlatBufferBuilder::new();
        let mixed_params = vec![
            ParameterValue::String("test".to_string()),
            ParameterValue::Int(42),
            ParameterValue::Bool(true),
            ParameterValue::VecBytes(vec![1, 2, 3, 4, 5]),
            ParameterValue::Double(3.14159),
        ];
        let function_call = FunctionCall::new(
            "mixed_params".to_string(),
            Some(mixed_params.clone()),
            FunctionCallType::Host,
            ReturnType::Void,
        );

        let encoded = function_call.encode(&mut builder);
        let decoded = FunctionCall::try_from(encoded).unwrap();

        assert_eq!(decoded.function_name, "mixed_params");
        assert_eq!(decoded.parameters.clone().unwrap(), mixed_params);
        assert_eq!(decoded.function_call_type(), FunctionCallType::Host);
        assert_eq!(decoded.expected_return_type, ReturnType::Void);
    }

    #[test]
    fn test_validate_guest_function_call_buffer_valid() {
        let mut builder = FlatBufferBuilder::new();
        let function_call = FunctionCall::new(
            "guest_func".to_string(),
            None,
            FunctionCallType::Guest,
            ReturnType::Int,
        );
        let encoded = function_call.encode(&mut builder);

        assert!(validate_guest_function_call_buffer(encoded).is_ok());
    }

    #[test]
    fn test_validate_guest_function_call_buffer_invalid() {
        let mut builder = FlatBufferBuilder::new();
        let function_call = FunctionCall::new(
            "host_func".to_string(),
            None,
            FunctionCallType::Host, // This should fail validation for guest
            ReturnType::Int,
        );
        let encoded = function_call.encode(&mut builder);

        let result = validate_guest_function_call_buffer(encoded);
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Invalid function call type"));
    }

    #[test]
    fn test_validate_host_function_call_buffer_valid() {
        let mut builder = FlatBufferBuilder::new();
        let function_call = FunctionCall::new(
            "host_func".to_string(),
            None,
            FunctionCallType::Host,
            ReturnType::String,
        );
        let encoded = function_call.encode(&mut builder);

        assert!(validate_host_function_call_buffer(encoded).is_ok());
    }

    #[test]
    fn test_validate_host_function_call_buffer_invalid() {
        let mut builder = FlatBufferBuilder::new();
        let function_call = FunctionCall::new(
            "guest_func".to_string(),
            None,
            FunctionCallType::Guest, // This should fail validation for host
            ReturnType::String,
        );
        let encoded = function_call.encode(&mut builder);

        let result = validate_host_function_call_buffer(encoded);
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Invalid function call type"));
    }

    #[test]
    fn test_validate_corrupted_buffer() {
        let corrupted_buffer = vec![0xFF, 0x00, 0x42, 0x13]; // Invalid flatbuffer data

        let guest_result = validate_guest_function_call_buffer(&corrupted_buffer);
        assert!(guest_result.is_err());
        let error_msg = guest_result.unwrap_err().to_string();
        assert!(error_msg.contains("Error reading function call buffer"));

        let host_result = validate_host_function_call_buffer(&corrupted_buffer);
        assert!(host_result.is_err());
        let error_msg = host_result.unwrap_err().to_string();
        assert!(error_msg.contains("Error reading function call buffer"));
    }

    #[test]
    fn test_try_from_corrupted_buffer() {
        let corrupted_buffer = vec![0x00, 0x01, 0x02, 0x03];
        let result = FunctionCall::try_from(corrupted_buffer.as_slice());

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Error reading function call buffer"));
    }

    #[test]
    fn test_all_return_types() {
        let return_types = vec![
            ReturnType::Int,
            ReturnType::UInt,
            ReturnType::Long,
            ReturnType::ULong,
            ReturnType::Float,
            ReturnType::Double,
            ReturnType::String,
            ReturnType::Bool,
            ReturnType::Void,
            ReturnType::VecBytes,
        ];

        for (i, return_type) in return_types.iter().enumerate() {
            let mut builder = FlatBufferBuilder::new();
            let function_call = FunctionCall::new(
                format!("test_return_type_{}", i),
                None,
                FunctionCallType::Guest,
                *return_type,
            );
            let encoded = function_call.encode(&mut builder);
            let decoded = FunctionCall::try_from(encoded).unwrap();
            assert_eq!(decoded.expected_return_type, *return_type);
        }
    }

    #[test]
    fn test_function_call_clone() {
        let original = FunctionCall::new(
            "cloneable".to_string(),
            Some(vec![ParameterValue::String("test".to_string())]),
            FunctionCallType::Host,
            ReturnType::Bool,
        );

        let cloned = original.clone();
        assert_eq!(cloned.function_name, original.function_name);
        assert_eq!(cloned.parameters, original.parameters);
        assert_eq!(cloned.function_call_type(), original.function_call_type());
        assert_eq!(cloned.expected_return_type, original.expected_return_type);
    }

    #[test]
    fn test_empty_function_name() {
        let mut builder = FlatBufferBuilder::new();
        let function_call = FunctionCall::new(
            "".to_string(), // Empty function name
            None,
            FunctionCallType::Guest,
            ReturnType::Void,
        );
        let encoded = function_call.encode(&mut builder);
        let decoded = FunctionCall::try_from(encoded).unwrap();
        assert_eq!(decoded.function_name, "");
    }

    #[test]
    fn test_large_parameter_count() {
        let mut builder = FlatBufferBuilder::new();
        let mut large_params = Vec::new();

        // Create 50 parameters of various types
        for i in 0..50 {
            match i % 9 {
                0 => large_params.push(ParameterValue::Int(i as i32)),
                1 => large_params.push(ParameterValue::UInt(i as u32)),
                2 => large_params.push(ParameterValue::Long(i as i64)),
                3 => large_params.push(ParameterValue::ULong(i as u64)),
                4 => large_params.push(ParameterValue::Float(i as f32 + 0.5)),
                5 => large_params.push(ParameterValue::Double(i as f64 + 0.25)),
                6 => large_params.push(ParameterValue::String(format!("param_{}", i))),
                7 => large_params.push(ParameterValue::Bool(i % 2 == 0)),
                8 => large_params.push(ParameterValue::VecBytes(vec![i as u8; 3])),
                _ => unreachable!(),
            }
        }

        let function_call = FunctionCall::new(
            "large_param_count".to_string(),
            Some(large_params.clone()),
            FunctionCallType::Guest,
            ReturnType::Int,
        );

        let encoded = function_call.encode(&mut builder);
        let decoded = FunctionCall::try_from(encoded).unwrap();

        assert_eq!(decoded.function_name, "large_param_count");
        let decoded_params = decoded.parameters.as_ref().unwrap();
        assert_eq!(*decoded_params, large_params);
        assert_eq!(decoded_params.len(), 50);
    }
}
