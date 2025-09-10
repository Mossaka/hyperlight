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
#[derive(Clone)]
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
    fn test_function_call_new() {
        let function_call = FunctionCall::new(
            "test_function".to_string(),
            Some(vec![ParameterValue::Int(42)]),
            FunctionCallType::Guest,
            ReturnType::Int,
        );

        assert_eq!(function_call.function_name, "test_function");
        assert!(function_call.parameters.is_some());
        assert_eq!(function_call.function_call_type(), FunctionCallType::Guest);
        assert_eq!(function_call.expected_return_type, ReturnType::Int);
    }

    #[test]
    fn test_function_call_new_with_none_parameters() {
        let function_call = FunctionCall::new(
            "no_params_function".to_string(),
            None,
            FunctionCallType::Host,
            ReturnType::Void,
        );

        assert_eq!(function_call.function_name, "no_params_function");
        assert!(function_call.parameters.is_none());
        assert_eq!(function_call.function_call_type(), FunctionCallType::Host);
        assert_eq!(function_call.expected_return_type, ReturnType::Void);
    }

    #[test]
    fn test_function_call_type_getter() {
        let guest_call = FunctionCall::new(
            "guest_func".to_string(),
            None,
            FunctionCallType::Guest,
            ReturnType::Int,
        );
        assert_eq!(guest_call.function_call_type(), FunctionCallType::Guest);

        let host_call = FunctionCall::new(
            "host_func".to_string(),
            None,
            FunctionCallType::Host,
            ReturnType::String,
        );
        assert_eq!(host_call.function_call_type(), FunctionCallType::Host);
    }

    #[test]
    fn test_encode_with_no_parameters() {
        let function_call = FunctionCall::new(
            "no_params".to_string(),
            None,
            FunctionCallType::Guest,
            ReturnType::Void,
        );

        let mut builder = FlatBufferBuilder::new();
        let encoded = function_call.encode(&mut builder);

        assert!(!encoded.is_empty());
        // Verify we can decode it back
        let decoded = FunctionCall::try_from(encoded).unwrap();
        assert_eq!(decoded.function_name, "no_params");
        assert!(decoded.parameters.is_none());
        assert_eq!(decoded.function_call_type, FunctionCallType::Guest);
    }

    #[test]
    fn test_encode_with_empty_parameters() {
        let function_call = FunctionCall::new(
            "empty_params".to_string(),
            Some(vec![]),
            FunctionCallType::Host,
            ReturnType::Int,
        );

        let mut builder = FlatBufferBuilder::new();
        let encoded = function_call.encode(&mut builder);

        assert!(!encoded.is_empty());
        // Verify we can decode it back
        let decoded = FunctionCall::try_from(encoded).unwrap();
        assert_eq!(decoded.function_name, "empty_params");
        // Empty parameter vec gets converted to None in the current implementation
        // This is because FlatBuffers treats empty vectors as None
        assert!(decoded.parameters.is_none());
    }

    #[test]
    fn test_encode_individual_parameter_types() -> Result<()> {
        // Test Int parameter
        let int_call = FunctionCall::new(
            "int_func".to_string(),
            Some(vec![ParameterValue::Int(42)]),
            FunctionCallType::Guest,
            ReturnType::Int,
        );
        let mut builder = FlatBufferBuilder::new();
        let encoded = int_call.encode(&mut builder);
        let decoded = FunctionCall::try_from(encoded)?;
        assert_eq!(
            decoded.parameters.as_ref().unwrap()[0],
            ParameterValue::Int(42)
        );

        // Test UInt parameter
        let uint_call = FunctionCall::new(
            "uint_func".to_string(),
            Some(vec![ParameterValue::UInt(123u32)]),
            FunctionCallType::Host,
            ReturnType::UInt,
        );
        let mut builder = FlatBufferBuilder::new();
        let encoded = uint_call.encode(&mut builder);
        let decoded = FunctionCall::try_from(encoded)?;
        assert_eq!(
            decoded.parameters.as_ref().unwrap()[0],
            ParameterValue::UInt(123)
        );

        // Test Long parameter
        let long_call = FunctionCall::new(
            "long_func".to_string(),
            Some(vec![ParameterValue::Long(9876543210i64)]),
            FunctionCallType::Guest,
            ReturnType::Long,
        );
        let mut builder = FlatBufferBuilder::new();
        let encoded = long_call.encode(&mut builder);
        let decoded = FunctionCall::try_from(encoded)?;
        assert_eq!(
            decoded.parameters.as_ref().unwrap()[0],
            ParameterValue::Long(9876543210)
        );

        // Test ULong parameter
        let ulong_call = FunctionCall::new(
            "ulong_func".to_string(),
            Some(vec![ParameterValue::ULong(18446744073709551615u64)]),
            FunctionCallType::Host,
            ReturnType::ULong,
        );
        let mut builder = FlatBufferBuilder::new();
        let encoded = ulong_call.encode(&mut builder);
        let decoded = FunctionCall::try_from(encoded)?;
        assert_eq!(
            decoded.parameters.as_ref().unwrap()[0],
            ParameterValue::ULong(18446744073709551615)
        );

        Ok(())
    }

    #[test]
    fn test_encode_float_and_double_parameters() -> Result<()> {
        // Test Float parameter
        let float_call = FunctionCall::new(
            "float_func".to_string(),
            Some(vec![ParameterValue::Float(3.14159f32)]),
            FunctionCallType::Guest,
            ReturnType::Float,
        );
        let mut builder = FlatBufferBuilder::new();
        let encoded = float_call.encode(&mut builder);
        let decoded = FunctionCall::try_from(encoded)?;
        assert_eq!(
            decoded.parameters.as_ref().unwrap()[0],
            ParameterValue::Float(3.14159)
        );

        // Test Double parameter
        let double_call = FunctionCall::new(
            "double_func".to_string(),
            Some(vec![ParameterValue::Double(2.718281828459045f64)]),
            FunctionCallType::Host,
            ReturnType::Double,
        );
        let mut builder = FlatBufferBuilder::new();
        let encoded = double_call.encode(&mut builder);
        let decoded = FunctionCall::try_from(encoded)?;
        assert_eq!(
            decoded.parameters.as_ref().unwrap()[0],
            ParameterValue::Double(2.718281828459045)
        );

        Ok(())
    }

    #[test]
    fn test_encode_bool_and_string_parameters() -> Result<()> {
        // Test Bool parameter (true)
        let bool_true_call = FunctionCall::new(
            "bool_func".to_string(),
            Some(vec![ParameterValue::Bool(true)]),
            FunctionCallType::Guest,
            ReturnType::Bool,
        );
        let mut builder = FlatBufferBuilder::new();
        let encoded = bool_true_call.encode(&mut builder);
        let decoded = FunctionCall::try_from(encoded)?;
        assert_eq!(
            decoded.parameters.as_ref().unwrap()[0],
            ParameterValue::Bool(true)
        );

        // Test Bool parameter (false)
        let bool_false_call = FunctionCall::new(
            "bool_func2".to_string(),
            Some(vec![ParameterValue::Bool(false)]),
            FunctionCallType::Host,
            ReturnType::Bool,
        );
        let mut builder = FlatBufferBuilder::new();
        let encoded = bool_false_call.encode(&mut builder);
        let decoded = FunctionCall::try_from(encoded)?;
        assert_eq!(
            decoded.parameters.as_ref().unwrap()[0],
            ParameterValue::Bool(false)
        );

        // Test String parameter
        let string_call = FunctionCall::new(
            "string_func".to_string(),
            Some(vec![ParameterValue::String(
                "Hello, Hyperlight!".to_string(),
            )]),
            FunctionCallType::Guest,
            ReturnType::String,
        );
        let mut builder = FlatBufferBuilder::new();
        let encoded = string_call.encode(&mut builder);
        let decoded = FunctionCall::try_from(encoded)?;
        assert_eq!(
            decoded.parameters.as_ref().unwrap()[0],
            ParameterValue::String("Hello, Hyperlight!".to_string())
        );

        Ok(())
    }

    #[test]
    fn test_encode_vecbytes_parameter() -> Result<()> {
        let vec_data = vec![0x01, 0x02, 0x03, 0xff, 0xaa, 0xbb, 0xcc];
        let vecbytes_call = FunctionCall::new(
            "vecbytes_func".to_string(),
            Some(vec![ParameterValue::VecBytes(vec_data.clone())]),
            FunctionCallType::Host,
            ReturnType::VecBytes,
        );

        let mut builder = FlatBufferBuilder::new();
        let encoded = vecbytes_call.encode(&mut builder);
        let decoded = FunctionCall::try_from(encoded)?;
        assert_eq!(
            decoded.parameters.as_ref().unwrap()[0],
            ParameterValue::VecBytes(vec_data)
        );

        Ok(())
    }

    #[test]
    fn test_encode_mixed_parameters() -> Result<()> {
        let mixed_call = FunctionCall::new(
            "mixed_func".to_string(),
            Some(vec![
                ParameterValue::Int(42),
                ParameterValue::String("test".to_string()),
                ParameterValue::Bool(true),
                ParameterValue::Float(1.23f32),
                ParameterValue::VecBytes(vec![1, 2, 3]),
            ]),
            FunctionCallType::Guest,
            ReturnType::Int,
        );

        let mut builder = FlatBufferBuilder::new();
        let encoded = mixed_call.encode(&mut builder);
        let decoded = FunctionCall::try_from(encoded)?;

        let params = decoded.parameters.as_ref().unwrap();
        assert_eq!(params.len(), 5);
        assert_eq!(params[0], ParameterValue::Int(42));
        assert_eq!(params[1], ParameterValue::String("test".to_string()));
        assert_eq!(params[2], ParameterValue::Bool(true));
        assert_eq!(params[3], ParameterValue::Float(1.23));
        assert_eq!(params[4], ParameterValue::VecBytes(vec![1, 2, 3]));

        Ok(())
    }

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
    fn test_validate_guest_function_call_buffer() -> Result<()> {
        // Test valid guest function call
        let guest_call = FunctionCall::new(
            "guest_func".to_string(),
            None,
            FunctionCallType::Guest,
            ReturnType::Void,
        );

        let mut builder = FlatBufferBuilder::new();
        let encoded = guest_call.encode(&mut builder);

        // Should validate successfully
        assert!(validate_guest_function_call_buffer(encoded).is_ok());

        // Test with host function call (should fail)
        let host_call = FunctionCall::new(
            "host_func".to_string(),
            None,
            FunctionCallType::Host,
            ReturnType::Void,
        );

        let mut builder = FlatBufferBuilder::new();
        let encoded = host_call.encode(&mut builder);

        // Should fail validation
        assert!(validate_guest_function_call_buffer(encoded).is_err());

        Ok(())
    }

    #[test]
    fn test_validate_host_function_call_buffer() -> Result<()> {
        // Test valid host function call
        let host_call = FunctionCall::new(
            "host_func".to_string(),
            None,
            FunctionCallType::Host,
            ReturnType::Void,
        );

        let mut builder = FlatBufferBuilder::new();
        let encoded = host_call.encode(&mut builder);

        // Should validate successfully
        assert!(validate_host_function_call_buffer(encoded).is_ok());

        // Test with guest function call (should fail)
        let guest_call = FunctionCall::new(
            "guest_func".to_string(),
            None,
            FunctionCallType::Guest,
            ReturnType::Void,
        );

        let mut builder = FlatBufferBuilder::new();
        let encoded = guest_call.encode(&mut builder);

        // Should fail validation
        assert!(validate_host_function_call_buffer(encoded).is_err());

        Ok(())
    }

    #[test]
    fn test_validate_functions_with_invalid_buffer() {
        let invalid_buffer = b"invalid flatbuffer data";

        // Both validation functions should handle invalid buffers gracefully
        assert!(validate_guest_function_call_buffer(invalid_buffer).is_err());
        assert!(validate_host_function_call_buffer(invalid_buffer).is_err());
    }

    #[test]
    fn test_function_call_type_enum_debug_and_clone() {
        let guest_type = FunctionCallType::Guest;
        let host_type = FunctionCallType::Host;

        // Test Debug trait
        assert_eq!(format!("{:?}", guest_type), "Guest");
        assert_eq!(format!("{:?}", host_type), "Host");

        // Test Clone trait
        let guest_clone = guest_type.clone();
        let host_clone = host_type.clone();
        assert_eq!(guest_type, guest_clone);
        assert_eq!(host_type, host_clone);

        // Test PartialEq and Eq
        assert_eq!(guest_type, FunctionCallType::Guest);
        assert_eq!(host_type, FunctionCallType::Host);
        assert_ne!(guest_type, host_type);
    }

    #[test]
    fn test_function_call_clone_trait() {
        let original = FunctionCall::new(
            "clone_test".to_string(),
            Some(vec![ParameterValue::Int(99)]),
            FunctionCallType::Guest,
            ReturnType::Int,
        );

        let cloned = original.clone();

        assert_eq!(original.function_name, cloned.function_name);
        assert_eq!(original.parameters, cloned.parameters);
        assert_eq!(original.function_call_type(), cloned.function_call_type());
        assert_eq!(original.expected_return_type, cloned.expected_return_type);
    }
}
