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

use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterType, ParameterValue};
use tracing::{Span, instrument};

use super::utils::for_each_tuple;
use crate::HyperlightError::{ParameterValueConversionFailure, UnexpectedNoOfArguments};
use crate::{Result, log_then_return};

/// This is a marker trait that is used to indicate that a type is a
/// valid Hyperlight parameter type.
///
/// For each parameter type Hyperlight supports in host functions, we
/// provide an implementation for `SupportedParameterType`
pub trait SupportedParameterType: Sized + Clone + Send + Sync + 'static {
    /// The underlying Hyperlight parameter type representing this `SupportedParameterType`
    const TYPE: ParameterType;

    /// Get the underling Hyperlight parameter value representing this
    /// `SupportedParameterType`
    fn into_value(self) -> ParameterValue;
    /// Get the actual inner value of this `SupportedParameterType`
    fn from_value(value: ParameterValue) -> Result<Self>;
}

// We can then implement these traits for each type that Hyperlight supports as a parameter or return type
macro_rules! for_each_param_type {
    ($macro:ident) => {
        $macro!(String, String);
        $macro!(i32, Int);
        $macro!(u32, UInt);
        $macro!(i64, Long);
        $macro!(u64, ULong);
        $macro!(f32, Float);
        $macro!(f64, Double);
        $macro!(bool, Bool);
        $macro!(Vec<u8>, VecBytes);
    };
}

macro_rules! impl_supported_param_type {
    ($type:ty, $enum:ident) => {
        impl SupportedParameterType for $type {
            const TYPE: ParameterType = ParameterType::$enum;

            #[instrument(skip_all, parent = Span::current(), level= "Trace")]
            fn into_value(self) -> ParameterValue {
                ParameterValue::$enum(self)
            }

            #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
            fn from_value(value: ParameterValue) -> Result<Self> {
                match value {
                    ParameterValue::$enum(i) => Ok(i),
                    other => {
                        log_then_return!(ParameterValueConversionFailure(
                            other.clone(),
                            stringify!($type)
                        ));
                    }
                }
            }
        }
    };
}

for_each_param_type!(impl_supported_param_type);

/// A trait to describe the tuple of parameters that a host function can take.
pub trait ParameterTuple: Sized + Clone + Send + Sync + 'static {
    /// The number of parameters in the tuple
    const SIZE: usize;

    /// The underlying Hyperlight parameter types representing this tuple of `SupportedParameterType`
    const TYPE: &[ParameterType];

    /// Get the underling Hyperlight parameter value representing this
    /// `SupportedParameterType`
    fn into_value(self) -> Vec<ParameterValue>;

    /// Get the actual inner value of this `SupportedParameterType`
    fn from_value(value: Vec<ParameterValue>) -> Result<Self>;
}

impl<T: SupportedParameterType> ParameterTuple for T {
    const SIZE: usize = 1;

    const TYPE: &[ParameterType] = &[T::TYPE];

    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn into_value(self) -> Vec<ParameterValue> {
        vec![self.into_value()]
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn from_value(value: Vec<ParameterValue>) -> Result<Self> {
        match <[ParameterValue; 1]>::try_from(value) {
            Ok([val]) => Ok(T::from_value(val)?),
            Err(value) => {
                log_then_return!(UnexpectedNoOfArguments(value.len(), 1));
            }
        }
    }
}

macro_rules! impl_param_tuple {
    ([$N:expr] ($($name:ident: $param:ident),*)) => {
        impl<$($param: SupportedParameterType),*> ParameterTuple for ($($param,)*) {
            const SIZE: usize = $N;

            const TYPE: &[ParameterType] = &[
                $($param::TYPE),*
            ];

            #[instrument(skip_all, parent = Span::current(), level= "Trace")]
            fn into_value(self) -> Vec<ParameterValue> {
                let ($($name,)*) = self;
                vec![$($name.into_value()),*]
            }

            #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
            fn from_value(value: Vec<ParameterValue>) -> Result<Self> {
                match <[ParameterValue; $N]>::try_from(value) {
                    Ok([$($name,)*]) => Ok(($($param::from_value($name)?,)*)),
                    Err(value) => { log_then_return!(UnexpectedNoOfArguments(value.len(), $N)); }
                }
            }
        }
    };
}

for_each_tuple!(impl_param_tuple);

#[cfg(test)]
mod tests {
    use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterType, ParameterValue};

    use super::*;

    #[test]
    fn test_string_supported_parameter_type() {
        let test_string = "test".to_string();
        assert_eq!(
            <String as SupportedParameterType>::TYPE,
            ParameterType::String
        );

        let value = <String as SupportedParameterType>::into_value(test_string.clone());
        match value {
            ParameterValue::String(s) => assert_eq!(s, test_string),
            _ => panic!("Expected String parameter value"),
        }

        let recovered = <String as SupportedParameterType>::from_value(ParameterValue::String(
            test_string.clone(),
        ))
        .unwrap();
        assert_eq!(recovered, test_string);
    }

    #[test]
    fn test_i32_supported_parameter_type() {
        let test_val = 42i32;
        assert_eq!(<i32 as SupportedParameterType>::TYPE, ParameterType::Int);

        let value = <i32 as SupportedParameterType>::into_value(test_val);
        match value {
            ParameterValue::Int(i) => assert_eq!(i, test_val),
            _ => panic!("Expected Int parameter value"),
        }

        let recovered =
            <i32 as SupportedParameterType>::from_value(ParameterValue::Int(test_val)).unwrap();
        assert_eq!(recovered, test_val);
    }

    #[test]
    fn test_parameter_type_conversion_error() {
        // Try to convert wrong type
        let result =
            <i32 as SupportedParameterType>::from_value(ParameterValue::String("test".to_string()));
        assert!(result.is_err());

        match result.unwrap_err() {
            crate::HyperlightError::ParameterValueConversionFailure(_, _) => {
                // Expected error
            }
            other => panic!("Unexpected error type: {:?}", other),
        }
    }

    #[test]
    fn test_single_parameter_tuple() {
        let test_val = 42i32;
        assert_eq!(<i32 as ParameterTuple>::SIZE, 1);
        assert_eq!(<i32 as ParameterTuple>::TYPE, &[ParameterType::Int]);

        let values = <i32 as ParameterTuple>::into_value(test_val);
        assert_eq!(values.len(), 1);

        let recovered = <i32 as ParameterTuple>::from_value(values).unwrap();
        assert_eq!(recovered, test_val);
    }

    #[test]
    fn test_two_parameter_tuple() {
        let test_tuple = (42i32, "test".to_string());
        assert_eq!(<(i32, String) as ParameterTuple>::SIZE, 2);
        assert_eq!(
            <(i32, String) as ParameterTuple>::TYPE,
            &[ParameterType::Int, ParameterType::String]
        );

        let values = <(i32, String) as ParameterTuple>::into_value(test_tuple.clone());
        assert_eq!(values.len(), 2);

        let recovered = <(i32, String) as ParameterTuple>::from_value(values).unwrap();
        assert_eq!(recovered.0, test_tuple.0);
        assert_eq!(recovered.1, test_tuple.1);
    }

    #[test]
    fn test_parameter_tuple_wrong_argument_count() {
        // Try to create a two-parameter tuple from one parameter
        let result = <(i32, String) as ParameterTuple>::from_value(vec![ParameterValue::Int(42)]);
        assert!(result.is_err());

        match result.unwrap_err() {
            crate::HyperlightError::UnexpectedNoOfArguments(got, expected) => {
                assert_eq!(got, 1);
                assert_eq!(expected, 2);
            }
            other => panic!("Unexpected error type: {:?}", other),
        }
    }

    #[test]
    fn test_empty_tuple() {
        // Test the unit type as a parameter tuple
        let unit = ();
        assert_eq!(<() as ParameterTuple>::SIZE, 0);
        assert_eq!(<() as ParameterTuple>::TYPE, &[]);

        let values = <() as ParameterTuple>::into_value(unit);
        assert_eq!(values.len(), 0);

        let recovered = <() as ParameterTuple>::from_value(values).unwrap();
        assert_eq!(recovered, ());
    }
}
