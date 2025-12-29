// Copyright (C) 2025 by Jamie Cui
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Error types for math operations

use std::fmt;

/// Errors that can occur during math operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MathError {
    /// Division by zero
    DivisionByZero,

    /// Invalid modulus for modular arithmetic
    InvalidModulus(String),

    /// Modular inverse does not exist (numbers not coprime)
    NoModularInverse,

    /// Invalid input for the operation
    InvalidInput(String),

    /// Overflow occurred during computation
    Overflow,

    /// Underflow occurred during computation
    Underflow,

    /// Value is out of range
    OutOfRange {
        min: String,
        max: String,
        actual: String,
    },

    /// Bit index out of bounds
    BitIndexOutOfBounds { index: i64, bit_count: usize },

    /// Prime-related operations
    PrimeError(String),

    /// Serialization/deserialization error
    SerializationError(String),

    /// Random number generation error
    RandomError(String),

    /// Field element not in the field
    NotInField(String),

    /// Generic error with message
    Generic(String),
}

impl fmt::Display for MathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MathError::DivisionByZero => {
                write!(f, "Division by zero")
            }
            MathError::InvalidModulus(msg) => {
                write!(f, "Invalid modulus: {}", msg)
            }
            MathError::NoModularInverse => {
                write!(f, "Modular inverse does not exist (numbers are not coprime)")
            }
            MathError::InvalidInput(msg) => {
                write!(f, "Invalid input: {}", msg)
            }
            MathError::Overflow => {
                write!(f, "Overflow occurred during computation")
            }
            MathError::Underflow => {
                write!(f, "Underflow occurred during computation")
            }
            MathError::OutOfRange { min, max, actual } => {
                write!(f, "Value out of range: {}, expected range [{}, {}]", actual, min, max)
            }
            MathError::BitIndexOutOfBounds { index, bit_count } => {
                write!(f, "Bit index {} out of bounds (bit count: {})", index, bit_count)
            }
            MathError::PrimeError(msg) => {
                write!(f, "Prime error: {}", msg)
            }
            MathError::SerializationError(msg) => {
                write!(f, "Serialization error: {}", msg)
            }
            MathError::RandomError(msg) => {
                write!(f, "Random number generation error: {}", msg)
            }
            MathError::NotInField(msg) => {
                write!(f, "Element not in field: {}", msg)
            }
            MathError::Generic(msg) => {
                write!(f, "Error: {}", msg)
            }
        }
    }
}

impl std::error::Error for MathError {}

/// Result type for math operations
pub type Result<T> = std::result::Result<T, MathError>;

// Implement conversions from common error types
impl From<num_bigint::ParseBigIntError> for MathError {
    fn from(err: num_bigint::ParseBigIntError) -> Self {
        MathError::InvalidInput(format!("Failed to parse big integer: {}", err))
    }
}

impl From<rand::Error> for MathError {
    fn from(err: rand::Error) -> Self {
        MathError::RandomError(format!("Random number generation failed: {}", err))
    }
}
