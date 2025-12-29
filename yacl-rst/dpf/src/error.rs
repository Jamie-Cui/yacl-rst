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

//! Error types for DPF operations

use std::fmt;

/// Errors that can occur during DPF operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Invalid input length for DPF operations
    InvalidInputLength { expected: usize, actual: usize },

    /// Key generation failed
    KeyGenerationFailed(String),

    /// Evaluation failed
    EvaluationFailed(String),

    /// Invalid key format or corrupted key
    InvalidKey(String),

    /// Cryptographic operation failed
    CryptographicError(String),

    /// Serialization/deserialization error
    SerializationError(String),

    /// Invalid parameters provided
    InvalidParameters(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidInputLength { expected, actual } => {
                write!(
                    f,
                    "Invalid input length: expected {}, got {}",
                    expected, actual
                )
            }
            Error::KeyGenerationFailed(msg) => {
                write!(f, "Key generation failed: {}", msg)
            }
            Error::EvaluationFailed(msg) => {
                write!(f, "Evaluation failed: {}", msg)
            }
            Error::InvalidKey(msg) => {
                write!(f, "Invalid key: {}", msg)
            }
            Error::CryptographicError(msg) => {
                write!(f, "Cryptographic error: {}", msg)
            }
            Error::SerializationError(msg) => {
                write!(f, "Serialization error: {}", msg)
            }
            Error::InvalidParameters(msg) => {
                write!(f, "Invalid parameters: {}", msg)
            }
        }
    }
}

impl std::error::Error for Error {}

/// Result type for DPF operations
pub type Result<T> = std::result::Result<T, Error>;
