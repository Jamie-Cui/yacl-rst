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

//! Pairing error types

use std::fmt;

/// Pairing error type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairingError {
    /// Invalid pairing curve
    InvalidCurve,
    /// Invalid point
    InvalidPoint,
    /// Unsupported operation
    UnsupportedOperation(String),
    /// Cryptographic error
    CryptoError(String),
}

impl fmt::Display for PairingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCurve => write!(f, "Invalid pairing curve"),
            Self::InvalidPoint => write!(f, "Invalid point"),
            Self::UnsupportedOperation(msg) => write!(f, "Unsupported operation: {}", msg),
            Self::CryptoError(msg) => write!(f, "Cryptographic error: {}", msg),
        }
    }
}

impl std::error::Error for PairingError {}

/// Pairing result type
pub type Result<T> = std::result::Result<T, PairingError>;
