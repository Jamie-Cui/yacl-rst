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

//! OPRF error types

use std::fmt;

/// OPRF error type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OprfError {
    /// Invalid configuration
    InvalidConfig(String),
    /// Invalid input
    InvalidInput,
    /// Context not initialized
    ContextNotInitialized,
    /// Cryptographic error
    CryptoError(String),
}

impl fmt::Display for OprfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(msg) => write!(f, "Invalid configuration: {}", msg),
            Self::InvalidInput => write!(f, "Invalid input"),
            Self::ContextNotInitialized => write!(f, "Context not initialized"),
            Self::CryptoError(msg) => write!(f, "Cryptographic error: {}", msg),
        }
    }
}

impl std::error::Error for OprfError {}

/// Convert from yacl_ecc::EcError
impl From<yacl_ecc::EcError> for OprfError {
    fn from(err: yacl_ecc::EcError) -> Self {
        OprfError::CryptoError(err.to_string())
    }
}

/// OPRF result type
pub type Result<T> = std::result::Result<T, OprfError>;
