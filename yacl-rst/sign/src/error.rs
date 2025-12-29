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

//! Error types for signature operations

use std::fmt;

/// Error types for signature operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignError {
    /// Invalid key size
    InvalidKeySize {
        /// The provided size
        provided: usize,
        /// The expected or minimum size
        expected: usize,
    },
    /// Invalid signature
    InvalidSignature,
    /// Signature verification failed
    VerificationFailed,
    /// Key generation error
    KeyGenerationError(String),
    /// Signing error
    SigningError(String),
    /// Verification error
    VerifyError(String),
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeySize { provided, expected } => write!(
                f,
                "Invalid key size: provided {}, expected at least {}",
                provided, expected
            ),
            Self::InvalidSignature => write!(f, "Invalid signature"),
            Self::VerificationFailed => write!(f, "Signature verification failed"),
            Self::KeyGenerationError(msg) => write!(f, "Key generation error: {}", msg),
            Self::SigningError(msg) => write!(f, "Signing error: {}", msg),
            Self::VerifyError(msg) => write!(f, "Verification error: {}", msg),
        }
    }
}

impl std::error::Error for SignError {}

/// Result type for signature operations
pub type Result<T> = std::result::Result<T, SignError>;
