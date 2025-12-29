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

//! Error types for AEAD operations

use std::fmt;

/// Error types for AEAD operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AeadError {
    /// Invalid key length
    InvalidKeyLength {
        /// The provided length
        provided: usize,
        /// The expected length
        expected: usize,
    },
    /// Invalid nonce length
    InvalidNonceLength {
        /// The provided length
        provided: usize,
        /// The expected length
        expected: usize,
    },
    /// Invalid tag length
    InvalidTagLength {
        /// The provided length
        provided: usize,
        /// The expected length
        expected: usize,
    },
    /// Authentication failed - tag verification failed
    AuthenticationFailed,
    /// Encryption error
    EncryptionError(String),
    /// Decryption error
    DecryptionError(String),
}

impl fmt::Display for AeadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyLength { provided, expected } => write!(
                f,
                "Invalid key length: provided {}, expected {}",
                provided, expected
            ),
            Self::InvalidNonceLength { provided, expected } => write!(
                f,
                "Invalid nonce length: provided {}, expected {}",
                provided, expected
            ),
            Self::InvalidTagLength { provided, expected } => write!(
                f,
                "Invalid tag length: provided {}, expected {}",
                provided, expected
            ),
            Self::AuthenticationFailed => write!(f, "Authentication failed: tag verification failed"),
            Self::EncryptionError(msg) => write!(f, "Encryption error: {}", msg),
            Self::DecryptionError(msg) => write!(f, "Decryption error: {}", msg),
        }
    }
}

impl std::error::Error for AeadError {}

/// Result type for AEAD operations
pub type Result<T> = std::result::Result<T, AeadError>;
