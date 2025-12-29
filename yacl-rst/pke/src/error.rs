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

//! PKE error types

use std::fmt;

/// PKE error type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PkeError {
    /// Invalid key size
    InvalidKeySize {
        provided: usize,
        expected: usize,
    },
    /// Encryption failed
    EncryptionFailed(String),
    /// Decryption failed
    DecryptionFailed(String),
    /// Invalid ciphertext
    InvalidCiphertext,
    /// Key generation failed
    KeyGenerationError(String),
    /// Message too long for the key size
    MessageTooLong,
}

impl fmt::Display for PkeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeySize { provided, expected } => write!(
                f,
                "Invalid key size: provided {}, expected {}",
                provided, expected
            ),
            Self::EncryptionFailed(msg) => write!(f, "Encryption failed: {}", msg),
            Self::DecryptionFailed(msg) => write!(f, "Decryption failed: {}", msg),
            Self::InvalidCiphertext => write!(f, "Invalid ciphertext"),
            Self::KeyGenerationError(msg) => write!(f, "Key generation failed: {}", msg),
            Self::MessageTooLong => write!(f, "Message too long for the key size"),
        }
    }
}

impl std::error::Error for PkeError {}

/// PKE result type
pub type Result<T> = std::result::Result<T, PkeError>;
