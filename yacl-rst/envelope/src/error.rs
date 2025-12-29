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

//! Envelope error types

use std::fmt;

/// Envelope error type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeError {
    /// Invalid sealed message format
    InvalidFormat,
    /// Key encryption failed
    KeyEncryptionFailed(String),
    /// Key decryption failed
    KeyDecryptionFailed(String),
    /// Data encryption failed
    DataEncryptionFailed(String),
    /// Data decryption failed
    DataDecryptionFailed(String),
    /// Authentication failed
    AuthenticationFailed,
    /// Invalid key size
    InvalidKeySize {
        provided: usize,
        expected: usize,
    },
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat => write!(f, "Invalid sealed message format"),
            Self::KeyEncryptionFailed(msg) => write!(f, "Key encryption failed: {}", msg),
            Self::KeyDecryptionFailed(msg) => write!(f, "Key decryption failed: {}", msg),
            Self::DataEncryptionFailed(msg) => write!(f, "Data encryption failed: {}", msg),
            Self::DataDecryptionFailed(msg) => write!(f, "Data decryption failed: {}", msg),
            Self::AuthenticationFailed => write!(f, "Authentication failed"),
            Self::InvalidKeySize { provided, expected } => write!(
                f,
                "Invalid key size: provided {}, expected {}",
                provided, expected
            ),
        }
    }
}

impl std::error::Error for EnvelopeError {}

/// Envelope result type
pub type Result<T> = std::result::Result<T, EnvelopeError>;
