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

//! AES symmetric encryption
//!
//! This module provides AES-128 encryption in ECB, CBC, and CTR modes.

pub mod error;
pub mod ecb;
pub mod cbc;
pub mod ctr;
pub mod cipher;

pub use ecb::Aes128Ecb;
pub use cbc::Aes128Cbc;
pub use ctr::Aes128Ctr;
pub use cipher::{AesCipher, Aes128Cipher};

use std::fmt;

/// Block size for AES (128 bits = 16 bytes)
pub const BLOCK_SIZE: usize = 16;

/// Key size for AES-128 (128 bits = 16 bytes)
pub const KEY_SIZE: usize = 16;

/// IV size for AES modes (128 bits = 16 bytes)
pub const IV_SIZE: usize = 16;

/// Error types for AES operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AesError {
    /// Invalid key length
    InvalidKeyLength {
        /// The provided length
        provided: usize,
        /// The expected length
        expected: usize,
    },
    /// Invalid IV length
    InvalidIvLength {
        /// The provided length
        provided: usize,
        /// The expected length
        expected: usize,
    },
    /// Invalid plaintext length
    InvalidPlaintextLength {
        /// The provided length
        provided: usize,
        /// The required length
        required: usize,
    },
    /// Encryption error
    EncryptionError(String),
    /// Decryption error
    DecryptionError(String),
}

impl fmt::Display for AesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyLength { provided, expected } => write!(
                f,
                "Invalid key length: provided {}, expected {}",
                provided, expected
            ),
            Self::InvalidIvLength { provided, expected } => write!(
                f,
                "Invalid IV length: provided {}, expected {}",
                provided, expected
            ),
            Self::InvalidPlaintextLength { provided, required } => write!(
                f,
                "Invalid plaintext length: provided {}, must be multiple of {}",
                provided, required
            ),
            Self::EncryptionError(msg) => write!(f, "Encryption error: {}", msg),
            Self::DecryptionError(msg) => write!(f, "Decryption error: {}", msg),
        }
    }
}

impl std::error::Error for AesError {}

/// Result type for AES operations
pub type Result<T> = std::result::Result<T, AesError>;

/// AES-128 key (16 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Aes128Key(pub [u8; KEY_SIZE]);

impl Aes128Key {
    /// Creates a new AES-128 key from bytes
    pub fn new(key: [u8; KEY_SIZE]) -> Self {
        Self(key)
    }

    /// Creates a new AES-128 key from a slice
    pub fn from_slice(key: &[u8]) -> Result<Self> {
        if key.len() != KEY_SIZE {
            return Err(AesError::InvalidKeyLength {
                provided: key.len(),
                expected: KEY_SIZE,
            });
        }
        let mut key_array = [0u8; KEY_SIZE];
        key_array.copy_from_slice(key);
        Ok(Self(key_array))
    }

    /// Returns the key as bytes
    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.0
    }
}

impl From<[u8; KEY_SIZE]> for Aes128Key {
    fn from(key: [u8; KEY_SIZE]) -> Self {
        Self(key)
    }
}

/// AES-128 IV (16 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Aes128Iv(pub [u8; IV_SIZE]);

impl Aes128Iv {
    /// Creates a new AES-128 IV from bytes
    pub fn new(iv: [u8; IV_SIZE]) -> Self {
        Self(iv)
    }

    /// Creates a new AES-128 IV from a slice
    pub fn from_slice(iv: &[u8]) -> Result<Self> {
        if iv.len() != IV_SIZE {
            return Err(AesError::InvalidIvLength {
                provided: iv.len(),
                expected: IV_SIZE,
            });
        }
        let mut iv_array = [0u8; IV_SIZE];
        iv_array.copy_from_slice(iv);
        Ok(Self(iv_array))
    }

    /// Creates a zero IV
    pub fn zero() -> Self {
        Self([0u8; IV_SIZE])
    }

    /// Returns the IV as bytes
    pub fn as_bytes(&self) -> &[u8; IV_SIZE] {
        &self.0
    }
}

impl From<[u8; IV_SIZE]> for Aes128Iv {
    fn from(iv: [u8; IV_SIZE]) -> Self {
        Self(iv)
    }
}

/// Cipher mode identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CipherMode {
    /// ECB (Electronic Codebook) mode
    Ecb,
    /// CBC (Cipher Block Chaining) mode
    Cbc,
    /// CTR (Counter) mode
    Ctr,
}

impl fmt::Display for CipherMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ecb => write!(f, "AES-128-ECB"),
            Self::Cbc => write!(f, "AES-128-CBC"),
            Self::Ctr => write!(f, "AES-128-CTR"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors from NIST
    const KEY_EXAMPLE: [u8; 16] = [
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    ];

    #[test]
    fn test_aes_key() {
        let key = Aes128Key::new(KEY_EXAMPLE);
        assert_eq!(key.as_bytes(), &KEY_EXAMPLE);
    }

    #[test]
    fn test_aes_key_from_slice() {
        let key = Aes128Key::from_slice(&KEY_EXAMPLE).unwrap();
        assert_eq!(key.as_bytes(), &KEY_EXAMPLE);
    }

    #[test]
    fn test_aes_key_invalid_length() {
        let result = Aes128Key::from_slice(&[0u8; 8]);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_iv() {
        let iv = Aes128Iv::new([0u8; 16]);
        assert_eq!(iv.as_bytes(), &[0u8; 16]);
    }

    #[test]
    fn test_aes_iv_zero() {
        let iv = Aes128Iv::zero();
        assert_eq!(iv.as_bytes(), &[0u8; 16]);
    }

    #[test]
    fn test_cipher_mode_display() {
        assert_eq!(format!("{}", CipherMode::Ecb), "AES-128-ECB");
        assert_eq!(format!("{}", CipherMode::Cbc), "AES-128-CBC");
        assert_eq!(format!("{}", CipherMode::Ctr), "AES-128-CTR");
    }

    #[test]
    fn test_constants() {
        assert_eq!(BLOCK_SIZE, 16);
        assert_eq!(KEY_SIZE, 16);
        assert_eq!(IV_SIZE, 16);
    }
}
