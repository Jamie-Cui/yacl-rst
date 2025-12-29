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

//! AEAD (Authenticated Encryption with Associated Data)
//!
//! This module provides AEAD algorithms including AES-128-GCM and AES-256-GCM.
//!
//! # What is AEAD?
//!
//! AEAD provides confidentiality by encrypting the data with a symmetric
//! encryption algorithm, and provides authenticity by using a MAC tag over the
//! encrypted data.
//!
//! # Supported Algorithms
//!
//! - AES-128-GCM: Galois/Counter Mode with 128-bit key
//! - AES-256-GCM: Galois/Counter Mode with 256-bit key
//!
//! # Example
//!
//! ```rust
//! use yacl_aead::{AeadCipher, Aes128Gcm};
//!
//! // Setup
//! let key = [0u8; 16];  // 128-bit key
//! let nonce = [0u8; 12]; // 96-bit nonce
//!
//! // Encrypt
//! let plaintext = b"Hello, world!";
//! let aad = b"additional data";
//! let cipher = Aes128Gcm::new(&key);
//! let (ciphertext, tag) = cipher.encrypt(plaintext, aad, &nonce).unwrap();
//!
//! // Decrypt
//! let decrypted = cipher.decrypt(&ciphertext, &tag, aad, &nonce).unwrap();
//! assert_eq!(decrypted, plaintext);
//! ```

pub mod error;
pub mod gcm;
pub mod cipher;

pub use error::{AeadError, Result};
pub use gcm::{Aes128Gcm, Aes256Gcm};
pub use cipher::AeadCipher;

use std::fmt;

/// AEAD algorithm identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AeadAlgorithm {
    /// AES-128-GCM: Galois/Counter Mode with 128-bit key
    Aes128Gcm,
    /// AES-256-GCM: Galois/Counter Mode with 256-bit key
    Aes256Gcm,
}

impl AeadAlgorithm {
    /// Returns the key size in bytes for this algorithm
    pub fn key_size(&self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm => 32,
        }
    }

    /// Returns the nonce size in bytes for this algorithm
    pub fn nonce_size(&self) -> usize {
        // GCM typically uses 96-bit (12 byte) nonces
        12
    }

    /// Returns the tag size in bytes for this algorithm
    pub fn tag_size(&self) -> usize {
        // GCM uses 128-bit (16 byte) tags
        16
    }
}

impl fmt::Display for AeadAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aes128Gcm => write!(f, "AES-128-GCM"),
            Self::Aes256Gcm => write!(f, "AES-256-GCM"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_key_sizes() {
        assert_eq!(AeadAlgorithm::Aes128Gcm.key_size(), 16);
        assert_eq!(AeadAlgorithm::Aes256Gcm.key_size(), 32);
    }

    #[test]
    fn test_algorithm_nonce_size() {
        assert_eq!(AeadAlgorithm::Aes128Gcm.nonce_size(), 12);
        assert_eq!(AeadAlgorithm::Aes256Gcm.nonce_size(), 12);
    }

    #[test]
    fn test_algorithm_tag_size() {
        assert_eq!(AeadAlgorithm::Aes128Gcm.tag_size(), 16);
        assert_eq!(AeadAlgorithm::Aes256Gcm.tag_size(), 16);
    }

    #[test]
    fn test_algorithm_display() {
        assert_eq!(format!("{}", AeadAlgorithm::Aes128Gcm), "AES-128-GCM");
        assert_eq!(format!("{}", AeadAlgorithm::Aes256Gcm), "AES-256-GCM");
    }
}
