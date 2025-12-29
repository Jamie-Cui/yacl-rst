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

//! Unified AEAD cipher interface

use crate::Result;
use std::fmt;

/// Trait for AEAD ciphers
///
/// This trait provides a unified interface for authenticated encryption with
/// associated data algorithms.
pub trait AeadCipher: fmt::Debug + Send + Sync {
    /// Returns the key size in bytes
    fn key_size(&self) -> usize;

    /// Returns the nonce size in bytes
    fn nonce_size(&self) -> usize;

    /// Returns the tag size in bytes
    fn tag_size(&self) -> usize;

    /// Encrypts plaintext and returns ciphertext with authentication tag
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The plaintext to encrypt
    /// * `aad` - Additional authenticated data (not encrypted but authenticated)
    /// * `nonce` - The nonce/IV for this encryption
    ///
    /// # Returns
    ///
    /// A tuple of (ciphertext, tag)
    ///
    /// # Errors
    ///
    /// Returns an error if the nonce length is invalid or encryption fails
    fn encrypt(&self, plaintext: &[u8], aad: &[u8], nonce: &[u8]) -> Result<(Vec<u8>, Vec<u8>)>;

    /// Decrypts ciphertext and verifies the authentication tag
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The ciphertext to decrypt
    /// * `tag` - The authentication tag to verify
    /// * `aad` - Additional authenticated data (not encrypted but authenticated)
    /// * `nonce` - The nonce/IV for this decryption
    ///
    /// # Returns
    ///
    /// The decrypted plaintext
    ///
    /// # Errors
    ///
    /// Returns an error if the nonce/tag length is invalid, authentication fails,
    /// or decryption fails
    fn decrypt(&self, ciphertext: &[u8], tag: &[u8], aad: &[u8], nonce: &[u8]) -> Result<Vec<u8>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock cipher for testing the trait
    #[derive(Debug)]
    struct MockAeadCipher;

    impl AeadCipher for MockAeadCipher {
        fn key_size(&self) -> usize {
            16
        }

        fn nonce_size(&self) -> usize {
            12
        }

        fn tag_size(&self) -> usize {
            16
        }

        fn encrypt(&self, _plaintext: &[u8], _aad: &[u8], _nonce: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
            Ok((vec![1, 2, 3], vec![4, 5, 6]))
        }

        fn decrypt(&self, _ciphertext: &[u8], _tag: &[u8], _aad: &[u8], _nonce: &[u8]) -> Result<Vec<u8>> {
            Ok(vec![7, 8, 9])
        }
    }

    #[test]
    fn test_aead_cipher_trait() {
        let cipher = MockAeadCipher;
        assert_eq!(cipher.key_size(), 16);
        assert_eq!(cipher.nonce_size(), 12);
        assert_eq!(cipher.tag_size(), 16);

        let (ct, tag) = cipher.encrypt(&[], &[], &[]).unwrap();
        assert_eq!(ct, vec![1, 2, 3]);
        assert_eq!(tag, vec![4, 5, 6]);

        let pt = cipher.decrypt(&[], &[], &[], &[]).unwrap();
        assert_eq!(pt, vec![7, 8, 9]);
    }
}
