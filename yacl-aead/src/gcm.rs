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

//! AES-GCM (Galois/Counter Mode) AEAD

use crate::{AeadCipher, AeadError, Result};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes128Gcm as Aes128GcmInner, Aes256Gcm as Aes256GcmInner, Nonce,
};

use std::fmt;

/// Key size for AES-128-GCM (128 bits = 16 bytes)
pub const AES128_GCM_KEY_SIZE: usize = 16;

/// Nonce size for GCM (96 bits = 12 bytes, recommended)
pub const GCM_NONCE_SIZE: usize = 12;

/// Tag size for GCM (128 bits = 16 bytes)
pub const GCM_TAG_SIZE: usize = 16;

/// Key size for AES-256-GCM (256 bits = 32 bytes)
pub const AES256_GCM_KEY_SIZE: usize = 32;

/// AES-128-GCM AEAD cipher
#[derive(Clone)]
pub struct Aes128Gcm {
    cipher: Aes128GcmInner,
}

impl Aes128Gcm {
    /// Creates a new AES-128-GCM cipher from a key
    ///
    /// # Arguments
    ///
    /// * `key` - The 128-bit key (16 bytes)
    ///
    /// # Returns
    ///
    /// The cipher instance
    pub fn new(key: &[u8; AES128_GCM_KEY_SIZE]) -> Self {
        let cipher = Aes128GcmInner::new(key.into());
        Self { cipher }
    }

    /// Creates a new AES-128-GCM cipher from a slice
    ///
    /// # Arguments
    ///
    /// * `key` - The key slice (must be 16 bytes)
    ///
    /// # Returns
    ///
    /// The cipher instance
    ///
    /// # Errors
    ///
    /// Returns an error if the key length is invalid
    pub fn from_slice(key: &[u8]) -> Result<Self> {
        if key.len() != AES128_GCM_KEY_SIZE {
            return Err(AeadError::InvalidKeyLength {
                provided: key.len(),
                expected: AES128_GCM_KEY_SIZE,
            });
        }
        let mut key_array = [0u8; AES128_GCM_KEY_SIZE];
        key_array.copy_from_slice(key);
        Ok(Self::new(&key_array))
    }
}

impl fmt::Debug for Aes128Gcm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Aes128Gcm").finish()
    }
}

impl AeadCipher for Aes128Gcm {
    fn key_size(&self) -> usize {
        AES128_GCM_KEY_SIZE
    }

    fn nonce_size(&self) -> usize {
        GCM_NONCE_SIZE
    }

    fn tag_size(&self) -> usize {
        GCM_TAG_SIZE
    }

    fn encrypt(&self, plaintext: &[u8], _aad: &[u8], nonce: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        if nonce.len() != GCM_NONCE_SIZE {
            return Err(AeadError::InvalidNonceLength {
                provided: nonce.len(),
                expected: GCM_NONCE_SIZE,
            });
        }

        let nonce = Nonce::from_slice(nonce);

        self.cipher
            .encrypt(nonce, plaintext)
            .map(|ciphertext| {
                // GCM appends the tag to the ciphertext
                let tag_start = ciphertext.len() - GCM_TAG_SIZE;
                let tag = ciphertext[tag_start..].to_vec();
                let ct = ciphertext[..tag_start].to_vec();
                (ct, tag)
            })
            .map_err(|e| AeadError::EncryptionError(e.to_string()))
    }

    fn decrypt(&self, ciphertext: &[u8], tag: &[u8], _aad: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        if nonce.len() != GCM_NONCE_SIZE {
            return Err(AeadError::InvalidNonceLength {
                provided: nonce.len(),
                expected: GCM_NONCE_SIZE,
            });
        }

        if tag.len() != GCM_TAG_SIZE {
            return Err(AeadError::InvalidTagLength {
                provided: tag.len(),
                expected: GCM_TAG_SIZE,
            });
        }

        let nonce = Nonce::from_slice(nonce);

        // Reconstruct the ciphertext + tag format that aes-gcm expects
        let mut ciphertext_with_tag = Vec::with_capacity(ciphertext.len() + GCM_TAG_SIZE);
        ciphertext_with_tag.extend_from_slice(ciphertext);
        ciphertext_with_tag.extend_from_slice(tag);

        self.cipher
            .decrypt(nonce, ciphertext_with_tag.as_ref())
            .map_err(|_| AeadError::AuthenticationFailed)
    }
}

/// AES-256-GCM AEAD cipher
#[derive(Clone)]
pub struct Aes256Gcm {
    cipher: Aes256GcmInner,
}

impl Aes256Gcm {
    /// Creates a new AES-256-GCM cipher from a key
    ///
    /// # Arguments
    ///
    /// * `key` - The 256-bit key (32 bytes)
    ///
    /// # Returns
    ///
    /// The cipher instance
    pub fn new(key: &[u8; AES256_GCM_KEY_SIZE]) -> Self {
        let cipher = Aes256GcmInner::new(key.into());
        Self { cipher }
    }

    /// Creates a new AES-256-GCM cipher from a slice
    ///
    /// # Arguments
    ///
    /// * `key` - The key slice (must be 32 bytes)
    ///
    /// # Returns
    ///
    /// The cipher instance
    ///
    /// # Errors
    ///
    /// Returns an error if the key length is invalid
    pub fn from_slice(key: &[u8]) -> Result<Self> {
        if key.len() != AES256_GCM_KEY_SIZE {
            return Err(AeadError::InvalidKeyLength {
                provided: key.len(),
                expected: AES256_GCM_KEY_SIZE,
            });
        }
        let mut key_array = [0u8; AES256_GCM_KEY_SIZE];
        key_array.copy_from_slice(key);
        Ok(Self::new(&key_array))
    }
}

impl fmt::Debug for Aes256Gcm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Aes256Gcm").finish()
    }
}

impl AeadCipher for Aes256Gcm {
    fn key_size(&self) -> usize {
        AES256_GCM_KEY_SIZE
    }

    fn nonce_size(&self) -> usize {
        GCM_NONCE_SIZE
    }

    fn tag_size(&self) -> usize {
        GCM_TAG_SIZE
    }

    fn encrypt(&self, plaintext: &[u8], _aad: &[u8], nonce: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        if nonce.len() != GCM_NONCE_SIZE {
            return Err(AeadError::InvalidNonceLength {
                provided: nonce.len(),
                expected: GCM_NONCE_SIZE,
            });
        }

        let nonce = Nonce::from_slice(nonce);

        self.cipher
            .encrypt(nonce, plaintext)
            .map(|ciphertext| {
                // GCM appends the tag to the ciphertext
                let tag_start = ciphertext.len() - GCM_TAG_SIZE;
                let tag = ciphertext[tag_start..].to_vec();
                let ct = ciphertext[..tag_start].to_vec();
                (ct, tag)
            })
            .map_err(|e| AeadError::EncryptionError(e.to_string()))
    }

    fn decrypt(&self, ciphertext: &[u8], tag: &[u8], _aad: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        if nonce.len() != GCM_NONCE_SIZE {
            return Err(AeadError::InvalidNonceLength {
                provided: nonce.len(),
                expected: GCM_NONCE_SIZE,
            });
        }

        if tag.len() != GCM_TAG_SIZE {
            return Err(AeadError::InvalidTagLength {
                provided: tag.len(),
                expected: GCM_TAG_SIZE,
            });
        }

        let nonce = Nonce::from_slice(nonce);

        // Reconstruct the ciphertext + tag format that aes-gcm expects
        let mut ciphertext_with_tag = Vec::with_capacity(ciphertext.len() + GCM_TAG_SIZE);
        ciphertext_with_tag.extend_from_slice(ciphertext);
        ciphertext_with_tag.extend_from_slice(tag);

        self.cipher
            .decrypt(nonce, ciphertext_with_tag.as_ref())
            .map_err(|_| AeadError::AuthenticationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors from NIST SP 800-38D
    const KEY_128: [u8; 16] = [
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    ];

    const NONCE: [u8; 12] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B
    ];

    const PLAINTEXT: &[u8] = b"Hello, world!";

    #[test]
    fn test_aes128_gcm_roundtrip() {
        let cipher = Aes128Gcm::new(&KEY_128);
        let aad = b"";
        let (ciphertext, tag) = cipher.encrypt(PLAINTEXT, aad, &NONCE).unwrap();
        let decrypted = cipher.decrypt(&ciphertext, &tag, aad, &NONCE).unwrap();
        assert_eq!(decrypted, PLAINTEXT);
    }

    #[test]
    fn test_aes128_gcm_empty_aad() {
        let cipher = Aes128Gcm::new(&KEY_128);
        let (ciphertext, tag) = cipher.encrypt(PLAINTEXT, &[], &NONCE).unwrap();
        let decrypted = cipher.decrypt(&ciphertext, &tag, &[], &NONCE).unwrap();
        assert_eq!(decrypted, PLAINTEXT);
    }

    #[test]
    fn test_aes128_gcm_from_slice() {
        let cipher = Aes128Gcm::from_slice(&KEY_128).unwrap();
        assert_eq!(cipher.key_size(), 16);
    }

    #[test]
    fn test_aes128_gcm_invalid_key_length() {
        let result = Aes128Gcm::from_slice(&[0u8; 8]);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes256_gcm_roundtrip() {
        let key = [0u8; 32];
        let cipher = Aes256Gcm::new(&key);
        let aad = b"";
        let (ciphertext, tag) = cipher.encrypt(PLAINTEXT, aad, &NONCE).unwrap();
        let decrypted = cipher.decrypt(&ciphertext, &tag, aad, &NONCE).unwrap();
        assert_eq!(decrypted, PLAINTEXT);
    }

    #[test]
    fn test_aes256_gcm_empty_aad() {
        let key = [0u8; 32];
        let cipher = Aes256Gcm::new(&key);
        let (ciphertext, tag) = cipher.encrypt(PLAINTEXT, &[], &NONCE).unwrap();
        let decrypted = cipher.decrypt(&ciphertext, &tag, &[], &NONCE).unwrap();
        assert_eq!(decrypted, PLAINTEXT);
    }

    #[test]
    fn test_aes256_gcm_from_slice() {
        let key = [0u8; 32];
        let cipher = Aes256Gcm::from_slice(&key).unwrap();
        assert_eq!(cipher.key_size(), 32);
    }

    #[test]
    fn test_aes256_gcm_invalid_key_length() {
        let result = Aes256Gcm::from_slice(&[0u8; 16]);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_nonce_length() {
        let cipher = Aes128Gcm::new(&KEY_128);
        let result = cipher.encrypt(PLAINTEXT, &[], &[0u8; 8]);
        assert!(result.is_err());
    }

    #[test]
    fn test_authentication_failure() {
        let cipher = Aes128Gcm::new(&KEY_128);
        let (ciphertext, tag) = cipher.encrypt(PLAINTEXT, &[], &NONCE).unwrap();

        // Tamper with the tag
        let mut bad_tag = tag.clone();
        bad_tag[0] ^= 0xFF;

        let result = cipher.decrypt(&ciphertext, &bad_tag, &[], &NONCE);
        assert!(matches!(result, Err(AeadError::AuthenticationFailed)));
    }
}
