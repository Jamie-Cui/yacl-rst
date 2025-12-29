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

//! AES-128 ECB (Electronic Codebook) mode

use crate::Aes128Key;
use aes_ext::Aes128;
use cipher::{Block, BlockDecryptMut, BlockEncryptMut, KeyInit};

/// AES-128 ECB mode encryptor/decryptor
///
/// NOTE: ECB mode is not recommended for most use cases as it doesn't
/// provide serious message confidentiality. Use CBC or CTR instead.
#[derive(Clone)]
pub struct Aes128Ecb {
    cipher: Aes128,
}

impl Aes128Ecb {
    /// Creates a new AES-128 ECB cipher
    pub fn new(key: &Aes128Key) -> Self {
        Self {
            cipher: Aes128::new(key.as_bytes().into()),
        }
    }

    /// Encrypts multiple blocks
    ///
    /// # Arguments
    ///
    /// * `plaintext` - Input plaintext (must be multiple of 16 bytes)
    ///
    /// # Returns
    ///
    /// Encrypted ciphertext
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut ciphertext = plaintext.to_vec();
        for chunk in ciphertext.chunks_exact_mut(16) {
            let mut cipher = self.cipher.clone();
            let block = Block::<Aes128>::from_mut_slice(chunk);
            cipher.encrypt_block_mut(block);
        }
        ciphertext
    }

    /// Decrypts multiple blocks
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - Input ciphertext (must be multiple of 16 bytes)
    ///
    /// # Returns
    ///
    /// Decrypted plaintext
    pub fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        let mut plaintext = ciphertext.to_vec();
        for chunk in plaintext.chunks_exact_mut(16) {
            let mut cipher = self.cipher.clone();
            let block = Block::<Aes128>::from_mut_slice(chunk);
            cipher.decrypt_block_mut(block);
        }
        plaintext
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors from NIST AES-128 ECB
    const KEY: [u8; 16] = [
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F,
        0x3C,
    ];

    const PLAINTEXT: [u8; 64] = [
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17,
        0x2A, 0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF,
        0x8E, 0x51, 0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A,
        0x0A, 0x52, 0xEF, 0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B,
        0xE6, 0x6C, 0x37, 0x10,
    ];

    const EXPECTED_CIPHERTEXT: [u8; 64] = [
        0x3A, 0xD7, 0x7B, 0xB4, 0x0D, 0x7A, 0x36, 0x60, 0xA8, 0x9E, 0xCA, 0xF3, 0x24, 0x66, 0xEF,
        0x97, 0xF5, 0xD3, 0xD5, 0x85, 0x03, 0xB9, 0x69, 0x9D, 0xE7, 0x85, 0x89, 0x5A, 0x96, 0xFD,
        0xBA, 0xAF, 0x43, 0xB1, 0xCD, 0x7F, 0x59, 0x8E, 0xCE, 0x23, 0x88, 0x1B, 0x00, 0xE3, 0xED,
        0x03, 0x06, 0x88, 0x7B, 0x0C, 0x78, 0x5E, 0x27, 0xE8, 0xAD, 0x3F, 0x82, 0x23, 0x20, 0x71,
        0x04, 0x72, 0x5D, 0xD4,
    ];

    #[test]
    fn test_aes128_ecb_encrypt() {
        let key = Aes128Key::new(KEY);
        let cipher = Aes128Ecb::new(&key);
        let ciphertext = cipher.encrypt(&PLAINTEXT);
        assert_eq!(ciphertext, &EXPECTED_CIPHERTEXT);
    }

    #[test]
    fn test_aes128_ecb_decrypt() {
        let key = Aes128Key::new(KEY);
        let cipher = Aes128Ecb::new(&key);
        let plaintext = cipher.decrypt(&EXPECTED_CIPHERTEXT);
        assert_eq!(plaintext, &PLAINTEXT);
    }

    #[test]
    fn test_aes128_ecb_roundtrip() {
        let key = Aes128Key::new(KEY);
        let cipher = Aes128Ecb::new(&key);
        let ciphertext = cipher.encrypt(&PLAINTEXT);
        let decrypted = cipher.decrypt(&ciphertext);
        assert_eq!(decrypted, &PLAINTEXT);
    }
}
