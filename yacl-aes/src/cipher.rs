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

//! Unified cipher interface

use crate::{Aes128Ecb, Aes128Cbc, Aes128Ctr, Aes128Iv, Aes128Key, CipherMode};
use std::fmt;

/// Trait for AES ciphers
pub trait AesCipher: fmt::Debug + Send + Sync {
    /// Returns the cipher mode
    fn mode(&self) -> CipherMode;

    /// Encrypts plaintext
    fn encrypt(&self, plaintext: &[u8]) -> Vec<u8>;

    /// Decrypts ciphertext
    fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8>;
}

/// Unified AES-128 cipher supporting multiple modes
#[derive(Clone)]
pub enum Aes128Cipher {
    /// ECB mode (only uses key)
    Ecb(Aes128Ecb),
    /// CBC mode (uses key and IV)
    Cbc { key: Aes128Key, iv: Aes128Iv },
    /// CTR mode (uses key and nonce/IV)
    Ctr { key: Aes128Key, nonce: Aes128Iv },
}

impl Aes128Cipher {
    /// Creates a new ECB cipher
    pub fn ecb(key: Aes128Key) -> Self {
        Self::Ecb(Aes128Ecb::new(&key))
    }

    /// Creates a new CBC cipher
    pub fn cbc(key: Aes128Key, iv: Aes128Iv) -> Self {
        Self::Cbc { key, iv }
    }

    /// Creates a new CTR cipher
    pub fn ctr(key: Aes128Key, nonce: Aes128Iv) -> Self {
        Self::Ctr { key, nonce }
    }

    /// Creates a cipher from the specified mode
    pub fn new(mode: CipherMode, key: Aes128Key, iv: Aes128Iv) -> Self {
        match mode {
            CipherMode::Ecb => Self::ecb(key),
            CipherMode::Cbc => Self::cbc(key, iv),
            CipherMode::Ctr => Self::ctr(key, iv),
        }
    }
}

impl AesCipher for Aes128Cipher {
    fn mode(&self) -> CipherMode {
        match self {
            Self::Ecb(_) => CipherMode::Ecb,
            Self::Cbc { .. } => CipherMode::Cbc,
            Self::Ctr { .. } => CipherMode::Ctr,
        }
    }

    fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        match self {
            Self::Ecb(cipher) => cipher.encrypt(plaintext),
            Self::Cbc { key, iv } => Aes128Cbc::encrypt(key, iv, plaintext),
            Self::Ctr { key, nonce } => Aes128Ctr::encrypt(key, nonce, plaintext),
        }
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        match self {
            Self::Ecb(cipher) => cipher.decrypt(ciphertext),
            Self::Cbc { key, iv } => Aes128Cbc::decrypt(key, iv, ciphertext),
            Self::Ctr { key, nonce } => Aes128Ctr::decrypt(key, nonce, ciphertext),
        }
    }
}

impl fmt::Debug for Aes128Cipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Aes128Cipher")
            .field("mode", &self.mode())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 16] = [
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    ];

    const IV: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    ];

    #[test]
    fn test_unified_ecb() {
        let key = Aes128Key::new(KEY);
        let cipher = Aes128Cipher::ecb(key);
        assert_eq!(cipher.mode(), CipherMode::Ecb);
    }

    #[test]
    fn test_unified_cbc() {
        let key = Aes128Key::new(KEY);
        let iv = Aes128Iv::new(IV);
        let cipher = Aes128Cipher::cbc(key, iv);
        assert_eq!(cipher.mode(), CipherMode::Cbc);
    }

    #[test]
    fn test_unified_ctr() {
        let key = Aes128Key::new(KEY);
        let nonce = Aes128Iv::new(IV);
        let cipher = Aes128Cipher::ctr(key, nonce);
        assert_eq!(cipher.mode(), CipherMode::Ctr);
    }

    #[test]
    fn test_unified_from_mode() {
        let key = Aes128Key::new(KEY);
        let iv = Aes128Iv::new(IV);

        let ecb = Aes128Cipher::new(CipherMode::Ecb, key, Aes128Iv::zero());
        assert_eq!(ecb.mode(), CipherMode::Ecb);

        let cbc = Aes128Cipher::new(CipherMode::Cbc, key, iv);
        assert_eq!(cbc.mode(), CipherMode::Cbc);

        let ctr = Aes128Cipher::new(CipherMode::Ctr, key, iv);
        assert_eq!(ctr.mode(), CipherMode::Ctr);
    }
}
