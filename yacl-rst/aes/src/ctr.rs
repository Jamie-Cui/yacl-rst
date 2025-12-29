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

//! AES-128 CTR (Counter) mode

use crate::{Aes128Iv, Aes128Key};
use aes_ext::Aes128;
use cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr64BE;

/// AES-128 CTR mode encryptor/decryptor
///
/// CTR mode turns a block cipher into a stream cipher. The same operation
/// is used for both encryption and decryption.
#[derive(Clone)]
pub struct Aes128Ctr;

impl Aes128Ctr {
    /// Encrypts or decrypts data using AES-128 CTR mode
    ///
    /// # Arguments
    ///
    /// * `key` - The AES-128 key
    /// * `nonce` - The nonce/counter (16 bytes)
    /// * `data` - Input data to encrypt/decrypt
    ///
    /// # Returns
    ///
    /// Encrypted/decrypted data
    pub fn apply(key: &Aes128Key, nonce: &Aes128Iv, data: &[u8]) -> Vec<u8> {
        let mut cipher = Ctr64BE::<Aes128>::new(key.as_bytes().into(), nonce.as_bytes().into());
        let mut result = data.to_vec();
        cipher.apply_keystream(&mut result);
        result
    }

    /// Encrypts data using AES-128 CTR mode
    pub fn encrypt(key: &Aes128Key, nonce: &Aes128Iv, plaintext: &[u8]) -> Vec<u8> {
        Self::apply(key, nonce, plaintext)
    }

    /// Decrypts data using AES-128 CTR mode
    pub fn decrypt(key: &Aes128Key, nonce: &Aes128Iv, ciphertext: &[u8]) -> Vec<u8> {
        Self::apply(key, nonce, ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors from NIST AES-128 CTR
    // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CTR.pdf
    const KEY: [u8; 16] = [
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F,
        0x3C,
    ];

    const COUNTER: [u8; 16] = [
        0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE,
        0xFF,
    ];

    const PLAINTEXT: [u8; 64] = [
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17,
        0x2A, 0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF,
        0x8E, 0x51, 0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A,
        0x0A, 0x52, 0xEF, 0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B,
        0xE6, 0x6C, 0x37, 0x10,
    ];

    const EXPECTED_CIPHERTEXT: [u8; 64] = [
        0x87, 0x4D, 0x61, 0x91, 0xB6, 0x20, 0xE3, 0x26, 0x1B, 0xEF, 0x68, 0x64, 0x99, 0x0D, 0xB6,
        0xCE, 0x98, 0x06, 0xF6, 0x6B, 0x79, 0x70, 0xFD, 0xFF, 0x86, 0x17, 0x18, 0x7B, 0xB9, 0xFF,
        0xFD, 0xFF, 0x5A, 0xE4, 0xDF, 0x3E, 0xDB, 0xD5, 0xD3, 0x5E, 0x5B, 0x4F, 0x09, 0x02, 0x0D,
        0xB0, 0x3E, 0xAB, 0x1E, 0x03, 0x1D, 0xDA, 0x2F, 0xBE, 0x03, 0xD1, 0x79, 0x21, 0x70, 0xA0,
        0xF3, 0x00, 0x9C, 0xEE,
    ];

    #[test]
    fn test_aes128_ctr_encrypt() {
        let key = Aes128Key::new(KEY);
        let nonce = Aes128Iv::new(COUNTER);
        let ciphertext = Aes128Ctr::encrypt(&key, &nonce, &PLAINTEXT);
        assert_eq!(ciphertext, &EXPECTED_CIPHERTEXT);
    }

    #[test]
    fn test_aes128_ctr_decrypt() {
        let key = Aes128Key::new(KEY);
        let nonce = Aes128Iv::new(COUNTER);
        let plaintext = Aes128Ctr::decrypt(&key, &nonce, &EXPECTED_CIPHERTEXT);
        assert_eq!(plaintext, &PLAINTEXT);
    }

    #[test]
    fn test_aes128_ctr_roundtrip() {
        let key = Aes128Key::new(KEY);
        let nonce = Aes128Iv::new(COUNTER);
        let ciphertext = Aes128Ctr::encrypt(&key, &nonce, &PLAINTEXT);
        let decrypted = Aes128Ctr::decrypt(&key, &nonce, &ciphertext);
        assert_eq!(decrypted, &PLAINTEXT);
    }
}
