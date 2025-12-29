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

//! AES-128 CBC (Cipher Block Chaining) mode

use crate::{Aes128Iv, Aes128Key};
use aes_ext::Aes128;
use cbc::Decryptor;
use cbc::Encryptor;
use cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};

/// AES-128 CBC mode encryptor/decryptor
#[derive(Clone)]
pub struct Aes128Cbc;

impl Aes128Cbc {
    /// Encrypts plaintext using AES-128 CBC mode
    ///
    /// # Arguments
    ///
    /// * `key` - The AES-128 key
    /// * `iv` - The initialization vector
    /// * `plaintext` - Input plaintext (must be multiple of 16 bytes)
    ///
    /// # Returns
    ///
    /// Encrypted ciphertext
    pub fn encrypt(key: &Aes128Key, iv: &Aes128Iv, plaintext: &[u8]) -> Vec<u8> {
        type Aes128CbcEnc = Encryptor<Aes128>;
        let encryptor = Aes128CbcEnc::new(key.as_bytes().into(), iv.as_bytes().into());

        let mut buf = vec![0u8; plaintext.len() + 16];
        buf[..plaintext.len()].copy_from_slice(plaintext);
        let result = encryptor
            .encrypt_padded_mut::<NoPadding>(&mut buf, plaintext.len())
            .expect("invalid length");
        result.to_vec()
    }

    /// Decrypts ciphertext using AES-128 CBC mode
    ///
    /// # Arguments
    ///
    /// * `key` - The AES-128 key
    /// * `iv` - The initialization vector
    /// * `ciphertext` - Input ciphertext (must be multiple of 16 bytes)
    ///
    /// # Returns
    ///
    /// Decrypted plaintext
    pub fn decrypt(key: &Aes128Key, iv: &Aes128Iv, ciphertext: &[u8]) -> Vec<u8> {
        type Aes128CbcDec = Decryptor<Aes128>;
        let decryptor = Aes128CbcDec::new(key.as_bytes().into(), iv.as_bytes().into());

        let mut buf = ciphertext.to_vec();
        let result = decryptor
            .decrypt_padded_mut::<NoPadding>(&mut buf)
            .expect("invalid length");
        result.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors from NIST AES-128 CBC
    // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CBC.pdf
    const KEY: [u8; 16] = [
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F,
        0x3C,
    ];

    const IV: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F,
    ];

    const PLAINTEXT: [u8; 64] = [
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17,
        0x2A, 0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF,
        0x8E, 0x51, 0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A,
        0x0A, 0x52, 0xEF, 0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B,
        0xE6, 0x6C, 0x37, 0x10,
    ];

    const EXPECTED_CIPHERTEXT: [u8; 64] = [
        0x76, 0x49, 0xAB, 0xAC, 0x81, 0x19, 0xB2, 0x46, 0xCE, 0xE9, 0x8E, 0x9B, 0x12, 0xE9, 0x19,
        0x7D, 0x50, 0x86, 0xCB, 0x9B, 0x50, 0x72, 0x19, 0xEE, 0x95, 0xDB, 0x11, 0x3A, 0x91, 0x76,
        0x78, 0xB2, 0x73, 0xBE, 0xD6, 0xB8, 0xE3, 0xC1, 0x74, 0x3B, 0x71, 0x16, 0xE6, 0x9E, 0x22,
        0x22, 0x95, 0x16, 0x3F, 0xF1, 0xCA, 0xA1, 0x68, 0x1F, 0xAC, 0x09, 0x12, 0x0E, 0xCA, 0x30,
        0x75, 0x86, 0xE1, 0xA7,
    ];

    #[test]
    fn test_aes128_cbc_encrypt() {
        let key = Aes128Key::new(KEY);
        let iv = Aes128Iv::new(IV);
        let ciphertext = Aes128Cbc::encrypt(&key, &iv, &PLAINTEXT);
        assert_eq!(ciphertext, &EXPECTED_CIPHERTEXT);
    }

    #[test]
    fn test_aes128_cbc_decrypt() {
        let key = Aes128Key::new(KEY);
        let iv = Aes128Iv::new(IV);
        let plaintext = Aes128Cbc::decrypt(&key, &iv, &EXPECTED_CIPHERTEXT);
        assert_eq!(plaintext, &PLAINTEXT);
    }

    #[test]
    fn test_aes128_cbc_roundtrip() {
        let key = Aes128Key::new(KEY);
        let iv = Aes128Iv::new(IV);
        let ciphertext = Aes128Cbc::encrypt(&key, &iv, &PLAINTEXT);
        let decrypted = Aes128Cbc::decrypt(&key, &iv, &ciphertext);
        assert_eq!(decrypted, &PLAINTEXT);
    }
}
