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

//! HMAC-BLAKE3 implementation

use crate::{Hmac, HmacAlgorithm};
use blake3::Hasher;
use std::fmt;

/// HMAC-BLAKE3
///
/// Produces a 32-byte (256-bit) MAC output by default.
/// BLAKE3 supports variable output, but for HMAC we use the standard 32-byte output.
#[derive(Clone)]
pub struct HmacBlake3 {
    inner: Hasher,
    key: Vec<u8>,
}

impl HmacBlake3 {
    /// Creates a new HMAC-BLAKE3 instance
    pub fn new(key: &[u8]) -> Self {
        // BLAKE3 uses a different key derivation approach
        // For HMAC-like behavior with BLAKE3, we use its keyed mode
        let key_hash = if key.len() <= 32 {
            let mut padded = [0u8; 32];
            padded[..key.len()].copy_from_slice(key);
            padded
        } else {
            // If key is longer than 32 bytes, hash it first
            let mut hasher = Hasher::new();
            hasher.update(key);
            let hash = hasher.finalize();
            let mut padded = [0u8; 32];
            padded.copy_from_slice(hash.as_bytes());
            padded
        };

        Self {
            inner: Hasher::new_keyed(&key_hash),
            key: key.to_vec(),
        }
    }

    /// Finalizes the HMAC and returns the MAC
    pub fn finalize(self) -> Vec<u8> {
        self.inner.finalize().as_bytes().to_vec()
    }

    /// Computes the MAC without consuming the instance
    pub fn cumulative_mac(&self) -> Vec<u8> {
        // Clone the inner state to compute the MAC
        let cloned = self.inner.clone();
        cloned.finalize().as_bytes().to_vec()
    }

    /// Computes the HMAC of a single piece of data
    pub fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
        let key_hash = if key.len() <= 32 {
            let mut padded = [0u8; 32];
            padded[..key.len()].copy_from_slice(key);
            padded
        } else {
            let mut hasher = Hasher::new();
            hasher.update(key);
            let hash = hasher.finalize();
            let mut padded = [0u8; 32];
            padded.copy_from_slice(hash.as_bytes());
            padded
        };

        let mut hasher = Hasher::new_keyed(&key_hash);
        hasher.update(data);
        hasher.finalize().as_bytes().to_vec()
    }
}

impl Hmac for HmacBlake3 {
    fn new(key: &[u8]) -> Self {
        Self::new(key)
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn reset(&mut self) {
        // Recreate the hasher with the same key
        let key_hash = if self.key.len() <= 32 {
            let mut padded = [0u8; 32];
            padded[..self.key.len()].copy_from_slice(&self.key);
            padded
        } else {
            let mut hasher = Hasher::new();
            hasher.update(&self.key);
            let hash = hasher.finalize();
            let mut padded = [0u8; 32];
            padded.copy_from_slice(hash.as_bytes());
            padded
        };
        self.inner = Hasher::new_keyed(&key_hash);
    }

    fn finalize(self) -> Vec<u8> {
        self.finalize()
    }

    fn cumulative_mac(&self) -> Vec<u8> {
        self.cumulative_mac()
    }

    fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
        Self::hmac(key, data)
    }

    fn algorithm(&self) -> HmacAlgorithm {
        HmacAlgorithm::HmacBlake3
    }

    fn output_size(&self) -> usize {
        32
    }
}

impl fmt::Debug for HmacBlake3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HmacBlake3")
            .field("algorithm", &HmacAlgorithm::HmacBlake3)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_blake3_one_shot() {
        let key = b"test_key";
        let data = b"test_data";
        let mac = HmacBlake3::hmac(key, data);
        assert_eq!(mac.len(), 32);
    }

    #[test]
    fn test_hmac_blake3_update() {
        let key = b"test_key";
        let mut hmac = HmacBlake3::new(key);
        hmac.update(b"hello ");
        hmac.update(b"world");
        let mac = hmac.cumulative_mac();
        assert_eq!(mac.len(), 32);
    }

    #[test]
    fn test_hmac_blake3_reset() {
        let key = b"test_key";
        let mut hmac = HmacBlake3::new(key);
        hmac.update(b"first");
        hmac.reset();
        hmac.update(b"second");
        let mac = hmac.finalize();
        assert_eq!(mac.len(), 32);
    }

    #[test]
    fn test_hmac_blake3_algorithm() {
        let hmac = HmacBlake3::new(b"test_key");
        assert_eq!(hmac.algorithm(), HmacAlgorithm::HmacBlake3);
        assert_eq!(hmac.output_size(), 32);
    }

    #[test]
    fn test_hmac_blake3_long_key() {
        let long_key = vec![0u8; 64]; // Key longer than 32 bytes
        let data = b"test_data";
        let mac = HmacBlake3::hmac(&long_key, data);
        assert_eq!(mac.len(), 32);
    }
}
