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

//! HMAC-SHA512 implementation

use crate::{Hmac, HmacAlgorithm};
use hmac_ext::{Hmac as HmacImpl, Mac};
use sha2::Sha512;
use std::fmt;

/// HMAC-SHA512
///
/// Produces a 64-byte (512-bit) MAC output.
#[derive(Clone)]
pub struct HmacSha512 {
    inner: HmacImpl<Sha512>,
    key: Vec<u8>,
}

impl HmacSha512 {
    /// Creates a new HMAC-SHA512 instance
    pub fn new(key: &[u8]) -> Self {
        Self {
            inner: HmacImpl::new_from_slice(key).expect("HMAC can accept keys of any size"),
            key: key.to_vec(),
        }
    }

    /// Finalizes the HMAC and returns the MAC
    pub fn finalize(self) -> Vec<u8> {
        self.inner.finalize().into_bytes().to_vec()
    }

    /// Computes the MAC without consuming the instance
    pub fn cumulative_mac(&self) -> Vec<u8> {
        // Clone the inner state to compute the MAC
        let cloned = self.inner.clone();
        cloned.finalize().into_bytes().to_vec()
    }

    /// Computes the HMAC of a single piece of data
    pub fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
        type HmacSha512Inner = HmacImpl<Sha512>;
        let mut mac =
            HmacSha512Inner::new_from_slice(key).expect("HMAC can accept keys of any size");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }
}

impl Hmac for HmacSha512 {
    fn new(key: &[u8]) -> Self {
        Self::new(key)
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn reset(&mut self) {
        self.inner = HmacImpl::new_from_slice(&self.key).expect("HMAC can accept keys of any size");
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
        HmacAlgorithm::HmacSha512
    }

    fn output_size(&self) -> usize {
        64
    }
}

impl fmt::Debug for HmacSha512 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HmacSha512")
            .field("algorithm", &HmacAlgorithm::HmacSha512)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sha512_one_shot() {
        let key = b"test_key";
        let data = b"test_data";
        let mac = HmacSha512::hmac(key, data);
        assert_eq!(mac.len(), 64);
    }

    #[test]
    fn test_hmac_sha512_update() {
        let key = b"test_key";
        let mut hmac = HmacSha512::new(key);
        hmac.update(b"hello ");
        hmac.update(b"world");
        let mac = hmac.cumulative_mac();
        assert_eq!(mac.len(), 64);
    }

    #[test]
    fn test_hmac_sha512_reset() {
        let key = b"test_key";
        let mut hmac = HmacSha512::new(key);
        hmac.update(b"first");
        hmac.reset();
        hmac.update(b"second");
        let mac = hmac.finalize();
        assert_eq!(mac.len(), 64);
    }

    #[test]
    fn test_hmac_sha512_algorithm() {
        let hmac = HmacSha512::new(b"test_key");
        assert_eq!(hmac.algorithm(), HmacAlgorithm::HmacSha512);
        assert_eq!(hmac.output_size(), 64);
    }
}
