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

//! HMAC-SHA256 implementation

use crate::{Hmac, HmacAlgorithm};
use hmac_ext::{Hmac as HmacImpl, Mac};
use sha2::Sha256;
use std::fmt;

/// HMAC-SHA256
///
/// Produces a 32-byte (256-bit) MAC output.
#[derive(Clone)]
pub struct HmacSha256 {
    inner: HmacImpl<Sha256>,
    key: Vec<u8>,
}

impl HmacSha256 {
    /// Creates a new HMAC-SHA256 instance
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
        type HmacSha256Inner = HmacImpl<Sha256>;
        let mut mac =
            HmacSha256Inner::new_from_slice(key).expect("HMAC can accept keys of any size");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }
}

impl Hmac for HmacSha256 {
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
        HmacAlgorithm::HmacSha256
    }

    fn output_size(&self) -> usize {
        32
    }
}

impl fmt::Debug for HmacSha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HmacSha256")
            .field("algorithm", &HmacAlgorithm::HmacSha256)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors from the C++ tests (openssl commands)
    // echo -n 'abc' | openssl sha256 -hmac "key_for_hmac"
    // echo -n 'abcdefabcdef' | openssl sha256 -hmac "key_for_hmac"
    const HMAC_SHA256_KEY: &[u8] = b"key_for_hmac";
    const HMAC_SHA256_DATA1: &[u8] = b"abc";
    const HMAC_SHA256_RESULT1: &str =
        "1c390b90a39a07cbc94ee6cc9c0086a1617d133d0238a2417c89081cb1b3704a";
    const HMAC_SHA256_DATA2: &[u8] = b"abcdefabcdef";
    const HMAC_SHA256_RESULT2: &str =
        "ed9547cd0d707caa7ce4a7549862079827ba43b49803e1dab937bca37a8eb324";

    #[test]
    fn test_hmac_sha256_one_shot() {
        let mac = HmacSha256::hmac(HMAC_SHA256_KEY, HMAC_SHA256_DATA1);
        assert_eq!(hex::encode(mac), HMAC_SHA256_RESULT1);
    }

    #[test]
    fn test_hmac_sha256_update() {
        let mut hmac = HmacSha256::new(HMAC_SHA256_KEY);
        hmac.update(HMAC_SHA256_DATA1);
        let mac = hmac.cumulative_mac();
        assert_eq!(hex::encode(mac), HMAC_SHA256_RESULT1);
    }

    #[test]
    fn test_hmac_sha256_finalize() {
        let mut hmac = HmacSha256::new(HMAC_SHA256_KEY);
        hmac.update(HMAC_SHA256_DATA2);
        let mac = hmac.finalize();
        assert_eq!(hex::encode(mac), HMAC_SHA256_RESULT2);
    }

    #[test]
    fn test_hmac_sha256_multiple_updates() {
        let mut hmac = HmacSha256::new(HMAC_SHA256_KEY);
        hmac.update(HMAC_SHA256_DATA1);
        let mac = hmac.cumulative_mac();
        assert_eq!(hex::encode(mac), HMAC_SHA256_RESULT1);

        // Continue updating with "def" to make "abcdef"
        hmac.update(b"def");
        hmac.update(b"abcdef");
        let mac = hmac.cumulative_mac();
        assert_eq!(hex::encode(mac), HMAC_SHA256_RESULT2);
    }

    #[test]
    fn test_hmac_sha256_reset() {
        let mut hmac = HmacSha256::new(HMAC_SHA256_KEY);
        hmac.update(HMAC_SHA256_DATA1);
        hmac.reset();
        hmac.update(HMAC_SHA256_DATA2);
        let mac = hmac.finalize();
        assert_eq!(hex::encode(mac), HMAC_SHA256_RESULT2);
    }

    #[test]
    fn test_hmac_sha256_algorithm() {
        let hmac = HmacSha256::new(b"test_key");
        assert_eq!(hmac.algorithm(), HmacAlgorithm::HmacSha256);
        assert_eq!(hmac.output_size(), 32);
    }
}
