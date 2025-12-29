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

//! SHA-256 hash function

use crate::{Hash, HashAlgorithm};
use sha2::{Digest, Sha256 as Sha256Inner};
use std::fmt;

/// SHA-256 hash function
///
/// Produces a 32-byte (256-bit) hash output.
#[derive(Clone)]
pub struct Sha256 {
    inner: Sha256Inner,
}

impl Sha256 {
    /// Creates a new SHA-256 hasher
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Sha256Inner::new(),
        }
    }

    /// Finalizes the hash and returns the digest
    #[must_use]
    pub fn finalize(self) -> Vec<u8> {
        self.inner.finalize().to_vec()
    }

    /// Finalizes the hash and returns the digest, then resets
    pub fn finalize_reset(&mut self) -> Vec<u8> {
        let result = self.inner.clone().finalize().to_vec();
        self.inner.reset();
        result
    }

    /// Computes the hash of a single piece of data
    #[must_use]
    pub fn digest(data: &[u8]) -> Vec<u8> {
        Sha256Inner::digest(data).to_vec()
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Hash for Sha256 {
    fn new() -> Self {
        Self::new()
    }

    fn update(&mut self, data: &[u8]) {
        Digest::update(&mut self.inner, data);
    }

    fn reset(&mut self) {
        self.inner.reset();
    }

    fn finalize(self) -> Vec<u8> {
        self.finalize()
    }

    fn finalize_reset(&mut self) -> Vec<u8> {
        self.finalize_reset()
    }

    fn digest(data: &[u8]) -> Vec<u8> {
        Self::digest(data)
    }

    fn algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::Sha256
    }

    fn output_size(&self) -> usize {
        32
    }
}

impl fmt::Debug for Sha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sha256")
            .field("algorithm", &HashAlgorithm::Sha256)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors from NIST FIPS 202
    const SHA256_EMPTY: &str =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const SHA256_ABC: &str =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const SHA256_ABCDBC: &str = "ab5dfd1e7829f0b9874809f75260c25d1184c4f83d19bfa253c5420568d62ce2";

    #[test]
    fn test_sha256_empty() {
        let result = Sha256::digest(b"");
        assert_eq!(hex::encode(result), SHA256_EMPTY);
    }

    #[test]
    fn test_sha256_abc() {
        let result = Sha256::digest(b"abc");
        assert_eq!(hex::encode(result), SHA256_ABC);
    }

    #[test]
    fn test_sha256_update() {
        let mut hasher = Sha256::new();
        hasher.update(b"abc");
        hasher.update(b"dbc");
        let result = hasher.finalize();
        assert_eq!(hex::encode(result), SHA256_ABCDBC);
    }

    #[test]
    fn test_sha256_finalize_reset() {
        let mut hasher = Sha256::new();
        hasher.update(b"abc");
        let result1 = hasher.finalize_reset();
        assert_eq!(hex::encode(result1), SHA256_ABC);

        hasher.update(b"abc");
        let result2 = hasher.finalize();
        assert_eq!(hex::encode(result2), SHA256_ABC);
    }

    #[test]
    fn test_sha256_algorithm() {
        let hasher = Sha256::new();
        assert_eq!(hasher.algorithm(), HashAlgorithm::Sha256);
        assert_eq!(hasher.output_size(), 32);
    }
}
