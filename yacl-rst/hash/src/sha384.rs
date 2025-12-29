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

//! SHA-384 hash function

use crate::{Hash, HashAlgorithm};
use sha2::{Digest, Sha384 as Sha384Inner};
use std::fmt;

/// SHA-384 hash function
///
/// Produces a 48-byte (384-bit) hash output.
#[derive(Clone)]
pub struct Sha384 {
    inner: Sha384Inner,
}

impl Sha384 {
    /// Creates a new SHA-384 hasher
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Sha384Inner::new(),
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
        Sha384Inner::digest(data).to_vec()
    }
}

impl Default for Sha384 {
    fn default() -> Self {
        Self::new()
    }
}

impl Hash for Sha384 {
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
        HashAlgorithm::Sha384
    }

    fn output_size(&self) -> usize {
        48
    }
}

impl fmt::Debug for Sha384 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sha384")
            .field("algorithm", &HashAlgorithm::Sha384)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors from NIST FIPS 202
    const SHA384_EMPTY: &str = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da\
                                 274edebfe76f65fbd51ad2f14898b95b";
    const SHA384_ABC: &str = "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
                                8086072ba1e7cc2358baeca134c825a7";

    #[test]
    fn test_sha384_empty() {
        let result = Sha384::digest(b"");
        assert_eq!(hex::encode(result), SHA384_EMPTY);
    }

    #[test]
    fn test_sha384_abc() {
        let result = Sha384::digest(b"abc");
        assert_eq!(hex::encode(result), SHA384_ABC);
    }

    #[test]
    fn test_sha384_update() {
        let mut hasher = Sha384::new();
        hasher.update(b"abc");
        hasher.update(b"");
        let result = hasher.finalize();
        assert_eq!(hex::encode(result), SHA384_ABC);
    }

    #[test]
    fn test_sha384_finalize_reset() {
        let mut hasher = Sha384::new();
        hasher.update(b"abc");
        let result1 = hasher.finalize_reset();
        assert_eq!(hex::encode(result1), SHA384_ABC);

        hasher.update(b"abc");
        let result2 = hasher.finalize();
        assert_eq!(hex::encode(result2), SHA384_ABC);
    }

    #[test]
    fn test_sha384_algorithm() {
        let hasher = Sha384::new();
        assert_eq!(hasher.algorithm(), HashAlgorithm::Sha384);
        assert_eq!(hasher.output_size(), 48);
    }
}
