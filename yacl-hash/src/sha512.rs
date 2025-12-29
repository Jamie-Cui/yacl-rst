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

//! SHA-512 hash function

use crate::{Hash, HashAlgorithm};
use sha2::{Digest, Sha512 as Sha512Inner};
use std::fmt;

/// SHA-512 hash function
///
/// Produces a 64-byte (512-bit) hash output.
#[derive(Clone)]
pub struct Sha512 {
    inner: Sha512Inner,
}

impl Sha512 {
    /// Creates a new SHA-512 hasher
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Sha512Inner::new(),
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
        Sha512Inner::digest(data).to_vec()
    }
}

impl Default for Sha512 {
    fn default() -> Self {
        Self::new()
    }
}

impl Hash for Sha512 {
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
        HashAlgorithm::Sha512
    }

    fn output_size(&self) -> usize {
        64
    }
}

impl fmt::Debug for Sha512 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sha512")
            .field("algorithm", &HashAlgorithm::Sha512)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors from NIST FIPS 202
    const SHA512_EMPTY: &str = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
                                 47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
    const SHA512_ABC: &str = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
                                2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";

    #[test]
    fn test_sha512_empty() {
        let result = Sha512::digest(b"");
        assert_eq!(hex::encode(result), SHA512_EMPTY);
    }

    #[test]
    fn test_sha512_abc() {
        let result = Sha512::digest(b"abc");
        assert_eq!(hex::encode(result), SHA512_ABC);
    }

    #[test]
    fn test_sha512_update() {
        let mut hasher = Sha512::new();
        hasher.update(b"abc");
        hasher.update(b"");
        let result = hasher.finalize();
        assert_eq!(hex::encode(result), SHA512_ABC);
    }

    #[test]
    fn test_sha512_finalize_reset() {
        let mut hasher = Sha512::new();
        hasher.update(b"abc");
        let result1 = hasher.finalize_reset();
        assert_eq!(hex::encode(result1), SHA512_ABC);

        hasher.update(b"abc");
        let result2 = hasher.finalize();
        assert_eq!(hex::encode(result2), SHA512_ABC);
    }

    #[test]
    fn test_sha512_algorithm() {
        let hasher = Sha512::new();
        assert_eq!(hasher.algorithm(), HashAlgorithm::Sha512);
        assert_eq!(hasher.output_size(), 64);
    }
}
