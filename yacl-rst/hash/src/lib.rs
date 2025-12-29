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

//! Cryptographic hash functions
//!
//! This module provides a unified interface for various hash functions
//! including SHA256, SHA384, SHA512, and BLAKE3.

pub mod error;
mod sha256;
mod sha384;
mod sha512;
mod blake3;
mod utils;

pub use error::{HashError, Result};
pub use sha256::Sha256;
pub use sha384::Sha384;
pub use sha512::Sha512;
pub use blake3::Blake3;
pub use utils::{blake3, sha256, sha384, sha512};

use std::fmt;

/// Hash algorithm identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HashAlgorithm {
    /// SHA-256 (32 bytes output)
    Sha256,
    /// SHA-384 (48 bytes output)
    Sha384,
    /// SHA-512 (64 bytes output)
    Sha512,
    /// BLAKE3 (variable output, defaults to 32 bytes)
    Blake3,
}

impl HashAlgorithm {
    /// Returns the name of this hash algorithm
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Sha256 => "SHA256",
            Self::Sha384 => "SHA384",
            Self::Sha512 => "SHA512",
            Self::Blake3 => "BLAKE3",
        }
    }

    /// Returns the default output size in bytes
    #[must_use]
    pub fn output_size(&self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
            Self::Blake3 => 32,
        }
    }

    /// Returns the block size in bytes
    #[must_use]
    pub fn block_size(&self) -> usize {
        match self {
            Self::Sha256 => 64,
            Self::Sha384 => 128,
            Self::Sha512 => 128,
            Self::Blake3 => 64,
        }
    }
}

/// Trait for hash functions
///
/// This trait provides a unified interface for computing hash digests.
pub trait Hash: fmt::Debug + Send + Sync {
    /// Creates a new hash instance
    fn new() -> Self
    where
        Self: Sized;

    /// Updates the hash with additional data
    fn update(&mut self, data: &[u8]);

    /// Resets the hash to its initial state
    fn reset(&mut self)
    where
        Self: Sized;

    /// Finalizes the hash and returns the digest
    ///
    /// This consumes the hash instance. Use `finalize_reset()` if you
    /// want to reuse the instance.
    #[must_use]
    fn finalize(self) -> Vec<u8>;

    /// Finalizes the hash and returns the digest, then resets
    ///
    /// This allows reusing the hash instance for multiple hashes.
    fn finalize_reset(&mut self) -> Vec<u8>
    where
        Self: Sized;

    /// Computes the hash of a single piece of data
    ///
    /// This is a convenience method for one-shot hashing.
    fn digest(data: &[u8]) -> Vec<u8>
    where
        Self: Sized;

    /// Returns the hash algorithm type
    fn algorithm(&self) -> HashAlgorithm;

    /// Returns the output size in bytes
    fn output_size(&self) -> usize;
}

/// A unified hash enum that can hold any hash type
#[derive(Clone)]
pub enum Hasher {
    /// SHA-256 hasher
    Sha256(sha256::Sha256),
    /// SHA-384 hasher
    Sha384(sha384::Sha384),
    /// SHA-512 hasher
    Sha512(sha512::Sha512),
    /// BLAKE3 hasher
    Blake3(blake3::Blake3),
}

impl Hasher {
    /// Creates a new hasher for the specified algorithm
    #[must_use]
    pub fn new(algorithm: HashAlgorithm) -> Self {
        match algorithm {
            HashAlgorithm::Sha256 => Self::Sha256(Sha256::new()),
            HashAlgorithm::Sha384 => Self::Sha384(Sha384::new()),
            HashAlgorithm::Sha512 => Self::Sha512(Sha512::new()),
            HashAlgorithm::Blake3 => Self::Blake3(Blake3::new()),
        }
    }

    /// Updates the hasher with additional data
    pub fn update(&mut self, data: &[u8]) {
        match self {
            Self::Sha256(h) => h.update(data),
            Self::Sha384(h) => h.update(data),
            Self::Sha512(h) => h.update(data),
            Self::Blake3(h) => h.update(data),
        }
    }

    /// Resets the hasher to its initial state
    pub fn reset(&mut self) {
        match self {
            Self::Sha256(h) => h.reset(),
            Self::Sha384(h) => h.reset(),
            Self::Sha512(h) => h.reset(),
            Self::Blake3(h) => h.reset(),
        }
    }

    /// Finalizes the hash and returns the digest
    #[must_use]
    pub fn finalize(self) -> Vec<u8> {
        match self {
            Self::Sha256(h) => h.finalize(),
            Self::Sha384(h) => h.finalize(),
            Self::Sha512(h) => h.finalize(),
            Self::Blake3(h) => h.finalize(),
        }
    }

    /// Finalizes the hash and returns the digest, then resets
    pub fn finalize_reset(&mut self) -> Vec<u8> {
        match self {
            Self::Sha256(h) => h.finalize_reset(),
            Self::Sha384(h) => h.finalize_reset(),
            Self::Sha512(h) => h.finalize_reset(),
            Self::Blake3(h) => h.finalize_reset(),
        }
    }

    /// Computes the hash of a single piece of data
    #[must_use]
    pub fn digest(algorithm: HashAlgorithm, data: &[u8]) -> Vec<u8> {
        match algorithm {
            HashAlgorithm::Sha256 => Sha256::digest(data),
            HashAlgorithm::Sha384 => Sha384::digest(data),
            HashAlgorithm::Sha512 => Sha512::digest(data),
            HashAlgorithm::Blake3 => Blake3::digest(data),
        }
    }

    /// Returns the hash algorithm type
    #[must_use]
    pub fn algorithm(&self) -> HashAlgorithm {
        match self {
            Self::Sha256(_) => HashAlgorithm::Sha256,
            Self::Sha384(_) => HashAlgorithm::Sha384,
            Self::Sha512(_) => HashAlgorithm::Sha512,
            Self::Blake3(_) => HashAlgorithm::Blake3,
        }
    }

    /// Returns the output size in bytes
    #[must_use]
    pub fn output_size(&self) -> usize {
        match self {
            Self::Sha256(h) => h.output_size(),
            Self::Sha384(h) => h.output_size(),
            Self::Sha512(h) => h.output_size(),
            Self::Blake3(h) => h.output_size(),
        }
    }
}

impl fmt::Debug for Hasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hasher")
            .field("algorithm", &self.algorithm())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors from NIST
    const SHA256_TEST_EMPTY: &str =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const SHA256_TEST_ABC: &str =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    #[test]
    fn test_hash_algorithm_metadata() {
        assert_eq!(HashAlgorithm::Sha256.name(), "SHA256");
        assert_eq!(HashAlgorithm::Sha256.output_size(), 32);
        assert_eq!(HashAlgorithm::Sha256.block_size(), 64);

        assert_eq!(HashAlgorithm::Blake3.name(), "BLAKE3");
        assert_eq!(HashAlgorithm::Blake3.output_size(), 32);
        assert_eq!(HashAlgorithm::Blake3.block_size(), 64);
    }

    #[test]
    fn test_hasher_unified() {
        let mut hasher = Hasher::new(HashAlgorithm::Sha256);
        hasher.update(b"abc");
        let result = hasher.finalize();

        assert_eq!(hex::encode(result), SHA256_TEST_ABC);
    }

    #[test]
    fn test_hasher_digest() {
        let result = Hasher::digest(HashAlgorithm::Sha256, b"");
        assert_eq!(hex::encode(result), SHA256_TEST_EMPTY);

        let result = Hasher::digest(HashAlgorithm::Sha256, b"abc");
        assert_eq!(hex::encode(result), SHA256_TEST_ABC);
    }
}
