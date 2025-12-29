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

//! HMAC (Hash-based Message Authentication Code) implementations
//!
//! This module provides HMAC implementations for various hash functions
//! including SHA256, SHA384, SHA512, and BLAKE3.

pub mod error;
mod hmac_blake3;
mod hmac_sha256;
mod hmac_sha384;
mod hmac_sha512;
mod utils;

pub use error::HmacError;
pub use hmac_blake3::HmacBlake3;
pub use hmac_sha256::HmacSha256;
pub use hmac_sha384::HmacSha384;
pub use hmac_sha512::HmacSha512;
pub use utils::{hmac_blake3, hmac_sha256, hmac_sha384, hmac_sha512};

use hash::HashAlgorithm;
use std::fmt;

/// HMAC algorithm identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HmacAlgorithm {
    /// HMAC with SHA-256
    HmacSha256,
    /// HMAC with SHA-384
    HmacSha384,
    /// HMAC with SHA-512
    HmacSha512,
    /// HMAC with BLAKE3
    HmacBlake3,
}

impl HmacAlgorithm {
    /// Returns the hash algorithm used by this HMAC
    #[must_use]
    pub fn hash_algorithm(&self) -> HashAlgorithm {
        match self {
            Self::HmacSha256 => HashAlgorithm::Sha256,
            Self::HmacSha384 => HashAlgorithm::Sha384,
            Self::HmacSha512 => HashAlgorithm::Sha512,
            Self::HmacBlake3 => HashAlgorithm::Blake3,
        }
    }

    /// Returns the name of this HMAC algorithm
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::HmacSha256 => "HMAC-SHA256",
            Self::HmacSha384 => "HMAC-SHA384",
            Self::HmacSha512 => "HMAC-SHA512",
            Self::HmacBlake3 => "HMAC-BLAKE3",
        }
    }

    /// Returns the output size in bytes
    #[must_use]
    pub fn output_size(&self) -> usize {
        self.hash_algorithm().output_size()
    }
}

/// Trait for HMAC implementations
///
/// This trait provides a unified interface for computing HMAC values.
pub trait Hmac: fmt::Debug + Send + Sync {
    /// Creates a new HMAC instance with the given key
    fn new(key: &[u8]) -> Self
    where
        Self: Sized;

    /// Updates the HMAC with additional data
    fn update(&mut self, data: &[u8]);

    /// Resets the HMAC to its initial state
    fn reset(&mut self)
    where
        Self: Sized;

    /// Finalizes the HMAC and returns the MAC
    ///
    /// This consumes the HMAC instance. Use `cumulative_mac()` if you
    /// want to reuse the instance.
    #[must_use]
    fn finalize(self) -> Vec<u8>;

    /// Computes the MAC without consuming the instance
    ///
    /// This allows continuing to update after getting the MAC.
    #[must_use]
    fn cumulative_mac(&self) -> Vec<u8>;

    /// Computes the HMAC of a single piece of data
    ///
    /// This is a convenience method for one-shot HMAC computation.
    #[must_use]
    fn hmac(key: &[u8], data: &[u8]) -> Vec<u8>
    where
        Self: Sized;

    /// Returns the HMAC algorithm type
    fn algorithm(&self) -> HmacAlgorithm;

    /// Returns the output size in bytes
    fn output_size(&self) -> usize;
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors from RFC 4231 (HMAC-SHA256)
    // Key: "key" (3 bytes)
    // Data: "The quick brown fox jumps over the lazy dog"
    const SHA256_TEST_KEY: &[u8] = b"key";
    const SHA256_TEST_DATA: &[u8] = b"The quick brown fox jumps over the lazy dog";
    const SHA256_TEST_MAC: &str =
        "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8";

    #[test]
    fn test_hmac_algorithm_metadata() {
        assert_eq!(HmacAlgorithm::HmacSha256.name(), "HMAC-SHA256");
        assert_eq!(HmacAlgorithm::HmacSha256.output_size(), 32);
        assert_eq!(
            HmacAlgorithm::HmacSha256.hash_algorithm(),
            HashAlgorithm::Sha256
        );
    }

    #[test]
    fn test_hmac_sha256_basic() {
        let mac = HmacSha256::hmac(SHA256_TEST_KEY, SHA256_TEST_DATA);
        assert_eq!(hex::encode(mac), SHA256_TEST_MAC);
    }
}
