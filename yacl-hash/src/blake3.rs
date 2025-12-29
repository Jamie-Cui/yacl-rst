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

//! BLAKE3 hash function

use crate::error::{HashError, Result};
use crate::{Hash, HashAlgorithm};
use blake3::Hasher as Blake3Hasher;
use std::fmt;

/// BLAKE3 hash function
///
/// BLAKE3 is a modern hash function that supports variable output length.
/// The default output is 32 bytes, but longer outputs are also supported.
#[derive(Clone)]
pub struct Blake3 {
    inner: Blake3Hasher,
    output_size: usize,
}

impl Blake3 {
    /// Creates a new BLAKE3 hasher with default 32-byte output
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Blake3Hasher::new(),
            output_size: 32,
        }
    }

    /// Creates a new BLAKE3 hasher with specified output size
    ///
    /// # Arguments
    ///
    /// * `output_size` - The desired output size in bytes
    ///
    /// # Panics
    ///
    /// Panics if output_size is 0
    #[must_use]
    pub fn with_output_size(output_size: usize) -> Self {
        assert!(output_size > 0, "output_size must be > 0");
        Self {
            inner: Blake3Hasher::new(),
            output_size,
        }
    }

    /// Finalizes the hash and returns the digest
    #[must_use]
    pub fn finalize(self) -> Vec<u8> {
        if self.output_size <= 32 {
            // For standard 32-byte output, use finalize()
            self.inner.finalize().as_bytes().to_vec()
        } else {
            // For longer outputs, use XOF (extendable-output function)
            let mut output = vec![0u8; self.output_size];
            self.inner.finalize_xof().fill(&mut output);
            output
        }
    }

    /// Finalizes the hash and returns the digest, then resets
    pub fn finalize_reset(&mut self) -> Vec<u8> {
        let hasher = self.inner.clone();
        let output = if self.output_size <= 32 {
            hasher.finalize().as_bytes().to_vec()
        } else {
            let mut out = vec![0u8; self.output_size];
            hasher.finalize_xof().fill(&mut out);
            out
        };
        self.inner.reset();
        output
    }

    /// Computes the hash of a single piece of data with default 32-byte output
    #[must_use]
    pub fn digest(data: &[u8]) -> Vec<u8> {
        blake3::hash(data).as_bytes().to_vec()
    }

    /// Computes the hash with a specified output size
    ///
    /// # Arguments
    ///
    /// * `data` - The data to hash
    /// * `output_size` - The desired output size in bytes
    ///
    /// # Errors
    ///
    /// Returns an error if output_size is 0
    pub fn digest_with_output_size(data: &[u8], output_size: usize) -> Result<Vec<u8>> {
        if output_size == 0 {
            return Err(HashError::InvalidOutputLength {
                requested: 0,
                max: usize::MAX,
            });
        }

        let hash = blake3::hash(data);
        let mut output = vec![0u8; output_size];

        // Copy the standard 32-byte hash
        output[..32.min(output_size)].copy_from_slice(
            hash.as_bytes().get(..output_size.min(32)).unwrap_or(hash.as_bytes())
        );

        // For outputs longer than 32 bytes, extend with XOF
        if output_size > 32 {
            let mut hasher = Blake3Hasher::new();
            hasher.update(data);
            hasher.finalize_xof().fill(&mut output[32..]);
        }

        Ok(output)
    }

    /// Returns the output size
    #[must_use]
    pub fn output_size(&self) -> usize {
        self.output_size
    }

    /// Sets the output size for finalization
    ///
    /// # Panics
    ///
    /// Panics if output_size is 0
    pub fn set_output_size(&mut self, output_size: usize) {
        assert!(output_size > 0, "output_size must be > 0");
        self.output_size = output_size;
    }
}

impl Default for Blake3 {
    fn default() -> Self {
        Self::new()
    }
}

impl Hash for Blake3 {
    fn new() -> Self {
        Self::new()
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
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
        HashAlgorithm::Blake3
    }

    fn output_size(&self) -> usize {
        self.output_size
    }
}

impl fmt::Debug for Blake3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Blake3")
            .field("algorithm", &HashAlgorithm::Blake3)
            .field("output_size", &self.output_size)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors from BLAKE3 spec
    const BLAKE3_EMPTY: &str = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
    const BLAKE3_ABC: &str = "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85";

    #[test]
    fn test_blake3_empty() {
        let result = Blake3::digest(b"");
        assert_eq!(hex::encode(result), BLAKE3_EMPTY);
    }

    #[test]
    fn test_blake3_abc() {
        let result = Blake3::digest(b"abc");
        assert_eq!(hex::encode(result), BLAKE3_ABC);
    }

    #[test]
    fn test_blake3_update() {
        let mut hasher = Blake3::new();
        hasher.update(b"abc");
        hasher.update(b"");
        let result = hasher.finalize();
        assert_eq!(hex::encode(result), BLAKE3_ABC);
    }

    #[test]
    fn test_blake3_finalize_reset() {
        let mut hasher = Blake3::new();
        hasher.update(b"abc");
        let result1 = hasher.finalize_reset();
        assert_eq!(hex::encode(result1), BLAKE3_ABC);

        hasher.update(b"abc");
        let result2 = hasher.finalize();
        assert_eq!(hex::encode(result2), BLAKE3_ABC);
    }

    #[test]
    fn test_blake3_algorithm() {
        let hasher = Blake3::new();
        assert_eq!(hasher.algorithm(), HashAlgorithm::Blake3);
        assert_eq!(hasher.output_size(), 32);
    }

    #[test]
    fn test_blake3_variable_output() {
        let mut hasher = Blake3::with_output_size(64);
        hasher.update(b"abc");
        let result = hasher.finalize();
        assert_eq!(result.len(), 64);
        // First 32 bytes should match standard output
        assert_eq!(hex::encode(&result[..32]), BLAKE3_ABC);
    }
}
