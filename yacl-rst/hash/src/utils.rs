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

//! Simple utility functions for one-shot hashing

use crate::sha256::Sha256;
use crate::sha384::Sha384;
use crate::sha512::Sha512;
use crate::blake3::Blake3;

/// Computes SHA-256 hash of the input data
///
/// # Arguments
///
/// * `data` - The data to hash
///
/// # Returns
///
/// A 32-byte hash digest
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let result = Sha256::digest(data);
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// Computes SHA-384 hash of the input data
///
/// # Arguments
///
/// * `data` - The data to hash
///
/// # Returns
///
/// A 48-byte hash digest
#[must_use]
pub fn sha384(data: &[u8]) -> [u8; 48] {
    let result = Sha384::digest(data);
    let mut output = [0u8; 48];
    output.copy_from_slice(&result);
    output
}

/// Computes SHA-512 hash of the input data
///
/// # Arguments
///
/// * `data` - The data to hash
///
/// # Returns
///
/// A 64-byte hash digest
#[must_use]
pub fn sha512(data: &[u8]) -> [u8; 64] {
    let result = Sha512::digest(data);
    let mut output = [0u8; 64];
    output.copy_from_slice(&result);
    output
}

/// Computes BLAKE3 hash of the input data
///
/// # Arguments
///
/// * `data` - The data to hash
///
/// # Returns
///
/// A 32-byte hash digest
#[must_use]
pub fn blake3(data: &[u8]) -> [u8; 32] {
    let result = Blake3::digest(data);
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA256_EMPTY: &str =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const BLAKE3_EMPTY: &str =
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";

    #[test]
    fn test_utils_sha256() {
        let result = sha256(b"");
        assert_eq!(hex::encode(result), SHA256_EMPTY);
    }

    #[test]
    fn test_utils_blake3() {
        let result = blake3(b"");
        assert_eq!(hex::encode(result), BLAKE3_EMPTY);
    }

    #[test]
    fn test_utils_sha384() {
        let result = sha384(b"");
        assert_eq!(result.len(), 48);
    }

    #[test]
    fn test_utils_sha512() {
        let result = sha512(b"");
        assert_eq!(result.len(), 64);
    }
}
