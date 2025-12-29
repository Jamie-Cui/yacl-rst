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

//! Simple utility functions for one-shot HMAC computation

use crate::hmac_sha256::HmacSha256;
use crate::hmac_sha384::HmacSha384;
use crate::hmac_sha512::HmacSha512;
use crate::hmac_blake3::HmacBlake3;

/// Computes HMAC-SHA256 of the input data with the given key
///
/// # Arguments
///
/// * `key` - The HMAC key
/// * `data` - The data to authenticate
///
/// # Returns
///
/// A 32-byte MAC
#[must_use]
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let result = HmacSha256::hmac(key, data);
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// Computes HMAC-SHA384 of the input data with the given key
///
/// # Arguments
///
/// * `key` - The HMAC key
/// * `data` - The data to authenticate
///
/// # Returns
///
/// A 48-byte MAC
#[must_use]
pub fn hmac_sha384(key: &[u8], data: &[u8]) -> [u8; 48] {
    let result = HmacSha384::hmac(key, data);
    let mut output = [0u8; 48];
    output.copy_from_slice(&result);
    output
}

/// Computes HMAC-SHA512 of the input data with the given key
///
/// # Arguments
///
/// * `key` - The HMAC key
/// * `data` - The data to authenticate
///
/// # Returns
///
/// A 64-byte MAC
#[must_use]
pub fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let result = HmacSha512::hmac(key, data);
    let mut output = [0u8; 64];
    output.copy_from_slice(&result);
    output
}

/// Computes HMAC-BLAKE3 of the input data with the given key
///
/// # Arguments
///
/// * `key` - The HMAC key
/// * `data` - The data to authenticate
///
/// # Returns
///
/// A 32-byte MAC
#[must_use]
pub fn hmac_blake3(key: &[u8], data: &[u8]) -> [u8; 32] {
    let result = HmacBlake3::hmac(key, data);
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_utils_hmac_sha256() {
        let key = b"test_key";
        let data = b"test_data";
        let result = hmac_sha256(key, data);
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_utils_hmac_sha384() {
        let key = b"test_key";
        let data = b"test_data";
        let result = hmac_sha384(key, data);
        assert_eq!(result.len(), 48);
    }

    #[test]
    fn test_utils_hmac_sha512() {
        let key = b"test_key";
        let data = b"test_data";
        let result = hmac_sha512(key, data);
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn test_utils_hmac_blake3() {
        let key = b"test_key";
        let data = b"test_data";
        let result = hmac_blake3(key, data);
        assert_eq!(result.len(), 32);
    }
}
