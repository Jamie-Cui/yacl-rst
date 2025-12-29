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

//! Core random number generation functions

use rand::Rng;
use rand::RngCore;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng as RandChaCha20Rng;
use std::cell::RefCell;

/// Thread-local RNG instance
thread_local! {
    static TLS_RNG: RefCell<RandChaCha20Rng> = RefCell::new(RandChaCha20Rng::from_entropy());
}

/// Generates random bytes and fills the provided buffer
///
/// # Arguments
///
/// * `buf` - Buffer to fill with random bytes
///
/// # Example
///
/// ```
/// use yacl_rand::fill_random;
///
/// let mut buf = [0u8; 32];
/// fill_random(&mut buf);
/// // buf is now filled with cryptographically secure random bytes
/// ```
pub fn fill_random(buf: &mut [u8]) {
    TLS_RNG.with_borrow_mut(|rng| rng.fill_bytes(buf));
}

/// Generates random bytes of the specified length
///
/// # Arguments
///
/// * `len` - Number of random bytes to generate
///
/// # Returns
///
/// A vector containing the random bytes
///
/// # Example
///
/// ```
/// use yacl_rand::random_bytes;
///
/// let bytes = random_bytes(32);
/// assert_eq!(bytes.len(), 32);
/// ```
#[must_use]
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    fill_random(&mut buf);
    buf
}

/// Generates a random `u32`
///
/// # Returns
///
/// A random `u32` value
#[must_use]
pub fn random_u32() -> u32 {
    TLS_RNG.with_borrow_mut(|rng| rng.next_u32())
}

/// Generates a random `u64`
///
/// # Returns
///
/// A random `u64` value
#[must_use]
pub fn random_u64() -> u64 {
    TLS_RNG.with_borrow_mut(|rng| rng.next_u64())
}

/// Generates a random `u128`
///
/// # Returns
///
/// A random `u128` value
#[must_use]
pub fn random_u128() -> u128 {
    TLS_RNG.with_borrow_mut(|rng| {
        let mut buf = [0u8; 16];
        rng.fill_bytes(&mut buf);
        u128::from_le_bytes(buf)
    })
}

/// Generates a random `usize`
///
/// # Returns
///
/// A random `usize` value
#[must_use]
pub fn random_usize() -> usize {
    TLS_RNG.with_borrow_mut(|rng| {
        let mut buf = [0u8; std::mem::size_of::<usize>()];
        rng.fill_bytes(&mut buf);
        usize::from_le_bytes(buf)
    })
}

/// Generates a random number in the range `[0, bound)`
///
/// This uses a rejection sampling approach to ensure uniform distribution.
///
/// # Arguments
///
/// * `bound` - Upper bound (exclusive)
///
/// # Returns
///
/// A random `u64` in the range `[0, bound)`
///
/// # Panics
///
/// Panics if `bound` is 0
#[must_use]
pub fn random_u64_below(bound: u64) -> u64 {
    assert!(bound > 0, "bound must be > 0");
    TLS_RNG.with_borrow_mut(|rng| rng.gen_range(0..bound))
}

/// Generates a random number in the range `[0, bound)`
///
/// This uses a rejection sampling approach to ensure uniform distribution.
///
/// # Arguments
///
/// * `bound` - Upper bound (exclusive)
///
/// # Returns
///
/// A random `u32` in the range `[0, bound)`
///
/// # Panics
///
/// Panics if `bound` is 0
#[must_use]
pub fn random_u32_below(bound: u32) -> u32 {
    assert!(bound > 0, "bound must be > 0");
    TLS_RNG.with_borrow_mut(|rng| rng.gen_range(0..bound))
}

/// Generates a random number in the range `[0, bound)`
///
/// This uses a rejection sampling approach to ensure uniform distribution.
///
/// # Arguments
///
/// * `bound` - Upper bound (exclusive)
///
/// # Returns
///
/// A random `usize` in the range `[0, bound)`
///
/// # Panics
///
/// Panics if `bound` is 0
#[must_use]
pub fn random_usize_below(bound: usize) -> usize {
    assert!(bound > 0, "bound must be > 0");
    TLS_RNG.with_borrow_mut(|rng| rng.gen_range(0..bound))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fill_random() {
        let mut buf = [0u8; 32];
        fill_random(&mut buf);
        assert_ne!(buf, [0u8; 32]);
    }

    #[test]
    fn test_random_bytes() {
        let bytes = random_bytes(32);
        assert_eq!(bytes.len(), 32);

        let bytes2 = random_bytes(32);
        assert_ne!(bytes, bytes2);
    }

    #[test]
    fn test_random_u32() {
        let r1 = random_u32();
        let r2 = random_u32();
        // Extremely unlikely to be equal
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_random_u64() {
        let r1 = random_u64();
        let r2 = random_u64();
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_random_u128() {
        let r1 = random_u128();
        let r2 = random_u128();
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_random_usize() {
        let r1 = random_usize();
        let r2 = random_usize();
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_random_u64_below() {
        for _ in 0..100 {
            let r = random_u64_below(100);
            assert!(r < 100);
        }
    }

    #[test]
    fn test_random_u32_below() {
        for _ in 0..100 {
            let r = random_u32_below(100);
            assert!(r < 100);
        }
    }

    #[test]
    fn test_random_usize_below() {
        for _ in 0..100 {
            let r = random_usize_below(100);
            assert!(r < 100);
        }
    }

    #[test]
    #[should_panic(expected = "bound must be > 0")]
    fn test_random_u64_below_panic() {
        random_u64_below(0);
    }
}
