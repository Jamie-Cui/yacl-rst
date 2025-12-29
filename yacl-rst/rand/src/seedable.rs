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

//! Seedable random number generator for testing

use rand_chacha::ChaCha20Rng as RandChaCha20Rng;
use rand_ext::Rng;
use rand_ext::RngCore;
use rand_ext::SeedableRng as RandSeedableRng;
use std::fmt;

/// Trait for seedable random number generators
///
/// This trait provides a common interface for RNGs that can be seeded
/// with reproducible values.
pub trait SeedableRng: fmt::Debug + Send + Sync {
    /// Creates a new RNG from a seed
    fn from_seed(seed: u64) -> Self;

    /// Fills a buffer with random bytes
    fn fill_bytes(&mut self, buf: &mut [u8]);

    /// Generates a random `u32`
    fn next_u32(&mut self) -> u32;

    /// Generates a random `u64`
    fn next_u64(&mut self) -> u64;

    /// Generates a random `u128`
    fn next_u128(&mut self) -> u128;

    /// Generates a random number in `[0, bound)`
    fn next_u64_below(&mut self, bound: u64) -> u64;

    /// Generates a random number in `[0, bound)`
    fn next_u32_below(&mut self, bound: u32) -> u32;
}

/// ChaCha20-based seedable RNG
///
/// This is a cryptographically secure PRNG that can be seeded with
/// a reproducible value for testing purposes.
#[derive(Clone)]
pub struct ChaCha20Rng {
    inner: RandChaCha20Rng,
}

impl ChaCha20Rng {
    /// Creates a new RNG from a 64-bit seed
    #[must_use]
    pub fn from_seed(seed: u64) -> Self {
        Self {
            inner: RandChaCha20Rng::seed_from_u64(seed),
        }
    }

    /// Creates a new RNG from entropy (non-deterministic)
    #[must_use]
    pub fn from_entropy() -> Self {
        Self {
            inner: RandChaCha20Rng::from_entropy(),
        }
    }
}

impl Default for ChaCha20Rng {
    fn default() -> Self {
        Self::from_entropy()
    }
}

impl SeedableRng for ChaCha20Rng {
    fn from_seed(seed: u64) -> Self {
        Self::from_seed(seed)
    }

    fn fill_bytes(&mut self, buf: &mut [u8]) {
        self.inner.fill_bytes(buf);
    }

    fn next_u32(&mut self) -> u32 {
        self.inner.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.inner.next_u64()
    }

    fn next_u128(&mut self) -> u128 {
        let mut buf = [0u8; 16];
        self.inner.fill_bytes(&mut buf);
        u128::from_le_bytes(buf)
    }

    fn next_u64_below(&mut self, bound: u64) -> u64 {
        self.inner.gen_range(0..bound)
    }

    fn next_u32_below(&mut self, bound: u32) -> u32 {
        self.inner.gen_range(0..bound)
    }
}

impl fmt::Debug for ChaCha20Rng {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChaCha20Rng")
            .field("inner", &"<ChaCha20Rng>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seedable_reproducibility() {
        let seed = 42u64;
        let mut rng1 = ChaCha20Rng::from_seed(seed);
        let mut rng2 = ChaCha20Rng::from_seed(seed);

        // Same seed should produce same sequence
        assert_eq!(rng1.next_u64(), rng2.next_u64());
        assert_eq!(rng1.next_u32(), rng2.next_u32());

        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];
        rng1.fill_bytes(&mut buf1);
        rng2.fill_bytes(&mut buf2);
        assert_eq!(buf1, buf2);
    }

    #[test]
    fn test_seedable_different_seeds() {
        let mut rng1 = ChaCha20Rng::from_seed(1);
        let mut rng2 = ChaCha20Rng::from_seed(2);

        // Different seeds should produce different sequences
        assert_ne!(rng1.next_u64(), rng2.next_u64());
    }

    #[test]
    fn test_seedable_u128() {
        let mut rng = ChaCha20Rng::from_seed(42);
        let r1 = rng.next_u128();
        let r2 = rng.next_u128();
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_seedable_below() {
        let mut rng = ChaCha20Rng::from_seed(42);

        for _ in 0..100 {
            let r = rng.next_u64_below(100);
            assert!(r < 100);
        }

        for _ in 0..100 {
            let r = rng.next_u32_below(50);
            assert!(r < 50);
        }
    }

    #[test]
    fn test_seedable_fill_bytes() {
        let mut rng = ChaCha20Rng::from_seed(42);
        let mut buf = [0u8; 32];
        rng.fill_bytes(&mut buf);
        assert_ne!(buf, [0u8; 32]);
    }

    #[test]
    fn test_from_entropy_different() {
        let mut rng1 = ChaCha20Rng::from_entropy();
        let mut rng2 = ChaCha20Rng::from_entropy();

        // From entropy should produce different sequences (with overwhelming probability)
        assert_ne!(rng1.next_u64(), rng2.next_u64());
    }
}
