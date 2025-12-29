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

//! Cryptographically secure random number generation
//!
//! This module provides secure random number generation using ChaCha20,
//! a cryptographically secure PRNG.

mod rng;
mod seedable;

pub use rng::{random_bytes, random_u128, random_u32, random_u64, random_usize, fill_random};
pub use seedable::{SeedableRng, ChaCha20Rng};

use std::fmt;

/// Random number generator configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RandConfig {
    /// Whether to use fast mode (less secure but faster)
    pub fast_mode: bool,
}

impl Default for RandConfig {
    fn default() -> Self {
        Self { fast_mode: false }
    }
}

impl RandConfig {
    /// Creates a new RandConfig
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets fast mode
    #[must_use]
    pub fn with_fast_mode(mut self, fast_mode: bool) -> Self {
        self.fast_mode = fast_mode;
        self
    }
}

/// Error type for random number generation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RandError {
    /// Buffer too large
    BufferTooLarge {
        /// Requested size
        requested: usize,
        /// Maximum allowed size
        max: usize,
    },
    /// Invalid range
    InvalidRange {
        /// The bound value
        bound: u64,
    },
}

impl fmt::Display for RandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooLarge { requested, max } => write!(
                f,
                "Buffer too large: requested {}, maximum is {}",
                requested, max
            ),
            Self::InvalidRange { bound } => {
                write!(f, "Invalid range: bound must be > 0, got {}", bound)
            }
        }
    }
}

impl std::error::Error for RandError {}

/// Result type for random operations
pub type Result<T> = std::result::Result<T, RandError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rand_config() {
        let config = RandConfig::new();
        assert_eq!(config.fast_mode, false);

        let config = RandConfig::new().with_fast_mode(true);
        assert_eq!(config.fast_mode, true);
    }

    #[test]
    fn test_random_bytes() {
        let bytes = random_bytes(32);
        assert_eq!(bytes.len(), 32);

        // Different calls should produce different results (with very high probability)
        let bytes2 = random_bytes(32);
        assert_ne!(bytes, bytes2);
    }

    #[test]
    fn test_random_u32() {
        let r1 = random_u32();
        let r2 = random_u32();
        // With extremely high probability, these should be different
        let r3 = random_u32();
        let r4 = random_u32();
        assert!(r1 != r2 || r3 != r4);
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
    fn test_fill_random() {
        let mut buf = [0u8; 16];
        fill_random(&mut buf);
        assert_ne!(buf, [0u8; 16]);

        let mut buf2 = [0u8; 16];
        fill_random(&mut buf2);
        assert_ne!(buf, buf2);
    }
}
