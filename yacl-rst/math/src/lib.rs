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

//! # yacl-rst/math
//!
//! Cryptographic math utilities - Rust port of the yacl math module.
//!
//! This crate provides mathematical primitives and utilities for cryptographic
//! operations, including:
//!
//! - **MPInt**: Multiple precision integer arithmetic with modular operations
//! - **Montgomery arithmetic**: Efficient modular multiplication
//! - **Galois Fields**: Abstractions for finite field operations
//! - **Utility functions**: Logarithms, ceiling division, etc.
//!
//! ## Modules
//!
//! - [`mpint`] - Multiple precision integer type wrapping `num_bigint`
//! - [`montgomery`] - Montgomery form arithmetic for efficient modular operations
//! - [`galois`] - Finite field abstractions (GF_p, GF_p^k, GF_2^k)
//! - [`gadget`] - Simple mathematical utility functions
//! - [`error`] - Error types for math operations
//!
//! ## Examples
//!
//! ```rust
//! use yacl_math::mpint::MPInt;
//!
//! // Create large integers
//! let a = MPInt::from_u64(12345);
//! let b = MPInt::from_str("0xdeadbeef", 0).unwrap();
//!
//! // Modular arithmetic
//! let m = MPInt::from_u64(10007);
//! let sum = a.add_mod(&b, &m).unwrap();
//!
//! // Modular exponentiation
//! let base = MPInt::from_u64(2);
//! let exp = MPInt::from_u64(100);
//! let result = base.pow_mod(&exp, &m).unwrap();
//! ```
//!
//! ```rust
//! use yacl_math::galois::{PrimeField, GaloisField};
//! use yacl_math::mpint::MPInt;
//!
//! // Create a prime field GF(10007)
//! let field = PrimeField::new(MPInt::from_u64(10007));
//!
//! let a = MPInt::from_u64(123);
//! let b = MPInt::from_u64(456);
//!
//! // Field arithmetic
//! let sum = field.add(&a, &b);
//! let product = field.mul(&a, &b);
//! let inverse = field.invert(&a).unwrap();
//! ```

pub mod error;
pub mod gadget;
pub mod galois;
pub mod montgomery;
pub mod mpint;

// Re-export commonly used types
pub use error::{MathError, Result};
pub use gadget::{div_ceil, gcd, is_power_of_two, lcm, log2_ceil, log2_floor, round_up_to};
pub use galois::{FieldType, GaloisField, PrimeField};
pub use montgomery::{BaseTable, MontgomerySpace};
pub use mpint::{PrimeType, MPInt};

/// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::ToPrimitive;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_mpint_basic() {
        let a = MPInt::from_u64(42);
        let b = MPInt::from_u64(10);

        assert_eq!((&a + &b).inner().to_u64().unwrap(), 52);
        assert_eq!((&a - &b).inner().to_u64().unwrap(), 32);
        assert_eq!((&a * &b).inner().to_u64().unwrap(), 420);
    }

    #[test]
    fn test_gadget_functions() {
        assert_eq!(log2_floor(16), 4);
        assert_eq!(log2_ceil(16), 4);
        assert_eq!(log2_ceil(17), 5);
        assert_eq!(div_ceil(10, 3), 4);
        assert_eq!(round_up_to(10, 8), 16);
        assert!(is_power_of_two(16));
        assert!(!is_power_of_two(15));
        assert_eq!(gcd(48, 18), 6);
        assert_eq!(lcm(4, 6), 12);
    }

    #[test]
    fn test_prime_field() {
        let p = MPInt::from_u64(10007);
        let field = PrimeField::new(p.clone());

        let a = MPInt::from_u64(123);
        let b = MPInt::from_u64(456);

        let sum = field.add(&a, &b);
        assert_eq!(sum, MPInt::from_u64(579));

        let product = field.mul(&a, &b);
        assert_eq!(product, MPInt::from_u64(56088).modulus(&p).unwrap());
    }
}
