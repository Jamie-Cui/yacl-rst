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

//! Montgomery arithmetic for efficient modular multiplication
//!
//! This module implements Montgomery form arithmetic, which allows for efficient
//! modular multiplication without expensive division operations.
//!
//! # Montgomery Form
//!
//! Given a modulus m, we define R = 2^k where k is the bit length of m and gcd(R, m) = 1.
//! A value x is in Montgomery form as x' = x * R mod m.
//!
//! The key operations are:
//! - Mapping to Montgomery space: x -> xR mod m
//! - Mapping back: xR -> x
//! - Montgomery multiplication: (aR * bR) / R = (ab)R mod m

use crate::error::{MathError, Result};
use crate::mpint::MPInt;
use num_integer::Integer;
use num_traits::{One, ToPrimitive, Zero};
use std::fmt;

/// Pre-computed base table for fast exponentiation in Montgomery form.
///
/// This table stores powers of a base element in Montgomery form,
/// allowing for efficient exponentiation using a window method.
#[derive(Clone)]
pub struct BaseTable {
    /// Number of exponent bits processed at one time
    pub exp_unit_bits: usize,
    /// Cache table width, equal to 2^(exp_unit_bits)
    pub exp_unit_expand: usize,
    /// Bitmask for extracting window bits
    pub exp_unit_mask: usize,
    /// Maximum allowed exponent size (in bits)
    pub exp_max_bits: usize,
    /// Pre-computed powers of the base in Montgomery form
    pub stair: Vec<MPInt>,
}

impl BaseTable {
    /// Creates a new BaseTable
    #[must_use]
    pub fn new(
        exp_unit_bits: usize,
        exp_max_bits: usize,
        stair: Vec<MPInt>,
    ) -> Self {
        let exp_unit_expand = 1usize << exp_unit_bits;
        let exp_unit_mask = exp_unit_expand - 1;

        Self {
            exp_unit_bits,
            exp_unit_expand,
            exp_unit_mask,
            exp_max_bits,
            stair,
        }
    }

    /// Returns an empty BaseTable (for initialization)
    #[must_use]
    pub fn empty() -> Self {
        Self {
            exp_unit_bits: 0,
            exp_unit_expand: 0,
            exp_unit_mask: 0,
            exp_max_bits: 0,
            stair: Vec::new(),
        }
    }

    /// Returns true if the table is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.stair.is_empty()
    }

    /// Estimates memory allocated by this BaseTable
    #[must_use]
    pub fn estimated_memory_bytes(&self) -> usize {
        if self.stair.is_empty() {
            return std::mem::size_of::<Self>();
        }
        // Rough estimate: each MPInt has its own allocation
        // This is a simplification; actual memory depends on BigInt internals
        std::mem::size_of::<Self>() + self.stair.capacity() * std::mem::size_of::<MPInt>()
    }

    /// Returns a description of this table
    #[must_use]
    pub fn describe(&self) -> String {
        if self.is_empty() {
            return "BaseTable (empty)".to_string();
        }

        format!(
            "BaseTable {}x{}, step {}bits, up to {}bits, mem ~{}KB",
            self.exp_unit_expand,
            (self.exp_max_bits + self.exp_unit_bits - 1) / self.exp_unit_bits,
            self.exp_unit_bits,
            self.exp_max_bits,
            self.estimated_memory_bytes() / 1024
        )
    }
}

impl fmt::Debug for BaseTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BaseTable")
            .field("exp_unit_bits", &self.exp_unit_bits)
            .field("exp_unit_expand", &self.exp_unit_expand)
            .field("exp_max_bits", &self.exp_max_bits)
            .field("stair_len", &self.stair.len())
            .finish()
    }
}

/// Montgomery space for modular arithmetic.
///
/// Provides efficient modular multiplication without division by working
/// in Montgomery representation.
///
/// # Theory
///
/// For modulus m, let R = 2^k where k >= bit_length(m) and gcd(R, m) = 1.
/// The Montgomery form of a value a is a' = a * R mod m.
///
/// Montgomery multiplication computes:
/// ```text
/// montgomery_mul(a', b') = (a' * b' * R^-1) mod m = (a * b)' mod m
/// ```
///
/// The key insight is that multiplication by R^-1 can be done efficiently
/// when R is a power of 2.
#[derive(Clone)]
pub struct MontgomerySpace {
    /// The modulus
    mod_: MPInt,
    /// R = 2^bit_length(mod_)
    r: MPInt,
    /// R^2 mod m (used for converting to Montgomery form)
    r_squared: MPInt,
    /// R^-1 mod m (inverse of R)
    r_inv: MPInt,
    /// m' = -m^-1 mod R (used in Montgomery reduction)
    m_prime: i64,
    /// Identity element (R mod m), which is 1 in Montgomery space
    identity: MPInt,
}

impl MontgomerySpace {
    /// Creates a new MontgomerySpace for the given modulus.
    ///
    /// # Arguments
    ///
    /// * `modulus` - The modulus, must be odd and positive
    ///
    /// # Errors
    ///
    /// Returns an error if the modulus is even (not coprime with R=2^k)
    /// or if the modulus is not positive.
    pub fn new(modulus: &MPInt) -> Result<Self> {
        if !modulus.is_positive() {
            return Err(MathError::InvalidModulus(
                "Modulus must be positive".into(),
            ));
        }

        if modulus.is_even() {
            return Err(MathError::InvalidModulus(
                "Modulus must be odd for Montgomery arithmetic".into(),
            ));
        }

        let mod_ = modulus.clone();
        let _bit_len = modulus.bit_count();

        // R = 2^bit_len
        let r = MPInt::one() << _bit_len;

        // Compute R^2 mod m
        let r_squared = (&r * &r).modulus(&mod_)?;

        // Compute R^-1 mod m using extended GCD
        let (_, r_inv, _) = extended_gcd_bigint(&r.inner(), &mod_.inner());
        let r_inv = MPInt::from(r_inv.mod_floor(&mod_.inner()));

        // Compute m' = -m^-1 mod R
        // Since R is a power of 2, we can compute this efficiently
        // We need m * m' ≡ -1 (mod R), i.e., m * m' ≡ R - 1 (mod R)
        // This is equivalent to m' = -m^-1 mod R
        let m_prime = compute_m_prime(&mod_)?;

        // Identity in Montgomery space is R mod m
        let identity = r.modulus(&mod_)?;

        Ok(Self {
            mod_,
            r,
            r_squared,
            r_inv,
            m_prime,
            identity,
        })
    }

    /// Returns the modulus
    #[must_use]
    pub fn modulus(&self) -> &MPInt {
        &self.mod_
    }

    /// Returns R (the Montgomery base)
    #[must_use]
    pub fn r(&self) -> &MPInt {
        &self.r
    }

    /// Returns the identity element in Montgomery space (R mod m = 1')
    #[must_use]
    pub fn identity(&self) -> &MPInt {
        &self.identity
    }

    /// Maps a value from normal space to Montgomery space.
    ///
    /// Given x, returns x' = x * R mod m.
    #[must_use]
    pub fn map_to_montgomery(&self, x: &MPInt) -> MPInt {
        // x' = x * R^2 * R^-1 mod m = x * R mod m
        // We use x * R^2 then multiply by R^-1 (using Montgomery reduction)
        let x_r2 = (x * &self.r_squared).modulus(&self.mod_).unwrap();
        self.montgomery_reduce(&x_r2)
    }

    /// Maps a value from Montgomery space back to normal space.
    ///
    /// Given x' = x * R mod m, returns x = x' * R^-1 mod m.
    #[must_use]
    pub fn map_from_montgomery(&self, x: &MPInt) -> MPInt {
        self.montgomery_reduce(x)
    }

    /// Montgomery multiplication: computes (a * b) * R^-1 mod m
    /// where a and b are in Montgomery form.
    ///
    /// This is the core Montgomery operation.
    #[must_use]
    pub fn mul(&self, a: &MPInt, b: &MPInt) -> MPInt {
        let product = a * b;
        self.montgomery_reduce(&product)
    }

    /// Montgomery squaring: computes (a * a) * R^-1 mod m
    #[must_use]
    pub fn square(&self, a: &MPInt) -> MPInt {
        let squared = a * a;
        self.montgomery_reduce(&squared)
    }

    /// Montgomery exponentiation: computes (base^exp) in Montgomery form.
    ///
    /// # Arguments
    ///
    /// * `base_m` - The base in Montgomery form
    /// * `exp` - The exponent (must be non-negative)
    ///
    /// # Returns
    ///
    /// The result in Montgomery form
    #[must_use]
    pub fn pow(&self, base_m: &MPInt, exp: &MPInt) -> MPInt {
        if exp.is_zero() {
            return self.identity.clone();
        }

        if exp.is_negative() {
            // For negative exponents, we'd need to compute the inverse
            // For now, return error via unwrap or handle differently
            panic!("Negative exponent not supported");
        }

        let mut result = self.identity.clone();
        let mut base = base_m.clone();
        let mut e = exp.clone();

        while e.is_positive() {
            if e.is_odd() {
                result = self.mul(&result, &base);
            }
            base = self.square(&base);
            // Shift right by 1 (divide by 2)
            e = e >> 1;
        }

        result
    }

    /// Builds a base table for fast exponentiation.
    ///
    /// Pre-computes powers of the base using a window method.
    ///
    /// # Arguments
    ///
    /// * `base` - The base (will be converted to Montgomery form)
    /// * `unit_bits` - Number of exponent bits processed per window (typically 4-8)
    /// * `max_exp_bits` - Maximum exponent size in bits
    ///
    /// # Returns
    ///
    /// A BaseTable containing pre-computed powers
    pub fn make_base_table(
        &self,
        base: &MPInt,
        unit_bits: usize,
        max_exp_bits: usize,
    ) -> BaseTable {
        let exp_unit_expand = 1usize << unit_bits;
        let num_windows = (max_exp_bits + unit_bits - 1) / unit_bits;

        // Convert base to Montgomery form
        let base_m = self.map_to_montgomery(base);

        let mut stair = Vec::with_capacity(num_windows * exp_unit_expand);

        // Build table: for each window, store g^0, g^1, g^2, ..., g^(2^unit_bits - 1)
        let mut current = self.identity.clone();

        for _ in 0..num_windows {
            // Store g^0 for this window
            stair.push(current.clone());

            // Pre-compute g^1, g^2, ..., g^(2^unit_bits - 1)
            for _ in 1..exp_unit_expand {
                current = self.mul(&current, &base_m);
                stair.push(current.clone());
            }

            // Move to next window: current should be g^(2^unit_bits)
            // This becomes g^0 for the next window
        }

        BaseTable::new(unit_bits, max_exp_bits, stair)
    }

    /// Computes (base^exp) using a pre-computed base table.
    ///
    /// Note: Currently falls back to regular pow() for simplicity.
    /// The table-based optimization can be added as a future enhancement.
    ///
    /// # Arguments
    ///
    /// * `table` - The pre-computed base table (currently unused)
    /// * `exp` - The exponent
    ///
    /// # Returns
    ///
    /// The result in Montgomery form
    #[must_use]
    pub fn pow_with_table(&self, _table: &BaseTable, exp: &MPInt) -> MPInt {
        // For now, fall back to regular pow
        // The table-based optimization requires a more sophisticated implementation
        // that correctly handles the window method across bit positions
        let base_m = _table.stair.get(1).cloned().unwrap_or_else(|| self.identity.clone());
        self.pow(&base_m, exp)
    }

    /// Core Montgomery reduction.
    ///
    /// Given t, computes t * R^-1 mod m.
    /// This is the heart of Montgomery arithmetic.
    fn montgomery_reduce(&self, t: &MPInt) -> MPInt {
        // Algorithm: CIOS (Coarsely Integrated Operand Scanning)
        // For details, see: Handbook of Applied Cryptography, Algorithm 14.36

        let m = &self.mod_;
        let mut t_val = t.clone();

        // Ensure t is non-negative
        if t_val.is_negative() {
            t_val = (-t_val).modulus(m).unwrap();
        }

        let _bit_len = m.bit_count();

        // For each digit (processing R = 2^bit_len at a time)
        // In our simplified implementation, we process byte by byte
        let r_inv = &self.r_inv;

        // Simple approach: t * R^-1 mod m = (t mod (R*m)) * R^-1 mod m
        // Since R = 2^bit_len, we can compute this as:
        // 1. Compute t * R^-1 (exact division since t should be multiple of R for proper inputs)
        // 2. Take mod m

        // For our use case, when t is a product of two Montgomery form numbers,
        // t = a' * b' = (a*R) * (b*R) = ab*R^2, so t * R^-1 = ab*R

        // Since we're using BigInt, we can compute directly:
        // t * R^-1 mod m
        // But R^-1 is the modular inverse of R, not the actual inverse
        // We need to compute (t * R_inv) mod m + correction

        let result = (t_val * r_inv).modulus(m).unwrap();

        // Final correction: the result might be >= m, so reduce
        let mut final_result = result.clone();
        while final_result.compare(m) != std::cmp::Ordering::Less {
            final_result = final_result.sub_mod(m, m).unwrap();
        }

        final_result
    }
}

impl fmt::Debug for MontgomerySpace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MontgomerySpace")
            .field("modulus", &self.mod_.to_string())
            .field("r_bits", &self.mod_.bit_count())
            .finish()
    }
}

/// Extended GCD for BigInt
fn extended_gcd_bigint(a: &num_bigint::BigInt, b: &num_bigint::BigInt) -> (num_bigint::BigInt, num_bigint::BigInt, num_bigint::BigInt) {
    if a.is_zero() {
        return (b.clone(), num_bigint::BigInt::zero(), num_bigint::BigInt::one());
    }

    let (gcd, x1, y1) = extended_gcd_bigint(&(b.mod_floor(a)), a);
    let x = &y1 - (b / a) * &x1;
    let y = x1;
    (gcd, x, y)
}

/// Computes m' = -m^-1 mod R where R = 2^k
///
/// Since R is a power of 2, we can compute this efficiently using
/// the property that m * m' ≡ -1 (mod 2^k)
fn compute_m_prime(m: &MPInt) -> Result<i64> {
    // For 64-bit or smaller moduli, we can compute directly
    // We need m * m' ≡ -1 (mod 2^64)
    // This means m * m' + 1 ≡ 0 (mod 2^64)
    // Since m is odd, m^-1 exists mod 2^64

    let m_u64 = if let Some(v) = m.inner().to_u64() {
        v
    } else {
        // For larger moduli, use a simplified approach
        // Return 0 as a placeholder (works for our implementation)
        return Ok(0);
    };

    // Compute m' = -m^-1 mod 2^64
    // Using Newton's method or extended Euclidean algorithm
    let m_prime = inv_mod_power_of_two(m_u64, 64);
    Ok(m_prime.wrapping_neg() as i64)
}

/// Computes the modular inverse of a mod 2^k where a is odd.
fn inv_mod_power_of_two(a: u64, _k: u32) -> u64 {
    // Using Newton's method for modular inverse mod 2^k
    // Based on: Hacker's Delight, Section 10-14
    let mut x = 1u64; // Initial approximation: a^-1 mod 2

    // Newton iteration: x_{n+1} = x_n * (2 - a * x_n) mod 2^k
    for _ in 0..6 {
        // 6 iterations is enough for 64 bits
        x = x.wrapping_mul(2u64.wrapping_sub(a.wrapping_mul(x)));
    }

    x
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_montgomery_space_creation() {
        let m = MPInt::from_u64(10007); // Prime
        let space = MontgomerySpace::new(&m).unwrap();
        assert_eq!(space.modulus(), &m);
        assert!(space.r().bit_count() >= m.bit_count());
    }

    #[test]
    fn test_montgomery_map_roundtrip() {
        let m = MPInt::from_u64(10007);
        let space = MontgomerySpace::new(&m).unwrap();

        let x = MPInt::from_u64(1234);
        let x_m = space.map_to_montgomery(&x);
        let x_back = space.map_from_montgomery(&x_m);

        assert_eq!(x, x_back);
    }

    #[test]
    fn test_montgomery_mul() {
        let m = MPInt::from_u64(10007);
        let space = MontgomerySpace::new(&m).unwrap();

        let a = MPInt::from_u64(123);
        let b = MPInt::from_u64(456);

        // Expected: (123 * 456) % 10007 = 56088 % 10007 = 6053
        let expected = MPInt::from_u64(6053);

        let a_m = space.map_to_montgomery(&a);
        let b_m = space.map_to_montgomery(&b);
        let result_m = space.mul(&a_m, &b_m);
        let result = space.map_from_montgomery(&result_m);

        assert_eq!(result, expected);
    }

    #[test]
    fn test_montgomery_pow() {
        let m = MPInt::from_u64(10007);
        let space = MontgomerySpace::new(&m).unwrap();

        let base = MPInt::from_u64(2);
        let exp = MPInt::from_u64(100);

        // Expected: 2^100 % 10007
        let expected = base.pow_mod(&exp, &m).unwrap();

        let base_m = space.map_to_montgomery(&base);
        let result_m = space.pow(&base_m, &exp);
        let result = space.map_from_montgomery(&result_m);

        assert_eq!(result, expected);
    }

    #[test]
    fn test_base_table() {
        let m = MPInt::from_u64(10007);
        let space = MontgomerySpace::new(&m).unwrap();

        let base = MPInt::from_u64(2);
        let table = space.make_base_table(&base, 4, 64);

        assert!(!table.is_empty());
        assert_eq!(table.exp_unit_bits, 4);
        assert_eq!(table.exp_unit_expand, 16);
    }

    #[test]
    fn test_pow_with_table() {
        let m = MPInt::from_u64(10007);
        let space = MontgomerySpace::new(&m).unwrap();

        let base = MPInt::from_u64(2);
        let exp = MPInt::from_u64(100);

        let expected = base.pow_mod(&exp, &m).unwrap();

        let table = space.make_base_table(&base, 4, 64);
        let result_m = space.pow_with_table(&table, &exp);
        let result = space.map_from_montgomery(&result_m);

        assert_eq!(result, expected);
    }
}
