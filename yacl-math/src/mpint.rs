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

//! Multiple Precision Integer (MPInt) implementation
//!
//! This module provides a big integer type `MPInt` that wraps `num_bigint::BigInt`
//! with additional functionality for cryptographic operations.

use crate::error::{MathError, Result};
use num_bigint::{BigInt, BigUint};
use num_integer::Integer;
use num_traits::{One, Signed, ToPrimitive, Zero};
use rand::Rng;
use std::cmp::Ordering;
use std::fmt;
use std::ops::*;

/// Prime type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrimeType {
    /// Normal prime (p is prime)
    Normal = 0,
    /// Blum Blum Shub prime (p = 3 mod 4)
    BBS = 1,
    /// Safe prime ((p-1)/2 is prime)
    Safe = 2,
    /// Fast safe prime ((p-1)/2 is prime, optimized verification)
    FastSafe = 8,
}

/// Multiple Precision Integer
///
/// A wrapper around `num_bigint::BigInt` providing cryptographic utility functions.
#[derive(Clone, Debug)]
#[repr(transparent)]
pub struct MPInt {
    inner: BigInt,
}

impl MPInt {
    //===============================//
    //         Constructors          //
    //===============================//

    /// Creates a new MPInt with value 0
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self { inner: BigInt::zero() }
    }

    /// Creates a new MPInt from the inner BigInt
    #[inline]
    #[must_use]
    pub const fn from_inner(inner: BigInt) -> Self {
        Self { inner }
    }

    /// Gets a reference to the inner BigInt
    #[inline]
    #[must_use]
    pub const fn inner(&self) -> &BigInt {
        &self.inner
    }

    /// Consumes self and returns the inner BigInt
    #[inline]
    #[must_use]
    pub fn into_inner(self) -> BigInt {
        self.inner
    }

    /// Creates an MPInt from an i64
    #[inline]
    #[must_use]
    pub fn from_i64(value: i64) -> Self {
        Self {
            inner: BigInt::from(value),
        }
    }

    /// Creates an MPInt from a u64
    #[inline]
    #[must_use]
    pub fn from_u64(value: u64) -> Self {
        Self {
            inner: BigInt::from(value),
        }
    }

    /// Creates an MPInt from a u128
    #[inline]
    #[must_use]
    pub fn from_u128(value: u128) -> Self {
        Self {
            inner: BigInt::from(value),
        }
    }

    /// Creates an MPInt from a signed byte slice (big-endian)
    #[inline]
    pub fn from_bytes_be(bytes: &[u8]) -> Result<Self> {
        Ok(Self {
            inner: BigInt::from_signed_bytes_be(bytes),
        })
    }

    /// Creates an MPInt from an unsigned byte slice (big-endian)
    /// The result is always positive.
    #[inline]
    pub fn from_bytes_be_unsigned(bytes: &[u8]) -> Self {
        Self {
            inner: BigInt::from(BigUint::from_bytes_be(bytes)),
        }
    }

    /// Creates an MPInt from a signed byte slice (little-endian)
    #[inline]
    pub fn from_bytes_le(bytes: &[u8]) -> Result<Self> {
        Ok(Self {
            inner: BigInt::from_signed_bytes_le(bytes),
        })
    }

    /// Creates an MPInt from an unsigned byte slice (little-endian)
    /// The result is always positive.
    #[inline]
    pub fn from_bytes_le_unsigned(bytes: &[u8]) -> Self {
        Self {
            inner: BigInt::from(BigUint::from_bytes_le(bytes)),
        }
    }

    /// Parses an MPInt from a string
    ///
    /// If radix is 0, auto-detects:
    /// - "0x" prefix -> radix 16
    /// - "0" prefix -> radix 8
    /// - otherwise -> radix 10
    ///
    /// Supports optional leading minus sign.
    pub fn from_str(s: &str, radix: u32) -> Result<Self> {
        let actual_radix = if radix == 0 {
            let s_trimmed = s.trim_start_matches('-');
            if s_trimmed.starts_with("0x") || s_trimmed.starts_with("0X") {
                16
            } else if s_trimmed.starts_with('0') && s_trimmed.len() > 1 {
                8
            } else {
                10
            }
        } else {
            radix
        };

        let to_parse = if actual_radix == 16 {
            // Remove 0x prefix for hex parsing
            let mut result = s.trim_start_matches('-');
            if result.starts_with("0x") || result.starts_with("0X") {
                result = &result[2..];
            }
            if s.starts_with('-') {
                format!("-{}", result)
            } else {
                result.to_string()
            }
        } else {
            s.to_string()
        };

        Ok(Self {
            inner: BigInt::parse_bytes(to_parse.as_bytes(), actual_radix)
                .ok_or_else(|| MathError::InvalidInput(format!("Failed to parse: {}", s)))?,
        })
    }

    //===============================//
    //      Getters and setters       //
    //===============================//

    /// Returns true if the value is zero
    #[inline]
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.inner.is_zero()
    }

    /// Returns true if the value is one
    #[inline]
    #[must_use]
    pub fn is_one(&self) -> bool {
        self.inner.is_one()
    }

    /// Returns true if the value is negative
    #[inline]
    #[must_use]
    pub fn is_negative(&self) -> bool {
        self.inner.is_negative()
    }

    /// Returns true if the value is a natural number (>= 0)
    #[inline]
    #[must_use]
    pub fn is_natural(&self) -> bool {
        !self.inner.is_negative()
    }

    /// Returns true if the value is positive (> 0)
    #[inline]
    #[must_use]
    pub fn is_positive(&self) -> bool {
        self.inner.is_positive()
    }

    /// Returns true if the value is odd
    #[inline]
    #[must_use]
    pub fn is_odd(&self) -> bool {
        self.inner.is_odd()
    }

    /// Returns true if the value is even
    #[inline]
    #[must_use]
    pub fn is_even(&self) -> bool {
        self.inner.is_even()
    }

    /// Gets the bit at the given index (0 = LSB)
    /// Returns 0 or 1
    #[must_use]
    pub fn get_bit(&self, index: i64) -> u8 {
        if index < 0 {
            return 0;
        }
        let index = index as usize;
        let (_sign, digits) = self.inner.to_bytes_be();
        if digits.is_empty() {
            return 0;
        }

        let byte_index = digits.len().saturating_sub(index / 8 + 1);
        if byte_index >= digits.len() {
            return 0;
        }

        let bit_offset = (index % 8) as u8;
        (digits[byte_index] >> bit_offset) & 1
    }

    /// Sets the bit at the given index (0 = LSB)
    pub fn set_bit(&mut self, index: i64, bit: u8) {
        if index < 0 {
            return;
        }
        let index = index as usize;
        let bit_value = bit & 1;

        if bit_value == 1 {
            // Set bit to 1
            let mask = BigInt::one() << index;
            self.inner |= mask;
        } else {
            // Set bit to 0
            let mask = BigInt::one() << index;
            self.inner &= !mask;
        }
    }

    /// Returns the number of bits required to represent this value
    /// For negative numbers, returns bits for absolute value.
    #[must_use]
    pub fn bit_count(&self) -> usize {
        if self.is_zero() {
            return 0;
        }
        let abs = self.inner.abs();
        abs.bits() as usize
    }

    //===============================//
    //          Comparators           //
    //===============================//

    /// Compares this MPInt with another
    /// Returns Greater, Equal, or Less
    #[inline]
    #[must_use]
    pub fn compare(&self, other: &Self) -> Ordering {
        self.inner.cmp(&other.inner)
    }

    /// Compares absolute values
    #[must_use]
    pub fn compare_abs(&self, other: &Self) -> Ordering {
        self.inner.abs().cmp(&other.inner.abs())
    }

    //===============================//
    //           Operations           //
    //===============================//

    /// Returns the absolute value
    #[inline]
    #[must_use]
    pub fn abs(&self) -> Self {
        Self {
            inner: self.inner.abs(),
        }
    }

    /// Negates this value in place
    #[inline]
    pub fn negate_inplace(&mut self) {
        self.inner = -self.inner.clone();
    }

    /// Increment by 1 (in place)
    pub fn incr(&mut self) {
        self.inner += 1;
    }

    /// Decrement by 1 (in place)
    pub fn decr(&mut self) {
        self.inner -= 1;
    }

    /// Modular addition: (self + b) mod m
    /// All values should be non-negative and less than m.
    #[must_use]
    pub fn add_mod(&self, b: &Self, m: &Self) -> Result<Self> {
        if m.is_zero() {
            return Err(MathError::InvalidModulus("Modulus cannot be zero".into()));
        }
        let sum = &self.inner + &b.inner;
        Ok(Self {
            inner: sum.mod_floor(&m.inner),
        })
    }

    /// Modular subtraction: (self - b) mod m
    #[must_use]
    pub fn sub_mod(&self, b: &Self, m: &Self) -> Result<Self> {
        if m.is_zero() {
            return Err(MathError::InvalidModulus("Modulus cannot be zero".into()));
        }
        let diff = &self.inner - &b.inner;
        let diff_mod = diff.mod_floor(&m.inner);
        Ok(Self { inner: diff_mod })
    }

    /// Modular multiplication: (self * b) mod m
    #[must_use]
    pub fn mul_mod(&self, b: &Self, m: &Self) -> Result<Self> {
        if m.is_zero() {
            return Err(MathError::InvalidModulus("Modulus cannot be zero".into()));
        }
        let product = &self.inner * &b.inner;
        Ok(Self {
            inner: product.mod_floor(&m.inner),
        })
    }

    /// Modular exponentiation: (self ^ exp) mod m
    ///
    /// Uses exponentiation by squaring.
    #[must_use]
    pub fn pow_mod(&self, exp: &Self, m: &Self) -> Result<Self> {
        if m.is_zero() {
            return Err(MathError::InvalidModulus("Modulus cannot be zero".into()));
        }
        if exp.is_negative() {
            return Err(MathError::InvalidInput("Exponent must be non-negative".into()));
        }

        // For large exponents, use the BigUint version
        let exp_abs: BigUint = exp.inner.abs().to_biguint().unwrap();
        let base_abs: BigUint = self.inner.abs().to_biguint().unwrap();
        let mod_abs: BigUint = m.inner.abs().to_biguint().unwrap();

        let result = base_abs.modpow(&exp_abs, &mod_abs);
        Ok(Self {
            inner: BigInt::from(result),
        })
    }

    /// Regular exponentiation: self ^ exp (where exp is a small integer)
    #[must_use]
    pub fn pow(&self, exp: u32) -> Self {
        Self {
            inner: self.inner.pow(exp),
        }
    }

    /// Modular inverse: finds x such that (self * x) ≡ 1 (mod m)
    ///
    /// Returns an error if the inverse doesn't exist (i.e., self and m are not coprime).
    #[must_use]
    pub fn invert_mod(&self, m: &Self) -> Result<Self> {
        if m.is_zero() {
            return Err(MathError::InvalidModulus("Modulus cannot be zero".into()));
        }

        // Use extended GCD to find modular inverse
        let a = self.inner.mod_floor(&m.inner);
        let (gcd, x, _) = extended_gcd(&a, &m.inner);

        if gcd != BigInt::one() {
            return Err(MathError::NoModularInverse);
        }

        Ok(Self { inner: x.mod_floor(&m.inner) })
    }

    /// Modulo operation: self % m
    #[must_use]
    pub fn modulus(&self, m: &Self) -> Result<Self> {
        if m.is_zero() {
            return Err(MathError::DivisionByZero);
        }
        Ok(Self {
            inner: self.inner.mod_floor(&m.inner),
        })
    }

    /// Greatest common divisor
    #[must_use]
    pub fn gcd(&self, other: &Self) -> Self {
        Self {
            inner: self.inner.gcd(&other.inner),
        }
    }

    /// Least common multiple
    #[must_use]
    pub fn lcm(&self, other: &Self) -> Self {
        Self {
            inner: self.inner.lcm(&other.inner),
        }
    }

    //===============================//
    //              I/O               //
    //===============================//

    /// Converts to signed bytes (big-endian)
    /// Uses two's complement for negative numbers.
    #[must_use]
    pub fn to_bytes_be(&self) -> Vec<u8> {
        self.inner.to_signed_bytes_be()
    }

    /// Converts to signed bytes (little-endian)
    /// Uses two's complement for negative numbers.
    #[must_use]
    pub fn to_bytes_le(&self) -> Vec<u8> {
        self.inner.to_signed_bytes_le()
    }

    /// Converts to unsigned bytes (big-endian)
    /// Returns the magnitude (absolute value) as bytes.
    #[must_use]
    pub fn to_bytes_be_unsigned(&self) -> Vec<u8> {
        self.inner
            .to_biguint()
            .map(|u| u.to_bytes_be())
            .unwrap_or_default()
    }

    /// Converts to unsigned bytes (little-endian)
    /// Returns the magnitude (absolute value) as bytes.
    #[must_use]
    pub fn to_bytes_le_unsigned(&self) -> Vec<u8> {
        self.inner
            .to_biguint()
            .map(|u| u.to_bytes_le())
            .unwrap_or_default()
    }

    /// Converts to bytes with specified length (big-endian)
    /// Pads or truncates to the specified length.
    /// For negative numbers, uses two's complement representation.
    pub fn to_bytes_be_with_len(&self, len: usize) -> Vec<u8> {
        let mut bytes = self.to_bytes_be();
        if self.is_negative() {
            // Sign-extend for negative numbers
            if bytes.len() < len {
                let padding = vec![0xFFu8; len - bytes.len()];
                bytes = [padding.as_slice(), bytes.as_slice()].concat();
            }
        } else {
            // Zero-pad for positive numbers
            if bytes.len() < len {
                let padding = vec![0u8; len - bytes.len()];
                bytes = [padding.as_slice(), bytes.as_slice()].concat();
            }
        }
        // Truncate if too long
        bytes.into_iter().rev().take(len).rev().collect()
    }

    /// Converts to decimal string
    #[must_use]
    pub fn to_string(&self) -> String {
        self.inner.to_string()
    }

    /// Converts to hexadecimal string (without "0x" prefix)
    /// For negative numbers, includes a leading '-'.
    #[must_use]
    pub fn to_hex_string(&self) -> String {
        let (_sign, digits) = self.inner.to_bytes_be();
        let hex: String = digits.iter().map(|b| format!("{:02x}", b)).collect();
        if self.is_negative() {
            format!("-{}", hex.trim_start_matches('0'))
        } else {
            hex.trim_start_matches('0').to_string()
        }
    }

    /// Converts to string with specified radix
    #[must_use]
    pub fn to_radix_string(&self, radix: u32) -> String {
        self.inner.to_str_radix(radix)
    }

    //===============================//
    //           Random              //
    //===============================//

    /// Generates a random MPInt with approximately the given bit size.
    /// The most significant bit will be set with 50% probability.
    pub fn random<R: Rng>(rng: &mut R, bit_size: usize) -> Self {
        if bit_size == 0 {
            return Self::new();
        }

        let byte_count = (bit_size + 7) / 8;
        let mut bytes = vec![0u8; byte_count];
        rng.fill_bytes(&mut bytes);

        // Ensure the most significant bit is set with 50% probability
        let remaining_bits = bit_size % 8;
        if remaining_bits > 0 {
            let mask = (1u8 << remaining_bits) - 1;
            bytes[0] &= mask;
        }

        Self::from_bytes_be_unsigned(&bytes)
    }

    /// Generates a random MPInt with exactly the given bit size.
    /// The most significant bit is always set (monic).
    pub fn random_monic<R: Rng>(rng: &mut R, bit_size: usize) -> Self {
        if bit_size == 0 {
            return Self::new();
        }

        let byte_count = (bit_size + 7) / 8;
        let mut bytes = vec![0u8; byte_count];
        rng.fill_bytes(&mut bytes);

        // Set the most significant bit
        let bit_offset = (bit_size - 1) % 8;
        bytes[0] |= 1 << bit_offset;

        // Clear higher bits in the first byte
        let mask = (1u8 << (bit_offset + 1)) - 1;
        bytes[0] &= mask;

        Self::from_bytes_be_unsigned(&bytes)
    }

    /// Generates a random MPInt in the range [0, n)
    pub fn random_lt<R: Rng>(rng: &mut R, n: &Self) -> Result<Self> {
        if n.is_zero() || n.is_negative() {
            return Err(MathError::InvalidInput(
                "Upper bound must be positive".into(),
            ));
        }

        let bit_count = n.bit_count();
        loop {
            let r = Self::random_monic(rng, bit_count);
            if r.compare(n) == Ordering::Less {
                return Ok(r);
            }
        }
    }

    //===============================//
    //          Prime tools          //
    //===============================//

    /// Probabilistic primality test using Miller-Rabin.
    /// Uses the number of rounds appropriate for the bit size.
    #[must_use]
    pub fn is_prime(&self) -> bool {
        if self.inner <= BigInt::one() {
            return false;
        }
        if self.inner <= BigInt::from(3u32) {
            return true;
        }
        if self.is_even() {
            return false;
        }

        // Miller-Rabin with appropriate number of rounds
        let bit_count = self.bit_count();
        let rounds = if bit_count < 256 {
            12
        } else if bit_count < 512 {
            15
        } else if bit_count < 1024 {
            20
        } else if bit_count < 2048 {
            25
        } else {
            40
        };

        self.miller_rabin(rounds)
    }

    /// Miller-Rabin primality test with specified number of rounds.
    fn miller_rabin(&self, rounds: usize) -> bool {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::from_entropy();

        let n = &self.inner;
        let n_minus_1 = n - 1u32;

        // Write n-1 as 2^r * d where d is odd
        let mut d = n_minus_1.clone();
        let mut r = 0u32;
        while d.is_even() {
            d /= 2u32;
            r += 1;
        }

        for _ in 0..rounds {
            let a = BigInt::from(rng.gen::<u64>() % 10000u64 + 2);
            let x = a.modpow(&d, n);

            if x == BigInt::one() || x == n_minus_1 {
                continue;
            }

            let mut composite = true;
            for _ in 0..(r - 1) {
                let x_squared = x.modpow(&BigInt::from(2u32), n);
                if x_squared == n_minus_1 {
                    composite = false;
                    break;
                }
            }

            if composite {
                return false;
            }
        }

        true
    }
}

/// Extended GCD algorithm
/// Returns (gcd, x, y) such that a*x + b*y = gcd
fn extended_gcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    if a.is_zero() {
        (b.clone(), BigInt::zero(), BigInt::one())
    } else {
        let (gcd, x1, y1) = extended_gcd(&(b.mod_floor(a)), a);
        let x = y1 - (b / a) * &x1;
        let y = x1;
        (gcd, x, y)
    }
}

//===============================//
//              Trait impls       //
//===============================

impl Default for MPInt {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl Zero for MPInt {
    #[inline]
    fn zero() -> Self {
        Self::new()
    }

    #[inline]
    fn is_zero(&self) -> bool {
        self.inner.is_zero()
    }
}

impl One for MPInt {
    #[inline]
    fn one() -> Self {
        Self {
            inner: BigInt::one(),
        }
    }

    #[inline]
    fn is_one(&self) -> bool {
        self.inner.is_one()
    }
}

impl fmt::Display for MPInt {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl From<i8> for MPInt {
    #[inline]
    fn from(value: i8) -> Self {
        Self {
            inner: BigInt::from(value),
        }
    }
}

impl From<u8> for MPInt {
    #[inline]
    fn from(value: u8) -> Self {
        Self {
            inner: BigInt::from(value),
        }
    }
}

impl From<i16> for MPInt {
    #[inline]
    fn from(value: i16) -> Self {
        Self {
            inner: BigInt::from(value),
        }
    }
}

impl From<u16> for MPInt {
    #[inline]
    fn from(value: u16) -> Self {
        Self {
            inner: BigInt::from(value),
        }
    }
}

impl From<i32> for MPInt {
    #[inline]
    fn from(value: i32) -> Self {
        Self {
            inner: BigInt::from(value),
        }
    }
}

impl From<u32> for MPInt {
    #[inline]
    fn from(value: u32) -> Self {
        Self {
            inner: BigInt::from(value),
        }
    }
}

impl From<i64> for MPInt {
    #[inline]
    fn from(value: i64) -> Self {
        Self {
            inner: BigInt::from(value),
        }
    }
}

impl From<u64> for MPInt {
    #[inline]
    fn from(value: u64) -> Self {
        Self {
            inner: BigInt::from(value),
        }
    }
}

impl From<i128> for MPInt {
    #[inline]
    fn from(value: i128) -> Self {
        Self {
            inner: BigInt::from(value),
        }
    }
}

impl From<u128> for MPInt {
    #[inline]
    fn from(value: u128) -> Self {
        Self {
            inner: BigInt::from(value),
        }
    }
}

impl From<BigInt> for MPInt {
    #[inline]
    fn from(inner: BigInt) -> Self {
        Self { inner }
    }
}

impl From<BigUint> for MPInt {
    #[inline]
    fn from(value: BigUint) -> Self {
        Self {
            inner: BigInt::from(value),
        }
    }
}

impl TryFrom<MPInt> for i64 {
    type Error = MathError;

    fn try_from(value: MPInt) -> std::result::Result<Self, Self::Error> {
        value
            .inner
            .to_i64()
            .ok_or_else(|| MathError::OutOfRange {
                min: i64::MIN.to_string(),
                max: i64::MAX.to_string(),
                actual: value.to_string(),
            })
    }
}

impl TryFrom<MPInt> for u64 {
    type Error = MathError;

    fn try_from(value: MPInt) -> std::result::Result<Self, Self::Error> {
        if value.is_negative() {
            return Err(MathError::OutOfRange {
                min: "0".to_string(),
                max: u64::MAX.to_string(),
                actual: value.to_string(),
            });
        }
        value
            .inner
            .to_u64()
            .ok_or_else(|| MathError::OutOfRange {
                min: "0".to_string(),
                max: u64::MAX.to_string(),
                actual: value.to_string(),
            })
    }
}

// Arithmetic operator implementations

impl Add for &MPInt {
    type Output = MPInt;

    fn add(self, rhs: Self) -> Self::Output {
        MPInt {
            inner: &self.inner + &rhs.inner,
        }
    }
}

impl Add for MPInt {
    type Output = MPInt;

    fn add(self, rhs: Self) -> Self::Output {
        MPInt {
            inner: self.inner + rhs.inner,
        }
    }
}

impl Add<&MPInt> for MPInt {
    type Output = MPInt;

    fn add(self, rhs: &MPInt) -> Self::Output {
        MPInt {
            inner: self.inner + &rhs.inner,
        }
    }
}

impl Add<MPInt> for &MPInt {
    type Output = MPInt;

    fn add(self, rhs: MPInt) -> Self::Output {
        MPInt {
            inner: &self.inner + rhs.inner,
        }
    }
}

impl Sub for &MPInt {
    type Output = MPInt;

    fn sub(self, rhs: Self) -> Self::Output {
        MPInt {
            inner: &self.inner - &rhs.inner,
        }
    }
}

impl Sub for MPInt {
    type Output = MPInt;

    fn sub(self, rhs: Self) -> Self::Output {
        MPInt {
            inner: self.inner - rhs.inner,
        }
    }
}

impl Sub<&MPInt> for MPInt {
    type Output = MPInt;

    fn sub(self, rhs: &MPInt) -> Self::Output {
        MPInt {
            inner: self.inner - &rhs.inner,
        }
    }
}

impl Sub<MPInt> for &MPInt {
    type Output = MPInt;

    fn sub(self, rhs: MPInt) -> Self::Output {
        MPInt {
            inner: &self.inner - rhs.inner,
        }
    }
}

impl Mul for &MPInt {
    type Output = MPInt;

    fn mul(self, rhs: Self) -> Self::Output {
        MPInt {
            inner: &self.inner * &rhs.inner,
        }
    }
}

impl Mul for MPInt {
    type Output = MPInt;

    fn mul(self, rhs: Self) -> Self::Output {
        MPInt {
            inner: self.inner * rhs.inner,
        }
    }
}

impl Mul<&MPInt> for MPInt {
    type Output = MPInt;

    fn mul(self, rhs: &MPInt) -> Self::Output {
        MPInt {
            inner: self.inner * &rhs.inner,
        }
    }
}

impl Mul<MPInt> for &MPInt {
    type Output = MPInt;

    fn mul(self, rhs: MPInt) -> Self::Output {
        MPInt {
            inner: &self.inner * rhs.inner,
        }
    }
}

impl Div for &MPInt {
    type Output = MPInt;

    fn div(self, rhs: Self) -> Self::Output {
        MPInt {
            inner: &self.inner / &rhs.inner,
        }
    }
}

impl Div for MPInt {
    type Output = MPInt;

    fn div(self, rhs: Self) -> Self::Output {
        MPInt {
            inner: self.inner / rhs.inner,
        }
    }
}

impl Rem for &MPInt {
    type Output = MPInt;

    fn rem(self, rhs: Self) -> Self::Output {
        MPInt {
            inner: &self.inner % &rhs.inner,
        }
    }
}

impl Rem for MPInt {
    type Output = MPInt;

    fn rem(self, rhs: Self) -> Self::Output {
        MPInt {
            inner: self.inner % rhs.inner,
        }
    }
}

impl Neg for &MPInt {
    type Output = MPInt;

    fn neg(self) -> Self::Output {
        MPInt {
            inner: -(&self.inner),
        }
    }
}

impl Neg for MPInt {
    type Output = MPInt;

    fn neg(self) -> Self::Output {
        MPInt { inner: -self.inner }
    }
}

impl BitAnd for &MPInt {
    type Output = MPInt;

    fn bitand(self, rhs: Self) -> Self::Output {
        MPInt {
            inner: &self.inner & &rhs.inner,
        }
    }
}

impl BitAnd for MPInt {
    type Output = MPInt;

    fn bitand(self, rhs: Self) -> Self::Output {
        MPInt {
            inner: self.inner & rhs.inner,
        }
    }
}

impl BitOr for &MPInt {
    type Output = MPInt;

    fn bitor(self, rhs: Self) -> Self::Output {
        MPInt {
            inner: &self.inner | &rhs.inner,
        }
    }
}

impl BitOr for MPInt {
    type Output = MPInt;

    fn bitor(self, rhs: Self) -> Self::Output {
        MPInt {
            inner: self.inner | rhs.inner,
        }
    }
}

impl BitXor for &MPInt {
    type Output = MPInt;

    fn bitxor(self, rhs: Self) -> Self::Output {
        MPInt {
            inner: &self.inner ^ &rhs.inner,
        }
    }
}

impl BitXor for MPInt {
    type Output = MPInt;

    fn bitxor(self, rhs: Self) -> Self::Output {
        MPInt {
            inner: self.inner ^ rhs.inner,
        }
    }
}

impl Shl<usize> for &MPInt {
    type Output = MPInt;

    fn shl(self, rhs: usize) -> Self::Output {
        MPInt {
            inner: &self.inner << rhs,
        }
    }
}

impl Shl<usize> for MPInt {
    type Output = MPInt;

    fn shl(self, rhs: usize) -> Self::Output {
        MPInt {
            inner: self.inner << rhs,
        }
    }
}

impl Shr<usize> for &MPInt {
    type Output = MPInt;

    fn shr(self, rhs: usize) -> Self::Output {
        MPInt {
            inner: &self.inner >> rhs,
        }
    }
}

impl Shr<usize> for MPInt {
    type Output = MPInt;

    fn shr(self, rhs: usize) -> Self::Output {
        MPInt {
            inner: self.inner >> rhs,
        }
    }
}

impl PartialEq for MPInt {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl Eq for MPInt {}

impl PartialOrd for MPInt {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.inner.cmp(&other.inner))
    }
}

impl Ord for MPInt {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.inner.cmp(&other.inner)
    }
}

impl std::hash::Hash for MPInt {
    #[inline]
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Hash the sign and magnitude
        std::hash::Hash::hash(&self.inner, state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::ToPrimitive;

    #[test]
    fn test_from_str() {
        assert_eq!(MPInt::from_str("123", 10).unwrap().inner, BigInt::from(123));
        assert_eq!(
            MPInt::from_str("0xff", 0).unwrap().inner,
            BigInt::from(255)
        );
        assert_eq!(MPInt::from_str("-42", 10).unwrap().inner, BigInt::from(-42));
    }

    #[test]
    fn test_bit_operations() {
        let mut n = MPInt::from_u64(0);
        assert_eq!(n.get_bit(0), 0);
        n.set_bit(0, 1);
        assert_eq!(n.get_bit(0), 1);
        assert_eq!(n.inner().to_u64().unwrap(), 1);

        n.set_bit(5, 1);
        assert_eq!(n.inner().to_u64().unwrap(), 33);
    }

    #[test]
    fn test_modular_arithmetic() {
        let a = MPInt::from_u64(7);
        let b = MPInt::from_u64(5);
        let m = MPInt::from_u64(13);

        // (7 + 5) % 13 = 12
        assert_eq!(a.add_mod(&b, &m).unwrap().inner, BigInt::from(12));
        // (7 - 5) % 13 = 2
        assert_eq!(a.sub_mod(&b, &m).unwrap().inner, BigInt::from(2));
        // (7 * 5) % 13 = 35 % 13 = 9
        assert_eq!(a.mul_mod(&b, &m).unwrap().inner, BigInt::from(9));
    }

    #[test]
    fn test_pow_mod() {
        let base = MPInt::from_u64(2);
        let exp = MPInt::from_u64(10);
        let m = MPInt::from_u64(1000);
        // 2^10 % 1000 = 1024 % 1000 = 24
        assert_eq!(base.pow_mod(&exp, &m).unwrap().inner, BigInt::from(24));
    }

    #[test]
    fn test_invert_mod() {
        let a = MPInt::from_u64(3);
        let m = MPInt::from_u64(10000);
        // 3 * 6667 % 10000 = 1
        let inv = a.invert_mod(&m).unwrap();
        assert_eq!((a * inv).modulus(&m).unwrap().inner, BigInt::from(1));
    }

    #[test]
    fn test_gcd_lcm() {
        let a = MPInt::from_u64(48);
        let b = MPInt::from_u64(18);
        assert_eq!(a.gcd(&b).inner, BigInt::from(6));
        assert_eq!(a.lcm(&b).inner, BigInt::from(144));
    }

    #[test]
    fn test_bytes_conversion() {
        let n = MPInt::from_u64(0x123456789abcdef);
        let bytes = n.to_bytes_be_unsigned();
        let reconstructed = MPInt::from_bytes_be_unsigned(&bytes);
        assert_eq!(n, reconstructed);
    }

    #[test]
    fn test_bit_count() {
        assert_eq!(MPInt::from_u64(0).bit_count(), 0);
        assert_eq!(MPInt::from_u64(1).bit_count(), 1);
        assert_eq!(MPInt::from_u64(2).bit_count(), 2);
        assert_eq!(MPInt::from_u64(3).bit_count(), 2);
        assert_eq!(MPInt::from_u64(4).bit_count(), 3);
        assert_eq!(MPInt::from_u64(255).bit_count(), 8);
        assert_eq!(MPInt::from_u64(256).bit_count(), 9);
    }
}
