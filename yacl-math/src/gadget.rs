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

//! Simple math utility functions (gadgets)
//!
//! This module provides basic mathematical utility functions used throughout
//! cryptographic operations.

/// Computes the floor of base-2 logarithm of a non-zero integer.
///
/// Returns the largest integer `k` such that `2^k <= x`.
///
/// # Arguments
///
/// * `x` - A non-zero unsigned integer
///
/// # Returns
///
/// The floor of log2(x)
///
/// # Panics
///
/// Panics if `x` is zero (since log2(0) is undefined).
///
/// # Examples
///
/// ```
/// use yacl_math::gadget::log2_floor;
///
/// assert_eq!(log2_floor(1), 0);   // 2^0 = 1
/// assert_eq!(log2_floor(2), 1);   // 2^1 = 2
/// assert_eq!(log2_floor(3), 1);   // 2^1 <= 3 < 2^2
/// assert_eq!(log2_floor(4), 2);   // 2^2 = 4
/// assert_eq!(log2_floor(15), 3);  // 2^3 <= 15 < 2^4
/// assert_eq!(log2_floor(16), 4);  // 2^4 = 16
/// ```
#[inline]
#[must_use]
pub const fn log2_floor(x: u64) -> u64 {
    if x == 0 {
        panic!("log2_floor: argument must be non-zero");
    }
    63 - x.leading_zeros() as u64
}

/// Computes the ceiling of base-2 logarithm of a non-zero integer.
///
/// Returns the smallest integer `k` such that `x <= 2^k`.
///
/// # Arguments
///
/// * `x` - A non-zero unsigned integer
///
/// # Returns
///
/// The ceiling of log2(x)
///
/// # Panics
///
/// Panics if `x` is zero (since log2(0) is undefined).
///
/// # Examples
///
/// ```
/// use yacl_math::gadget::log2_ceil;
///
/// assert_eq!(log2_ceil(1), 0);   // 1 <= 2^0
/// assert_eq!(log2_ceil(2), 1);   // 2 <= 2^1
/// assert_eq!(log2_ceil(3), 2);   // 3 <= 2^2
/// assert_eq!(log2_ceil(4), 2);   // 4 <= 2^2
/// assert_eq!(log2_ceil(5), 3);   // 5 <= 2^3
/// assert_eq!(log2_ceil(8), 3);   // 8 <= 2^3
/// ```
#[inline]
#[must_use]
pub const fn log2_ceil(x: u64) -> u64 {
    if x == 0 {
        panic!("log2_ceil: argument must be non-zero");
    }
    if x == 1 {
        0
    } else {
        log2_floor(x - 1) + 1
    }
}

/// Computes ceiling division: ceil(x / y)
///
/// Returns the smallest integer >= x / y.
///
/// # Arguments
///
/// * `x` - Dividend (non-negative)
/// * `y` - Divisor (positive)
///
/// # Returns
///
/// The ceiling of x divided by y
///
/// # Panics
///
/// Panics if `y` is zero.
///
/// # Examples
///
/// ```
/// use yacl_math::gadget::div_ceil;
///
/// assert_eq!(div_ceil(0, 5), 0);
/// assert_eq!(div_ceil(5, 5), 1);
/// assert_eq!(div_ceil(6, 5), 2);
/// assert_eq!(div_ceil(9, 5), 2);
/// assert_eq!(div_ceil(10, 5), 2);
/// assert_eq!(div_ceil(11, 5), 3);
/// ```
#[inline]
#[must_use]
pub const fn div_ceil(x: u64, y: u64) -> u64 {
    if y == 0 {
        panic!("div_ceil: division by zero");
    }
    if x == 0 {
        0
    } else {
        1 + (x - 1) / y
    }
}

/// Rounds `x` up to the nearest multiple of `y`.
///
/// # Arguments
///
/// * `x` - The value to round
/// * `y` - The multiple to round up to (must be positive)
///
/// # Returns
///
/// The smallest multiple of `y` that is >= `x`
///
/// # Panics
///
/// Panics if `y` is zero.
///
/// # Examples
///
/// ```
/// use yacl_math::gadget::round_up_to;
///
/// assert_eq!(round_up_to(0, 8), 0);
/// assert_eq!(round_up_to(1, 8), 8);
/// assert_eq!(round_up_to(7, 8), 8);
/// assert_eq!(round_up_to(8, 8), 8);
/// assert_eq!(round_up_to(9, 8), 16);
/// assert_eq!(round_up_to(15, 8), 16);
/// assert_eq!(round_up_to(16, 8), 16);
/// ```
#[inline]
#[must_use]
pub const fn round_up_to(x: u64, y: u64) -> u64 {
    div_ceil(x, y) * y
}

/// Checks if a number is a power of 2.
///
/// # Arguments
///
/// * `x` - A non-negative integer
///
/// # Returns
///
/// `true` if `x` is a power of 2, `false` otherwise
///
/// # Examples
///
/// ```
/// use yacl_math::gadget::is_power_of_two;
///
/// assert!(!is_power_of_two(0));
/// assert!(is_power_of_two(1));
/// assert!(is_power_of_two(2));
/// assert!(!is_power_of_two(3));
/// assert!(is_power_of_two(4));
/// assert!(!is_power_of_two(5));
/// assert!(!is_power_of_two(6));
/// assert!(!is_power_of_two(7));
/// assert!(is_power_of_two(8));
/// ```
#[inline]
#[must_use]
pub const fn is_power_of_two(x: u64) -> bool {
    x != 0 && (x & (x - 1)) == 0
}

/// Computes the greatest common divisor (GCD) of two numbers.
///
/// This is a convenience wrapper around `num_integer::gcd`.
///
/// # Examples
///
/// ```
/// use yacl_math::gadget::gcd;
///
/// assert_eq!(gcd(48, 18), 6);
/// assert_eq!(gcd(17, 5), 1);
/// assert_eq!(gcd(0, 5), 5);
/// ```
#[inline]
#[must_use]
pub fn gcd<T>(a: T, b: T) -> T
where
    T: num_integer::Integer + Copy,
{
    a.gcd(&b)
}

/// Computes the least common multiple (LCM) of two numbers.
///
/// This is a convenience wrapper around `num_integer::lcm`.
///
/// # Examples
///
/// ```
/// use yacl_math::gadget::lcm;
///
/// assert_eq!(lcm(4, 6), 12);
/// assert_eq!(lcm(5, 7), 35);
/// ```
#[inline]
#[must_use]
pub fn lcm<T>(a: T, b: T) -> T
where
    T: num_integer::Integer + Copy,
{
    a.lcm(&b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log2_floor() {
        assert_eq!(log2_floor(1), 0);
        assert_eq!(log2_floor(2), 1);
        assert_eq!(log2_floor(3), 1);
        assert_eq!(log2_floor(4), 2);
        assert_eq!(log2_floor(7), 2);
        assert_eq!(log2_floor(8), 3);
        assert_eq!(log2_floor(u64::MAX), 63);
    }

    #[test]
    #[should_panic(expected = "must be non-zero")]
    fn test_log2_floor_zero() {
        log2_floor(0);
    }

    #[test]
    fn test_log2_ceil() {
        assert_eq!(log2_ceil(1), 0);
        assert_eq!(log2_ceil(2), 1);
        assert_eq!(log2_ceil(3), 2);
        assert_eq!(log2_ceil(4), 2);
        assert_eq!(log2_ceil(5), 3);
        assert_eq!(log2_ceil(8), 3);
        assert_eq!(log2_ceil(9), 4);
    }

    #[test]
    #[should_panic(expected = "must be non-zero")]
    fn test_log2_ceil_zero() {
        log2_ceil(0);
    }

    #[test]
    fn test_div_ceil() {
        assert_eq!(div_ceil(0, 5), 0);
        assert_eq!(div_ceil(5, 5), 1);
        assert_eq!(div_ceil(6, 5), 2);
        assert_eq!(div_ceil(10, 5), 2);
        assert_eq!(div_ceil(11, 5), 3);
        assert_eq!(div_ceil(100, 7), 15);
    }

    #[test]
    #[should_panic(expected = "division by zero")]
    fn test_div_ceil_zero_divisor() {
        div_ceil(5, 0);
    }

    #[test]
    fn test_round_up_to() {
        assert_eq!(round_up_to(0, 8), 0);
        assert_eq!(round_up_to(1, 8), 8);
        assert_eq!(round_up_to(8, 8), 8);
        assert_eq!(round_up_to(9, 8), 16);
        assert_eq!(round_up_to(16, 8), 16);
        assert_eq!(round_up_to(17, 8), 24);
        assert_eq!(round_up_to(100, 64), 128);
    }

    #[test]
    fn test_is_power_of_two() {
        assert!(!is_power_of_two(0));
        for i in 0..64 {
            assert!(is_power_of_two(1u64 << i));
        }
        assert!(!is_power_of_two(3));
        assert!(!is_power_of_two(5));
        assert!(!is_power_of_two(6));
        assert!(!is_power_of_two(7));
        assert!(!is_power_of_two(9));
    }

    #[test]
    fn test_gcd() {
        assert_eq!(gcd(48u64, 18), 6);
        assert_eq!(gcd(17u64, 5), 1);
        assert_eq!(gcd(0u64, 5), 5);
        assert_eq!(gcd(5u64, 0), 5);
        assert_eq!(gcd(0u64, 0), 0);
    }

    #[test]
    fn test_lcm() {
        assert_eq!(lcm(4u64, 6), 12);
        assert_eq!(lcm(5u64, 7), 35);
        assert_eq!(lcm(4u64, 8), 8);
    }
}
