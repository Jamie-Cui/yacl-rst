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

//! Prime field implementation GF(p)
//!
//! This module provides an implementation of prime fields, where the field
//! order is a prime number p.

use crate::error::{MathError, Result};
use crate::galois::{FieldType, GaloisField};
use crate::mpint::MPInt;
use num_traits::{One, ToPrimitive, Zero};
use rand::Rng;
use std::fmt;

/// A prime field GF(p) where p is a prime number.
///
/// All arithmetic operations are performed modulo p.
#[derive(Clone)]
pub struct PrimeField {
    /// The prime modulus
    modulus: MPInt,
    /// The modulus as u64 if it fits (for faster operations)
    modulus_u64: Option<u64>,
    /// Cached value of modulus - 1
    modulus_minus_1: MPInt,
}

impl PrimeField {
    /// Creates a new prime field GF(modulus).
    ///
    /// # Arguments
    ///
    /// * `modulus` - The prime modulus p
    ///
    /// # Note
    ///
    /// This constructor does not verify that the modulus is actually prime.
    /// For cryptographic applications, you should verify primality first.
    #[must_use]
    pub fn new(modulus: MPInt) -> Self {
        let modulus_u64 = modulus.inner().to_u64();
        let modulus_minus_1 = &modulus - MPInt::one();

        Self {
            modulus,
            modulus_u64,
            modulus_minus_1,
        }
    }

    /// Returns the modulus of this field
    #[must_use]
    pub fn modulus(&self) -> &MPInt {
        &self.modulus
    }

    /// Reduces a value to be in the field [0, p)
    fn reduce(&self, x: &MPInt) -> MPInt {
        if x.is_negative() {
            // For negative numbers, we need to compute x mod p
            // The formula is: ((x % p) + p) % p
            let m = x.modulus(&self.modulus).unwrap();
            if m.is_zero() {
                m
            } else {
                &self.modulus - m
            }
        } else {
            x.modulus(&self.modulus).unwrap()
        }
    }

    /// Optimized reduction for small (u64) values
    #[inline]
    fn reduce_u64(&self, x: u64) -> u64 {
        if let Some(m) = self.modulus_u64 {
            x % m
        } else {
            // Fall back to MPInt
            self.reduce(&MPInt::from_u64(x))
                .inner()
                .to_u64()
                .unwrap_or(x % (1u64 << 32))
        }
    }
}

impl GaloisField for PrimeField {
    fn field_type(&self) -> FieldType {
        FieldType::PrimeField
    }

    fn field_name(&self) -> String {
        format!("GF({})", self.modulus.to_string())
    }

    fn order(&self) -> MPInt {
        self.modulus.clone()
    }

    fn base_field_order(&self) -> MPInt {
        self.modulus.clone()
    }

    fn multiplicative_group_order(&self) -> MPInt {
        self.modulus_minus_1.clone()
    }

    fn additive_group_order(&self) -> MPInt {
        self.modulus.clone()
    }

    fn zero(&self) -> MPInt {
        MPInt::zero()
    }

    fn one(&self) -> MPInt {
        MPInt::one()
    }

    fn negate(&self, x: &MPInt) -> MPInt {
        if x.is_zero() {
            return MPInt::zero();
        }
        // -x mod p = p - (x mod p)
        let x_mod = self.reduce(x);
        if x_mod.is_zero() {
            MPInt::zero()
        } else {
            &self.modulus - x_mod
        }
    }

    fn invert(&self, x: &MPInt) -> Result<MPInt> {
        if x.is_zero() {
            return Err(MathError::NoModularInverse);
        }
        x.invert_mod(&self.modulus)
    }

    fn add(&self, x: &MPInt, y: &MPInt) -> MPInt {
        // Fast path for small values
        if let (Some(x_val), Some(y_val), Some(m)) = (
            x.inner().to_u64(),
            y.inner().to_u64(),
            self.modulus_u64,
        ) {
            let sum = x_val.wrapping_add(y_val);
            return MPInt::from_u64(if sum >= m { sum - m } else { sum });
        }

        let sum = x + y;
        if sum.compare(&self.modulus) >= std::cmp::Ordering::Equal {
            sum - &self.modulus
        } else {
            sum
        }
    }

    fn sub(&self, x: &MPInt, y: &MPInt) -> MPInt {
        // Fast path for small values
        if let (Some(x_val), Some(y_val), Some(m)) = (
            x.inner().to_u64(),
            y.inner().to_u64(),
            self.modulus_u64,
        ) {
            let (diff, underflow) = x_val.overflowing_sub(y_val);
            return MPInt::from_u64(if underflow {
                m.wrapping_sub(y_val - x_val)
            } else {
                diff
            });
        }

        let diff = x - y;
        if diff.is_negative() {
            diff + &self.modulus
        } else {
            diff
        }
    }

    fn mul(&self, x: &MPInt, y: &MPInt) -> MPInt {
        // Use modular multiplication
        x.mul_mod(y, &self.modulus).unwrap_or_else(|_| {
            // Fallback to manual reduction
            let product = x * y;
            self.reduce(&product)
        })
    }

    fn pow(&self, x: &MPInt, y: &MPInt) -> MPInt {
        // For negative exponents, compute inverse first
        if y.is_negative() {
            let abs_y = -y.clone();
            let x_inv = self.invert(x).unwrap_or_else(|_| MPInt::zero());
            if x_inv.is_zero() {
                return MPInt::zero();
            }
            return x_inv.pow_mod(&abs_y, &self.modulus).unwrap_or_else(|_| MPInt::zero());
        }

        x.pow_mod(y, &self.modulus)
            .unwrap_or_else(|_| MPInt::zero())
    }

    fn is_in_field(&self, x: &MPInt) -> bool {
        if x.is_negative() {
            return false;
        }
        x.compare(&self.modulus) < std::cmp::Ordering::Equal
    }

    fn random<R: Rng>(&self, rng: &mut R) -> MPInt {
        if let Some(m) = self.modulus_u64 {
            // Fast path for small moduli
            if m <= (1u64 << 32) {
                // Rejection sampling
                loop {
                    let r = rng.gen::<u32>() as u64;
                    if r < m {
                        return MPInt::from_u64(r);
                    }
                }
            }
        }

        // General case: generate random bytes and reduce
        let byte_len = (self.modulus.bit_count() + 7) / 8;
        let mut bytes = vec![0u8; byte_len];
        rng.fill_bytes(&mut bytes);

        // Ensure the result is less than modulus
        let candidate = MPInt::from_bytes_be_unsigned(&bytes);
        if candidate.compare(&self.modulus) < std::cmp::Ordering::Equal {
            candidate
        } else {
            // If overflow, try modulo reduction
            self.reduce(&candidate)
        }
    }

    fn to_string(&self, x: &MPInt) -> String {
        x.to_string()
    }

    fn serialize(&self, x: &MPInt) -> Vec<u8> {
        // Serialize as unsigned bytes with length matching the modulus
        let byte_len = (self.modulus.bit_count() + 7) / 8;
        x.to_bytes_be_with_len(byte_len)
    }

    fn deserialize(&self, bytes: &[u8]) -> Result<MPInt> {
        let x = MPInt::from_bytes_be_unsigned(bytes);
        if !self.is_in_field(&x) {
            return Err(MathError::NotInField(
                "Deserialized value not in field range".into(),
            ));
        }
        Ok(x)
    }
}

impl fmt::Debug for PrimeField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrimeField")
            .field("modulus", &self.modulus.to_string())
            .field("modulus_bits", &self.modulus.bit_count())
            .finish()
    }
}

impl PartialEq for PrimeField {
    fn eq(&self, other: &Self) -> bool {
        self.modulus == other.modulus
    }
}

impl Eq for PrimeField {}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    fn test_field() -> PrimeField {
        PrimeField::new(MPInt::from_u64(10007))
    }

    #[test]
    fn test_prime_field_creation() {
        let field = test_field();
        assert_eq!(field.modulus(), &MPInt::from_u64(10007));
        assert_eq!(field.field_type(), FieldType::PrimeField);
    }

    #[test]
    fn test_identities() {
        let field = test_field();
        assert_eq!(field.zero(), MPInt::zero());
        assert_eq!(field.one(), MPInt::one());
    }

    #[test]
    fn test_add() {
        let field = test_field();

        let a = MPInt::from_u64(5000);
        let b = MPInt::from_u64(6000);
        // (5000 + 6000) % 10007 = 11000 % 10007 = 993
        let sum = field.add(&a, &b);
        assert_eq!(sum, MPInt::from_u64(993));

        // Test wrapping
        let c = MPInt::from_u64(10006);
        let d = MPInt::from_u64(2);
        // (10006 + 2) % 10007 = 1
        let sum2 = field.add(&c, &d);
        assert_eq!(sum2, MPInt::one());
    }

    #[test]
    fn test_sub() {
        let field = test_field();

        let a = MPInt::from_u64(100);
        let b = MPInt::from_u64(200);
        // (100 - 200) mod 10007 = -100 mod 10007 = 9907
        let diff = field.sub(&a, &b);
        assert_eq!(diff, MPInt::from_u64(9907));

        let c = MPInt::from_u64(200);
        let d = MPInt::from_u64(100);
        // (200 - 100) mod 10007 = 100
        let diff2 = field.sub(&c, &d);
        assert_eq!(diff2, MPInt::from_u64(100));
    }

    #[test]
    fn test_mul() {
        let field = test_field();

        let a = MPInt::from_u64(100);
        let b = MPInt::from_u64(200);
        // (100 * 200) = 20000, 20000 - 10007 = 9993
        let product = field.mul(&a, &b);
        assert_eq!(product, MPInt::from_u64(9993));
    }

    #[test]
    fn test_negate() {
        let field = test_field();

        let a = MPInt::from_u64(100);
        // -100 mod 10007 = 9907
        let neg = field.negate(&a);
        assert_eq!(neg, MPInt::from_u64(9907));

        // a + (-a) = 0
        let sum = field.add(&a, &neg);
        assert_eq!(sum, MPInt::zero());
    }

    #[test]
    fn test_invert() {
        let field = test_field();

        let a = MPInt::from_u64(2);
        let inv = field.invert(&a).unwrap();

        // 2 * inv = 1 mod 10007
        let product = field.mul(&a, &inv);
        assert_eq!(product, MPInt::one());
    }

    #[test]
    fn test_pow() {
        let field = test_field();

        let base = MPInt::from_u64(2);
        let exp = MPInt::from_u64(20);
        // 2^20 = 1048576
        // 1048576 / 10007 = 104 remainder 7848
        // So 2^20 mod 10007 = 7848
        let result = field.pow(&base, &exp);
        assert_eq!(result, MPInt::from_u64(7848));
    }

    #[test]
    fn test_pow_negative() {
        let field = test_field();

        let base = MPInt::from_u64(2);
        let exp = MPInt::from_i64(-1);
        // 2^(-1) mod 10007 = modular inverse of 2
        let result = field.pow(&base, &exp);
        let expected = field.invert(&base).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_double() {
        let field = test_field();

        let a = MPInt::from_u64(5000);
        // 2 * 5000 = 10000 < 10007, so no wrap needed
        let doubled = field.double(&a);
        assert_eq!(doubled, MPInt::from_u64(10000));
    }

    #[test]
    fn test_square() {
        let field = test_field();

        let a = MPInt::from_u64(100);
        // 100^2 = 10000 < 10007, so no wrap needed
        let squared = field.square(&a);
        assert_eq!(squared, MPInt::from_u64(10000));
    }

    #[test]
    fn test_div() {
        let field = test_field();

        let a = MPInt::from_u64(100);
        let b = MPInt::from_u64(2);
        // 100 / 2 mod 10007 = 50
        let result = field.div(&a, &b).unwrap();
        assert_eq!(result, MPInt::from_u64(50));
    }

    #[test]
    fn test_is_in_field() {
        let field = test_field();

        assert!(field.is_in_field(&MPInt::zero()));
        assert!(field.is_in_field(&MPInt::one()));
        assert!(field.is_in_field(&MPInt::from_u64(10006)));
        assert!(!field.is_in_field(&MPInt::from_u64(10007)));
        assert!(!field.is_in_field(&MPInt::from_i64(-1)));
    }

    #[test]
    fn test_is_zero_is_one() {
        let field = test_field();

        assert!(field.is_zero(&MPInt::zero()));
        assert!(!field.is_zero(&MPInt::one()));
        assert!(field.is_one(&MPInt::one()));
        assert!(!field.is_one(&MPInt::zero()));
    }

    #[test]
    fn test_equal() {
        let field = test_field();

        let a = MPInt::from_u64(100);
        let b = MPInt::from_u64(100);
        let c = MPInt::from_u64(200);

        assert!(field.equal(&a, &b));
        assert!(!field.equal(&a, &c));
    }

    #[test]
    fn test_random() {
        let field = test_field();
        let mut rng = ChaCha8Rng::from_seed([42; 32]);

        for _ in 0..10 {
            let r = field.random(&mut rng);
            assert!(field.is_in_field(&r));
        }
    }

    #[test]
    fn test_serialize_deserialize() {
        let field = test_field();

        // Use a value < 10007 (the modulus)
        let x = MPInt::from_u64(1234);

        let bytes = field.serialize(&x);
        let reconstructed = field.deserialize(&bytes).unwrap();

        assert_eq!(x, reconstructed);
    }

    #[test]
    fn test_deserialize_out_of_range() {
        let field = test_field();

        // Value larger than modulus
        let bytes = MPInt::from_u64(10007).to_bytes_be_unsigned();
        let result = field.deserialize(&bytes);

        assert!(result.is_err());
    }

    #[test]
    fn test_order() {
        let field = test_field();

        // For GF(p), the field order is p
        assert_eq!(field.order(), MPInt::from_u64(10007));

        // Multiplicative group order is p - 1
        assert_eq!(field.multiplicative_group_order(), MPInt::from_u64(10006));

        // Additive group order is p
        assert_eq!(field.additive_group_order(), MPInt::from_u64(10007));
    }

    #[test]
    fn test_large_prime() {
        // Test with a larger prime (64-bit)
        let p = MPInt::from_str("18446744073709551557", 10).unwrap();
        let field = PrimeField::new(p.clone());

        let a = MPInt::from_u64(123456789);
        let b = MPInt::from_u64(987654321);

        let sum = field.add(&a, &b);
        let expected = (&a + &b).modulus(&p).unwrap();
        assert_eq!(sum, expected);

        let product = field.mul(&a, &b);
        let expected_product = a.mul_mod(&b, &p).unwrap();
        assert_eq!(product, expected_product);
    }
}
