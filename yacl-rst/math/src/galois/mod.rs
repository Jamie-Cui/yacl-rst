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

//! Galois Field (Finite Field) abstraction
//!
//! This module provides a trait-based abstraction for working with finite fields,
//! including prime fields (GF_p), extension fields (GF_p^k), and binary fields (GF_2^k).

pub mod prime;

pub use prime::PrimeField;

use crate::error::Result;
use crate::mpint::MPInt;
use std::fmt;

/// Field type identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldType {
    /// Prime field GF(p)
    PrimeField,
    /// Extension field GF(p^k)
    ExtensionField,
    /// Binary field GF(2^k)
    BinaryField,
}

/// A trait representing a Galois Field (finite field).
///
/// This trait provides the core operations for working with finite fields,
/// including arithmetic operations and field element manipulation.
pub trait GaloisField: fmt::Debug {
    //===============================//
    //         Meta information       //
    //===============================//

    /// Returns the name of the library/backend implementation
    fn library_name(&self) -> &str {
        "yacl-rst/math"
    }

    /// Returns the field type
    fn field_type(&self) -> FieldType;

    /// Returns the name/identifier of this field
    fn field_name(&self) -> String;

    /// Returns the order of the field (p^k for GF(p^k))
    ///
    /// For extension fields, this returns p^k (which may not be directly useful).
    fn order(&self) -> MPInt;

    /// Returns the extension degree k (returns 1 for prime fields)
    fn extension_degree(&self) -> u64 {
        1
    }

    /// Returns the order of the base field (p for GF(p^k))
    fn base_field_order(&self) -> MPInt;

    /// Returns the order of the multiplicative group
    ///
    /// For prime fields, this is p - 1.
    fn multiplicative_group_order(&self) -> MPInt;

    /// Returns the order of the additive group
    ///
    /// For prime fields, this is p.
    fn additive_group_order(&self) -> MPInt;

    //===============================//
    //          Identity elements     //
    //===============================//

    /// Returns the additive identity (zero)
    fn zero(&self) -> MPInt;

    /// Returns the multiplicative identity (one)
    fn one(&self) -> MPInt;

    //===============================//
    //         Field operations       //
    //===============================//

    /// Negates a field element: returns -x
    fn negate(&self, x: &MPInt) -> MPInt;

    /// Computes the multiplicative inverse: returns x^-1
    fn invert(&self, x: &MPInt) -> Result<MPInt>;

    /// Adds two field elements
    fn add(&self, x: &MPInt, y: &MPInt) -> MPInt;

    /// Subtracts two field elements
    fn sub(&self, x: &MPInt, y: &MPInt) -> MPInt;

    /// Multiplies two field elements
    fn mul(&self, x: &MPInt, y: &MPInt) -> MPInt;

    /// Divides two field elements: x / y
    fn div(&self, x: &MPInt, y: &MPInt) -> Result<MPInt> {
        let y_inv = self.invert(y)?;
        Ok(self.mul(x, &y_inv))
    }

    /// Exponentiation: x^y
    fn pow(&self, x: &MPInt, y: &MPInt) -> MPInt;

    /// Doubles a field element: x + x
    #[inline]
    fn double(&self, x: &MPInt) -> MPInt {
        self.add(x, x)
    }

    /// Squares a field element: x * x
    #[inline]
    fn square(&self, x: &MPInt) -> MPInt {
        self.mul(x, x)
    }

    //===============================//
    //           Predicates           //
    //===============================//

    /// Returns true if x equals the additive identity (zero)
    fn is_zero(&self, x: &MPInt) -> bool {
        x.is_zero()
    }

    /// Returns true if x equals the multiplicative identity (one)
    fn is_one(&self, x: &MPInt) -> bool {
        x == &self.one()
    }

    /// Returns true if x is a valid field element
    fn is_in_field(&self, x: &MPInt) -> bool;

    /// Compares two field elements for equality
    fn equal(&self, x: &MPInt, y: &MPInt) -> bool {
        x.compare(y) == std::cmp::Ordering::Equal
    }

    //===============================//
    //           Random               //
    //===============================//

    /// Generates a random field element
    fn random<R: rand::Rng>(&self, rng: &mut R) -> MPInt;

    //===============================//
    //              I/O               //
    //===============================//

    /// Converts a field element to a human-readable string
    fn to_string(&self, x: &MPInt) -> String {
        x.to_string()
    }

    /// Serializes a field element to bytes
    fn serialize(&self, x: &MPInt) -> Vec<u8> {
        x.to_bytes_be_unsigned()
    }

    /// Deserializes bytes to a field element
    fn deserialize(&self, bytes: &[u8]) -> Result<MPInt>;
}

/// Factory for creating GaloisField instances.
///
/// This enum allows for runtime polymorphism over different field types.
#[derive(Clone)]
pub enum Field {
    /// A prime field GF(p)
    Prime(PrimeField),
}

impl Field {
    /// Creates a new prime field GF(p)
    pub fn prime(modulus: MPInt) -> Self {
        Self::Prime(PrimeField::new(modulus))
    }
}

impl fmt::Debug for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Field::Prime(pf) => f.debug_tuple("Field::Prime").field(pf).finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::{One, Zero};
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    #[test]
    fn test_prime_field_basic() {
        let p = MPInt::from_u64(10007);
        let field = PrimeField::new(p.clone());

        assert_eq!(field.field_type(), FieldType::PrimeField);
        assert_eq!(field.base_field_order(), p);
        assert_eq!(field.order(), p);
        assert_eq!(field.multiplicative_group_order(), MPInt::from_u64(10006));
    }

    #[test]
    fn test_prime_field_arithmetic() {
        let p = MPInt::from_u64(10007);
        let field = PrimeField::new(p.clone());

        let a = MPInt::from_u64(123);
        let b = MPInt::from_u64(456);

        // Addition: (123 + 456) % 10007 = 579
        let sum = field.add(&a, &b);
        assert_eq!(sum, MPInt::from_u64(579));

        // Subtraction: (123 - 456) % 10007 = 9674
        let diff = field.sub(&a, &b);
        assert_eq!(diff, MPInt::from_u64(9674));

        // Multiplication: (123 * 456) % 10007 = 6053
        let product = field.mul(&a, &b);
        assert_eq!(product, MPInt::from_u64(6053));
    }

    #[test]
    fn test_prime_field_inverse() {
        let p = MPInt::from_u64(10007);
        let field = PrimeField::new(p.clone());

        let a = MPInt::from_u64(123);
        let inv = field.invert(&a).unwrap();

        // a * a^(-1) = 1 (mod p)
        let result = field.mul(&a, &inv);
        assert_eq!(result, MPInt::one());
    }

    #[test]
    fn test_prime_field_pow() {
        let p = MPInt::from_u64(10007);
        let field = PrimeField::new(p.clone());

        let base = MPInt::from_u64(2);
        let exp = MPInt::from_u64(100);

        // 2^100 % 10007
        let result = field.pow(&base, &exp);

        // Verify using pow_mod
        let expected = base.pow_mod(&exp, &p).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_prime_field_random() {
        let p = MPInt::from_u64(10007);
        let field = PrimeField::new(p.clone());

        let mut rng = ChaCha8Rng::from_seed([42; 32]);
        let r = field.random(&mut rng);

        assert!(field.is_in_field(&r));
        assert!(r >= MPInt::zero());
        assert!(r < p);
    }

    #[test]
    fn test_prime_field_serialization() {
        let p = MPInt::from_u64(10007);
        let field = PrimeField::new(p.clone());

        // Use a value < 10007 (the modulus)
        let x = MPInt::from_u64(1234);

        let bytes = field.serialize(&x);
        let reconstructed = field.deserialize(&bytes).unwrap();

        assert_eq!(x, reconstructed);
    }
}
