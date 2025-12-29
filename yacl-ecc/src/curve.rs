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

//! Elliptic curve group operations

use crate::{Result, EcError, CurveName, Point, Scalar};
use rand::RngCore;
use std::fmt;

/// Elliptic curve type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CurveType {
    /// P-256 curve
    P256,
    /// Secp256k1 curve
    Secp256k1,
}

/// Trait for elliptic curve group operations
pub trait EcGroup: fmt::Debug + Send + Sync {
    /// Returns the curve name
    fn curve_name(&self) -> CurveName;

    /// Returns the curve type
    fn curve_type(&self) -> CurveType;

    /// Returns the generator point
    fn generator(&self) -> Point;

    /// Generates a random scalar
    fn random_scalar(&self) -> Scalar;

    /// Multiplies a point by a scalar
    fn mul(&self, point: &Point, scalar: &Scalar) -> Result<Point>;

    /// Adds two points
    fn add(&self, a: &Point, b: &Point) -> Result<Point>;

    /// Returns the point at infinity
    fn identity(&self) -> Point;

    /// Returns the order of the curve (number of points)
    fn order(&self) -> Vec<u8>;

    /// Returns the field size (modulus size in bytes)
    fn field_size(&self) -> usize;
}

/// P-256 (prime256v1) curve implementation
#[derive(Clone)]
pub struct P256;

impl P256 {
    pub fn new() -> Self {
        Self
    }
}

impl Default for P256 {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for P256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("P256").finish()
    }
}

impl EcGroup for P256 {
    fn curve_name(&self) -> CurveName {
        CurveName::P256
    }

    fn curve_type(&self) -> CurveType {
        CurveType::P256
    }

    fn generator(&self) -> Point {
        // P-256 generator point in uncompressed form (ANSI X9.62)
        // 0x04 + x-coordinate (32 bytes) + y-coordinate (32 bytes) = 65 bytes
        // x = 6b17d1f2e12c4247f8bce6e5c63a440f277037d812deb33a0f4a13945d898c29
        // y = 4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
        let g_bytes = vec![
            0x04,
            // x-coordinate
            0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
            0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x9f,
            // y-coordinate
            0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
            0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
        ];
        Point::new(g_bytes)
    }

    fn random_scalar(&self) -> Scalar {
        let mut rng = rand::rngs::OsRng;
        let mut bytes = vec![0u8; 32];
        rng.fill_bytes(&mut bytes);
        Scalar::new(bytes).unwrap()
    }

    fn mul(&self, point: &Point, scalar: &Scalar) -> Result<Point> {
        // For p256, we'll use a simplified approach: return the point if scalar is 1
        // In a full implementation, we'd use elliptic curve multiplication
        if scalar.len() == 1 && scalar.as_bytes()[0] == 1 {
            Ok(point.clone())
        } else {
            // Placeholder: return the point unchanged
            // In a full implementation, this would perform actual EC multiplication
            Ok(point.clone())
        }
    }

    fn add(&self, _a: &Point, _b: &Point) -> Result<Point> {
        // Point addition is complex and requires low-level EC operations
        // For now, return the generator as a placeholder
        Ok(self.generator())
    }

    fn identity(&self) -> Point {
        // Point at infinity (compressed form: 0x00)
        Point::new(vec![0x00])
    }

    fn order(&self) -> Vec<u8> {
        // P-256 order: n = FFFFFFFF 00000000 FFFFFFFFFFFFFFFFFFFFFFFF BCE6FAADA7179E84F3B9CAC2FC632551
        vec![
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
            0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
        ]
    }

    fn field_size(&self) -> usize {
        32 // 256 bits = 32 bytes
    }
}

/// Secp256k1 curve implementation
#[derive(Clone)]
pub struct Secp256k1;

impl Secp256k1 {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Secp256k1 {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Secp256k1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Secp256k1").finish()
    }
}

impl EcGroup for Secp256k1 {
    fn curve_name(&self) -> CurveName {
        CurveName::Secp256k1
    }

    fn curve_type(&self) -> CurveType {
        CurveType::Secp256k1
    }

    fn generator(&self) -> Point {
        // Secp256k1 generator point in uncompressed form
        // 0x04 + x-coordinate (32 bytes) + y-coordinate (32 bytes) = 65 bytes
        // x = 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
        // y = 483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
        let g_bytes = vec![
            0x04,
            // x-coordinate
            0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
            0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
            // y-coordinate
            0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11, 0x08, 0xa8,
            0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19, 0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8,
        ];
        Point::new(g_bytes)
    }

    fn random_scalar(&self) -> Scalar {
        let mut rng = rand::rngs::OsRng;
        let mut bytes = vec![0u8; 32];
        rng.fill_bytes(&mut bytes);
        Scalar::new(bytes).unwrap()
    }

    fn mul(&self, point: &Point, scalar: &Scalar) -> Result<Point> {
        // Simplified: return the point unchanged for all scalars
        // In a full implementation, this would perform actual EC multiplication
        if scalar.len() == 1 && scalar.as_bytes()[0] == 1 {
            Ok(point.clone())
        } else {
            Ok(point.clone())
        }
    }

    fn add(&self, _a: &Point, _b: &Point) -> Result<Point> {
        Ok(self.generator())
    }

    fn identity(&self) -> Point {
        Point::new(vec![0x00])
    }

    fn order(&self) -> Vec<u8> {
        // Secp256k1 order: n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
            0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
            0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
        ]
    }

    fn field_size(&self) -> usize {
        32 // 256 bits = 32 bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p256_generator() {
        let curve = P256::new();
        let g = curve.generator();
        assert_eq!(g.len(), 65);
    }

    #[test]
    fn test_p256_order() {
        let curve = P256::new();
        let order = curve.order();
        assert_eq!(order.len(), 32);
    }

    #[test]
    fn test_p256_random_scalar() {
        let curve = P256::new();
        let scalar = curve.random_scalar();
        assert_eq!(scalar.len(), 32);
        assert!(!scalar.is_zero());
    }

    #[test]
    fn test_secp256k1_generator() {
        let curve = Secp256k1::new();
        let g = curve.generator();
        assert_eq!(g.len(), 65);
    }

    #[test]
    fn test_secp256k1_order() {
        let curve = Secp256k1::new();
        let order = curve.order();
        assert_eq!(order.len(), 32);
    }

    #[test]
    fn test_secp256k1_random_scalar() {
        let curve = Secp256k1::new();
        let scalar = curve.random_scalar();
        assert_eq!(scalar.len(), 32);
        assert!(!scalar.is_zero());
    }
}
