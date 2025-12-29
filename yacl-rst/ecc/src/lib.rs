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

//! Elliptic curve cryptography
//!
//! This module provides elliptic curve operations for commonly used curves.
//!
//! # Supported Curves
//!
//! - **P-256** (prime256v1): NIST P-256 curve
//! - **Secp256k1**: Bitcoin/Kovan curve
//!
//! # Example
//!
//! ```rust
//! use yacl_ecc::{EcGroup, Point, Scalar, P256};
//!
//! // Create a curve instance
//! let curve = P256::new();
//!
//! // Get the generator point
//! let g = curve.generator();
//!
//! // Generate a random scalar
//! let scalar = curve.random_scalar();
//!
//! // Multiply point by scalar
//! let point = curve.mul(&g, &scalar);
//! ```

pub mod error;
pub mod point;
pub mod scalar;
pub mod curve;

pub use error::{EcError, Result};
pub use point::{Point, AffinePoint};
pub use scalar::Scalar;
pub use curve::{EcGroup, P256, Secp256k1, CurveType};

use std::fmt;

/// Elliptic curve identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CurveName {
    /// NIST P-256 curve (prime256v1)
    P256,
    /// NIST P-384 curve
    P384,
    /// NIST P-521 curve
    P521,
    /// Secp256k1 curve (Bitcoin)
    Secp256k1,
}

impl fmt::Display for CurveName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::P256 => write!(f, "P-256"),
            Self::P384 => write!(f, "P-384"),
            Self::P521 => write!(f, "P-521"),
            Self::Secp256k1 => write!(f, "Secp256k1"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_curve_name_display() {
        assert_eq!(format!("{}", CurveName::P256), "P-256");
        assert_eq!(format!("{}", CurveName::Secp256k1), "Secp256k1");
    }
}
