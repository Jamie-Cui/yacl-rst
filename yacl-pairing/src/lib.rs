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

//! Pairing-based cryptography
//!
//! This module provides bilinear pairing operations for pairing-friendly curves.
//!
//! # Supported Curves
//!
//! - **BN254**: Barreto-Naehrig 254-bit curve
//! - **BLS12-381**: Barreto-Lynn-Scott 12-381 curve
//! - **BLS12-447**: Barreto-Lynn-Scott 12-447 curve
//!
//! # Example
//!
//! ```rust
//! use yacl_pairing::{PairingGroup, BN254Pairing};
//!
//! let pairing = BN254Pairing::new();
//! let g1 = pairing.group1().generator();
//! let g2 = pairing.group2().generator();
//!
//! // Compute pairing e(g1, g2)
//! let result = pairing.pairing(&g1, &g2).unwrap();
//! ```

pub mod error;
pub mod types;
pub mod pairing;

pub use error::{PairingError, Result};
pub use types::{PairingCurve, PairingAlgorithm, GTElement};
pub use pairing::{PairingGroup, BN254Pairing};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bn254_pairing_full_workflow() {
        let pairing = BN254Pairing::new();
        let g1 = pairing.group1().generator();
        let g2 = pairing.group2().generator();

        // Test pairing
        let result = pairing.pairing(&g1, &g2).unwrap();
        assert!(!result.is_identity());
        assert_eq!(result.as_bytes().len(), 48);
    }

    #[test]
    fn test_pairing_curve_display() {
        assert_eq!(PairingCurve::BN254.to_string(), "BN254");
        assert_eq!(PairingCurve::BLS12_381.to_string(), "BLS12-381");
    }

    #[test]
    fn test_pairing_algorithm_display() {
        assert_eq!(PairingAlgorithm::Ate.to_string(), "Ate");
        assert_eq!(PairingAlgorithm::Weil.to_string(), "Weil");
    }
}
