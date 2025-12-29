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

//! Pairing types

use std::fmt;

/// Pairing curve types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PairingCurve {
    /// BN254 curve (Barreto-Naehrig 254-bit)
    BN254,
    /// BLS12-381 curve (Barreto-Lynn-Scott 12-381)
    BLS12_381,
    /// BLS12-447 curve
    BLS12_447,
}

impl fmt::Display for PairingCurve {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BN254 => write!(f, "BN254"),
            Self::BLS12_381 => write!(f, "BLS12-381"),
            Self::BLS12_447 => write!(f, "BLS12-447"),
        }
    }
}

/// Pairing algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PairingAlgorithm {
    /// Weil pairing
    Weil,
    /// Tate pairing
    Tate,
    /// Ate pairing
    Ate,
    /// R-ate pairing
    RAte,
    /// Optimal Ate pairing
    OptimalAte,
}

impl fmt::Display for PairingAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Weil => write!(f, "Weil"),
            Self::Tate => write!(f, "Tate"),
            Self::Ate => write!(f, "Ate"),
            Self::RAte => write!(f, "R-Ate"),
            Self::OptimalAte => write!(f, "Optimal-Ate"),
        }
    }
}

/// Element in the target group GT (multiplicative group over extension field)
///
/// This is a placeholder - in a real implementation, this would be an element
/// of the extension field F_q^k where k is the embedding degree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GTElement {
    /// The underlying bytes representation
    bytes: Vec<u8>,
}

impl GTElement {
    /// Creates a new GT element from bytes
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Returns the element as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns true if this is the identity element (1 in multiplicative group)
    pub fn is_identity(&self) -> bool {
        // Placeholder: treat all-zero as identity
        self.bytes.iter().all(|&b| b == 0)
    }

    /// Returns the identity element
    pub fn identity() -> Self {
        Self { bytes: vec![0u8; 48] }
    }
}

impl AsRef<[u8]> for GTElement {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pairing_curve_display() {
        assert_eq!(format!("{}", PairingCurve::BN254), "BN254");
        assert_eq!(format!("{}", PairingCurve::BLS12_381), "BLS12-381");
    }

    #[test]
    fn test_pairing_algorithm_display() {
        assert_eq!(format!("{}", PairingAlgorithm::Ate), "Ate");
        assert_eq!(format!("{}", PairingAlgorithm::Weil), "Weil");
    }

    #[test]
    fn test_gt_element() {
        let elem = GTElement::new(vec![1u8; 48]);
        assert_eq!(elem.as_bytes().len(), 48);
        assert!(!elem.is_identity());

        let identity = GTElement::identity();
        assert!(identity.is_identity());
    }
}
