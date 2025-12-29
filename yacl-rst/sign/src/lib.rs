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

//! Digital signatures
//!
//! This module provides digital signature algorithms including RSA and Ed25519.
//!
//! # Supported Algorithms
//!
//! - RSA-PKCS1v15 with SHA-256: RSA signatures with PKCS#1 v1.5 padding
//! - RSA-PSS with SHA-256: RSA signatures with PSS padding
//! - Ed25519: Edwards-curve Digital Signature Algorithm
//!
//! # Example
//!
//! ```rust
//! use yacl_sign::{Signer, Verifier, RsaSha256Signer};
//!
//! // Setup - generate key pair
//! let mut rng = rand::rngs::OsRng;
//! let signer = RsaSha256Signer::new(&mut rng, 2048).unwrap();
//!
//! // Sign a message
//! let message = b"Hello, world!";
//! let signature = signer.sign(message).unwrap();
//!
//! // Verify the signature
//! let verifier = signer.verifier();
//! assert!(verifier.verify(message, &signature).is_ok());
//! ```

pub mod error;
pub mod rsa;
pub mod ed25519;
pub mod traits;

pub use error::{SignError, Result};
pub use rsa::{RsaSha256Signer, RsaSha256Verifier, RsaPublicKey, RsaPrivateKey};
pub use ed25519::{Ed25519Signer, Ed25519Verifier, Ed25519PublicKey, Ed25519PrivateKey};
pub use traits::{Signer, Verifier};

use std::fmt;

/// Signature scheme identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SignatureScheme {
    /// RSA with PKCS#1 v1.5 padding and SHA-256
    RsaPkcs1v15Sha256,
    /// RSA with PSS padding and SHA-256
    RsaPssSha256,
    /// Ed25519 (EdDSA)
    Ed25519,
}

impl fmt::Display for SignatureScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RsaPkcs1v15Sha256 => write!(f, "RSA-PKCS1v15-SHA256"),
            Self::RsaPssSha256 => write!(f, "RSA-PSS-SHA256"),
            Self::Ed25519 => write!(f, "Ed25519"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_scheme_display() {
        assert_eq!(format!("{}", SignatureScheme::RsaPkcs1v15Sha256), "RSA-PKCS1v15-SHA256");
        assert_eq!(format!("{}", SignatureScheme::RsaPssSha256), "RSA-PSS-SHA256");
        assert_eq!(format!("{}", SignatureScheme::Ed25519), "Ed25519");
    }
}
