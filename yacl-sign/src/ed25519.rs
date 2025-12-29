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

//! Ed25519 signatures

use crate::{Result, SignError, Signer, Verifier, SignatureScheme};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer as EdSigner, Verifier as EdVerifier};
use rand::RngCore;
use std::fmt;

/// Ed25519 public key (32 bytes)
#[derive(Clone, PartialEq, Eq)]
pub struct Ed25519PublicKey {
    bytes: [u8; 32],
}

impl Ed25519PublicKey {
    /// Creates a new public key from bytes
    ///
    /// # Arguments
    ///
    /// * `bytes` - 32-byte public key
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self { bytes: *bytes }
    }

    /// Returns the public key as bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }
}

impl fmt::Debug for Ed25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519PublicKey")
            .field("bytes", &self.bytes)
            .finish()
    }
}

/// Ed25519 private key (32 bytes)
#[derive(Clone)]
pub struct Ed25519PrivateKey {
    bytes: [u8; 32],
}

impl Ed25519PrivateKey {
    /// Creates a new private key from bytes
    ///
    /// # Arguments
    ///
    /// * `bytes` - 32-byte private key
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self { bytes: *bytes }
    }

    /// Generates a new random private key
    pub fn generate() -> Self {
        let mut rng = rand::rngs::OsRng;
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self { bytes }
    }

    /// Returns the public key for this private key
    pub fn public_key(&self) -> Ed25519PublicKey {
        // For Ed25519, derive public key from private key
        let signing_key = SigningKey::from_bytes(&self.bytes);
        let verifying_key = signing_key.verifying_key();
        Ed25519PublicKey {
            bytes: verifying_key.to_bytes(),
        }
    }
}

impl fmt::Debug for Ed25519PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519PrivateKey").finish_non_exhaustive()
    }
}

impl Default for Ed25519PrivateKey {
    fn default() -> Self {
        Self::generate()
    }
}

/// Ed25519 signer
#[derive(Clone)]
pub struct Ed25519Signer {
    signing_key: SigningKey,
}

impl Ed25519Signer {
    /// Creates a new Ed25519 signer by generating a new key pair
    ///
    /// # Returns
    ///
    /// The signer instance
    pub fn new() -> Self {
        let mut rng = rand::rngs::OsRng;
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self {
            signing_key: SigningKey::from_bytes(&bytes),
        }
    }

    /// Creates a new Ed25519 signer from an existing signing key
    ///
    /// # Arguments
    ///
    /// * `signing_key` - The Ed25519 signing key
    pub fn from_key(signing_key: SigningKey) -> Self {
        Self { signing_key }
    }

    /// Returns the public key verifier for this signer
    pub fn verifier(&self) -> Ed25519Verifier {
        Ed25519Verifier {
            verifying_key: self.signing_key.verifying_key(),
        }
    }

    /// Returns the signature scheme
    pub fn scheme(&self) -> SignatureScheme {
        SignatureScheme::Ed25519
    }

    /// Returns the public key
    pub fn public_key(&self) -> Ed25519PublicKey {
        Ed25519PublicKey {
            bytes: self.signing_key.verifying_key().to_bytes(),
        }
    }
}

impl Default for Ed25519Signer {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Ed25519Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519Signer")
            .field("scheme", &self.scheme())
            .finish()
    }
}

impl Signer for Ed25519Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let sig = self.signing_key.sign(message);
        Ok(sig.to_bytes().to_vec())
    }
}

/// Ed25519 verifier
#[derive(Clone, PartialEq, Eq)]
pub struct Ed25519Verifier {
    verifying_key: VerifyingKey,
}

impl Ed25519Verifier {
    /// Creates a new Ed25519 verifier from a public key
    ///
    /// # Arguments
    ///
    /// * `public_key` - The Ed25519 public key
    pub fn new(public_key: Ed25519PublicKey) -> Self {
        Self {
            verifying_key: VerifyingKey::from_bytes(&public_key.bytes)
                .expect("invalid public key"),
        }
    }

    /// Returns the signature scheme
    pub fn scheme(&self) -> SignatureScheme {
        SignatureScheme::Ed25519
    }
}

impl fmt::Debug for Ed25519Verifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519Verifier")
            .field("scheme", &self.scheme())
            .finish()
    }
}

impl Verifier for Ed25519Verifier {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        let sig = Signature::try_from(signature)
            .map_err(|_| SignError::InvalidSignature)?;

        self.verifying_key
            .verify(message, &sig)
            .map_err(|_| SignError::VerificationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_sign_verify() {
        let signer = Ed25519Signer::new();
        let verifier = signer.verifier();

        let message = b"Hello, world!";
        let signature = signer.sign(message).unwrap();
        assert!(verifier.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_ed25519_invalid_signature() {
        let signer = Ed25519Signer::new();
        let verifier = signer.verifier();

        let message = b"Hello, world!";
        let mut signature = signer.sign(message).unwrap();
        signature[0] ^= 0xFF; // Tamper with signature

        assert!(verifier.verify(message, &signature).is_err());
    }

    #[test]
    fn test_ed25519_wrong_message() {
        let signer = Ed25519Signer::new();
        let verifier = signer.verifier();

        let message = b"Hello, world!";
        let signature = signer.sign(message).unwrap();
        let wrong_message = b"Wrong message";

        assert!(verifier.verify(wrong_message, &signature).is_err());
    }

    #[test]
    fn test_ed25519_keypair_roundtrip() {
        let signer = Ed25519Signer::new();
        let public_key = signer.public_key();
        let verifier = Ed25519Verifier::new(public_key);

        let message = b"Test message";
        let signature = signer.sign(message).unwrap();
        assert!(verifier.verify(message, &signature).is_ok());
    }
}
