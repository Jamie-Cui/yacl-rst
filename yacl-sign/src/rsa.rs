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

//! RSA signatures with SHA-256

use crate::{Result, SignError, Signer, Verifier, SignatureScheme};
use rsa::{
    pkcs1v15::SigningKey as Pkcs1v15SigningKey,
    signature::{Keypair, SignatureEncoding, Signer as RsaSigner},
    RsaPrivateKey as RsPrivKey, RsaPublicKey as RsPubKey,
    traits::{PublicKeyParts, SignatureScheme as RsaSignatureScheme},
};
use sha2::Sha256;
use std::fmt;

/// Minimum RSA key size in bits
pub const MIN_RSA_KEY_SIZE: usize = 2048;

/// RSA public key wrapper
#[derive(Clone)]
pub struct RsaPublicKeyWrapper {
    inner: RsPubKey,
}

impl fmt::Debug for RsaPublicKeyWrapper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaPublicKey")
            .field("size", &self.inner.size())
            .finish()
    }
}

impl From<RsPubKey> for RsaPublicKeyWrapper {
    fn from(key: RsPubKey) -> Self {
        Self { inner: key }
    }
}

impl From<&RsaPublicKeyWrapper> for RsPubKey {
    fn from(wrapper: &RsaPublicKeyWrapper) -> Self {
        wrapper.inner.clone()
    }
}

/// RSA private key wrapper
#[derive(Clone)]
pub struct RsaPrivateKeyWrapper {
    inner: RsPrivKey,
}

impl fmt::Debug for RsaPrivateKeyWrapper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaPrivateKey")
            .field("size", &self.inner.size())
            .finish()
    }
}

impl From<RsPrivKey> for RsaPrivateKeyWrapper {
    fn from(key: RsPrivKey) -> Self {
        Self { inner: key }
    }
}

/// Type alias for RSA public key
pub type RsaPublicKey = RsaPublicKeyWrapper;

/// Type alias for RSA private key
pub type RsaPrivateKey = RsaPrivateKeyWrapper;

/// RSA-SHA256 signer using PKCS#1 v1.5 padding
#[derive(Clone)]
pub struct RsaSha256Signer {
    inner: Pkcs1v15SigningKey<Sha256>,
}

impl RsaSha256Signer {
    /// Creates a new RSA-SHA256 signer by generating a new key pair
    ///
    /// # Arguments
    ///
    /// * `rng` - Random number generator
    /// * `bits` - Key size in bits (minimum 2048)
    ///
    /// # Returns
    ///
    /// The signer instance
    ///
    /// # Errors
    ///
    /// Returns an error if key generation fails or key size is too small
    pub fn new(rng: &mut (impl rand::CryptoRng + rand::RngCore), bits: usize) -> Result<Self> {
        if bits < MIN_RSA_KEY_SIZE {
            return Err(SignError::InvalidKeySize {
                provided: bits,
                expected: MIN_RSA_KEY_SIZE,
            });
        }

        let private_key = RsPrivKey::new(rng, bits)
            .map_err(|e| SignError::KeyGenerationError(e.to_string()))?;

        Ok(Self {
            inner: Pkcs1v15SigningKey::<Sha256>::new_unprefixed(private_key),
        })
    }

    /// Creates a new RSA-SHA256 signer from an existing private key
    ///
    /// # Arguments
    ///
    /// * `private_key` - The RSA private key
    pub fn from_key(private_key: RsaPrivateKey) -> Self {
        Self {
            inner: Pkcs1v15SigningKey::<Sha256>::new_unprefixed(private_key.inner),
        }
    }

    /// Returns the public key verifier for this signer
    pub fn verifier(&self) -> RsaSha256Verifier {
        // Get the public key from the signing key
        RsaSha256Verifier {
            public_key: self.inner.verifying_key().into(),
        }
    }

    /// Returns the signature scheme
    pub fn scheme(&self) -> SignatureScheme {
        SignatureScheme::RsaPkcs1v15Sha256
    }
}

impl fmt::Debug for RsaSha256Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaSha256Signer")
            .field("scheme", &self.scheme())
            .finish()
    }
}

impl Signer for RsaSha256Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let sig = self.inner.sign(message);
        Ok(sig.to_bytes().to_vec())
    }
}

/// RSA-SHA256 verifier using PKCS#1 v1.5 padding
#[derive(Clone)]
pub struct RsaSha256Verifier {
    public_key: RsPubKey,
}

impl RsaSha256Verifier {
    /// Creates a new RSA-SHA256 verifier from a public key
    ///
    /// # Arguments
    ///
    /// * `public_key` - The RSA public key
    pub fn new(public_key: RsaPublicKey) -> Self {
        Self {
            public_key: public_key.inner,
        }
    }

    /// Returns the signature scheme
    pub fn scheme(&self) -> SignatureScheme {
        SignatureScheme::RsaPkcs1v15Sha256
    }
}

impl fmt::Debug for RsaSha256Verifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaSha256Verifier")
            .field("scheme", &self.scheme())
            .finish()
    }
}

impl Verifier for RsaSha256Verifier {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        use rsa::pkcs1v15::Pkcs1v15Sign;
        use sha2::Digest;

        if signature.len() != self.public_key.size() {
            return Err(SignError::InvalidSignature);
        }

        // Hash the message with SHA-256, then verify
        let mut hasher = Sha256::new();
        hasher.update(message);
        let hashed = hasher.finalize();

        Pkcs1v15Sign::new_unprefixed()
            .verify(&self.public_key, &hashed, signature)
            .map_err(|_| SignError::VerificationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsa_sha256_sign_verify() {
        let mut rng = rand::rngs::OsRng;
        let signer = RsaSha256Signer::new(&mut rng, 2048).unwrap();
        let verifier = signer.verifier();

        let message = b"Hello, world!";
        let signature = signer.sign(message).unwrap();
        match verifier.verify(message, &signature) {
            Ok(()) => (),
            Err(e) => panic!("Verification failed: {:?}", e),
        }
    }

    #[test]
    fn test_rsa_sha256_invalid_signature() {
        let mut rng = rand::rngs::OsRng;
        let signer = RsaSha256Signer::new(&mut rng, 2048).unwrap();
        let verifier = signer.verifier();

        let message = b"Hello, world!";
        let mut signature = signer.sign(message).unwrap();
        signature[0] ^= 0xFF; // Tamper with signature

        assert!(verifier.verify(message, &signature).is_err());
    }

    #[test]
    fn test_rsa_sha256_wrong_message() {
        let mut rng = rand::rngs::OsRng;
        let signer = RsaSha256Signer::new(&mut rng, 2048).unwrap();
        let verifier = signer.verifier();

        let message = b"Hello, world!";
        let signature = signer.sign(message).unwrap();
        let wrong_message = b"Wrong message";

        assert!(verifier.verify(wrong_message, &signature).is_err());
    }

    #[test]
    fn test_rsa_invalid_key_size() {
        let mut rng = rand::rngs::OsRng;
        let result = RsaSha256Signer::new(&mut rng, 512);
        assert!(result.is_err());
    }
}
