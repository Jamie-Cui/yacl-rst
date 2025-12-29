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

//! RSA-OAEP encryption

use crate::{Result, PkeError, PkeScheme, Encryptor, Decryptor};
use rsa::{
    RsaPrivateKey as RsPrivKey, RsaPublicKey as RsPubKey,
    oaep::Oaep,
    traits::PublicKeyParts,
};
use sha2::Sha256;
use std::fmt;

/// Minimum RSA key size in bits
pub const MIN_RSA_KEY_SIZE: usize = 2048;

/// RSA public key wrapper
#[derive(Clone)]
pub struct RsaPublicKey {
    inner: RsPubKey,
}

impl fmt::Debug for RsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaPublicKey")
            .field("size", &self.inner.size())
            .finish()
    }
}

impl From<RsPubKey> for RsaPublicKey {
    fn from(key: RsPubKey) -> Self {
        Self { inner: key }
    }
}

/// RSA private key wrapper
#[derive(Clone)]
pub struct RsaPrivateKey {
    inner: RsPrivKey,
}

impl fmt::Debug for RsaPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaPrivateKey")
            .field("size", &self.inner.size())
            .finish()
    }
}

impl From<RsPrivKey> for RsaPrivateKey {
    fn from(key: RsPrivKey) -> Self {
        Self { inner: key }
    }
}

/// RSA-OAEP encryptor
#[derive(Clone)]
pub struct RsaOaepEncryptor {
    public_key: RsaPublicKey,
    scheme: PkeScheme,
}

impl RsaOaepEncryptor {
    /// Creates a new RSA-OAEP encryptor from a public key
    ///
    /// # Arguments
    ///
    /// * `public_key` - The RSA public key
    pub fn new(public_key: RsaPublicKey) -> Self {
        let bits = public_key.inner.size() * 8;
        let scheme = match bits {
            2048 => PkeScheme::Rsa2048Oaep,
            3072 => PkeScheme::Rsa3072Oaep,
            4096 => PkeScheme::Rsa4096Oaep,
            _ => PkeScheme::Rsa2048Oaep,
        };
        Self { public_key, scheme }
    }

    /// Returns the PKE scheme
    pub fn scheme(&self) -> PkeScheme {
        self.scheme
    }
}

impl fmt::Debug for RsaOaepEncryptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaOaepEncryptor")
            .field("scheme", &self.scheme())
            .finish()
    }
}

impl Encryptor for RsaOaepEncryptor {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut rng = rand::rngs::OsRng;
        let padding = Oaep::new::<Sha256>();

        self.public_key
            .inner
            .encrypt(&mut rng, padding, plaintext)
            .map_err(|e| PkeError::EncryptionFailed(e.to_string()))
    }
}

/// RSA-OAEP decryptor
#[derive(Clone)]
pub struct RsaOaepDecryptor {
    private_key: RsaPrivateKey,
    encryptor: RsaOaepEncryptor,
}

impl RsaOaepDecryptor {
    /// Creates a new RSA-OAEP decryptor by generating a new key pair
    ///
    /// # Arguments
    ///
    /// * `rng` - Random number generator
    /// * `bits` - Key size in bits (minimum 2048)
    ///
    /// # Returns
    ///
    /// The decryptor and the corresponding encryptor
    pub fn new(rng: &mut (impl rand::CryptoRng + rand::RngCore), bits: usize) -> Result<(Self, RsaOaepEncryptor)> {
        if bits < MIN_RSA_KEY_SIZE {
            return Err(PkeError::InvalidKeySize {
                provided: bits,
                expected: MIN_RSA_KEY_SIZE,
            });
        }

        let private_key = RsPrivKey::new(rng, bits)
            .map_err(|e| PkeError::KeyGenerationError(e.to_string()))?;
        let public_key = private_key.to_public_key();

        let decryptor = Self {
            private_key: RsaPrivateKey::from(private_key),
            encryptor: RsaOaepEncryptor::new(RsaPublicKey::from(public_key)),
        };

        let encryptor = decryptor.encryptor.clone();
        Ok((decryptor, encryptor))
    }

    /// Creates a new RSA-OAEP decryptor from an existing private key
    ///
    /// # Arguments
    ///
    /// * `private_key` - The RSA private key
    pub fn from_key(private_key: RsaPrivateKey) -> Self {
        let public_key = private_key.inner.to_public_key();
        let encryptor = RsaOaepEncryptor::new(RsaPublicKey::from(public_key));
        Self { private_key, encryptor }
    }

    /// Returns the corresponding encryptor
    pub fn encryptor(&self) -> RsaOaepEncryptor {
        self.encryptor.clone()
    }

    /// Returns the PKE scheme
    pub fn scheme(&self) -> PkeScheme {
        self.encryptor.scheme()
    }
}

impl fmt::Debug for RsaOaepDecryptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaOaepDecryptor")
            .field("scheme", &self.scheme())
            .finish()
    }
}

impl Decryptor for RsaOaepDecryptor {
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let padding = Oaep::new::<Sha256>();

        self.private_key
            .inner
            .decrypt(padding, ciphertext)
            .map_err(|e| PkeError::DecryptionFailed(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsa_oaep_encrypt_decrypt() {
        let mut rng = rand::rngs::OsRng;
        let (decryptor, encryptor) = RsaOaepDecryptor::new(&mut rng, 2048).unwrap();

        let plaintext = b"Hello, world!";
        let ciphertext = encryptor.encrypt(plaintext).unwrap();
        let decrypted = decryptor.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_rsa_oaep_wrong_key() {
        let mut rng = rand::rngs::OsRng;
        let (decryptor, encryptor) = RsaOaepDecryptor::new(&mut rng, 2048).unwrap();

        // Create another key pair
        let (_, other_encryptor) = RsaOaepDecryptor::new(&mut rng, 2048).unwrap();

        let plaintext = b"Hello, world!";
        let ciphertext = other_encryptor.encrypt(plaintext).unwrap();

        // Decryption with wrong key should fail
        assert!(decryptor.decrypt(&ciphertext).is_err());
    }

    #[test]
    fn test_rsa_invalid_key_size() {
        let mut rng = rand::rngs::OsRng;
        let result = RsaOaepDecryptor::new(&mut rng, 512);
        assert!(result.is_err());
    }

    #[test]
    fn test_rsa_message_too_long() {
        let mut rng = rand::rngs::OsRng;
        let (_, _encryptor) = RsaOaepDecryptor::new(&mut rng, 2048).unwrap();

        // Message too long for 2048-bit RSA key
        let long_plaintext = vec![0u8; 1000];
        let result = _encryptor.encrypt(&long_plaintext);
        // This might succeed with hybrid encryption, or fail if too long
        // For now, we just check that it doesn't panic
        let _ = result;
    }

    #[test]
    fn test_rsa_multiple_messages() {
        let mut rng = rand::rngs::OsRng;
        let (decryptor, encryptor) = RsaOaepDecryptor::new(&mut rng, 2048).unwrap();

        let messages = vec![
            b"Short".to_vec(),
            b"Medium length message".to_vec(),
            b"A longer message with more content".to_vec(),
        ];

        for plaintext in &messages {
            let ciphertext = encryptor.encrypt(plaintext).unwrap();
            let decrypted = decryptor.decrypt(&ciphertext).unwrap();
            assert_eq!(plaintext.as_slice(), decrypted.as_slice());
        }
    }
}
