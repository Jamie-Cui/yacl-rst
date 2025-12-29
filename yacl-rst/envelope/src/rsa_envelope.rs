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

//! RSA + AES-GCM envelope (hybrid encryption)

use crate::{EnvelopeError, Result};
use aead::{AeadCipher, Aes128Gcm};
use pke::{Decryptor, Encryptor, RsaOaepDecryptor, RsaOaepEncryptor};
use rand::fill_random;
use rand_ext::CryptoRng as RandCryptoRng;
use rand_ext::RngCore as RandRngCore;
use std::fmt;

/// A sealed message containing the encrypted key and ciphertext
#[derive(Clone, PartialEq, Eq)]
pub struct SealedMessage {
    /// Encrypted symmetric key
    pub encrypted_key: Vec<u8>,
    /// IV/nonce for AEAD
    pub nonce: Vec<u8>,
    /// Ciphertext (data encrypted with symmetric key)
    pub ciphertext: Vec<u8>,
    /// Authentication tag
    pub tag: Vec<u8>,
}

impl fmt::Debug for SealedMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedMessage")
            .field("encrypted_key_len", &self.encrypted_key.len())
            .field("nonce_len", &self.nonce.len())
            .field("ciphertext_len", &self.ciphertext.len())
            .field("tag_len", &self.tag.len())
            .finish()
    }
}

impl SealedMessage {
    /// Creates a new sealed message from components
    pub fn new(encrypted_key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>, tag: Vec<u8>) -> Self {
        Self {
            encrypted_key,
            nonce,
            ciphertext,
            tag,
        }
    }

    /// Serializes the sealed message to a single byte vector
    pub fn to_vec(&self) -> Vec<u8> {
        let mut result = Vec::new();

        // Format: [ek_len(2)][encrypted_key][nonce][tag][ciphertext]
        let ek_len = self.encrypted_key.len() as u16;
        result.extend_from_slice(&ek_len.to_be_bytes());
        result.extend_from_slice(&self.encrypted_key);
        result.extend_from_slice(&self.nonce);
        result.extend_from_slice(&self.tag);
        result.extend_from_slice(&self.ciphertext);

        result
    }

    /// Deserializes a sealed message from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 2 {
            return Err(EnvelopeError::InvalidFormat);
        }

        let ek_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        let offset = 2;

        if data.len() < offset + ek_len + 12 + 16 {
            return Err(EnvelopeError::InvalidFormat);
        }

        let encrypted_key = data[offset..offset + ek_len].to_vec();
        let offset = offset + ek_len;

        let nonce = data[offset..offset + 12].to_vec();
        let offset = offset + 12;

        let tag = data[offset..offset + 16].to_vec();
        let offset = offset + 16;

        let ciphertext = data[offset..].to_vec();

        Ok(Self {
            encrypted_key,
            nonce,
            ciphertext,
            tag,
        })
    }
}

/// Envelope sealer trait
pub trait Sealer: fmt::Debug + Send + Sync {
    /// Seals a message using hybrid encryption
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The plaintext to seal
    ///
    /// # Returns
    ///
    /// The sealed message
    fn seal(&self, plaintext: &[u8]) -> Result<SealedMessage>;
}

/// Envelope opener trait
pub trait Opener: fmt::Debug + Send + Sync {
    /// Opens a sealed message
    ///
    /// # Arguments
    ///
    /// * `sealed` - The sealed message
    ///
    /// # Returns
    ///
    /// The decrypted plaintext
    fn open(&self, sealed: &SealedMessage) -> Result<Vec<u8>>;
}

/// RSA-OAEP + AES-128-GCM sealer
#[derive(Clone)]
pub struct RsaAes128GcmSealer {
    encryptor: RsaOaepEncryptor,
}

impl RsaAes128GcmSealer {
    /// Creates a new RSA-AES-GCM sealer
    ///
    /// # Arguments
    ///
    /// * `encryptor` - The RSA-OAEP encryptor
    pub fn new(encryptor: RsaOaepEncryptor) -> Self {
        Self { encryptor }
    }
}

impl fmt::Debug for RsaAes128GcmSealer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaAes128GcmSealer")
            .field("scheme", &self.encryptor.scheme())
            .finish()
    }
}

impl Sealer for RsaAes128GcmSealer {
    fn seal(&self, plaintext: &[u8]) -> Result<SealedMessage> {
        // Generate a random symmetric key and nonce
        let mut symmetric_key = [0u8; 16]; // AES-128
        let mut nonce = [0u8; 12]; // 96-bit nonce for GCM
        fill_random(&mut symmetric_key);
        fill_random(&mut nonce);

        // Encrypt the plaintext with AES-128-GCM
        let aead = Aes128Gcm::new(&symmetric_key);
        let (ciphertext, tag) = aead
            .encrypt(plaintext, &[], &nonce)
            .map_err(|e| EnvelopeError::DataEncryptionFailed(e.to_string()))?;

        // Encrypt the symmetric key with RSA-OAEP
        let encrypted_key = self
            .encryptor
            .encrypt(&symmetric_key)
            .map_err(|e| EnvelopeError::KeyEncryptionFailed(e.to_string()))?;

        Ok(SealedMessage {
            encrypted_key,
            nonce: nonce.to_vec(),
            ciphertext,
            tag,
        })
    }
}

/// RSA-OAEP + AES-128-GCM opener
#[derive(Clone)]
pub struct RsaAes128GcmOpener {
    decryptor: RsaOaepDecryptor,
}

impl RsaAes128GcmOpener {
    /// Creates a new RSA-AES-GCM opener by generating a new key pair
    ///
    /// # Arguments
    ///
    /// * `rng` - Random number generator
    /// * `bits` - RSA key size in bits (minimum 2048)
    ///
    /// # Returns
    ///
    /// The opener and the corresponding sealer
    pub fn new(
        rng: &mut (impl RandCryptoRng + RandRngCore),
        bits: usize,
    ) -> Result<(Self, RsaAes128GcmSealer)> {
        let (decryptor, encryptor) = RsaOaepDecryptor::new(rng, bits)
            .map_err(|e| EnvelopeError::KeyEncryptionFailed(e.to_string()))?;

        let opener = Self { decryptor };
        let sealer = RsaAes128GcmSealer::new(encryptor);

        Ok((opener, sealer))
    }

    /// Creates a new RSA-AES-GCM opener from an existing RSA decryptor
    ///
    /// # Arguments
    ///
    /// * `decryptor` - The RSA-OAEP decryptor
    pub fn from_decryptor(decryptor: RsaOaepDecryptor) -> Self {
        Self { decryptor }
    }

    /// Returns the corresponding sealer
    pub fn sealer(&self) -> RsaAes128GcmSealer {
        RsaAes128GcmSealer::new(self.decryptor.encryptor())
    }
}

impl fmt::Debug for RsaAes128GcmOpener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaAes128GcmOpener")
            .field("scheme", &self.decryptor.scheme())
            .finish()
    }
}

impl Opener for RsaAes128GcmOpener {
    fn open(&self, sealed: &SealedMessage) -> Result<Vec<u8>> {
        // Decrypt the symmetric key with RSA-OAEP
        let symmetric_key = self
            .decryptor
            .decrypt(&sealed.encrypted_key)
            .map_err(|e| EnvelopeError::KeyDecryptionFailed(e.to_string()))?;

        if symmetric_key.len() != 16 {
            return Err(EnvelopeError::InvalidKeySize {
                provided: symmetric_key.len(),
                expected: 16,
            });
        }

        let key: [u8; 16] =
            symmetric_key
                .try_into()
                .map_err(|_| EnvelopeError::InvalidKeySize {
                    provided: 0,
                    expected: 16,
                })?;

        if sealed.nonce.len() != 12 {
            return Err(EnvelopeError::InvalidFormat);
        }

        let nonce: [u8; 12] = sealed
            .nonce
            .clone()
            .try_into()
            .map_err(|_| EnvelopeError::InvalidFormat)?;

        // Decrypt the ciphertext with AES-128-GCM
        let aead = Aes128Gcm::new(&key);
        aead.decrypt(&sealed.ciphertext, &sealed.tag, &[], &nonce)
            .map_err(|e| EnvelopeError::DataDecryptionFailed(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsa_aes_envelope_seal_open() {
        let mut rng = rand::rngs::OsRng;
        let (opener, sealer) = RsaAes128GcmOpener::new(&mut rng, 2048).unwrap();

        let plaintext = b"Hello, world! This is a longer message that needs proper encryption.";
        let sealed = sealer.seal(plaintext).unwrap();
        let opened = opener.open(&sealed).unwrap();

        assert_eq!(plaintext, opened.as_slice());
    }

    #[test]
    fn test_rsa_aes_envelope_serialization() {
        let mut rng = rand::rngs::OsRng;
        let (opener, sealer) = RsaAes128GcmOpener::new(&mut rng, 2048).unwrap();

        let plaintext = b"Hello, world!";
        let sealed = sealer.seal(plaintext).unwrap();

        // Serialize
        let serialized = sealed.to_vec();

        // Deserialize
        let deserialized = SealedMessage::from_bytes(&serialized).unwrap();

        // Open should work
        let opened = opener.open(&deserialized).unwrap();
        assert_eq!(plaintext, opened.as_slice());
    }

    #[test]
    fn test_rsa_aes_envelope_wrong_key() {
        let mut rng = rand::rngs::OsRng;
        let (opener, _sealer) = RsaAes128GcmOpener::new(&mut rng, 2048).unwrap();

        // Create another key pair
        let (_, other_sealer) = RsaAes128GcmOpener::new(&mut rng, 2048).unwrap();

        let plaintext = b"Hello, world!";
        let sealed = other_sealer.seal(plaintext).unwrap();

        // Opening with wrong key should fail
        assert!(opener.open(&sealed).is_err());
    }

    #[test]
    fn test_rsa_aes_envelope_empty_message() {
        let mut rng = rand::rngs::OsRng;
        let (opener, sealer) = RsaAes128GcmOpener::new(&mut rng, 2048).unwrap();

        let plaintext = b"";
        let sealed = sealer.seal(plaintext).unwrap();
        let opened = opener.open(&sealed).unwrap();

        assert_eq!(plaintext, opened.as_slice());
    }

    #[test]
    fn test_rsa_aes_envelope_long_message() {
        let mut rng = rand::rngs::OsRng;
        let (opener, sealer) = RsaAes128GcmOpener::new(&mut rng, 2048).unwrap();

        let plaintext = vec![b'X'; 10000];
        let sealed = sealer.seal(&plaintext).unwrap();
        let opened = opener.open(&sealed).unwrap();

        assert_eq!(plaintext, opened.as_slice());
    }

    #[test]
    fn test_rsa_aes_envelope_tampered_ciphertext() {
        let mut rng = rand::rngs::OsRng;
        let (opener, sealer) = RsaAes128GcmOpener::new(&mut rng, 2048).unwrap();

        let plaintext = b"Hello, world!";
        let mut sealed = sealer.seal(plaintext).unwrap();
        sealed.ciphertext[0] ^= 0xFF; // Tamper

        assert!(opener.open(&sealed).is_err());
    }
}
