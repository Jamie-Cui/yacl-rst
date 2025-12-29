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

//! Public key encryption
//!
//! This module provides public key encryption algorithms including RSA-OAEP.
//!
//! # Supported Algorithms
//!
//! - RSA-OAEP with SHA-256: RSA encryption with OAEP padding
//!
//! # Example
//!
//! ```
//! use pke::{Encryptor, Decryptor, RsaOaepEncryptor, RsaOaepDecryptor};
//!
//! // Setup - generate key pair
//! let mut rng = rand::rngs::OsRng;
//! let (decryptor, encryptor) = RsaOaepDecryptor::new(&mut rng, 2048).unwrap();
//!
//! // Encrypt a message
//! let plaintext = b"Hello, world!";
//! let ciphertext = encryptor.encrypt(plaintext).unwrap();
//!
//! // Decrypt the message
//! let decrypted = decryptor.decrypt(&ciphertext).unwrap();
//! assert_eq!(plaintext, decrypted.as_slice());
//! ```

pub mod error;
pub mod rsa;
pub mod traits;

pub use error::{PkeError, Result};
pub use rsa::{RsaOaepDecryptor, RsaOaepEncryptor, RsaPrivateKey, RsaPublicKey};
pub use traits::{Decryptor, Encryptor};

use std::fmt;

/// PKE scheme identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PkeScheme {
    /// RSA with OAEP padding (2048-bit key)
    Rsa2048Oaep,
    /// RSA with OAEP padding (3072-bit key)
    Rsa3072Oaep,
    /// RSA with OAEP padding (4096-bit key)
    Rsa4096Oaep,
}

impl fmt::Display for PkeScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rsa2048Oaep => write!(f, "RSA2048-OAEP"),
            Self::Rsa3072Oaep => write!(f, "RSA3072-OAEP"),
            Self::Rsa4096Oaep => write!(f, "RSA4096-OAEP"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pke_scheme_display() {
        assert_eq!(format!("{}", PkeScheme::Rsa2048Oaep), "RSA2048-OAEP");
        assert_eq!(format!("{}", PkeScheme::Rsa3072Oaep), "RSA3072-OAEP");
        assert_eq!(format!("{}", PkeScheme::Rsa4096Oaep), "RSA4096-OAEP");
    }
}
