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

//! PKE traits

use crate::Result;
use std::fmt;

/// Public key encryptor trait
pub trait Encryptor: fmt::Debug + Send + Sync {
    /// Encrypts the plaintext
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The plaintext to encrypt
    ///
    /// # Returns
    ///
    /// The ciphertext
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>>;
}

/// Private key decryptor trait
pub trait Decryptor: fmt::Debug + Send + Sync {
    /// Decrypts the ciphertext
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The ciphertext to decrypt
    ///
    /// # Returns
    ///
    /// The decrypted plaintext
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockEncryptor;

    impl fmt::Debug for MockEncryptor {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("MockEncryptor").finish()
        }
    }

    impl Encryptor for MockEncryptor {
        fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
            Ok(plaintext.to_vec())
        }
    }

    struct MockDecryptor;

    impl fmt::Debug for MockDecryptor {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("MockDecryptor").finish()
        }
    }

    impl Decryptor for MockDecryptor {
        fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
            Ok(ciphertext.to_vec())
        }
    }

    #[test]
    fn test_encryptor_trait() {
        let encryptor = MockEncryptor;
        let plaintext = b"Hello, world!";
        let ciphertext = encryptor.encrypt(plaintext).unwrap();
        assert_eq!(plaintext, ciphertext.as_slice());
    }

    #[test]
    fn test_decryptor_trait() {
        let decryptor = MockDecryptor;
        let ciphertext = b"Hello, world!";
        let plaintext = decryptor.decrypt(ciphertext).unwrap();
        assert_eq!(ciphertext, plaintext.as_slice());
    }
}
