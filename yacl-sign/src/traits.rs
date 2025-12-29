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

//! Signature traits

use crate::Result;
use std::fmt;

/// Trait for signing messages
pub trait Signer: fmt::Debug + Send + Sync {
    /// Signs the given message
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign
    ///
    /// # Returns
    ///
    /// The signature bytes
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>>;
}

/// Trait for verifying signatures
pub trait Verifier: fmt::Debug + Send + Sync {
    /// Verifies a signature for the given message
    ///
    /// # Arguments
    ///
    /// * `message` - The message that was signed
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    ///
    /// Ok(()) if the signature is valid
    ///
    /// # Errors
    ///
    /// Returns an error if verification fails
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock signer/verifier for testing the traits
    #[derive(Debug)]
    struct MockSigner;

    impl Signer for MockSigner {
        fn sign(&self, _message: &[u8]) -> Result<Vec<u8>> {
            Ok(vec![1, 2, 3, 4])
        }
    }

    #[derive(Debug)]
    struct MockVerifier {
        valid: bool,
    }

    impl Verifier for MockVerifier {
        fn verify(&self, _message: &[u8], _signature: &[u8]) -> Result<()> {
            if self.valid {
                Ok(())
            } else {
                Err(crate::SignError::VerificationFailed)
            }
        }
    }

    #[test]
    fn test_signer_trait() {
        let signer = MockSigner;
        let sig = signer.sign(b"test").unwrap();
        assert_eq!(sig, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_verifier_trait_valid() {
        let verifier = MockVerifier { valid: true };
        assert!(verifier.verify(b"test", &[1, 2, 3, 4]).is_ok());
    }

    #[test]
    fn test_verifier_trait_invalid() {
        let verifier = MockVerifier { valid: false };
        assert!(verifier.verify(b"test", &[1, 2, 3, 4]).is_err());
    }
}
