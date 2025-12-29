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

//! Scalar (private key) representation

use crate::{Result, EcError};
use std::fmt;

/// A scalar value (private key/integer modulo curve order)
#[derive(Clone, PartialEq, Eq)]
pub struct Scalar {
    bytes: Vec<u8>,
}

impl Scalar {
    /// Creates a new scalar from bytes
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        if bytes.is_empty() {
            return Err(EcError::InvalidScalar);
        }
        Ok(Self { bytes })
    }

    /// Creates a scalar from a fixed-size array
    pub fn from_bytes<const N: usize>(bytes: &[u8; N]) -> Self {
        Self { bytes: bytes.to_vec() }
    }

    /// Returns the scalar as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the length of the scalar in bytes
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns true if the scalar is zero
    pub fn is_zero(&self) -> bool {
        self.bytes.iter().all(|&b| b == 0)
    }
}

impl fmt::Debug for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Scalar")
            .field("len", &self.bytes.len())
            .finish()
    }
}

impl AsRef<[u8]> for Scalar {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scalar_new() {
        let bytes = vec![1u8; 32];
        let scalar = Scalar::new(bytes.clone()).unwrap();
        assert_eq!(scalar.as_bytes(), &bytes[..]);
    }

    #[test]
    fn test_scalar_empty() {
        let scalar = Scalar::new(vec![]);
        assert!(scalar.is_err());
    }

    #[test]
    fn test_scalar_zero() {
        let scalar = Scalar::new(vec![0u8; 32]).unwrap();
        assert!(scalar.is_zero());
    }

    #[test]
    fn test_scalar_nonzero() {
        let scalar = Scalar::new(vec![1u8; 32]).unwrap();
        assert!(!scalar.is_zero());
    }
}
