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

//! Error types for HMAC operations

use std::fmt;

/// Errors that can occur during HMAC operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HmacError {
    /// Invalid key length
    InvalidKeyLength {
        /// The provided key length
        provided: usize,
        /// The minimum required key length
        min: usize,
    },

    /// Generic HMAC error
    HmacError(String),
}

impl fmt::Display for HmacError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyLength { provided, min } => write!(
                f,
                "Invalid key length: provided {}, minimum is {}",
                provided, min
            ),
            Self::HmacError(msg) => write!(f, "HMAC error: {}", msg),
        }
    }
}

impl std::error::Error for HmacError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = HmacError::InvalidKeyLength {
            provided: 0,
            min: 1,
        };
        assert_eq!(format!("{}", err), "Invalid key length: provided 0, minimum is 1");
    }
}
