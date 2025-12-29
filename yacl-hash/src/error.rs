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

//! Error types for hash operations

use std::fmt;

/// Errors that can occur during hash operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashError {
    /// Invalid output length specified
    InvalidOutputLength {
        /// The requested length
        requested: usize,
        /// The maximum allowed length
        max: usize,
    },

    /// Generic hash error
    HashError(String),
}

impl fmt::Display for HashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidOutputLength { requested, max } => write!(
                f,
                "Invalid output length: requested {}, maximum is {}",
                requested, max
            ),
            Self::HashError(msg) => write!(f, "Hash error: {}", msg),
        }
    }
}

impl std::error::Error for HashError {}

/// Result type for hash operations
pub type Result<T> = std::result::Result<T, HashError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = HashError::InvalidOutputLength {
            requested: 100,
            max: 64,
        };
        assert_eq!(
            format!("{}", err),
            "Invalid output length: requested 100, maximum is 64"
        );
    }
}
