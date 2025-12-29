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

//! ECC error types

use std::fmt;

/// ECC error type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EcError {
    /// Invalid point
    InvalidPoint,
    /// Invalid scalar
    InvalidScalar,
    /// Point not on curve
    PointNotOnCurve,
    /// Unsupported curve
    UnsupportedCurve,
    /// Arithmetic error
    ArithmeticError(String),
}

impl fmt::Display for EcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPoint => write!(f, "Invalid point"),
            Self::InvalidScalar => write!(f, "Invalid scalar"),
            Self::PointNotOnCurve => write!(f, "Point not on curve"),
            Self::UnsupportedCurve => write!(f, "Unsupported curve"),
            Self::ArithmeticError(msg) => write!(f, "Arithmetic error: {}", msg),
        }
    }
}

impl std::error::Error for EcError {}

/// ECC result type
pub type Result<T> = std::result::Result<T, EcError>;
