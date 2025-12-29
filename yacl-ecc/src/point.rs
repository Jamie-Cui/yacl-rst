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

//! Elliptic curve point representation

use std::fmt;

/// An elliptic curve point in compressed or uncompressed form
#[derive(Clone, PartialEq, Eq)]
pub struct Point {
    bytes: Vec<u8>,
}

impl Point {
    /// Creates a new point from bytes
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Returns the point as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the length of the point in bytes
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns true if the point is empty
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl fmt::Debug for Point {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Point")
            .field("len", &self.bytes.len())
            .finish()
    }
}

impl AsRef<[u8]> for Point {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// An affine point (x, y coordinates)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AffinePoint {
    pub x: Vec<u8>,
    pub y: Vec<u8>,
}

impl AffinePoint {
    /// Creates a new affine point from coordinates
    pub fn new(x: Vec<u8>, y: Vec<u8>) -> Self {
        Self { x, y }
    }

    /// Returns true if this is the point at infinity
    pub fn is_identity(&self) -> bool {
        self.x.is_empty() && self.y.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_point_new() {
        let bytes = vec![0u8; 65];
        let point = Point::new(bytes.clone());
        assert_eq!(point.as_bytes(), &bytes[..]);
    }

    #[test]
    fn test_affine_point() {
        let x = vec![1u8; 32];
        let y = vec![2u8; 32];
        let point = AffinePoint::new(x.clone(), y.clone());
        assert_eq!(point.x, x);
        assert_eq!(point.y, y);
        assert!(!point.is_identity());
    }

    #[test]
    fn test_affine_point_identity() {
        let point = AffinePoint::new(vec![], vec![]);
        assert!(point.is_identity());
    }
}
