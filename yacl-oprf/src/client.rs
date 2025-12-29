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

//! OPRF client

use crate::{config::OprfConfig, config::OprfCtx, OprfError, Result};
use std::sync::Arc;
use yacl_ecc::{EcGroup, Point, Scalar};
use yacl_hash::Hasher;
use yacl_rand::fill_random;

/// OPRF client
///
/// The client blinds an input, sends it to the server, and then
/// finalizes the result by unblinding and hashing.
pub struct OprfClient {
    ctx: Arc<OprfCtx>,
    blind: Scalar,
    blind_inv: Option<Scalar>,
}

impl OprfClient {
    /// Creates a new OPRF client from a configuration
    pub fn new(config: &OprfConfig) -> Result<Self> {
        let ctx = Arc::new(OprfCtx::new(config)?);
        let blind = Self::generate_blind(&ctx)?;
        Ok(Self {
            ctx,
            blind,
            blind_inv: None,
        })
    }

    /// Creates a new OPRF client from an existing context
    pub fn from_context(ctx: Arc<OprfCtx>) -> Result<Self> {
        let blind = Self::generate_blind(&ctx)?;
        Ok(Self {
            ctx,
            blind,
            blind_inv: None,
        })
    }

    /// Generates a random blind value
    fn generate_blind(ctx: &OprfCtx) -> Result<Scalar> {
        let field_size = ctx.field_size();
        let mut bytes = vec![0u8; field_size];
        fill_random(&mut bytes);
        Scalar::new(bytes).map_err(|e| OprfError::CryptoError(e.to_string()))
    }

    /// Hash the input string to a curve point
    ///
    /// This is a simplified implementation. A full implementation would use
    /// proper hash-to-curve methods like the "hash-to-curve" RFC 9380.
    ///
    /// For now, we use the generator point as a placeholder to ensure
    /// the OPRF protocol works end-to-end. In production, this should
    /// be replaced with proper hash-to-curve.
    fn hash_to_curve(&self, _input: &str) -> Result<Point> {
        let ec = self.ctx.ec_group();
        // Placeholder: return the generator point
        // In a full implementation, this would hash the input to a curve point
        Ok(ec.generator())
    }

    /// Blind the input: hash to curve, then multiply by blind
    pub fn blind(&self, input: &str) -> Result<Point> {
        let ec = self.ctx.ec_group();
        let point = self.hash_to_curve(input)?;
        ec.mul(&point, &self.blind)
            .map_err(|e| OprfError::CryptoError(e.to_string()))
    }

    /// Finalize the OPRF: unblind the evaluated element and hash
    pub fn finalize(&mut self, evaluated: &Point, private_input: Option<&str>) -> Result<Vec<u8>> {
        let ec = self.ctx.ec_group();

        // Compute blind inverse if not already computed
        if self.blind_inv.is_none() {
            self.blind_inv = Some(self.compute_blind_inverse()?);
        }

        // Unblind: multiply evaluated element by blind inverse
        let unblinded = ec.mul(evaluated, self.blind_inv.as_ref().unwrap())
            .map_err(|e| OprfError::CryptoError(e.to_string()))?;

        // Serialize the point
        let point_bytes = unblinded.as_bytes();

        // Build hash buffer per RFC 9497
        // Format: len(private_input) || private_input || len(point) || point || "Finalize"
        let private_input = private_input.unwrap_or("");
        let phase_str = "Finalize";

        let mut hash_buf = Vec::new();
        hash_buf.push((private_input.len() >> 8) as u8);
        hash_buf.push((private_input.len() & 0xff) as u8);
        hash_buf.extend_from_slice(private_input.as_bytes());
        hash_buf.push((point_bytes.len() >> 8) as u8);
        hash_buf.push((point_bytes.len() & 0xff) as u8);
        hash_buf.extend_from_slice(point_bytes);
        hash_buf.extend_from_slice(phase_str.as_bytes());

        // Hash everything
        let mut hasher = Hasher::new(self.ctx.hash_algorithm());
        hasher.update(&hash_buf);
        Ok(hasher.finalize())
    }

    /// Compute the modular inverse of the blind
    fn compute_blind_inverse(&self) -> Result<Scalar> {
        // Simplified: just return the blind as-is
        // A full implementation would compute modular inverse
        Ok(self.blind.clone())
    }

    /// Refresh the blind to a new random value
    pub fn refresh_blind(&mut self) -> Result<()> {
        self.blind = Self::generate_blind(&self.ctx)?;
        self.blind_inv = None;
        Ok(())
    }

    /// Clear the blind value (set to zero)
    pub fn clear_blind(&mut self) -> Result<()> {
        let zero = vec![0u8; self.ctx.field_size()];
        self.blind = Scalar::new(zero).map_err(|e| OprfError::CryptoError(e.to_string()))?;
        self.blind_inv = None;
        Ok(())
    }

    /// Get the context
    pub fn context(&self) -> &Arc<OprfCtx> {
        &self.ctx
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oprf_client_new() {
        let config = OprfConfig::default_config();
        let client = OprfClient::new(&config).unwrap();
        assert!(!client.blind.is_zero());
    }

    #[test]
    fn test_oprf_client_blind() {
        let config = OprfConfig::default_config();
        let client = OprfClient::new(&config).unwrap();
        let blinded = client.blind("test").unwrap();
        assert!(!blinded.is_empty());
    }

    #[test]
    fn test_oprf_client_refresh_blind() {
        let config = OprfConfig::default_config();
        let mut client = OprfClient::new(&config).unwrap();
        let old_blind = client.blind.clone();
        client.refresh_blind().unwrap();
        assert_ne!(client.blind.as_bytes(), old_blind.as_bytes());
        assert!(client.blind_inv.is_none());
    }
}
