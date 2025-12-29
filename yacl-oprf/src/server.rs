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

//! OPRF server

use crate::{config::OprfConfig, config::OprfCtx, OprfError, Result};
use std::sync::Arc;
use yacl_ecc::{EcGroup, Point, Scalar};
use yacl_rand::fill_random;

/// OPRF server
///
/// The server receives a blinded element from the client, evaluates it
/// by multiplying with its secret key, and returns the result.
pub struct OprfServer {
    ctx: Arc<OprfCtx>,
    blind: Scalar,
}

impl OprfServer {
    /// Creates a new OPRF server from a configuration
    pub fn new(config: &OprfConfig) -> Result<Self> {
        let ctx = Arc::new(OprfCtx::new(config)?);
        let blind = Self::generate_blind(&ctx)?;
        Ok(Self { ctx, blind })
    }

    /// Creates a new OPRF server from an existing context
    pub fn from_context(ctx: Arc<OprfCtx>) -> Result<Self> {
        let blind = Self::generate_blind(&ctx)?;
        Ok(Self { ctx, blind })
    }

    /// Generates a random blind value
    fn generate_blind(ctx: &OprfCtx) -> Result<Scalar> {
        let field_size = ctx.field_size();
        let mut bytes = vec![0u8; field_size];
        fill_random(&mut bytes);
        Scalar::new(bytes).map_err(|e| OprfError::CryptoError(e.to_string()))
    }

    /// Blind evaluate: multiplies the input point by the server's blind
    pub fn blind_evaluate(&self, input: &Point) -> Result<Point> {
        let ec = self.ctx.ec_group();
        ec.mul(input, &self.blind)
            .map_err(|e| OprfError::CryptoError(e.to_string()))
    }

    /// Refresh the blind to a new random value
    pub fn refresh_blind(&mut self) -> Result<()> {
        self.blind = Self::generate_blind(&self.ctx)?;
        Ok(())
    }

    /// Clear the blind value (set to zero)
    pub fn clear_blind(&mut self) -> Result<()> {
        let zero = vec![0u8; self.ctx.field_size()];
        self.blind = Scalar::new(zero).map_err(|e| OprfError::CryptoError(e.to_string()))?;
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
    fn test_oprf_server_new() {
        let config = OprfConfig::default_config();
        let server = OprfServer::new(&config).unwrap();
        assert!(!server.blind.is_zero());
    }

    #[test]
    fn test_oprf_server_refresh_blind() {
        let config = OprfConfig::default_config();
        let mut server = OprfServer::new(&config).unwrap();
        let old_blind = server.blind.clone();
        server.refresh_blind().unwrap();
        // Random values are almost always different
        assert_ne!(server.blind.as_bytes(), old_blind.as_bytes());
    }

    #[test]
    fn test_oprf_server_clear_blind() {
        let config = OprfConfig::default_config();
        let mut server = OprfServer::new(&config).unwrap();
        server.clear_blind().unwrap();
        assert!(server.blind.is_zero());
    }
}
