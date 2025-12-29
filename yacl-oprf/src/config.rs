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

//! OPRF configuration and context

use crate::{OprfError, Result};
use std::fmt;
use std::sync::Arc;
use yacl_ecc::{CurveName, EcGroup, P256, Point, Scalar};
use yacl_hash::HashAlgorithm;

/// OPRF mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OprfMode {
    /// Basic OPRF
    Oprf = 0x00,
    /// Verifiable OPRF
    Voprf = 0x01,
    /// Partially oblivious OPRF
    Poprf = 0x02,
}

impl OprfMode {
    pub fn from_u8(x: u8) -> Result<Self> {
        match x {
            0x00 => Ok(Self::Oprf),
            0x01 => Ok(Self::Voprf),
            0x02 => Ok(Self::Poprf),
            _ => Err(OprfError::InvalidConfig(format!("Invalid OPRF mode: {}", x))),
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// OPRF cipher suite
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OprfCipherSuite {
    /// P-256 with SHA-256
    P256Sha256,
    /// P-384 with SHA-384
    P384Sha384,
    /// P-521 with SHA-512
    P521Sha512,
}

impl OprfCipherSuite {
    pub fn from_str(s: &str) -> Result<Self> {
        match s {
            "P256-SHA256" => Ok(Self::P256Sha256),
            "P384-SHA384" => Ok(Self::P384Sha384),
            "P521-SHA512" => Ok(Self::P521Sha512),
            _ => Err(OprfError::InvalidConfig(format!(
                "Unrecognized cipher suite: {}",
                s
            ))),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::P256Sha256 => "P256-SHA256",
            Self::P384Sha384 => "P384-SHA384",
            Self::P521Sha512 => "P521-SHA512",
        }
    }

    pub fn curve_name(&self) -> CurveName {
        match self {
            Self::P256Sha256 => CurveName::P256,
            Self::P384Sha384 => CurveName::P384,
            Self::P521Sha512 => CurveName::P521,
        }
    }

    pub fn hash_algorithm(&self) -> HashAlgorithm {
        match self {
            Self::P256Sha256 => HashAlgorithm::Sha256,
            Self::P384Sha384 => HashAlgorithm::Sha384,
            Self::P521Sha512 => HashAlgorithm::Sha512,
        }
    }
}

/// OPRF configuration
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OprfConfig {
    mode: OprfMode,
    cipher_suite: OprfCipherSuite,
}

impl OprfConfig {
    pub fn new(mode: OprfMode, cipher_suite: OprfCipherSuite) -> Self {
        Self { mode, cipher_suite }
    }

    pub fn default_config() -> Self {
        Self {
            mode: OprfMode::Oprf,
            cipher_suite: OprfCipherSuite::P256Sha256,
        }
    }

    pub fn mode(&self) -> OprfMode {
        self.mode
    }

    pub fn cipher_suite(&self) -> OprfCipherSuite {
        self.cipher_suite
    }

    pub fn to_context_string(&self) -> String {
        format!(
            "OPRFV1-{}-{}",
            self.mode.to_u8(),
            self.cipher_suite.as_str()
        )
    }

    pub fn from_context_string(s: &str) -> Result<Self> {
        // Format: OPRFV1-{mode}-{cipher_suite}
        // where cipher_suite may contain dashes (e.g., P256-SHA256)
        if !s.starts_with("OPRFV1-") {
            return Err(OprfError::InvalidConfig(format!(
                "Invalid context string prefix: {}",
                s
            )));
        }
        let rest = &s[7..]; // Skip "OPRFV1-"
        let dash_idx = rest.find('-').ok_or_else(|| {
            OprfError::InvalidConfig(format!("Invalid context string: {}", s))
        })?;
        let mode_str = &rest[..dash_idx];
        let cipher_suite_str = &rest[dash_idx + 1..];

        let mode = OprfMode::from_u8(mode_str.parse().map_err(|_| {
            OprfError::InvalidConfig(format!("Invalid mode byte: {}", mode_str))
        })?)?;
        let cipher_suite = OprfCipherSuite::from_str(cipher_suite_str)?;
        Ok(Self { mode, cipher_suite })
    }
}

impl Default for OprfConfig {
    fn default() -> Self {
        Self::default_config()
    }
}

/// OPRF context
pub struct OprfCtx {
    ctx_str: String,
    mode: OprfMode,
    ec: Arc<dyn EcGroup>,
    hash: HashAlgorithm,
}

impl OprfCtx {
    pub fn new(config: &OprfConfig) -> Result<Self> {
        let ctx_str = config.to_context_string();
        let mode = config.mode();
        let hash = config.cipher_suite().hash_algorithm();

        // Create EC group based on cipher suite
        let ec: Arc<dyn EcGroup> = match config.cipher_suite() {
            OprfCipherSuite::P256Sha256 => Arc::new(P256::new()),
            // TODO: Add P384 and P521 support
            _ => {
                return Err(OprfError::InvalidConfig(format!(
                    "Unsupported cipher suite: {:?}",
                    config.cipher_suite()
                )))
            }
        };

        Ok(Self {
            ctx_str,
            mode,
            ec,
            hash,
        })
    }

    pub fn default_context() -> Result<Self> {
        Self::new(&OprfConfig::default_config())
    }

    pub fn context_string(&self) -> &str {
        &self.ctx_str
    }

    pub fn mode(&self) -> OprfMode {
        self.mode
    }

    pub fn ec_group(&self) -> &Arc<dyn EcGroup> {
        &self.ec
    }

    pub fn hash_algorithm(&self) -> HashAlgorithm {
        self.hash
    }

    pub fn curve_name(&self) -> CurveName {
        self.ec.curve_name()
    }

    pub fn field_size(&self) -> usize {
        self.ec.field_size()
    }

    pub fn order(&self) -> Vec<u8> {
        self.ec.order()
    }
}

impl fmt::Debug for OprfCtx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OprfCtx")
            .field("ctx_str", &self.ctx_str)
            .field("mode", &self.mode)
            .field("curve", &self.ec.curve_name())
            .field("hash", &self.hash)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oprf_config_default() {
        let config = OprfConfig::default_config();
        assert_eq!(config.mode(), OprfMode::Oprf);
        assert_eq!(config.cipher_suite(), OprfCipherSuite::P256Sha256);
    }

    #[test]
    fn test_oprf_config_context_string() {
        let config = OprfConfig::default_config();
        let ctx_str = config.to_context_string();
        assert_eq!(ctx_str, "OPRFV1-0-P256-SHA256");

        let parsed = OprfConfig::from_context_string(&ctx_str).unwrap();
        assert_eq!(parsed.mode(), config.mode());
        assert_eq!(parsed.cipher_suite(), config.cipher_suite());
    }

    #[test]
    fn test_oprf_cipher_suite_from_str() {
        assert_eq!(
            OprfCipherSuite::from_str("P256-SHA256").unwrap(),
            OprfCipherSuite::P256Sha256
        );
        assert!(OprfCipherSuite::from_str("invalid").is_err());
    }

    #[test]
    fn test_oprf_mode_from_u8() {
        assert_eq!(OprfMode::from_u8(0).unwrap(), OprfMode::Oprf);
        assert_eq!(OprfMode::from_u8(1).unwrap(), OprfMode::Voprf);
        assert_eq!(OprfMode::from_u8(2).unwrap(), OprfMode::Poprf);
        assert!(OprfMode::from_u8(3).is_err());
    }

    #[test]
    fn test_oprf_ctx_default() {
        let ctx = OprfCtx::default_context().unwrap();
        assert_eq!(ctx.mode(), OprfMode::Oprf);
        assert_eq!(ctx.curve_name(), CurveName::P256);
        assert_eq!(ctx.hash_algorithm(), HashAlgorithm::Sha256);
        assert_eq!(ctx.field_size(), 32);
    }
}
