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

//! Oblivious pseudorandom function (OPRF)
//!
//! This module implements RFC 9497: OPRF using prime-order groups.
//!
//! # Protocol
//!
//! ```text
//! Client(input)                                        Server(skS)
//!   -------------------------------------------------------------------
//!   blind, blindedElement = Blind(input)
//!
//!                              blindedElement
//!                                ---------->
//!
//!                 evaluatedElement = BlindEvaluate(skS, blindedElement)
//!
//!                              evaluatedElement
//!                                <----------
//!
//!   output = Finalize(input, blind, evaluatedElement)
//! ```
//!
//! # Example
//!
//! ```rust
//! use yacl_oprf::{OprfClient, OprfServer, OprfConfig};
//!
//! let config = OprfConfig::default_config();
//! let mut client = OprfClient::new(&config).unwrap();
//! let server = OprfServer::new(&config).unwrap();
//!
//! let input = "test_element";
//! let blinded = client.blind(input).unwrap();
//! let evaluated = server.blind_evaluate(&blinded).unwrap();
//! let output = client.finalize(&evaluated, None).unwrap();
//! ```

pub mod error;
pub mod config;
pub mod client;
pub mod server;

pub use error::{OprfError, Result};
pub use config::{OprfConfig, OprfCtx, OprfMode, OprfCipherSuite};
pub use client::OprfClient;
pub use server::OprfServer;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oprf_full_protocol() {
        let config = OprfConfig::default_config();
        let mut client = OprfClient::new(&config).unwrap();
        let server = OprfServer::new(&config).unwrap();

        let input = "test_element";

        // Client blinds the input
        let blinded = client.blind(input).unwrap();

        // Server evaluates blindly
        let evaluated = server.blind_evaluate(&blinded).unwrap();

        // Client finalizes to get the output
        let output = client.finalize(&evaluated, None).unwrap();

        // Output should be a hash (non-empty)
        assert!(!output.is_empty());
        assert_eq!(output.len(), 32); // SHA-256 output
    }

    #[test]
    fn test_oprf_multiple_inputs() {
        let config = OprfConfig::default_config();
        let mut client = OprfClient::new(&config).unwrap();
        let server = OprfServer::new(&config).unwrap();

        let inputs = vec!["hello", "world", "test"];

        for input in inputs {
            let blinded = client.blind(input).unwrap();
            let evaluated = server.blind_evaluate(&blinded).unwrap();
            let output = client.finalize(&evaluated, None).unwrap();
            assert!(!output.is_empty());
        }
    }
}
