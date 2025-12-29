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

//! Digital envelope (hybrid encryption)
//!
//! This module provides hybrid encryption combining asymmetric and symmetric encryption.
//!
//! # Example
//!
//! ```rust
//! use yacl_envelope::{Sealer, Opener, RsaAes128GcmSealer, RsaAes128GcmOpener};
//!
//! // Setup - generate key pair
//! let mut rng = rand::rngs::OsRng;
//! let (opener, sealer) = RsaAes128GcmOpener::new(&mut rng, 2048).unwrap();
//!
//! // Seal the message
//! let plaintext = b"Hello, world! This is a longer message.";
//! let sealed = sealer.seal(plaintext).unwrap();
//!
//! // Open the message
//! let opened = opener.open(&sealed).unwrap();
//! assert_eq!(plaintext, opened.as_slice());
//! ```

pub mod error;
pub mod rsa_envelope;

pub use error::{EnvelopeError, Result};
pub use rsa_envelope::{RsaAes128GcmSealer, RsaAes128GcmOpener, SealedMessage, Sealer, Opener};
