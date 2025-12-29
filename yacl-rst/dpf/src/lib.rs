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

//! # Distributed Point Function (DPF) Implementation
//!
//! This crate provides a comprehensive implementation of Distributed Point Functions (DPF),
//! which are cryptographic primitives that allow two parties to securely evaluate a function
//! where only one party knows the input point and the other party knows the function value.
//!
//! ## Overview
//!
//! A DPF allows a secret point `alpha` and value `beta` to be split between two parties such that:
//! - Each party receives a share that reveals no information about `alpha` or `beta`
//! - When both parties evaluate their shares on any input `x`, they get partial results
//! - The partial results XOR to `beta` when `x = alpha`, and `0` otherwise
//!
//! ## Key Components
//!
//! - [`Dpf`] - Core trait defining the DPF interface
//! - [`DpfKey`] - Represents a secret key share for DPF evaluation
//! - [`Cw`] - Control word used in the evaluation process
//! - [`Error`] - Error types for DPF operations

pub mod dpf;
pub mod error;

// Examples module - include when building with examples feature or during testing
#[cfg(any(feature = "examples", test))]
pub mod examples;

pub use dpf::{
    get_terminate_level, split_dpf_seed, ControlWord, Cw, Dpf, DpfKey, DpfKeyImpl, DpfPrg, GE2n,
    XorDpf, XorDpfKey, YaclDpf,
};
pub use error::Error;
