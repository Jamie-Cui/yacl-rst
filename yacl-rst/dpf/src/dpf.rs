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

//! Core Distributed Point Function implementation

use crate::error::{Error, Result};
use rand::{Rng, CryptoRng};
use serde::{Serialize, Deserialize};

/// The maximum supported input size in bits for DPF
pub const MAX_INPUT_SIZE: usize = 64;

/// Default security parameter in bits
pub const DEFAULT_SECURITY_PARAMETER: usize = 128;

/// Core trait defining the Distributed Point Function interface
pub trait Dpf {
    /// The type used to represent DPF keys
    type Key: DpfKeyShare;
    
    /// The type used to represent input points
    type Input: Clone + PartialEq + Eq;
    
    /// The type used to represent output values
    type Output: Clone + PartialEq + Eq;
    
    /// Generate DPF keys for a given point and value
    /// 
    /// # Arguments
    /// * `alpha` - The secret point where the function should output `beta`
    /// * `beta` - The value to output at point `alpha`
    /// * `input_size` - The size of the input domain in bits
    /// * `rng` - Cryptographically secure random number generator
    /// 
    /// # Returns
    /// A tuple of two keys (key_0, key_1) that can be distributed to two parties
    fn generate_keys<R: Rng + CryptoRng>(
        &self,
        alpha: &Self::Input,
        beta: &Self::Output,
        input_size: usize,
        rng: &mut R,
    ) -> Result<(Self::Key, Self::Key)>;
    
    /// Evaluate a DPF key at a given input point
    /// 
    /// # Arguments
    /// * `key` - The DPF key share to evaluate
    /// * `x` - The input point to evaluate
    /// 
    /// # Returns
    /// The share of the function value at point `x`
    fn evaluate(&self, key: &Self::Key, x: &Self::Input) -> Result<Self::Output>;
    
    /// Batch evaluate a DPF key at multiple input points
    /// 
    /// # Arguments
    /// * `key` - The DPF key share to evaluate
    /// * `inputs` - Slice of input points to evaluate
    /// 
    /// # Returns
    /// Vector of function value shares for each input point
    fn batch_evaluate(&self, key: &Self::Key, inputs: &[Self::Input]) -> Result<Vec<Self::Output>> {
        inputs
            .iter()
            .map(|x| self.evaluate(key, x))
            .collect()
    }
    
    /// Combine two DPF shares to get the final result
    /// 
    /// # Arguments
    /// * `share_0` - Share from party 0
    /// * `share_1` - Share from party 1
    /// 
    /// # Returns
    /// The combined result (beta if evaluating at alpha, 0 otherwise)
    fn combine_shares(&self, share_0: &Self::Output, share_1: &Self::Output) -> Self::Output;
}

/// Trait for DPF key shares
pub trait DpfKeyShare: Clone + Send + Sync + Serialize + for<'de> Deserialize<'de> {
    /// The party index (0 or 1) for this key share
    fn party_index(&self) -> usize;
    
    /// The size of the input domain in bits
    fn input_size(&self) -> usize;
    
    /// Validate that the key share is well-formed
    fn validate(&self) -> Result<()>;
}

/// A simple XOR-based DPF implementation for demonstration
#[derive(Debug, Clone)]
pub struct XorDpf {
    #[allow(dead_code)] // Reserved for future cryptographic enhancements
    security_parameter: usize,
}

impl XorDpf {
    /// Create a new XOR DPF instance
    pub fn new(security_parameter: usize) -> Self {
        Self {
            security_parameter: security_parameter.min(MAX_INPUT_SIZE),
        }
    }
    
    /// Create a new XOR DPF with default security parameter
    pub fn default() -> Self {
        Self::new(DEFAULT_SECURITY_PARAMETER)
    }
}

impl Default for XorDpf {
    fn default() -> Self {
        Self::default()
    }
}

/// XOR DPF key share implementation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XorDpfKey {
    /// Party index (0 or 1)
    party_index: usize,
    /// Input size in bits
    input_size: usize,
    /// Secret share of the point alpha
    alpha_share: u64,
    /// Secret share of the value beta
    beta_share: u64,
    /// Random mask for this share
    mask: u64,
}

impl XorDpfKey {
    /// Create a new XOR DPF key share
    pub fn new(party_index: usize, input_size: usize, alpha_share: u64, beta_share: u64, mask: u64) -> Self {
        Self {
            party_index,
            input_size,
            alpha_share,
            beta_share,
            mask,
        }
    }
    
    /// Get the alpha share
    pub fn alpha_share(&self) -> u64 {
        self.alpha_share
    }
    
    /// Get the beta share
    pub fn beta_share(&self) -> u64 {
        self.beta_share
    }
    
    /// Get the mask
    pub fn mask(&self) -> u64 {
        self.mask
    }
}

impl DpfKeyShare for XorDpfKey {
    fn party_index(&self) -> usize {
        self.party_index
    }
    
    fn input_size(&self) -> usize {
        self.input_size
    }
    
    fn validate(&self) -> Result<()> {
        if self.party_index > 1 {
            return Err(Error::InvalidKey("Party index must be 0 or 1".to_string()));
        }
        if self.input_size == 0 || self.input_size > MAX_INPUT_SIZE {
            return Err(Error::InvalidKey("Invalid input size".to_string()));
        }
        Ok(())
    }
}

/// Control word used in DPF evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cw {
    /// Control bits for the evaluation
    pub control_bits: Vec<bool>,
    /// Pseudorandom seed
    pub seed: [u8; 32],
    /// Current level in the evaluation tree
    pub level: usize,
}

impl Cw {
    /// Create a new control word
    pub fn new(control_bits: Vec<bool>, seed: [u8; 32], level: usize) -> Self {
        Self {
            control_bits,
            seed,
            level,
        }
    }
    
    /// Create an empty control word
    pub fn empty() -> Self {
        Self {
            control_bits: Vec::new(),
            seed: [0u8; 32],
            level: 0,
        }
    }
    
    /// Get the number of control bits
    pub fn len(&self) -> usize {
        self.control_bits.len()
    }
    
    /// Check if the control word is empty
    pub fn is_empty(&self) -> bool {
        self.control_bits.is_empty()
    }
}

impl Dpf for XorDpf {
    type Key = XorDpfKey;
    type Input = u64;
    type Output = u64;
    
    fn generate_keys<R: Rng + CryptoRng>(
        &self,
        alpha: &Self::Input,
        beta: &Self::Output,
        input_size: usize,
        rng: &mut R,
    ) -> Result<(Self::Key, Self::Key)> {
        if input_size > MAX_INPUT_SIZE {
            return Err(Error::InvalidInputLength {
                expected: MAX_INPUT_SIZE,
                actual: input_size,
            });
        }
        
  // For this simplified XOR DPF implementation, we use a deterministic approach:
        // Both parties get the same alpha and beta values, but different masks
        // This makes the evaluation logic simpler for demonstration
        
        // For this demo, both parties get the same alpha (in real DPF they'd get different shares)
        let alpha_share = *alpha;
        
        // Split beta between the two parties using modular addition to avoid overflow
        let beta_share_0: u64 = rng.gen_range(0..=*beta);
        let beta_share_1 = beta - beta_share_0; // This will always be >= 0
        
        // Use simple masks (in real DPF these would be more complex)
        let mask_0 = 0u64;
        let mask_1 = 0u64;
        
        let key_0 = XorDpfKey::new(0, input_size, alpha_share, beta_share_0, mask_0);
        let key_1 = XorDpfKey::new(1, input_size, alpha_share, beta_share_1, mask_1);
        
        Ok((key_0, key_1))
    }
    
    fn evaluate(&self, key: &Self::Key, x: &Self::Input) -> Result<Self::Output> {
        key.validate()?;
        
        // For this simplified XOR DPF implementation:
        // - When x == alpha_share, return beta_share ^ mask
        // - When x != alpha_share, return mask
        // This ensures that when both parties' shares are combined:
        // - At x == alpha: (beta_share_0 ^ mask_0) ^ (beta_share_1 ^ mask_1) = beta ^ (mask_0 ^ mask_1)
        // - At x != alpha: mask_0 ^ mask_1
        // Since mask_0 ^ mask_1 = 0 in our construction, this gives the correct behavior
        
        if *x == key.alpha_share() {
            Ok(key.beta_share() ^ key.mask())
        } else {
            Ok(0) // Return 0 for non-matching points (simplified)
        }
    }
    
    fn combine_shares(&self, share_0: &Self::Output, share_1: &Self::Output) -> Self::Output {
        // For this simplified DPF, we use addition to combine shares
        share_0 + share_1
    }
}

/// DpfKey - a generic wrapper for DPF keys
#[derive(Debug, Clone)]
pub struct DpfKey<K: DpfKeyShare> {
    inner: K,
}

impl<K: DpfKeyShare> DpfKey<K> {
    /// Create a new DPF key from a key share
    pub fn new(key_share: K) -> Self {
        Self { inner: key_share }
    }
    
    /// Get a reference to the inner key share
    pub fn inner(&self) -> &K {
        &self.inner
    }
    
    /// Get a mutable reference to the inner key share  
    pub fn inner_mut(&mut self) -> &mut K {
        &mut self.inner
    }
    
    /// Consume the DpfKey and return the inner key share
    pub fn into_inner(self) -> K {
        self.inner
    }
    
    /// Get the party index for this key
    pub fn party_index(&self) -> usize {
        self.inner.party_index()
    }
    
    /// Get the input size for this key
    pub fn input_size(&self) -> usize {
        self.inner.input_size()
    }
    
    /// Validate the key
    pub fn validate(&self) -> Result<()> {
        self.inner.validate()
    }
}

impl<K: DpfKeyShare> From<K> for DpfKey<K> {
    fn from(key_share: K) -> Self {
        Self::new(key_share)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;
    
    #[test]
    fn test_xor_dpf_key_generation() -> Result<()> {
        let dpf = XorDpf::default();
        let mut rng = thread_rng();
        
        let alpha = 42u64;
        let beta = 100u64;
        let input_size = 16;
        
        let (key_0, key_1) = dpf.generate_keys(&alpha, &beta, input_size, &mut rng)?;
        
        assert_eq!(key_0.party_index(), 0);
        assert_eq!(key_1.party_index(), 1);
        assert_eq!(key_0.input_size(), input_size);
        assert_eq!(key_1.input_size(), input_size);
        
        key_0.validate()?;
        key_1.validate()?;
        
        Ok(())
    }
    
    #[test]
    fn test_xor_dpf_evaluation() -> Result<()> {
        let dpf = XorDpf::default();
        let mut rng = thread_rng();
        
        let alpha = 42u64;
        let beta = 100u64;
        let input_size = 16;
        
        let (key_0, key_1) = dpf.generate_keys(&alpha, &beta, input_size, &mut rng)?;
        
        // Test evaluation at alpha
        let share_0 = dpf.evaluate(&key_0, &alpha)?;
        let share_1 = dpf.evaluate(&key_1, &alpha)?;
        let combined = dpf.combine_shares(&share_0, &share_1);
        
        // In this simplified implementation, we should get exactly beta at alpha
        assert_eq!(combined, beta, "Combined result at alpha should equal beta");
        
        Ok(())
    }
    
    #[test]
    fn test_control_word() {
        let cw = Cw::new(vec![true, false, true], [42u8; 32], 2);
        assert_eq!(cw.len(), 3);
        assert_eq!(cw.level, 2);
        assert!(!cw.is_empty());
        
        let empty_cw = Cw::empty();
        assert!(empty_cw.is_empty());
        assert_eq!(empty_cw.len(), 0);
    }
}
