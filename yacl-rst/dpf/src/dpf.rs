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
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};

/// The maximum supported input size in bits for DPF
pub const MAX_INPUT_SIZE: usize = 64;

/// Default security parameter in bits
pub const DEFAULT_SECURITY_PARAMETER: usize = 128;

/// Group Element in 2^n - represents elements in the field GF(2^n)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GE2n<const N: usize> {
    value: u128,
}

impl<const N: usize> GE2n<N> {
    /// Create a new GE2n element with the given value
    pub fn new(value: u128) -> Self {
        Self {
            value: value & Self::mask(),
        }
    }

    /// Get the mask for N bits
    pub fn mask() -> u128 {
        if N == 128 {
            u128::MAX
        } else {
            (1u128 << N) - 1
        }
    }

    /// Get the N-bit truncated value
    pub fn get_val(&self) -> u128 {
        self.value & Self::mask()
    }

    /// Get the N-bit mask
    pub fn get_mask(&self) -> u128 {
        Self::mask()
    }

    /// Get the number of bits
    pub fn get_n(&self) -> usize {
        N
    }

    /// Get the i-th least significant bit (0-indexed)
    pub fn get_bit(&self, i: usize) -> u8 {
        if i >= 128 {
            panic!("GetBit: index out of range");
        }
        ((self.value >> i) & 1) as u8
    }

    /// Reverse the group element in place (2^n - value)
    pub fn reverse_inplace(&mut self) {
        self.value = Self::mask() - self.get_val() + 1;
    }

    /// Get the reversed group element
    pub fn get_reverse(&self) -> Self {
        Self::new(Self::mask() - self.get_val() + 1)
    }

    /// Convert to u128
    pub fn as_u128(&self) -> u128 {
        self.get_val()
    }
}

impl<const N: usize> From<u128> for GE2n<N> {
    fn from(value: u128) -> Self {
        Self::new(value)
    }
}

impl<const N: usize> From<u64> for GE2n<N> {
    fn from(value: u64) -> Self {
        Self::new(value as u128)
    }
}

impl<const N: usize> From<GE2n<N>> for u128 {
    fn from(ge: GE2n<N>) -> Self {
        ge.get_val()
    }
}

impl<const N: usize> std::ops::Add for GE2n<N> {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self::new(self.get_val() + other.get_val())
    }
}

impl<const N: usize> std::ops::AddAssign for GE2n<N> {
    fn add_assign(&mut self, other: Self) {
        self.value = (self.get_val() + other.get_val()) & Self::mask();
    }
}

impl<const N: usize> std::ops::Sub for GE2n<N> {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        Self::new(self.get_val() - other.get_val())
    }
}

impl<const N: usize> std::ops::SubAssign for GE2n<N> {
    fn sub_assign(&mut self, other: Self) {
        self.value = (self.get_val() - other.get_val()) & Self::mask();
    }
}

impl<const N: usize> std::ops::Mul<u8> for GE2n<N> {
    type Output = Self;

    fn mul(self, scalar: u8) -> Self {
        Self::new(self.get_val() * (scalar as u128))
    }
}

/// Pseudorandom Generator for DPF operations
#[derive(Debug, Clone)]
pub struct DpfPrg {
    seed: u128,
}

impl DpfPrg {
    /// Create a new PRG with the given seed
    pub fn new(seed: u128) -> Self {
        Self { seed }
    }

    /// Generate the next 128-bit random value
    pub fn next(&mut self) -> u128 {
        // Simple PRG based on Xorshift - in production, use AES-CTR or similar
        let mut x = self.seed;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.seed = x;
        x
    }

    /// Generate a GE2n<N> value
    pub fn generate_ge2n<const N: usize>(&mut self) -> GE2n<N> {
        GE2n::new(self.next())
    }
}

/// Split DPF seed into left and right parts with control bits
pub fn split_dpf_seed(seed: u128) -> (u128, bool, u128, bool) {
    let mut prng = DpfPrg::new(seed);
    let seed_left = prng.next();
    let seed_right = prng.next();
    let tmp = prng.next();

    let t_left = ((tmp >> 1) & 1) != 0;
    let t_right = ((tmp >> 2) & 1) != 0;

    (seed_left, t_left, seed_right, t_right)
}

/// Get termination level for evaluation (based on security parameter)
pub fn get_terminate_level(enable_evalall: bool, m: usize, n: usize) -> usize {
    if !enable_evalall {
        return m;
    }

    // Simple security parameter calculation
    // In the original code, this uses YACL_MODULE_SECPARAM_C_UINT("dpf")
    let c = 128u64; // Default security parameter
    let x = (m as f64 - ((c as f64 / n as f64).log2().ceil())).round() as usize;
    std::cmp::min(m, x)
}

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
        inputs.iter().map(|x| self.evaluate(key, x)).collect()
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

/// A proper DPF implementation based on the yacl C++ algorithm
#[derive(Debug, Clone)]
pub struct YaclDpf<const M: usize, const N: usize> {
    _phantom: std::marker::PhantomData<(GE2n<M>, GE2n<N>)>,
}

impl<const M: usize, const N: usize> YaclDpf<M, N> {
    /// Create a new DPF instance
    pub fn new() -> Self {
        // Validate constraints
        assert!(M > 0 && M <= 64, "Input bits must be between 1 and 64");
        assert!(N > 0 && N <= 128, "Output bits must be between 1 and 128");

        Self {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<const M: usize, const N: usize> Default for YaclDpf<M, N> {
    fn default() -> Self {
        Self::new()
    }
}

/// A simple XOR-based DPF implementation for demonstration (legacy)
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

/// DPF Key implementation matching the C++ structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpfKeyImpl {
    /// Whether full domain evaluation is enabled
    pub enable_evalall: bool,
    /// Control words for each level
    pub cws_vec: Vec<ControlWord>,
    /// Final correlation words
    pub last_cw_vec: Vec<u128>,
    /// Party rank (0 or 1)
    rank: bool,
    /// Master seed
    mseed: u128,
}

impl DpfKeyImpl {
    /// Create a new DPF key
    pub fn new(rank: bool, mseed: u128) -> Self {
        Self {
            enable_evalall: false,
            cws_vec: Vec::new(),
            last_cw_vec: Vec::new(),
            rank,
            mseed,
        }
    }

    /// Enable full domain evaluation
    pub fn enable_evalall(&mut self) {
        self.enable_evalall = true;
    }

    /// Disable full domain evaluation
    pub fn disable_evalall(&mut self) {
        self.enable_evalall = false;
    }

    /// Get the party rank
    pub fn get_rank(&self) -> bool {
        self.rank
    }

    /// Set the party rank
    pub fn set_rank(&mut self, rank: bool) {
        self.rank = rank;
    }

    /// Get the master seed
    pub fn get_seed(&self) -> u128 {
        self.mseed
    }

    /// Set the master seed
    pub fn set_seed(&mut self, seed: u128) {
        self.mseed = seed;
    }
}

/// XOR DPF key share implementation (legacy)
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
    pub fn new(
        party_index: usize,
        input_size: usize,
        alpha_share: u64,
        beta_share: u64,
        mask: u64,
    ) -> Self {
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

impl DpfKeyShare for DpfKeyImpl {
    fn party_index(&self) -> usize {
        if self.rank {
            1
        } else {
            0
        }
    }

    fn input_size(&self) -> usize {
        // This should be set based on the DPF parameters, but for now we return a default
        64
    }

    fn validate(&self) -> Result<()> {
        if self.cws_vec.is_empty() && self.last_cw_vec.is_empty() {
            return Err(Error::InvalidKey("Key appears to be empty".to_string()));
        }
        Ok(())
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

/// Control word used in DPF evaluation - matches C++ CW structure
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlWord {
    /// Seed for this level
    seed: u128,
    /// Control bits storage: bit 0 = t_left, bit 1 = t_right
    t_store: u8,
}

impl ControlWord {
    /// Create a new control word
    pub fn new(seed: u128, t_left: bool, t_right: bool) -> Self {
        let t_store = (t_right as u8) << 1 | (t_left as u8);
        Self { seed, t_store }
    }

    /// Get left control bit
    pub fn get_lt(&self) -> bool {
        (self.t_store & 1) != 0
    }

    /// Get right control bit
    pub fn get_rt(&self) -> bool {
        ((self.t_store >> 1) & 1) != 0
    }

    /// Get seed
    pub fn get_seed(&self) -> u128 {
        self.seed
    }

    /// Get t_store value
    pub fn get_t_store(&self) -> u8 {
        self.t_store
    }

    /// Set left control bit
    pub fn set_lt(&mut self, t_left: bool) {
        self.t_store = ((self.t_store >> 1) << 1) | (t_left as u8);
    }

    /// Set right control bit
    pub fn set_rt(&mut self, t_right: bool) {
        self.t_store = (self.t_store & 1) | ((t_right as u8) << 1);
    }

    /// Set seed
    pub fn set_seed(&mut self, seed: u128) {
        self.seed = seed;
    }
}

/// Legacy Cw type for backward compatibility
pub type Cw = ControlWord;

impl<const M: usize, const N: usize> Dpf for YaclDpf<M, N> {
    type Key = DpfKeyImpl;
    type Input = GE2n<M>;
    type Output = GE2n<N>;

    fn generate_keys<R: Rng + CryptoRng>(
        &self,
        alpha: &Self::Input,
        beta: &Self::Output,
        _input_size: usize,
        rng: &mut R,
    ) -> Result<(Self::Key, Self::Key)> {
        // Generate master seeds
        let first_mk: u128 = rng.gen();
        let second_mk: u128 = rng.gen();
        self.generate_keys_internal(alpha, beta, first_mk, second_mk, false)
    }

    fn evaluate(&self, key: &Self::Key, input: &Self::Input) -> Result<Self::Output> {
        if key.enable_evalall {
            return Err(Error::EvaluationFailed(
                "Use batch_evaluate for evalall keys".to_string(),
            ));
        }

        let mut seed_working = key.get_seed();
        let mut t_working = key.get_rank();

        for i in 0..M {
            let cw_seed = key.cws_vec[i].get_seed();
            let cw_t_left = key.cws_vec[i].get_lt();
            let cw_t_right = key.cws_vec[i].get_rt();

            let (seed_left, t_left, seed_right, t_right) = split_dpf_seed(seed_working);

            let seed_left = if t_working {
                seed_left ^ cw_seed
            } else {
                seed_left
            };
            let t_left = t_left ^ ((t_working as u8 & cw_t_left as u8) != 0);
            let seed_right = if t_working {
                seed_right ^ cw_seed
            } else {
                seed_right
            };
            let t_right = t_right ^ ((t_working as u8 & cw_t_right as u8) != 0);

            if input.get_bit(i) != 0 {
                seed_working = seed_right;
                t_working = t_right;
            } else {
                seed_working = seed_left;
                t_working = t_left;
            }
        }

        let mut prg = DpfPrg::new(seed_working);
        let prg_output = prg.generate_ge2n::<N>();
        let tmp = GE2n::new(if t_working { key.last_cw_vec[0] } else { 0 });

        let result = if key.get_rank() {
            (prg_output + tmp).get_reverse()
        } else {
            prg_output + tmp
        };

        Ok(result)
    }

    fn combine_shares(&self, share_0: &Self::Output, share_1: &Self::Output) -> Self::Output {
        *share_0 + *share_1
    }

    fn batch_evaluate(&self, key: &Self::Key, inputs: &[Self::Input]) -> Result<Vec<Self::Output>> {
        if key.enable_evalall {
            return self.eval_all(key);
        }

        // For non-evalall keys, use the default implementation
        inputs.iter().map(|x| self.evaluate(key, x)).collect()
    }
}

impl<const M: usize, const N: usize> YaclDpf<M, N> {
    /// Internal key generation matching the C++ implementation
    pub fn generate_keys_internal(
        &self,
        alpha: &GE2n<M>,
        beta: &GE2n<N>,
        first_mk: u128,
        second_mk: u128,
        enable_evalall: bool,
    ) -> Result<(DpfKeyImpl, DpfKeyImpl)> {
        let term_level = get_terminate_level(enable_evalall, M, N);

        // Set up the return keys
        let mut first_key = DpfKeyImpl::new(false, first_mk);
        let mut second_key = DpfKeyImpl::new(true, second_mk);
        first_key
            .cws_vec
            .resize(term_level, ControlWord::new(0, false, false));
        second_key
            .cws_vec
            .resize(term_level, ControlWord::new(0, false, false));

        let mut seeds_working = [first_mk, second_mk];
        let mut t_working = [false, true]; // default by definition

        for i in 0..term_level {
            let mut seed_left = [0u128; 2];
            let mut seed_right = [0u128; 2];
            let mut t_left = [false; 2];
            let mut t_right = [false; 2];

            let alpha_bit = alpha.get_bit(i) != 0;

            // Use working seed to generate seeds
            let (sl, tl, sr, tr) = split_dpf_seed(seeds_working[0]);
            seed_left[0] = sl;
            t_left[0] = tl;
            seed_right[0] = sr;
            t_right[0] = tr;

            let (sl, tl, sr, tr) = split_dpf_seed(seeds_working[1]);
            seed_left[1] = sl;
            t_left[1] = tl;
            seed_right[1] = sr;
            t_right[1] = tr;

            let keep_seed = if alpha_bit { seed_right } else { seed_left };
            let lose_seed = if alpha_bit { seed_left } else { seed_right };
            let t_keep = if alpha_bit { t_right } else { t_left };

            let cw_seed = lose_seed[0] ^ lose_seed[1];
            let cw_t_left = t_left[0] ^ t_left[1] ^ alpha_bit ^ true;
            let cw_t_right = t_right[0] ^ t_right[1] ^ alpha_bit;
            let cw_t_keep = if alpha_bit { cw_t_right } else { cw_t_left };

            // Get the seeds_working and t_working for next level
            seeds_working[0] = if t_working[0] {
                keep_seed[0] ^ cw_seed
            } else {
                keep_seed[0]
            };
            seeds_working[1] = if t_working[1] {
                keep_seed[1] ^ cw_seed
            } else {
                keep_seed[1]
            };

            t_working[0] = t_keep[0] ^ (t_working[0] && cw_t_keep);
            t_working[1] = t_keep[1] ^ (t_working[1] && cw_t_keep);

            first_key.cws_vec[i] = ControlWord::new(cw_seed, cw_t_left, cw_t_right);
            second_key.cws_vec[i] = first_key.cws_vec[i];
        }

        // Expand final seed_working and get final correlation words
        let mut prg0 = DpfPrg::new(seeds_working[0]);
        let mut prg1 = DpfPrg::new(seeds_working[1]);

        if !enable_evalall {
            // Single point evaluation
            let last_cw =
                (*beta + prg0.generate_ge2n::<N>().get_reverse() + prg1.generate_ge2n::<N>())
                    .get_val();
            first_key.last_cw_vec.push(if t_working[1] {
                GE2n::<N>::new(last_cw).get_reverse().get_val()
            } else {
                last_cw
            });
            second_key.last_cw_vec.push(first_key.last_cw_vec[0]);
        } else {
            // Full domain evaluation
            first_key.enable_evalall();
            second_key.enable_evalall();

            let alpha_pos_term_level = (alpha.get_val() >> term_level) as u32;
            let expand_num = 1u32 << (M - term_level);

            for i in 0..expand_num {
                let last_cw = if i == alpha_pos_term_level {
                    *beta + prg0.generate_ge2n::<N>().get_reverse() + prg1.generate_ge2n::<N>()
                } else {
                    prg0.generate_ge2n::<N>().get_reverse() + prg1.generate_ge2n::<N>()
                };

                let cw_val = if t_working[1] {
                    last_cw.get_reverse().get_val()
                } else {
                    last_cw.get_val()
                };

                first_key.last_cw_vec.push(cw_val);
                second_key.last_cw_vec.push(cw_val);
            }
        }

        Ok((first_key, second_key))
    }

    /// Evaluate all points in the domain (full domain evaluation)
    pub fn eval_all(&self, key: &DpfKeyImpl) -> Result<Vec<GE2n<N>>> {
        if !key.enable_evalall {
            return Err(Error::EvaluationFailed(
                "Key not configured for evalall".to_string(),
            ));
        }

        let term_level = get_terminate_level(true, M, N);
        let num_outputs = 1usize << M;
        let mut outputs = vec![GE2n::<N>::new(0); num_outputs];

        self.traverse(
            key,
            &mut outputs,
            0, // current_level
            0, // current_pos
            key.get_seed(),
            key.get_rank(),
            term_level,
        );

        Ok(outputs)
    }

    /// Traverse the evaluation tree (recursive implementation)
    pub fn traverse(
        &self,
        key: &DpfKeyImpl,
        result: &mut [GE2n<N>],
        current_level: usize,
        current_pos: usize,
        seed_working: u128,
        t_working: bool,
        term_level: usize,
    ) {
        if current_level < term_level {
            let (seed_left, t_left, seed_right, t_right) = split_dpf_seed(seed_working);

            let cw_seed = key.cws_vec[current_level].get_seed();
            let cw_t_left = key.cws_vec[current_level].get_lt();
            let cw_t_right = key.cws_vec[current_level].get_rt();

            let seed_left = if t_working {
                seed_left ^ cw_seed
            } else {
                seed_left
            };
            let t_left = t_left ^ (t_working && cw_t_left);
            let seed_right = if t_working {
                seed_right ^ cw_seed
            } else {
                seed_right
            };
            let t_right = t_right ^ (t_working && cw_t_right);

            let next_left_pos = current_pos;
            let next_right_pos = (1 << current_level) + current_pos;

            self.traverse(
                key,
                result,
                current_level + 1,
                next_left_pos,
                seed_left,
                t_left,
                term_level,
            );
            self.traverse(
                key,
                result,
                current_level + 1,
                next_right_pos,
                seed_right,
                t_right,
                term_level,
            );
        } else {
            let mut prg = DpfPrg::new(seed_working);
            let expand_num = 1 << (M - term_level);

            for i in 0..expand_num {
                let tmp = GE2n::new(if t_working { key.last_cw_vec[i] } else { 0 });
                let prg_output = prg.generate_ge2n::<N>();

                result[current_pos + (i << term_level)] = if key.get_rank() {
                    (prg_output + tmp).get_reverse()
                } else {
                    prg_output + tmp
                };

                // Update PRG for next iteration
                let next_val = prg.next();
                prg = DpfPrg::new(next_val);
            }
        }
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
    fn test_ge2n_operations() {
        let ge1 = GE2n::<64>::new(42);
        let ge2 = GE2n::<64>::new(100);

        assert_eq!(ge1.get_val(), 42);
        assert_eq!(ge2.get_val(), 100);

        let sum = ge1 + ge2;
        assert_eq!(sum.get_val(), 142);

        assert_eq!(ge1.get_bit(0), 0);
        assert_eq!(ge1.get_bit(1), 1);
        assert_eq!(ge1.get_bit(5), 1);

        let rev = ge1.get_reverse();
        assert_ne!(rev.get_val(), ge1.get_val());
    }

    #[test]
    fn test_control_word() {
        let cw = ControlWord::new(12345, true, false);
        assert_eq!(cw.get_seed(), 12345);
        assert!(cw.get_lt());
        assert!(!cw.get_rt());

        let mut cw2 = cw;
        cw2.set_rt(true);
        assert!(cw2.get_rt());
    }

    #[test]
    fn test_prg() {
        let mut prg = DpfPrg::new(42);
        let val1 = prg.next();
        let val2 = prg.next();

        assert_ne!(val1, val2);

        let ge_val = prg.generate_ge2n::<64>();
        assert!(ge_val.get_val() < (1u128 << 64));
    }

    #[test]
    fn test_split_dpf_seed() {
        let (seed_left, _t_left, seed_right, _t_right) = split_dpf_seed(12345);

        assert_ne!(seed_left, seed_right);
        assert!(seed_left != 0 || seed_right != 0); // At least one should be non-zero
    }

    #[test]
    fn test_yacl_dpf_key_generation() -> Result<()> {
        let dpf = YaclDpf::<16, 64>::new();
        let mut rng = thread_rng();

        let alpha = GE2n::<16>::new(42);
        let beta = GE2n::<64>::new(100);

        let (key_0, key_1) = dpf.generate_keys(&alpha, &beta, 16, &mut rng)?;

        assert!(!key_0.get_rank()); // rank 0
        assert!(key_1.get_rank()); // rank 1

        key_0.validate()?;
        key_1.validate()?;

        Ok(())
    }

    #[test]
    fn test_yacl_dpf_evaluation() -> Result<()> {
        let dpf = YaclDpf::<8, 64>::new();
        let mut rng = thread_rng();

        let alpha = GE2n::<8>::new(42);
        let beta = GE2n::<64>::new(100);

        let (key_0, key_1) = dpf.generate_keys(&alpha, &beta, 8, &mut rng)?;

        // Test evaluation at alpha
        let share_0 = dpf.evaluate(&key_0, &alpha)?;
        let share_1 = dpf.evaluate(&key_1, &alpha)?;
        let combined = dpf.combine_shares(&share_0, &share_1);

        // Should get beta at alpha
        assert_eq!(combined.get_val(), beta.get_val());

        // Test evaluation at different point
        let other_point = GE2n::<8>::new(123);
        let share_0_other = dpf.evaluate(&key_0, &other_point)?;
        let share_1_other = dpf.evaluate(&key_1, &other_point)?;
        let combined_other = dpf.combine_shares(&share_0_other, &share_1_other);

        // Should get 0 at other points
        assert_eq!(combined_other.get_val(), 0);

        Ok(())
    }

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
}
