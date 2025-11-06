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

//! Example usage of the Distributed Point Function implementation

use crate::dpf::{ControlWord, Dpf, DpfKey, DpfKeyShare, GE2n, XorDpf, YaclDpf};
use crate::error::Result;
use rand::{thread_rng, Rng};

/// Basic DPF usage example
///
/// This example demonstrates how to:
/// 1. Create a DPF instance
/// 2. Generate keys for a secret point-value pair
/// 3. Evaluate the DPF at different points
/// 4. Combine shares to get the final result
pub fn basic_dpf_example() -> Result<()> {
    println!("=== Basic DPF Example ===\n");

    // Create a DPF instance
    let dpf = XorDpf::default();
    let mut rng = thread_rng();

    // Define the secret point (alpha) and value (beta)
    let alpha = 42u64; // Secret point where function outputs beta
    let beta = 100u64; // Value to output at point alpha
    let input_size = 16; // Input domain size in bits

    println!("Secret point (alpha): {}", alpha);
    println!("Secret value (beta): {}", beta);
    println!("Input domain size: {} bits\n", input_size);

    // Generate two key shares
    let (key_0, key_1) = dpf.generate_keys(&alpha, &beta, input_size, &mut rng)?;

    println!("[OK] Generated two key shares:");
    println!(
        "  - Key 0 (Party 0): party_index={}, input_size={}",
        key_0.party_index(),
        key_0.input_size()
    );
    println!(
        "  - Key 1 (Party 1): party_index={}, input_size={}",
        key_1.party_index(),
        key_1.input_size()
    );

    // Test points to evaluate
    let test_points = vec![0u64, 42u64, 100u64, 1000u64];

    println!("\n--- Evaluating DPF ---");
    for &x in &test_points {
        // Each party evaluates their key share independently
        let share_0 = dpf.evaluate(&key_0, &x)?;
        let share_1 = dpf.evaluate(&key_1, &x)?;

        // Combine shares to get final result
        let result = dpf.combine_shares(&share_0, &share_1);

        println!(
            "x = {:4}: share_0 = {:4}, share_1 = {:4}, result = {:4} {}",
            x,
            share_0,
            share_1,
            result,
            if x == alpha {
                "[OK] (beta)"
            } else if result == 0 {
                "[OK] (0)"
            } else {
                "?"
            }
        );
    }

    Ok(())
}

/// Batch evaluation example
///
/// Demonstrates how to evaluate a DPF key at multiple points efficiently
pub fn batch_evaluation_example() -> Result<()> {
    println!("\n=== Batch Evaluation Example ===\n");

    let dpf = XorDpf::default();
    let mut rng = thread_rng();

    let alpha = 123u64;
    let beta = 456u64;
    let input_size = 16;

    println!("Secret point (alpha): {}", alpha);
    println!("Secret value (beta): {}", beta);

    // Generate keys
    let (key_0, key_1) = dpf.generate_keys(&alpha, &beta, input_size, &mut rng)?;

    // Create batch of test points
    let test_points: Vec<u64> = (0..20).step_by(3).collect();

    println!("\nBatch evaluating {} points:", test_points.len());

    // Batch evaluate
    let shares_0 = dpf.batch_evaluate(&key_0, &test_points)?;
    let shares_1 = dpf.batch_evaluate(&key_1, &test_points)?;

    println!("Results:");
    for (i, &x) in test_points.iter().enumerate() {
        let result = dpf.combine_shares(&shares_0[i], &shares_1[i]);
        println!(
            "  x = {:3}: result = {:4} {}",
            x,
            result,
            if x == alpha {
                "[OK]"
            } else if result == 0 {
                "[OK]"
            } else {
                "?"
            }
        );
    }

    Ok(())
}

/// Control word usage example
///
/// Demonstrates how to work with control words in DPF evaluation
pub fn control_word_example() -> Result<()> {
    println!("\n=== Control Word Example ===\n");

    // Create control words for different stages of evaluation
    let cw_initial = ControlWord::new(42, true, false);
    let cw_intermediate = ControlWord::new(123, false, true);
    let cw_final = ControlWord::new(255, true, true);

    println!("Control Words:");
    println!(
        "  Initial: seed={}, left={}, right={}",
        cw_initial.get_seed(),
        cw_initial.get_lt(),
        cw_initial.get_rt()
    );
    println!(
        "  Intermediate: seed={}, left={}, right={}",
        cw_intermediate.get_seed(),
        cw_intermediate.get_lt(),
        cw_intermediate.get_rt()
    );
    println!(
        "  Final: seed={}, left={}, right={}",
        cw_final.get_seed(),
        cw_final.get_lt(),
        cw_final.get_rt()
    );

    // Demonstrate control word modification
    let mut cw_modifiable = cw_initial;
    cw_modifiable.set_rt(true);
    println!(
        "\nModified control word: seed={}, left={}, right={}",
        cw_modifiable.get_seed(),
        cw_modifiable.get_lt(),
        cw_modifiable.get_rt()
    );

    Ok(())
}

/// Key validation example
///
/// Demonstrates key validation and error handling
pub fn key_validation_example() -> Result<()> {
    println!("\n=== Key Validation Example ===\n");

    let dpf = XorDpf::default();
    let mut rng = thread_rng();

    // Generate valid keys
    let (key_0, key_1) = dpf.generate_keys(&100u64, &200u64, 16, &mut rng)?;

    println!("Validating generated keys:");
    println!("  Key 0 valid: {}", key_0.validate().is_ok());
    println!("  Key 1 valid: {}", key_1.validate().is_ok());

    // Demonstrate DpfKey wrapper
    let wrapped_key_0 = DpfKey::new(key_0.clone());
    let wrapped_key_1: DpfKey<_> = key_1.clone().into();

    println!("\nUsing DpfKey wrapper:");
    println!("  Wrapped key 0 party: {}", wrapped_key_0.party_index());
    println!("  Wrapped key 1 party: {}", wrapped_key_1.party_index());
    println!(
        "  Both keys valid: {}",
        wrapped_key_0.validate().is_ok() && wrapped_key_1.validate().is_ok()
    );

    Ok(())
}

/// Advanced YaclDpf example
///
/// Demonstrates the more sophisticated DPF implementation based on yacl C++ algorithm
pub fn yacl_dpf_example() -> Result<()> {
    println!("\n=== Yacl DPF Example ===\n");

    // Create a DPF instance with 8-bit input and 64-bit output
    let dpf = YaclDpf::<8, 64>::new();
    let mut rng = thread_rng();

    // Define secret point and value using GE2n
    let alpha = GE2n::<8>::new(42); // Secret point
    let beta = GE2n::<64>::new(100); // Secret value

    println!("Secret point (alpha): {}", alpha.get_val());
    println!("Secret value (beta): {}", beta.get_val());
    println!("DPF parameters: input bits=8, output bits=64");

    // Generate keys
    let (key_0, key_1) = dpf.generate_keys(&alpha, &beta, 8, &mut rng)?;

    println!("\n[OK] Generated Yacl DPF keys:");
    println!(
        "  - Key 0: rank={}, control_words={}",
        key_0.get_rank(),
        key_0.cws_vec.len()
    );
    println!(
        "  - Key 1: rank={}, control_words={}",
        key_1.get_rank(),
        key_1.cws_vec.len()
    );

    // Test evaluation at multiple points
    let test_points = vec![
        GE2n::<8>::new(0),
        GE2n::<8>::new(42), // secret point
        GE2n::<8>::new(100),
        GE2n::<8>::new(200),
    ];

    println!("\n--- Evaluating Yacl DPF ---");
    for x in &test_points {
        let share_0 = dpf.evaluate(&key_0, x)?;
        let share_1 = dpf.evaluate(&key_1, x)?;
        let result = dpf.combine_shares(&share_0, &share_1);

        let is_secret_point = x.get_val() == alpha.get_val();
        let should_be_beta = is_secret_point && result.get_val() == beta.get_val();
        let should_be_zero = !is_secret_point && result.get_val() == 0;

        println!(
            "x = {:3}: share_0 = {:3}, share_1 = {:3}, result = {:3} {}",
            x.get_val(),
            share_0.get_val(),
            share_1.get_val(),
            result.get_val(),
            if should_be_beta {
                "[OK] (beta)"
            } else if should_be_zero {
                "[OK] (0)"
            } else {
                "[FAIL]"
            }
        );
    }

    Ok(())
}

/// Full domain evaluation example
///
/// Demonstrates how to use the evalall functionality
pub fn full_domain_evaluation_example() -> Result<()> {
    println!("\n=== Full Domain Evaluation Example ===\n");

    // Use small domain for demonstration (4-bit input = 16 points)
    let dpf = YaclDpf::<4, 64>::new();
    let mut rng = thread_rng();

    let alpha = GE2n::<4>::new(7); // Secret point
    let beta = GE2n::<64>::new(42); // Secret value

    println!("Secret point (alpha): {}", alpha.get_val());
    println!("Secret value (beta): {}", beta.get_val());
    println!("Domain size: {} points", 1 << 4);

    // Generate evalall keys
    let (key_0_raw, key_1_raw) =
        dpf.generate_keys_internal(&alpha, &beta, rng.gen(), rng.gen(), true)?;

    println!(
        "\n[OK] Generated evalall keys with {} last correlation words",
        key_0_raw.last_cw_vec.len()
    );

    // Evaluate all points
    let all_shares_0 = dpf.eval_all(&key_0_raw)?;
    let all_shares_1 = dpf.eval_all(&key_1_raw)?;

    println!("\n--- Full Domain Results ---");
    for i in 0..all_shares_0.len() {
        let result = dpf.combine_shares(&all_shares_0[i], &all_shares_1[i]);
        let is_correct = if i == alpha.get_val() as usize {
            result.get_val() == beta.get_val()
        } else {
            result.get_val() == 0
        };

        println!(
            "x = {:2}: result = {:4} {}",
            i,
            result.get_val(),
            if is_correct { "[OK]" } else { "[FAIL]" }
        );
    }

    Ok(())
}

/// Main example runner
pub fn run_all_examples() -> Result<()> {
    basic_dpf_example()?;
    batch_evaluation_example()?;
    control_word_example()?;
    key_validation_example()?;
    yacl_dpf_example()?;
    full_domain_evaluation_example()?;

    println!("\n=== All Examples Completed ===");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_example() {
        basic_dpf_example().expect("Basic example should work");
    }

    #[test]
    fn test_batch_evaluation_example() {
        batch_evaluation_example().expect("Batch evaluation example should work");
    }

    #[test]
    fn test_control_word_example() {
        control_word_example().expect("Control word example should work");
    }

    #[test]
    fn test_key_validation_example() {
        key_validation_example().expect("Key validation example should work");
    }

    #[test]
    fn test_yacl_dpf_example() {
        yacl_dpf_example().expect("Yacl DPF example should work");
    }

    #[test]
    fn test_full_domain_evaluation_example() {
        full_domain_evaluation_example().expect("Full domain evaluation example should work");
    }

    #[test]
    fn test_all_examples() {
        run_all_examples().expect("All examples should work");
    }
}
