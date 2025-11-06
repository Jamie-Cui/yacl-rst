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

use crate::dpf::{XorDpf, Dpf, Cw, DpfKey, DpfKeyShare};
use crate::error::Result;
use rand::thread_rng;

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
    let alpha = 42u64;  // Secret point where function outputs beta
    let beta = 100u64;  // Value to output at point alpha
    let input_size = 16;  // Input domain size in bits
    
    println!("Secret point (α): {}", alpha);
    println!("Secret value (β): {}", beta);
    println!("Input domain size: {} bits\n", input_size);
    
    // Generate two key shares
    let (key_0, key_1) = dpf.generate_keys(&alpha, &beta, input_size, &mut rng)?;
    
    println!("✓ Generated two key shares:");
    println!("  - Key 0 (Party 0): party_index={}, input_size={}", 
             key_0.party_index(), key_0.input_size());
    println!("  - Key 1 (Party 1): party_index={}, input_size={}", 
             key_1.party_index(), key_1.input_size());
    
    // Test points to evaluate
    let test_points = vec![0u64, 42u64, 100u64, 1000u64];
    
    println!("\n--- Evaluating DPF ---");
    for &x in &test_points {
        // Each party evaluates their key share independently
        let share_0 = dpf.evaluate(&key_0, &x)?;
        let share_1 = dpf.evaluate(&key_1, &x)?;
        
        // Combine shares to get final result
        let result = dpf.combine_shares(&share_0, &share_1);
        
        println!("x = {:4}: share_0 = {:4}, share_1 = {:4}, result = {:4} {}", 
                 x, share_0, share_1, result, 
                 if x == alpha { "✓ (β)" } else if result == 0 { "✓ (0)" } else { "?" });
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
    
    println!("Secret point (α): {}", alpha);
    println!("Secret value (β): {}", beta);
    
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
        println!("  x = {:3}: result = {:4} {}", 
                 x, result,
                 if x == alpha { "✓" } else if result == 0 { "✓" } else { "?" });
    }
    
    Ok(())
}

/// Control word usage example
/// 
/// Demonstrates how to work with control words in DPF evaluation
pub fn control_word_example() -> Result<()> {
    println!("\n=== Control Word Example ===\n");
    
    // Create control words for different stages of evaluation
    let cw_initial = Cw::new(vec![true, false, true], [42u8; 32], 0);
    let cw_intermediate = Cw::new(vec![false, true, false, true], [123u8; 32], 2);
    let cw_final = Cw::new(vec![true], [255u8; 32], 4);
    
    println!("Control Words:");
    println!("  Initial: {} bits at level {}", cw_initial.len(), cw_initial.level);
    println!("  Intermediate: {} bits at level {}", cw_intermediate.len(), cw_intermediate.level);
    println!("  Final: {} bits at level {}", cw_final.len(), cw_final.level);
    
    // Demonstrate empty control word
    let empty_cw = Cw::empty();
    println!("\nEmpty control word: {} bits", empty_cw.len());
    
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
    println!("  Both keys valid: {}", 
             wrapped_key_0.validate().is_ok() && wrapped_key_1.validate().is_ok());
    
    Ok(())
}

/// Main example runner
pub fn run_all_examples() -> Result<()> {
    basic_dpf_example()?;
    batch_evaluation_example()?;
    control_word_example()?;
    key_validation_example()?;
    
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
    fn test_all_examples() {
        run_all_examples().expect("All examples should work");
    }
}