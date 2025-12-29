#!/usr/bin/env cargo script

//! DPF Demo Script
//! 
//! This script demonstrates the usage of the Rust DPF implementation
//! based on the yacl C++ algorithm.

use dpf::{YaclDpf, GE2n};
use rand::{thread_rng, Rng};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("[DPF] DPF (Distributed Point Function) Demo");
    println!("==========================================");
    
    // Create a DPF instance with 16-bit input and 64-bit output
    let dpf = YaclDpf::<16, 64>::new();
    let mut rng = thread_rng();
    
    // Define secret point and value
    let alpha = GE2n::<16>::new(12345);  // Secret point
    let beta = GE2n::<64>::new(98765);   // Secret value
    
    println!("\n[INFO] Configuration:");
    println!("  Input bits: 16");
    println!("  Output bits: 64");
    println!("  Secret point (alpha): {}", alpha.get_val());
    println!("  Secret value (beta): {}", beta.get_val());
    
    // Generate keys
    let (key_0, key_1) = dpf.generate_keys(&alpha, &beta, 16, &mut rng)?;
    
    println!("\n[KEYS] Key Generation:");
    println!("  [OK] Key 0 (Party 0): rank={}, control_words={}", 
             key_0.get_rank(), key_0.cws_vec.len());
    println!("  [OK] Key 1 (Party 1): rank={}, control_words={}", 
             key_1.get_rank(), key_1.cws_vec.len());
    
    // Test evaluation at secret point
    println!("\n[EVAL] Evaluation at Secret Point:");
    let share_0 = dpf.evaluate(&key_0, &alpha)?;
    let share_1 = dpf.evaluate(&key_1, &alpha)?;
    let result = dpf.combine_shares(&share_0, &share_1);
    
    println!("  Secret point: {}", alpha.get_val());
    println!("  Share 0: {}", share_0.get_val());
    println!("  Share 1: {}", share_1.get_val());
    println!("  Combined result: {}", result.get_val());
    println!("  Expected value: {}", beta.get_val());
    println!("  [OK] Correct: {}", result.get_val() == beta.get_val());
    
    // Test evaluation at other points
    println!("\n[TEST] Evaluation at Other Points:");
    let test_points = [0, 1000, 5000, 20000, 65535];
    
    for &point in &test_points {
        if point == alpha.get_val() as u64 {
            continue; // Skip the secret point
        }
        
        let x = GE2n::<16>::new(point as u128);
        let share_0 = dpf.evaluate(&key_0, &x)?;
        let share_1 = dpf.evaluate(&key_1, &x)?;
        let result = dpf.combine_shares(&share_0, &share_1);
        
        println!("  Point {}: result = {} {}",
                 point, result.get_val(),
                 if result.get_val() == 0 { "[OK]" } else { "[FAIL]" });
    }
    
    // Demonstrate full domain evaluation (small domain)
    println!("\n[DOMAIN] Full Domain Evaluation (4-bit example):");
    let small_dpf = YaclDpf::<4, 64>::new();
    let small_alpha = GE2n::<4>::new(5);
    let small_beta = GE2n::<64>::new(42);
    
    let (key_0_small, key_1_small) = small_dpf.generate_keys_internal(
        &small_alpha, &small_beta, rng.gen(), rng.gen(), true)?;
    
    let shares_0 = small_dpf.eval_all(&key_0_small)?;
    let shares_1 = small_dpf.eval_all(&key_1_small)?;
    
    println!("  Domain size: {} points", shares_0.len());
    println!("  Results:");
    
    for i in 0..shares_0.len() {
        let result = small_dpf.combine_shares(&shares_0[i], &shares_1[i]);
        let is_correct = if i == small_alpha.get_val() as usize {
            result.get_val() == small_beta.get_val()
        } else {
            result.get_val() == 0
        };
        
        let marker = if i == small_alpha.get_val() as usize { "[*]" } else { "  " };
        println!("  {}[{:2}] = {:3} {}", marker, i, result.get_val(), 
                 if is_correct { "[OK]" } else { "[FAIL]" });
    }
    
    println!("\n[DONE] Demo completed successfully!");
    println!("   The DPF implementation correctly hides the secret point");
    println!("   while allowing evaluation at any input point.");
    
    Ok(())
}