# Distributed Point Function (DPF) Implementation

A comprehensive Rust implementation of Distributed Point Functions (DPF), which are cryptographic primitives that allow two parties to securely evaluate a function where only one party knows the input point and the other party knows the function value.

## Overview

A DPF allows a secret point `alpha` and value `beta` to be split between two parties such that:

- Each party receives a share that reveals no information about `alpha` or `beta`
- When both parties evaluate their shares on any input `x`, they get partial results
- The partial results combine to `beta` when `x = alpha`, and `0` otherwise

## Features

- **Modular Design**: Clean trait-based architecture for easy extension
- **Type-Safe**: Comprehensive error handling and validation
- **Flexible**: Supports generic input/output types
- **Batch Operations**: Efficient batch evaluation capabilities
- **Serialization**: Built-in support for key serialization/deserialization
- **Well-Documented**: Extensive documentation and examples

## Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
dpf = "1.0.0"
```

## Basic Usage

```rust
use dpf::{XorDpf, Dpf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a DPF instance
    let dpf = XorDpf::default();
    let mut rng = rand::thread_rng();
    
    // Define the secret point (alpha) and value (beta)
    let alpha = 42u64;  // Secret point where function outputs beta
    let beta = 100u64;  // Value to output at point alpha
    let input_size = 16;  // Input domain size in bits
    
    // Generate two key shares
    let (key_0, key_1) = dpf.generate_keys(&alpha, &beta, input_size, &mut rng)?;
    
    // Distribute keys to two parties (they must remain secret!)
    
    // Each party evaluates their key independently
    let test_points = vec![0u64, 42u64, 100u64];
    
    for &x in &test_points {
        let share_0 = dpf.evaluate(&key_0, &x)?;
        let share_1 = dpf.evaluate(&key_1, &x)?;
        
        // Combine shares to get final result
        let result = dpf.combine_shares(&share_0, &share_1);
        
        println!("x = {}: result = {} {}", 
                 x, result, 
                 if x == alpha { "(beta)" } else if result == 0 { "(0)" } else { "" });
    }
    
    Ok(())
}
```

## Architecture

### Core Components

#### `Dpf` Trait
The main trait defining the DPF interface:

```rust
pub trait Dpf {
    type Key: DpfKeyShare;
    type Input: Clone + PartialEq + Eq;
    type Output: Clone + PartialEq + Eq;
    
    fn generate_keys<R: Rng + CryptoRng>(
        &self,
        alpha: &Self::Input,
        beta: &Self::Output,
        input_size: usize,
        rng: &mut R,
    ) -> Result<(Self::Key, Self::Key)>;
    
    fn evaluate(&self, key: &Self::Key, x: &Self::Input) -> Result<Self::Output>;
    fn batch_evaluate(&self, key: &Self::Key, inputs: &[Self::Input]) -> Result<Vec<Self::Output>>;
    fn combine_shares(&self, share_0: &Self::Output, share_1: &Self::Output) -> Self::Output;
}
```

#### `DpfKeyShare` Trait
Trait for DPF key shares with serialization support:

```rust
pub trait DpfKeyShare: Clone + Send + Sync + Serialize + for<'de> Deserialize<'de> {
    fn party_index(&self) -> usize;
    fn input_size(&self) -> usize;
    fn validate(&self) -> Result<()>;
}
```

#### `XorDpf` Implementation
A simple XOR-based DPF implementation for demonstration purposes:

- Uses additive secret sharing
- Supports 64-bit inputs and outputs
- Configurable input domain size
- Deterministic behavior for testing

### Key Types

- **`DpfKey<K>`**: Generic wrapper for DPF keys
- **`XorDpfKey`**: Concrete implementation of XOR DPF keys
- **`Cw`**: Control word used in DPF evaluation (extensible for future implementations)

## Advanced Usage

### Batch Evaluation

Efficiently evaluate multiple points at once:

```rust
let test_points: Vec<u64> = (0..100).step_by(5).collect();
let shares_0 = dpf.batch_evaluate(&key_0, &test_points)?;
let shares_1 = dpf.batch_evaluate(&key_1, &test_points)?;

let results: Vec<u64> = shares_0.iter()
    .zip(shares_1.iter())
    .map(|(s0, s1)| dpf.combine_shares(s0, s1))
    .collect();
```

### Key Serialization

DPF keys support serialization for storage and transmission:

```rust
use serde_json;

// Serialize a key
let serialized = serde_json::to_string(&key_0)?;

// Deserialize a key
let deserialized_key: XorDpfKey = serde_json::from_str(&serialized)?;
```

### Custom DPF Implementations

Implement the `Dpf` trait for custom DPF schemes:

```rust
#[derive(Debug, Clone)]
pub struct MyCustomDpf { /* custom fields */ }

impl Dpf for MyCustomDpf {
    type Key = MyCustomKey;
    type Input = u64;
    type Output = u64;
    
    fn generate_keys<R: Rng + CryptoRng>(
        &self,
        alpha: &Self::Input,
        beta: &Self::Output,
        input_size: usize,
        rng: &mut R,
    ) -> Result<(Self::Key, Self::Key)> {
        // Your implementation here
    }
    
    // ... implement other required methods
}
```

## Error Handling

The library provides comprehensive error handling:

```rust
use dpf::Error;

match dpf.generate_keys(&alpha, &beta, input_size, &mut rng) {
    Ok(keys) => println!("Keys generated successfully"),
    Err(Error::InvalidInputLength { expected, actual }) => {
        eprintln!("Invalid input: expected {}, got {}", expected, actual);
    }
    Err(Error::KeyGenerationFailed(msg)) => {
        eprintln!("Key generation failed: {}", msg);
    }
    Err(e) => eprintln!("Other error: {}", e),
}
```

## Security Considerations

### Current Implementation

The `XorDpf` implementation is simplified for demonstration purposes:

- **NOT** suitable for production cryptographic use
- Uses additive sharing instead of proper DPF construction
- Provides correct functionality but lacks security guarantees

### Production Considerations

For production DPF implementations, consider:

- Proper cryptographic pseudorandom generators
- Secure key generation and distribution
- Side-channel attack resistance
- Formal security proofs
- Compliance with relevant standards

## Performance

The current implementation is optimized for clarity rather than performance:

- Basic additive sharing: O(1) operations
- Batch evaluation: O(n) where n is the number of inputs
- Key generation: O(1) with random number generation
- Memory usage: O(1) per key

## Testing

Run the test suite:

```bash
cargo test
```

Run examples:

```bash
cargo test --features examples
```

## Contributing

This is a research/educational implementation. Contributions are welcome for:

1. Production-ready DPF implementations
2. Performance optimizations
3. Additional DPF variants
4. Security improvements
5. Documentation enhancements

## License

This project is licensed under the Apache License 2.0. See LICENSE file for details.

## References

- [Distributed Point Functions](https://eprint.iacr.org/2018/707) - Original DPF paper
- [Fast Distributed Point Functions](https://eprint.iacr.org/2020/1241) - Optimized DPF constructions
- [PIR and DPF Survey](https://eprint.iacr.org/2021/1170) - Comprehensive survey