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
rand = "0.8"
```

## Examples

The crate includes a comprehensive demo showing DPF functionality:

```bash
# Run the DPF demo
cargo run -p dpf --example dpf_demo
```

The demo demonstrates:
- Key generation for secret points and values
- Evaluation at secret and non-secret points
- Full domain evaluation
- Share combination to recover the secret value

## Basic Usage

```rust
use dpf::{YaclDpf, Dpf, GE2n};
use rand::thread_rng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a DPF instance with 16-bit input and 64-bit output
    let dpf = YaclDpf::<16, 64>::new();
    let mut rng = thread_rng();
    
    // Define the secret point (alpha) and value (beta)
    let alpha = GE2n::<16>::new(12345);  // Secret point
    let beta = GE2n::<64>::new(98765);   // Secret value
    
    // Generate two key shares
    let (key_0, key_1) = dpf.generate_keys(&alpha, &beta, 16, &mut rng)?;
    
    // Evaluate at the secret point
    let share_0 = dpf.evaluate(&key_0, &alpha)?;
    let share_1 = dpf.evaluate(&key_1, &alpha)?;
    let result = dpf.combine_shares(&share_0, &share_1);
    
    assert_eq!(result.get_val(), beta.get_val());
    
    // Evaluate at other points (should return 0)
    let other_point = GE2n::<16>::new(100);
    let share_0 = dpf.evaluate(&key_0, &other_point)?;
    let share_1 = dpf.evaluate(&key_1, &other_point)?;
    let result = dpf.combine_shares(&share_0, &share_1);
    
    assert_eq!(result.get_val(), 0);
    
    Ok(())
}
```

## Architecture

### Core Components

#### `Dpf` Trait
The main trait defining the DPF interface:

```rust
pub trait Dpf {
    type Key: DpfKey;
    type Input: Clone;
    type Output: Clone;

    fn generate_keys<R: Rng + CryptoRng>(
        &self,
        alpha: &Self::Input,
        beta: &Self::Output,
        input_size: usize,
        rng: &mut R,
    ) -> Result<(Self::Key, Self::Key)>;

    fn evaluate(&self, key: &Self::Key, x: &Self::Input) -> Result<Self::Output>;
    fn combine_shares(&self, share_0: &Self::Output, share_1: &Self::Output) -> Self::Output;
}
```

#### `YaclDpf<M, N>` Implementation
A production-ready DPF implementation based on the yacl algorithm:

- Generic over input bit width `M` and output bit width `N`
- Uses cryptographic PRG for secure key generation
- Supports full domain evaluation with `eval_all()`
- Efficient batch evaluation capabilities
- Configurable input/output sizes

#### `XorDpf` Implementation
A simplified XOR-based DPF implementation for testing:

- Uses additive secret sharing
- Supports 64-bit inputs and outputs
- Useful for testing and understanding DPF concepts

### Key Types

- **`DpfKey`**: Trait representing DPF key shares
- **`DpfKeyImpl`**: Concrete implementation of DPF keys with control words
- **`Cw` (Control Word)**: Used in the DPF evaluation process
- **`GE2n<N>`**: Represents Galois Extension field elements with N-bit values

## Advanced Usage

### Full Domain Evaluation

Evaluate the DPF at all points in the domain:

```rust
use dpf::{YaclDpf, Dpf, GE2n};

// Create a small DPF for demonstration
let dpf = YaclDpf::<4, 64>::new();
let alpha = GE2n::<4>::new(5);
let beta = GE2n::<64>::new(42);

let (key_0, key_1) = dpf.generate_keys(&alpha, &beta, 4, &mut rng)?;

// Evaluate at all domain points
let shares_0 = dpf.eval_all(&key_0)?;
let shares_1 = dpf.eval_all(&key_1)?;

// Combine shares
for (i, (s0, s1)) in shares_0.iter().zip(shares_1.iter()).enumerate() {
    let result = dpf.combine_shares(s0, s1);
    println!("Point {}: {}", i, result.get_val());
}
```

### Configurable Bit Widths

The `YaclDpf` implementation is generic over input and output bit widths:

```rust
// 8-bit input, 32-bit output
let dpf_small = YaclDpf::<8, 32>::new();

// 16-bit input, 64-bit output (common configuration)
let dpf_medium = YaclDpf::<16, 64>::new();

// 32-bit input, 128-bit output (large domains)
let dpf_large = YaclDpf::<32, 128>::new();
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

### Implementation

This crate provides two DPF implementations:

1. **`YaclDpf`** - Production-ready implementation based on the yacl algorithm:
   - Uses cryptographic PRG (ChaCha20) for secure key generation
   - Suitable for production use with proper security parameters
   - Implements standard DPF constructions

2. **`XorDpf`** - Simplified implementation for testing:
   - Uses basic additive secret sharing
   - Useful for understanding DPF concepts and testing
   - Not recommended for production cryptographic use

### Best Practices

When using DPF in production:
- Ensure secure key distribution channels
- Use appropriate bit widths for your security requirements
- Validate keys before use with the `validate()` method
- Keep key shares secret and separate
- Consider side-channel attack resistance in your implementation

## Performance

Performance characteristics of the `YaclDpf` implementation:

- **Key Generation**: O(n) where n is the input size in bits
- **Evaluation**: O(n) per point evaluation
- **Full Domain Evaluation**: O(n·2^n) for n-bit inputs
- **Memory Usage**: O(n) per key

The implementation balances security and performance for practical use cases.

## Testing

Run the test suite:

```bash
cargo test -p dpf
```

Run tests with output:

```bash
cargo test -p dpf -- --nocapture
```

Run the example demo:

```bash
cargo run -p dpf --example dpf_demo
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
