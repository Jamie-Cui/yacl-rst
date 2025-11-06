# yacl-rst

A Rust implementation of cryptographic Distributed Point Functions (DPF) based on the yacl C++ library.

## Overview

This project provides a comprehensive implementation of Distributed Point Functions (DPF), which are cryptographic primitives that allow two parties to securely evaluate a function where only one party knows the input point and the other party knows the function value.

This implementation is based on the algorithm from the [yacl C++ library](https://github.com/secretflow/yacl), providing a faithful Rust port with modern language features.

## Features

- **🔐 Production-Ready DPF**: Based on the proven yacl C++ algorithm
- **📊 Generic Support**: Configurable input/output bit sizes (1-64 bits input, 1-128 bits output)
- **⚡ Efficient Evaluation**: Tree-based evaluation with early termination
- **🌐 Full Domain Support**: Batch evaluation of all domain points
- **🔒 Type-Safe API**: Comprehensive error handling and validation
- **📦 Serialization**: Built-in support for key serialization
- **🎯 Two Implementations**: 
  - `YaclDpf`: Full-featured implementation matching yacl C++
  - `XorDpf`: Simplified implementation for learning/demonstration

## Quick Start

```bash
# Clone and build
git clone <repository-url>
cd yacl-rst
cargo build

# Run tests
cargo test

# Run demo
cargo run --bin dpf_demo
```

## Usage Examples

### Basic DPF Usage

```rust
use dpf::{YaclDpf, GE2n};
use rand::thread_rng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dpf = YaclDpf::<16, 64>::new();  // 16-bit input, 64-bit output
    let mut rng = thread_rng();
    
    // Define secret point and value
    let alpha = GE2n::<16>::new(12345);  // Secret point
    let beta = GE2n::<64>::new(98765);   // Secret value
    
    // Generate two key shares
    let (key_0, key_1) = dpf.generate_keys(&alpha, &beta, 16, &mut rng)?;
    
    // Each party evaluates independently
    let share_0 = dpf.evaluate(&key_0, &alpha)?;
    let share_1 = dpf.evaluate(&key_1, &alpha)?;
    
    // Combine shares to reveal result
    let result = dpf.combine_shares(&share_0, &share_1);
    
    assert_eq!(result.get_val(), beta.get_val());  // ✅ Returns beta at alpha
    println!("DPF evaluation successful!");
    
    Ok(())
}
```

### Full Domain Evaluation

```rust
use dpf::{YaclDpf, GE2n};

let dpf = YaclDpf::<4, 64>::new();  // Small 4-bit domain for demo
let alpha = GE2n::<4>::new(5);
let beta = GE2n::<64>::new(42);

// Generate evalall keys
let (key_0, key_1) = dpf.generate_keys_internal(&alpha, &beta, seed1, seed2, true)?;

// Evaluate all 16 points in the domain
let shares_0 = dpf.eval_all(&key_0)?;
let shares_1 = dpf.eval_all(&key_1)?;

// Combine results
for i in 0..shares_0.len() {
    let result = dpf.combine_shares(&shares_0[i], &shares_1[i]);
    if i == alpha.get_val() as usize {
        assert_eq!(result.get_val(), beta.get_val());  // Secret point
    } else {
        assert_eq!(result.get_val(), 0);               // All other points
    }
}
```

## Algorithm Details

This implementation closely follows the yacl C++ algorithm:

1. **Tree-Based Construction**: Uses a binary tree where each level contains control words
2. **PRG-Based Expansion**: Pseudorandom generators expand seeds for evaluation paths
3. **Early Termination**: Optimized evaluation based on security parameters
4. **Control Words**: Each level contains seeds and control bits for path selection

### Key Components

- **`GE2n<N>`**: Group elements in GF(2^n) with bitwise operations
- **`ControlWord`**: Stores seeds and control bits for tree navigation  
- **`DpfPrg`**: Pseudorandom generator for seed expansion
- **`YaclDpf<M,N>`**: Main DPF implementation with configurable parameters

## Project Structure

```
yacl-rst/
├── Cargo.toml              # Workspace configuration
├── README.md               # This file
├── CLAUDE.md               # Development guidance
├── dpf_demo.rs             # Demo script
└── yacl-rst/
    └── dpf/                # DPF package
        ├── Cargo.toml      
        └── src/
            ├── lib.rs      # Public API exports
            ├── dpf.rs      # Core DPF implementation  
            ├── error.rs    # Error types
            └── examples.rs # Usage examples
```

## Development

```bash
# Development commands
cargo check           # Quick syntax check
cargo build           # Build debug version
cargo build --release # Build optimized version
cargo test            # Run all tests
cargo clippy          # Run lints
cargo fmt             # Format code

# Run examples
cargo test --features examples

# Generate documentation
cargo doc --no-deps --open
```

## Supported Parameter Pairs

The implementation supports the same parameter pairs as yacl C++:

- **Input bits (M)**: 1, 2, 4, 8, 16, 32, 64
- **Output bits (N)**: 1, 2, 4, 8, 16, 32, 64, 128

## Testing

The project includes comprehensive tests:

- Unit tests for all core components
- Integration tests for complete DPF workflows
- Property-based tests for mathematical correctness
- Example tests demonstrating real usage

Run tests with: `cargo test -p dpf`

## License

Licensed under the Apache License 2.0. See LICENSE file for details.

## Acknowledgments

This implementation is based on the [yacl C++ library](https://github.com/secretflow/yacl) by Ant Group. The algorithm follows the academic paper on Distributed Point Functions and maintains cryptographic security properties.

## Development

### Building

```bash
# Build debug version
cargo build

# Build release version
cargo build --release

# Build specific package
cargo build -p dpf
```

### Testing

```bash
# Run all tests
cargo test

# Run tests for specific package
cargo test -p dpf

# Run examples (requires examples feature)
cargo test --features examples
```

### Development Commands

```bash
# Check code without building
cargo check

# Format code
cargo fmt

# Run lints
cargo clippy

# Generate documentation
cargo doc --no-deps
```

## Architecture

### Workspace Configuration

- Uses Cargo workspace with resolver version 2
- Designed for modular development and future expansion
- Clean separation between workspace and package dependencies

### DPF Module Design

The DPF module follows these design principles:

1. **Trait-Based**: Core functionality defined through `Dpf` trait
2. **Type Safety**: Generic types with comprehensive error handling
3. **Extensibility**: Easy to add new DPF implementations
4. **Documentation**: Extensive inline documentation and examples

## License

This project is licensed under the Apache License 2.0. See LICENSE file for details.

## Contributing

This project follows standard Rust development practices. See [CLAUDE.md](CLAUDE.md) for development guidance when using AI assistants.
