# yacl-rst

A Rust workspace implementing cryptographic functionality, specifically focused on Distributed Point Functions (DPF).

## Overview

This project provides a comprehensive implementation of Distributed Point Functions (DPF), which are cryptographic primitives that allow two parties to securely evaluate a function where only one party knows the input point and the other party knows the function value.

## Structure

The project is organized as a Rust workspace with the following structure:

```
yacl-rst/
├── Cargo.toml              # Workspace configuration
├── README.md               # This file
├── CLAUDE.md               # Development guidance for Claude Code
└── yacl-rst/
    └── dpf/                # DPF (Distributed Point Functions) module
        ├── Cargo.toml      # Package configuration
        ├── README.md       # Detailed DPF documentation
        └── src/
            ├── lib.rs      # Library entry point
            ├── dpf.rs      # Main DPF implementation
            ├── error.rs    # Error handling
            └── examples.rs # Usage examples (feature-gated)
```

## Key Features

- **Modular DPF Implementation**: Clean trait-based architecture
- **Type-Safe Design**: Comprehensive error handling and validation
- **Flexible Interface**: Supports generic input/output types
- **Batch Operations**: Efficient multi-point evaluation
- **Serialization Support**: Built-in key serialization capabilities
- **Extensive Documentation**: Complete API documentation and examples

## Quick Start

```bash
# Clone the repository
git clone <repository-url>
cd yacl-rst

# Build the project
cargo build

# Run tests
cargo test

# Build with release optimizations
cargo build --release
```

## DPF Module Usage

The DPF module provides a complete implementation:

```rust
use dpf::{XorDpf, Dpf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dpf = XorDpf::default();
    let mut rng = rand::thread_rng();
    
    // Generate keys for secret point-value pair
    let alpha = 42u64;
    let beta = 100u64;
    let (key_0, key_1) = dpf.generate_keys(&alpha, &beta, 16, &mut rng)?;
    
    // Evaluate at test points
    let share_0 = dpf.evaluate(&key_0, &alpha)?;
    let share_1 = dpf.evaluate(&key_1, &alpha)?;
    let result = dpf.combine_shares(&share_0, &share_1);
    
    assert_eq!(result, beta);
    Ok(())
}
```

For detailed documentation and examples, see [yacl-rst/dpf/README.md](yacl-rst/dpf/README.md).

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
