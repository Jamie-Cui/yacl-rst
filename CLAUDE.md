# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Rust workspace implementing cryptographic functionality, specifically focused on Distributed Point Functions (DPF). The project uses a Cargo workspace structure with potential for multiple modules.

## Architecture

**Workspace Structure:**
- Root workspace contains the main `Cargo.toml` with workspace configuration
- Multiple cryptographic packages in `yacl-rst/` directory:
  - `dpf/` - Distributed Point Functions implementation
  - `aead/`, `aes/`, `ecc/`, `envelope/`, `hash/`, `hmac/`, `math/`, `oprf/`, `pairing/`, `pke/`, `rand/`, `sign/` - other cryptographic modules
- Uses resolver version 2 for dependency management
- Licensed under Apache License 2.0
- Examples are located in each package's `examples/` directory

**Main Components:**
- `DpfKey` struct - handles DPF key operations
- `Cw` struct - control word functionality
- `YaclDpf` struct - main DPF implementation with configurable bit widths
- `Dpf` trait - defines the interface for DPF operations (key generation, evaluation, share combining)
- `GE2n` struct - represents Galois Extension field elements

**Examples:**
- `dpf_demo.rs` - Comprehensive demo showing DPF key generation, evaluation at secret/non-secret points, and full domain evaluation
  - Located in `yacl-rst/dpf/examples/`
  - Run with: `cargo run -p dpf --example dpf_demo`

## Development Commands

**Building:**
```bash
# Build all workspace members
cargo build

# Build with release optimizations
cargo build --release

# Build specific package
cargo build -p dpf
```

**Testing:**
```bash
# Run all tests in workspace
cargo test

# Run tests for specific package
cargo test -p dpf

# Run tests with verbose output
cargo test -p dpf -- --nocapture

# Run specific test by name
cargo test -p dpf test_name
```

**Development:**
```bash
# Check code without building
cargo check

# Check specific package
cargo check -p dpf

# Format code
cargo fmt

# Run clippy lints
cargo clippy

# Build documentation
cargo doc --no-deps

# Run examples
cargo run -p dpf --example dpf_demo
```

## Working Directory Context

When running commands, you can work from either:
- Root workspace directory (`/Users/jamie/proj/yacl-rst/`) - affects all workspace members
- Package directory (e.g., `yacl-rst/dpf/`) - affects only a specific package

## Important Notes

- **Examples Location**: Each package has its own `examples/` directory for example code
- **Trait Imports**: When using DPF functionality, ensure the `Dpf` trait is in scope: `use dpf::{YaclDpf, Dpf};`
- **Cryptographic Modules**: The workspace contains multiple cryptographic packages beyond DPF, each in its own directory under `yacl-rst/`

## Code Style

All source files include Apache License 2.0 headers. The project follows standard Rust conventions with:
- Consistent error handling patterns
- Proper module organization
- Library crate structure for reusability
