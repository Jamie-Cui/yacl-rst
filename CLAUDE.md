# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Rust workspace implementing cryptographic functionality, specifically focused on Distributed Point Functions (DPF). The project uses a Cargo workspace structure with potential for multiple modules.

## Architecture

**Workspace Structure:**
- Root workspace contains the main `Cargo.toml` with workspace configuration
- Main implementation located in `yacl-rst/dpf/` directory  
- Uses resolver version 2 for dependency management
- Licensed under Apache License 2.0

**Main Components:**
- `DpfKey` struct - handles DPF key operations
- `Cw` struct - control word functionality
- Currently in early development stage with basic structure definitions

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
```

## Working Directory Context

When running commands, you can work from either:
- Root workspace directory (`/Users/jamie/proj/yacl-rst/`) - affects all workspace members
- Package directory (`/Users/jamie/proj/yacl-rst/yacl-rst/dpf/`) - affects only the DPF package

## Code Style

All source files include Apache License 2.0 headers. The project follows standard Rust conventions with:
- Consistent error handling patterns
- Proper module organization
- Library crate structure for reusability