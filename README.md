# yacl-rst

A comprehensive Rust implementation of cryptographic primitives based on the yacl C++ library.

## Overview

This project provides Rust implementations of modern cryptographic primitives, including:

- **Distributed Point Functions (DPF)** - Cryptographic primitives that allow two parties to securely evaluate a function where only one party knows the input point and the other party knows the function value
- **Authenticated Encryption (AEAD)** - Secure encryption with authentication
- **AES Cryptography** - Advanced Encryption Standard implementations
- **Elliptic Curve Cryptography (ECC)** - Modern public-key cryptography
- **Hash Functions** - Cryptographic hash algorithms
- **HMAC** - Keyed-hash message authentication codes
- **Oblivious Pseudo-Random Functions (OPRF)** - Privacy-preserving PRFs
- **Pairing-Based Cryptography** - Advanced cryptographic operations
- **Public Key Encryption (PKE)** - Asymmetric encryption schemes
- **Digital Signatures** - Signature algorithms and verification
- **Envelope Encryption** - Secure data encapsulation

These implementations are based on algorithms from the [yacl C++ library](https://github.com/secretflow/yacl) by Ant Group, providing faithful Rust ports with modern language features and memory safety guarantees.

## Quick Start

```bash
# Clone and build
git clone <repository-url>
cd yacl-rst
cargo build

# Run tests
cargo test

# Run DPF demo
cargo run -p dpf --example dpf_demo
```

## Project Structure

```
yacl-rst/
|-- Cargo.toml              # Workspace configuration
|-- README.md               # This file
|-- CLAUDE.md               # Development guidance
`-- yacl-rst/               # Main workspace
    |-- aead/               # Authenticated Encryption
    |-- aes/                # AES cryptographic primitives
    |-- common/             # Shared utilities
    |-- dpf/                # Distributed Point Functions
    |   |-- Cargo.toml
    |   |-- README.md
    |   |-- src/
    |   |   |-- lib.rs      # Public API exports
    |   |   |-- dpf.rs      # Core DPF implementation
    |   |   |-- error.rs    # Error types
    |   |   `-- examples.rs # Usage examples
    |   `-- examples/
    |       `-- dpf_demo.rs # DPF demonstration
    |-- ecc/                # Elliptic Curve Cryptography
    |-- envelope/           # Envelope encryption
    |-- hash/               # Hash functions
    |-- hmac/               # HMAC implementation
    |-- math/               # Mathematical utilities
    |-- oprf/               # Oblivious Pseudo-Random Functions
    |-- pairing/            # Pairing-based cryptography
    |-- pke/                # Public Key Encryption
    |-- rand/               # Random number generation
    `-- sign/               # Digital signatures
```

## Acknowledgments

This implementation is based on the [yacl C++ library](https://github.com/secretflow/yacl) by Ant Group. The algorithm follows the academic paper on Distributed Point Functions and maintains cryptographic security properties.


## License

This project is licensed under the Apache License 2.0. See LICENSE file for details.

## Contributing

This project follows standard Rust development practices. See [CLAUDE.md](CLAUDE.md) for development guidance when using AI assistants.
