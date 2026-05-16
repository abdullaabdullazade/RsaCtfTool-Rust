---
layout: default
title: Home
nav_order: 1
description: Official documentation for RsaCtfTool-Rust
---

# RsaCtfTool-Rust

RsaCtfTool-Rust is a high-performance Rust implementation of practical RSA attack workflows inspired by Python RsaCtfTool.

## Why This Project

- Fast big integer operations with `rug` and GMP backend
- Parallel attack execution with `rayon`
- Compatible attack naming for easier migration from Python scripts
- Built-in benchmark workflow for Rust vs Python comparison

## Quick Start

```bash
git clone https://github.com/abdullaabdullazade/RsaCtfTool-Rust.git
cd RsaCtfTool-Rust
cargo build --release
./target/release/RsaRustTool --help
```

## Documentation

- [Getting Started](getting-started)
- [CLI Reference](cli)
- [Architecture](architecture)
- [Attack Compatibility](attacks)
- [Benchmarking](benchmark)
- [Troubleshooting](troubleshooting)
