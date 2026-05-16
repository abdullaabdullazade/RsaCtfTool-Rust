---
layout: default
title: Getting Started
nav_order: 2
---

# Getting Started

## Requirements

- Rust stable toolchain (`rustup` + `cargo`)
- GMP development library

### Fedora / RHEL

```bash
sudo dnf install -y gmp-devel
```

### Debian / Ubuntu

```bash
sudo apt update
sudo apt install -y libgmp-dev build-essential pkg-config
```

## Build

```bash
git clone https://github.com/abdullaabdullazade/RsaCtfTool-Rust.git
cd RsaCtfTool-Rust
cargo build --release
```

## First Command

```bash
./target/release/RsaRustTool --publickey ./tests/fixtures/sample.pub --private
```

## Add Global Command (Optional)

```bash
ln -sf "$PWD/target/release/RsaRustTool" ~/.local/bin/RsaRustTool
```

Ensure `~/.local/bin` is in your `PATH`.
