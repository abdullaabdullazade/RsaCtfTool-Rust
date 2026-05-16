---
layout: default
title: Getting Started
nav_order: 2
---

# Getting Started

<div class="rr-note">
  This guide gets you from fresh machine to first successful RSA attack run.
</div>

## Requirements

- Rust stable toolchain (`rustup` + `cargo`)
- GMP development library

## Install System Dependencies

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

## First Run

```bash
./target/release/RsaRustTool --publickey ./tests/fixtures/sample.pub --private
```

## Global Command (Optional)

```bash
ln -sf "$PWD/target/release/RsaRustTool" ~/.local/bin/RsaRustTool
```

Ensure `~/.local/bin` is in your `PATH`.
