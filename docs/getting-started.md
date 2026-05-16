# Getting Started

## Clone and Build

```bash
git clone https://github.com/abdullaabdullazade/RsaCtfTool-Rust.git
cd RsaCtfTool-Rust
cargo build --release
```

## System Dependencies

### Fedora/RHEL

```bash
sudo dnf install -y gmp-devel
```

### Debian/Ubuntu

```bash
sudo apt update
sudo apt install -y libgmp-dev build-essential pkg-config
```

## Run

```bash
./target/release/RsaRustTool --help
```

## Optional: global command

If you want to run `RsaRustTool` directly without full path:

```bash
ln -sf "$PWD/target/release/RsaRustTool" ~/.local/bin/RsaRustTool
```

Make sure `~/.local/bin` is in your `PATH`.
