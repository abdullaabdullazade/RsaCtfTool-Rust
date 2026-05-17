# RsaRustTool

[![Crates.io](https://img.shields.io/crates/v/rsa-rust-tool.svg)](https://crates.io/crates/rsa-rust-tool)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A Rust port of [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) — a high-performance RSA attack framework with compatible CLI syntax and output format.

---

## Why Rust?

| Feature               | Python RsaCtfTool      | RsaRustTool            |
|-----------------------|------------------------|------------------------|
| Arithmetic            | gmpy2 (GMP)            | rug (GMP, same backend)|
| Parallelism           | Single-threaded        | rayon (all cores)      |
| Startup time          | ~1–2 s                 | ~10 ms                 |
| Fermat attack         | baseline               | 3–5× faster            |
| Brent / Pollard       | baseline               | 4–8× faster            |
| External dependencies | sage, yafu, ecm …      | none                   |
| Binary size           | N/A                    | 2.5 MB                 |

---

## Installation

### Prerequisites

```bash
# Fedora / RHEL
sudo dnf install gmp-devel

# Debian / Ubuntu
sudo apt install libgmp-dev
```

### Build from source

```bash
git clone https://github.com/abdullaabdullazade/RsaRustTool.git
cd RsaRustTool

# Install Rust toolchain if missing
curl https://sh.rustup.rs -sSf | sh
source "$HOME/.cargo/env"

cargo build --release
./target/release/RsaRustTool --help
```

### Install via Cargo

```bash
cargo install rsa-rust-tool
```

### Global command (optional)

```bash
mkdir -p ~/.local/bin
ln -sf "$PWD/target/release/RsaRustTool" ~/.local/bin/RsaRustTool

# Add to PATH (Bash / Zsh)
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc

# Fish
fish_add_path ~/.local/bin
```

---

## Documentation

Full documentation is available on GitHub Pages:

| Page | Description |
|------|-------------|
| [Getting Started](https://abdullaabdullazade.github.io/RsaCtfTool-Rust/getting-started) | Installation, build, first command, global PATH setup |
| [CLI Reference](https://abdullaabdullazade.github.io/RsaCtfTool-Rust/cli) | All flags, examples, and attack selection |
| [Attack Compatibility](https://abdullaabdullazade.github.io/RsaCtfTool-Rust/attacks) | Coverage, runtime groups, and stubs |
| [Architecture](https://abdullaabdullazade.github.io/RsaCtfTool-Rust/architecture) | Internal flow, scheduler model, module responsibilities |
| [Benchmarking](https://abdullaabdullazade.github.io/RsaCtfTool-Rust/benchmark) | Rust vs Python workflow and reproducibility tips |
| [Troubleshooting](https://abdullaabdullazade.github.io/RsaCtfTool-Rust/troubleshooting) | Quick fixes for timeout, panic, and environment issues |

---

## Usage

```bash
# Factor a public key and print the private key
./RsaRustTool --publickey key.pub --private

# Decrypt ciphertext (hex or integer)
./RsaRustTool --publickey key.pub --decrypt <hex_or_int>

# Decrypt from file
./RsaRustTool --publickey key.pub --decryptfile cipher.bin

# Run specific attacks
./RsaRustTool --publickey key.pub --attack fermat,wiener

# Provide n and e directly
./RsaRustTool -n 123456789 -e 65537 --private

# Multiple keys (enables common_factors, hastads, common_modulus_related_message)
./RsaRustTool --publickey "*.pub" --private

# Create a public key from components
./RsaRustTool -n 123456789 -e 65537 --createpub

# Dump key parameters
./RsaRustTool --publickey key.pub --dumpkey

# Extended dump (dp, dq, pinv, qinv)
./RsaRustTool --publickey key.pub --dumpkey --ext

# Set timeout and thread count
./RsaRustTool --publickey key.pub --timeout 120 -j 4

# Verbose output
./RsaRustTool --publickey key.pub --verbosity DEBUG
```

---

## CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--publickey` | — | PEM public key file (wildcards supported) |
| `--key` | — | Private key file |
| `--output` | — | Write result to file |
| `--timeout` | 60 | Attack timeout (seconds) |
| `--attack` | all | Attack names (comma-separated) |
| `-n / -e / -p / -q / -d` | — | Provide key components directly |
| `--private` | false | Print private key |
| `--createpub` | false | Create public key from n, e |
| `--dumpkey` | false | Show n, e, d, p, q |
| `--ext` | false | Also show dp, dq, pinv, qinv |
| `--decrypt` | — | Decrypt hex/int ciphertext |
| `--decryptfile` | — | Decrypt from file |
| `--verbosity` | INFO | DEBUG / INFO / WARNING / ERROR / CRITICAL |
| `--check_publickey` | false | Validate key shape |
| `--isroca` | false | Check ROCA vulnerability |
| `--isconspicuous` | false | Run suspicious-key checks |
| `--partial` | false | Work with partial key inputs |
| `--convert_idrsa_pub` | false | Convert idrsa.pub → PEM |
| `--show_modulus` | false | Print modulus |
| `--cleanup` | false | Remove generated `*.pub` files |
| `--password` | — | Key password |
| `--ecmdigits` | — | Digit length hint for ECM |
| `--sendtofdb` | false | Send to FactorDB (no-op) |
| `--tests` | false | Run attack tests |
| `--withtraceback` | false | Print traceback |
| `-j / --threads` | 0 (all) | Rayon thread count |

---

## Attack Compatibility

Status as of 2026-05-16:

| Metric | Value |
|--------|-------|
| RsaCtfTool attack names | 59 / 59 present |
| RsaRustTool total registry | 61 names |
| Extra internal names | `coppersmith`, `nullattack` |
| Single-key registry | 57 |
| Multi-key registry | 4 |

**Runtime status:**
- **50** attacks are runnable (`can_run = true`).
- **11** are compatibility stubs (`can_run = false`): `factordb`, `pastctfprimes`, `rapid7primes`, `lattice`, `qicheng`, `qs`, `siqs`, `small_crt_exp`, `wolframalpha`, `z3_solver`, `neca`.

**Speed groups:**

| Group | Count |
|-------|-------|
| Fast | 9 |
| Medium | 36 |
| Slow | 12 |
| Multi-key | 4 |

---

## Benchmark

Run a Rust vs Python comparison:

```bash
python -u scripts/benchmark_compare_attacks.py --attacks all --timeout 6 --repeat 1
```

The script requires a local clone of [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) with its Python environment set up. Use `--rsactf-root`, `--python-bin`, and `--rust-bin` if paths differ on your machine.

**2026-05-16 snapshot (both-ok subset, 43 attacks):**

| Metric | Value |
|--------|-------|
| Avg speedup (Py / Rust) | ×57.98 |
| Median speedup | ×56.55 |
| Python timeouts | 16 |
| Rust timeouts | 0 |
| Rust slower than Python | 0 |

Top speedups:

| Attack | Python (s) | Rust (s) | Speedup |
|--------|----------:|--------:|--------:|
| `boneh_durfee` | 0.339 | 0.003 | ×105.00 |
| `ecm2` | 0.509 | 0.005 | ×103.27 |
| `siqs` | 0.317 | 0.003 | ×99.22 |
| `noveltyprimes` | 0.597 | 0.006 | ×97.86 |
| `factordb` | 0.386 | 0.004 | ×97.17 |

---

## Output Format

```
Results for key.pub:

Private key :
-----BEGIN RSA PRIVATE KEY-----
...
-----END RSA PRIVATE KEY-----

Decrypted data :
HEX : 0x666c61677b...
INT (big endian) : 123456789...
INT (little endian) : 987654321...
utf-8 : flag{...}
STR : b'flag{...}'
```

---

## Tests

```bash
# Run all tests
cargo test --release

# Run a single test
cargo test --release test_fermat

# With output
cargo test --release -- --nocapture
```

---

## Architecture

```
src/
├── main.rs          — CLI (clap), Python-compatible flags
├── lib.rs           — crate root
├── attack.rs        — RsaAttack trait + AttackEngine (rayon parallel)
├── key.rs           — PEM import/export (manual DER)
├── math.rs          — Miller-Rabin, iroot, mlucas, CRT, gcdext
├── output.rs        — Python-compatible output formatting
└── attacks/
    ├── mod.rs       — Registry: single_key_attacks(), multi_key_attacks()
    └── *.rs         — 55 attack modules
scripts/
└── benchmark_compare_attacks.py
tests/
└── attack_tests.rs
```

**Design decisions:**
- **`rug` only** — all arithmetic through GMP; no `num-bigint`.
- **`rayon` parallel** — attacks run concurrently; first success aborts the rest.
- **Pure Rust** — no unsafe code.
- **Offline-first** — no live FactorDB calls.
- **Manual DER** — no `rsa` crate dependency.
- **ANSI colors** — matches Python's `CustomFormatter` output style.

---

## License

MIT
