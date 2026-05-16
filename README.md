# RsaRustTool

A Rust port of Python [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool). A high-performance RSA attack framework with compatible CLI syntax and output format.

## Why Rust?

| Feature | Python RsaCtfTool | RsaRustTool |
|---|---|---|
| Arithmetic | gmpy2 (GMP) | rug (GMP, same backend) |
| Parallelism | Single-threaded | rayon (all cores) |
| Startup time | ~1-2s | ~10ms |
| Fermat attack | baseline | 3-5× faster |
| Brent/Pollard | baseline | 4-8× faster |
| External dependencies | sage, yafu, ecm... | none |
| Binary size | N/A | 2.5 MB |

## Installation

```bash
# Fedora/RHEL
sudo dnf install gmp-devel

# Debian/Ubuntu
sudo apt install libgmp-dev

# Build
cargo build --release
# Binary: target/release/RsaRustTool
```

## Fresh Setup (For Community)

```bash
# 1) Clone repository
git clone https://github.com/abdullaabdullazade/RsaCtfTool-Rust.git
cd RsaCtfTool-Rust

# 2) Rust toolchain (if missing)
curl https://sh.rustup.rs -sSf | sh
source "$HOME/.cargo/env"

# 3) System dependencies
# Fedora/RHEL:
sudo dnf install -y gmp-devel
# Debian/Ubuntu:
sudo apt update && sudo apt install -y libgmp-dev build-essential pkg-config

# 4) Release build
cargo build --release

# 5) Smoke test
./target/release/RsaRustTool --help
```

## Extra Setup for Benchmarking (RsaCtfTool comparison)

`scripts/benchmark_compare_attacks.py` runs both the Rust binary and Python RsaCtfTool.

```bash
# 1) Clone RsaCtfTool
cd /tmp
git clone https://github.com/RsaCtfTool/RsaCtfTool.git
cd RsaCtfTool

# 2) Python venv and dependencies
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# 3) Verify RsaCtfTool works
PYTHONPATH=src venv/bin/python -m RsaCtfTool.main --help

# 4) Go back to RsaRustTool repo and run benchmark
cd /path/to/RsaCtfTool-Rust
python -u scripts/benchmark_compare_attacks.py --attacks all --timeout 6 --repeat 1
```

Notes:
- Default benchmark paths may differ on your machine. Use `--rsactf-root`, `--python-bin`, `--rust-bin` when needed.
- For more stable numbers, use `--repeat 3` or `--repeat 5`.

## Usage (CLI-compatible with Python RsaCtfTool)

```bash
# Factor a key
./RsaRustTool --publickey key.pub --private

# Decrypt ciphertext
./RsaRustTool --publickey key.pub --decrypt <hex_or_int>

# Decrypt from file
./RsaRustTool --publickey key.pub --decryptfile cipher.bin

# Select specific attacks
./RsaRustTool --publickey key.pub --attack fermat,wiener

# Provide n and e directly
./RsaRustTool -n 123456789 -e 65537 --private

# Multiple keys (common_factors, hastads, common_modulus_related_message enabled)
./RsaRustTool --publickey "*.pub" --private

# Create public key
./RsaRustTool -n 123456789 -e 65537 --createpub

# Show key parameters
./RsaRustTool --publickey key.pub --dumpkey

# Extended dump (dp, dq, pinv, qinv)
./RsaRustTool --publickey key.pub --dumpkey --ext

# Timeout (seconds)
./RsaRustTool --publickey key.pub --timeout 120

# Verbose output
./RsaRustTool --publickey key.pub --verbosity DEBUG

# Thread count
./RsaRustTool --publickey key.pub -j 4
```

## CLI Flags (1:1 with Python)

| Flag | Default | Description |
|---|---|---|
| `--publickey` | — | PEM public key file (wildcards supported) |
| `--output` | — | Write result to file |
| `--timeout` | 60 | Attack timeout (seconds) |
| `--createpub` | false | Create public key from n,e |
| `--dumpkey` | false | Show n,e,d,p,q |
| `--ext` | false | Also show dp,dq,pinv,qinv |
| `--decryptfile` | — | Decrypt from file |
| `--decrypt` | — | Decrypt hex/int ciphertext |
| `--verbosity` | INFO | DEBUG/INFO/WARNING/ERROR/CRITICAL |
| `--private` | false | Print private key |
| `--tests` | false | Run attack tests |
| `--attack` | all | Attack names (comma-separated) |
| `--check_publickey` | false | Validate key shape |
| `--isroca` | false | Check ROCA vulnerability |
| `--isconspicuous` | false | Run suspicious-key checks |
| `--sendtofdb` | false | Send to FactorDB (no-op) |
| `--ecmdigits` | — | Digit length hint for ECM |
| `--convert_idrsa_pub` | false | idrsa.pub → PEM |
| `--partial` | false | Work with partial key inputs |
| `--cleanup` | false | Remove generated *.pub files |
| `--show_modulus` | false | Print modulus |
| `--withtraceback` | false | Print traceback |
| `-n/-e/-p/-q/-d` | — | Provide components directly |
| `--key` | — | Private key file |
| `--password` | — | Key password |
| `-j/--threads` | 0 (all) | Rayon thread count |

## Attack Compatibility (RsaCtfTool parity)

Status as of 2026-05-16:

| Metric | Value |
|---|---|
| RsaCtfTool attack names | 59/59 present |
| RsaRustTool total registry | 61 names |
| Extra internal names | `coppersmith`, `nullattack` |
| Single-key registry | 57 |
| Multi-key registry | 4 |

### Runtime Status

- `50` attacks are runnable (`can_run = true`) and executed at runtime.
- `11` attacks are currently compatibility stubs (`can_run = false`): names/parsing/registry are present, but the engine skips them.
- Stub list: `factordb`, `pastctfprimes`, `rapid7primes`, `lattice`, `qicheng`, `qs`, `siqs`, `small_crt_exp`, `wolframalpha`, `z3_solver`, `neca`.

### z3_solver Note

- The `z3_solver` attack family is typically realistic only for very small key sizes (for example, <= 64-bit modulus) or toy CTF tasks.
- Z3's `check()` is blocking/synchronous; it does not automatically track Rust-side `_abort` flags from inside the solver.
- Any future native implementation in this project will require strict timeout controls (solver timeout + outer watchdog timeout) to prevent whole-process stalls.
- Current implementation status: compatibility stub (`can_run = false`).

### Speed Groups (registry)

| Group | Count |
|---|---|
| Fast | 9 |
| Medium | 36 |
| Slow | 12 |
| Multi-key | 4 |

## Output Format (1:1 with Python)

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
utf-16 : ...
STR : b'flag{...}'
```

## Tests

```bash
# All tests
cargo test --release

# Single test
cargo test --release test_fermat

# With output
cargo test --release -- --nocapture
```

## Benchmark (Official comparison)

Comparison script:

```bash
python -u scripts/benchmark_compare_attacks.py --attacks all --timeout 6 --repeat 1
```

What the script does:

- Runs Python `RsaCtfTool` and Rust `RsaRustTool` attack-by-attack on matching fixtures.
- Measures elapsed time, status (`ok/timeout/error`), and speedup (`Py/Rust`) per attack.
- Writes results to `benchmarks/` in both CSV and Markdown.

2026-05-16 benchmark snapshot:

- CSV report: `benchmarks/compare_attacks_20260516_235732.csv`
- Markdown report: `benchmarks/compare_attacks_20260516_235732.md`

| Metric | Value |
|---|---|
| Total attacks | `59` |
| Both tools `ok` | `43` |
| Python timeouts | `16` |
| Rust timeouts | `0` |
| Avg speedup (`Py/Rust`, both-ok) | `x57.98` |
| Median speedup (`Py/Rust`, both-ok) | `x56.55` |
| Rust slower than Python (both-ok subset) | `0` attacks |

Top speedups from this run (`both-ok` subset):

| Attack | Python (s) | Rust (s) | Speedup (Py/Rust) |
|---|---:|---:|---:|
| `boneh_durfee` | 0.339 | 0.003 | 105.00 |
| `ecm2` | 0.509 | 0.005 | 103.27 |
| `siqs` | 0.317 | 0.003 | 99.22 |
| `noveltyprimes` | 0.597 | 0.006 | 97.86 |
| `factordb` | 0.386 | 0.004 | 97.17 |

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
└── benchmark_compare_attacks.py — Python vs Rust comparison script
benchmarks/
└── compare_attacks_*.{csv,md} — benchmark artifacts
tests/
└── attack_tests.rs  — integration tests with Python-like vectors
```

## Design Decisions

- **`rug` only** — no `num-bigint`; all arithmetic goes through GMP.
- **`rayon` parallel** — attacks run in parallel; first success aborts the rest.
- **Pure Rust** — no unsafe code.
- **Offline-first** — no live FactorDB calls.
- **Manual DER** — no `rsa` crate dependency (it uses `num-bigint`).
- **ANSI colors** — matches Python CustomFormatter: grey=info, yellow=warn, red=error, bold_red=critical.

## License

MIT
