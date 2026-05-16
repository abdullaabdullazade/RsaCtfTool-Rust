---
layout: default
title: Troubleshooting
nav_order: 7
---

# Troubleshooting

## `RsaRustTool` Command Not Found

```bash
ln -sf "$PWD/target/release/RsaRustTool" ~/.local/bin/RsaRustTool
```

Ensure `~/.local/bin` exists and is included in `PATH`.

## Program Runs Too Long

- Set `--timeout` for per-attack limits.
- Use targeted execution with `--attack` instead of full auto mode.

## Panic / Crash Diagnostics

```bash
RUST_BACKTRACE=1 RsaRustTool --publickey key.pub --private
```

When opening an issue, include:

- exact command
- key type and size
- full panic/error output

## Abort Safety Note

Blocking third-party solvers should have internal timeout settings, because external `check()` calls may not observe Rust-side abort flags until they return.
