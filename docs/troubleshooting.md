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

Make sure `~/.local/bin` exists and is present in `PATH`.

## Program Runs Too Long

- Set `--timeout` for attack-level limits.
- Use targeted runs with `--attack` instead of full auto mode.

## Panic / Crash Diagnostics

```bash
RUST_BACKTRACE=1 RsaRustTool --publickey key.pub --private
```

When opening an issue, include:

- exact command
- key type and size
- full panic or error output

## Abort Safety

Blocking third-party solvers should be configured with their own timeout settings, because external `check()` calls may not observe Rust-side abort flags until they return.
