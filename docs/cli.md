---
layout: default
title: CLI Reference
nav_order: 3
---

# CLI Reference

## Basic Usage

```bash
RsaRustTool --publickey key.pub --private
```

## Common Examples

```bash
# Run selected attacks only
RsaRustTool --publickey key.pub --attack fermat,wiener --private

# Decrypt inline ciphertext
RsaRustTool --publickey key.pub --decrypt <hex_or_int> --private

# Decrypt ciphertext file
RsaRustTool --publickey key.pub --decryptfile cipher.bin --private

# Dump parsed key parameters
RsaRustTool --publickey key.pub --dumpkey
```

## Key Flags

- `--publickey`: input public key path (wildcards supported)
- `--attack`: comma-separated attack names
- `--timeout`: per-attack timeout in seconds
- `--private`: print recovered private key
- `--decrypt`: decrypt inline ciphertext
- `--decryptfile`: decrypt ciphertext from a file
- `--dumpkey`: print key details
- `-j`, `--threads`: rayon thread count

## Full Help

```bash
RsaRustTool --help
```
