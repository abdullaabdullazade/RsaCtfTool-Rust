---
layout: default
title: Attack Compatibility
nav_order: 5
---

# Attack Compatibility

## Coverage Summary

- RsaCtfTool attack names covered: `59/59`
- Total registered names in Rust: `61`
- Extra internal names: `coppersmith`, `nullattack`

## Runtime Groups

- Fast: 9
- Medium: 36
- Slow: 12
- Multi-key: 4

## Compatibility Stubs (`can_run = false`)

- `factordb`
- `pastctfprimes`
- `rapid7primes`
- `lattice`
- `qicheng`
- `qs`
- `siqs`
- `small_crt_exp`
- `wolframalpha`
- `z3_solver`
- `neca`

## Notes

Some names are retained for CLI compatibility even when the Rust implementation is intentionally disabled.
