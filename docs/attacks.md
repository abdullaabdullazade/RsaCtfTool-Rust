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

<div class="rr-note">
  Some attack names are preserved for CLI compatibility and migration parity, even when their runtime implementation is intentionally disabled.
</div>
