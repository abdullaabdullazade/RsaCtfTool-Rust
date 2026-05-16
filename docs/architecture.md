---
layout: default
title: Architecture
nav_order: 4
---

# Architecture

## Execution Flow

1. CLI parses options and key material.
2. Attack scheduler builds a runnable attack set.
3. Attacks execute with timeout and cancellation checks.
4. First successful recovery returns private key and optional decrypt output.

## Core Modules

- `src/main.rs`: CLI entrypoint and orchestration
- `src/attack.rs`: shared `RsaAttack` trait and metadata
- `src/attacks/`: concrete attack implementations
- `src/key.rs`: RSA key parsing and conversion helpers
- `src/math.rs`: common math primitives

## Concurrency Model

- Parallel attack execution uses `rayon` worker threads.
- Attack-level timeout is enforced by scheduler and abort flags.
- Long-running algorithms should periodically check abort state.

## Reliability Rules

- Prefer guarded indexing and checked arithmetic for panic safety.
- Solver-based attacks (example: Z3) must set strict internal timeouts.
- Benchmarking should run under stable CPU/load conditions.
