---
layout: default
title: Architecture
nav_order: 4
---

# Architecture

## High-Level Flow

1. CLI parses options and key material.
2. Attack scheduler builds runnable attack set.
3. Attacks execute with timeout/cancellation checks.
4. First successful recovery returns private key and optional decrypt output.

## Core Modules

- `src/main.rs`: CLI entrypoint and execution orchestration
- `src/attack.rs`: shared attack trait (`RsaAttack`) and metadata
- `src/attacks/`: concrete attack implementations
- `src/key.rs`: RSA key parsing and transformation helpers
- `src/math.rs`: common math routines and utilities

## Concurrency Model

- Parallel attack execution uses `rayon` worker threads.
- Attack-level timeout is enforced by scheduler and abort flags.
- Long-running algorithms should periodically check abort state.

## Reliability Notes

- Panic-prone code paths should prefer guarded indexing and checked arithmetic.
- Solver-based attacks (example: Z3) should always use explicit timeout limits.
- Benchmarking should run with stable CPU load to reduce variance.
