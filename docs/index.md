---
layout: default
title: Home
nav_order: 1
description: Official documentation for RsaCtfTool-Rust
---

<div class="rr-hero">
  <span class="rr-badge">Official Docs</span>
  <h1 style="margin-top:0;">RsaCtfTool-Rust</h1>
  <p class="rr-subtitle">A high-performance Rust implementation of practical RSA attack workflows, designed for RsaCtfTool-compatible usage and faster real-world execution.</p>
</div>

## At a Glance

<div class="rr-kpi">
  <div class="rr-kpi-box"><span class="rr-kpi-label">Attack Coverage</span><span class="rr-kpi-value">59 / 59</span></div>
  <div class="rr-kpi-box"><span class="rr-kpi-label">Runtime Engine</span><span class="rr-kpi-value">Rust + Rayon</span></div>
  <div class="rr-kpi-box"><span class="rr-kpi-label">Big Integer Core</span><span class="rr-kpi-value">GMP via rug</span></div>
  <div class="rr-kpi-box"><span class="rr-kpi-label">Benchmark Win</span><span class="rr-kpi-value">x57.98 avg</span></div>
</div>

## Start Here

<div class="rr-grid">
  <a class="rr-card" href="getting-started">
    <span class="rr-card-title">Getting Started</span>
    Installation, build, first command, and global PATH setup.
  </a>
  <a class="rr-card" href="cli">
    <span class="rr-card-title">CLI Reference</span>
    Main flags, examples, and attack selection usage.
  </a>
  <a class="rr-card" href="architecture">
    <span class="rr-card-title">Architecture</span>
    Internal flow, scheduler model, and module responsibilities.
  </a>
  <a class="rr-card" href="attacks">
    <span class="rr-card-title">Attack Compatibility</span>
    Coverage, runtime groups, and compatibility stubs.
  </a>
  <a class="rr-card" href="benchmark">
    <span class="rr-card-title">Benchmarking</span>
    Rust vs Python benchmark workflow and reproducibility tips.
  </a>
  <a class="rr-card" href="troubleshooting">
    <span class="rr-card-title">Troubleshooting</span>
    Quick fixes for timeout, panic, and environment issues.
  </a>
</div>

## Quick Build

```bash
git clone https://github.com/abdullaabdullazade/RsaCtfTool-Rust.git
cd RsaCtfTool-Rust
cargo build --release
./target/release/RsaRustTool --help
```

<div class="rr-note">
  <strong>Tip:</strong> For direct `RsaRustTool` command usage, symlink the release binary into <code>~/.local/bin</code>.
</div>
