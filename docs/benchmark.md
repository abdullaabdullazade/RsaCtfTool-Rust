---
layout: default
title: Benchmarking
nav_order: 6
---

# Benchmarking

## Rust vs Python (RsaCtfTool)

Use the comparison script to run both tools against the same fixture set.

```bash
python -u scripts/benchmark_compare_attacks.py --attacks all --timeout 6 --repeat 1
```

Generated artifacts:

- `benchmarks/*.csv`
- `benchmarks/*.md`

## Latest Snapshot

| Metric | Value |
|---|---|
| Total attacks | 59 |
| Both tools OK | 43 |
| Python timeouts | 16 |
| Rust timeouts | 0 |
| Avg speedup (Py/Rust, both-ok) | x57.98 |
| Median speedup (Py/Rust, both-ok) | x56.55 |

## Reproducibility Tips

- Use the same machine and CPU governor.
- Run `--repeat 3` or `--repeat 5` and compare median.
- Keep background tasks minimal.
