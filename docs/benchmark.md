# Benchmark Guide

## Run full comparison

```bash
python -u scripts/benchmark_compare_attacks.py --attacks all --timeout 6 --repeat 1
```

This runs Rust and Python attack-by-attack on matching fixtures and writes:

- `benchmarks/*.csv`
- `benchmarks/*.md`

## Latest recorded snapshot

- Total attacks: 59
- Both tools OK: 43
- Python timeouts: 16
- Rust timeouts: 0
- Average speedup (`Py/Rust`, both-ok): x57.98
- Median speedup (`Py/Rust`, both-ok): x56.55

## Tips for stable numbers

- Use `--repeat 3` or `--repeat 5`
- Keep CPU governor and background load stable
- Compare runs from the same machine
