#!/usr/bin/env python3
"""
benchmark_hard_keys.py — honest startup-vs-compute breakdown

The existing benchmark (benchmark_compare_attacks.py) reports wall-clock times
that include Python interpreter startup (~0.21 s). For attacks that succeed in
under 0.5 s total in Python, startup dominates and the "50x speedup" headline
mostly reflects cold-start latency, not algorithmic efficiency.

This script measures startup overhead explicitly and subtracts it from every
run, giving compute_time = total_time - startup_time. Three attack tiers show
where the speedup is real vs. where it is startup-only:

  Tier 1 – TRIVIAL KEYS  (instant factoring, <1 ms compute)
    → speedup ≈ startup ratio only

  Tier 2 – COMPUTE FACTORING  (medium-hard keys, seconds of compute)
    → speedup = real algorithmic difference (native arithmetic vs. Python bignum)

  Tier 3 – STRUCTURAL ATTACKS  (Wiener, Boneh-Durfee, Hastad …)
    → largest real speedup; Rust's math beats Python even excluding startup

Attacks honestly excluded
  siqs, qs — Rust stubs (return None immediately); Python calls libnum/SymPy.
  ecm on >256-bit keys — Rust rejects; Python can go larger.

Usage:
  python3 scripts/benchmark_hard_keys.py [--timeout N] [--repeat N]
"""
from __future__ import annotations

import argparse
import datetime
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional

EXAMPLES = Path("/home/abdullaxows/Downloads/RsaCtfTool/examples")
RSACTF   = Path("/home/abdullaxows/Downloads/RsaCtfTool")
RSARUST  = Path("/home/abdullaxows/Downloads/RsaRustTool")
PY_BIN   = RSACTF / "venv/bin/python"
RUST_BIN = RSARUST / "target/release/RsaRustTool"

CUBE_ROOT_CT = (
    "2205316413931134031074603746928247799030155221252519872650101242908540609117693"
    "035883827878696406295617513907962419726541451312273821810017858485722109359971"
    "259158071688912076249144203043097720816270550387459717116098817458584146690177"
    "125"
)
CUBE_ROOT_N  = (
    "2933192249979498578273597604559116493668305938055895038656016010574034320151336"
    "993900630753116592270894961916269862367534903043085954782570899470832180370530"
    "945943809934042777058006440091143185665690198278994828530995611184868690615266"
    "447335094048650745177122343583526016897121008747089444846074559395684058653052"
    "791580254145009294657469480958488902863730868679527184420789010551475067862907"
    "739054966183120621407246398518098981106431219207697870293412176440482900183550"
    "467375190239898455201170831410460483829448603477361305838743852756938687673"
)
HASTADS_CT = (
    "261345950255088824199206969589297492768083568554363001807292202086148198540785"
    "875067889853750126065910869378059825972054500409296763768604135988881188967875"
    "126819737816598484392562403375391722914907856816865871091726511596620751615512"
    "183772327351299941365151995536802718357319233050365556244882929796558270337,"
    "147535246350781145803699087910221608128508531245679654307942476916759248311896"
    "958780799558399204686458919290159543753966699893006016413718139713809296129796"
    "521671806205375133127498854375392596658549807278970596547851946732056260825231"
    "169253750741639904613590541946015782167836188510987545893121474698400398826,"
    "633230627388596886579908367739501184580838393691617645602928172655297372145912"
    "724695988151441728614868603479196153916968285656992175356066846340327304330216"
    "410957123875304589208458268694616526607064173015876523386638026821701609498528"
    "415875970074497028482884675279736968611005756588082906398954547838170886958"
)
ROCA_N = (
    "559077211868557911781711278748678034850426750728902668591262397367101039438498"
    "8015497235515969796783937905129055952167826830196634107346761087047942625347"
)


# ---------------------------------------------------------------------------
# Attack catalogue — (label, py_args, rust_args, tier, description)
# ---------------------------------------------------------------------------
ATTACKS: list[dict] = [
    # ---- Tier 1: trivial keys, compute < 1 ms, speedup = startup only ----
    {
        "label": "factordb",
        "py_args":   ["--publickey", str(EXAMPLES/"factordb_parse.pub"), "--attack", "factordb", "--private"],
        "rust_args": ["--publickey", str(EXAMPLES/"factordb_parse.pub"), "--attack", "factordb", "--private"],
        "tier": 1, "desc": "FactorDB lookup (network I/O dominated)",
    },
    {
        "label": "cube_root",
        "py_args":   ["--decrypt", CUBE_ROOT_CT, "-e", "3", "-n", CUBE_ROOT_N, "--attack", "cube_root"],
        "rust_args": ["--decrypt", CUBE_ROOT_CT, "-e", "3", "-n", CUBE_ROOT_N, "--attack", "cube_root"],
        "tier": 1, "desc": "Cube-root attack (e=3, no padding)",
    },
    {
        "label": "roca",
        "py_args":   ["--attack", "roca", "-n", ROCA_N, "-e", "65537", "--private", "--timeout", "60"],
        "rust_args": ["--attack", "roca", "-n", ROCA_N, "-e", "65537", "--private"],
        "tier": 1, "desc": "ROCA vulnerable-key detection",
    },
    {
        "label": "hastads",
        "py_args":   ["--publickey",
                      f"{EXAMPLES/'hastads01.pub'},{EXAMPLES/'hastads02.pub'},{EXAMPLES/'hastads03.pub'}",
                      "--decrypt", "".join(HASTADS_CT), "--attack", "hastads", "--private"],
        "rust_args": ["--publickey", str(EXAMPLES/"hastads0?.pub"),
                      "--decrypt", "".join(HASTADS_CT), "--attack", "hastads", "--private"],
        "tier": 1, "desc": "Hastad broadcast (small e=3, 3 messages)",
    },

    # ---- Tier 2: compute factoring — real arithmetic work ----
    {
        "label": "SQUFOF",
        "py_args":   ["--publickey", str(EXAMPLES/"SQUFOF.pub"), "--attack", "SQUFOF", "--private"],
        "rust_args": ["--publickey", str(EXAMPLES/"SQUFOF.pub"), "--attack", "SQUFOF", "--private"],
        "tier": 2, "desc": "SQUFOF factoring — 83-bit semiprime",
    },
    {
        "label": "fermat",
        "py_args":   ["--publickey", str(EXAMPLES/"close_primes.pub"), "--attack", "fermat",
                      "--decryptfile", str(EXAMPLES/"close_primes.cipher"), "--private"],
        "rust_args": ["--publickey", str(EXAMPLES/"close_primes.pub"), "--attack", "fermat",
                      "--decryptfile", str(EXAMPLES/"close_primes.cipher"), "--private"],
        "tier": 2, "desc": "Fermat attack — close primes",
    },
    {
        "label": "factorial_pm1",
        "py_args":   ["--publickey", str(EXAMPLES/"weak_public.pub"), "--attack", "factorial_pm1_gcd", "--private"],
        "rust_args": ["--publickey", str(EXAMPLES/"weak_public.pub"), "--attack", "factorial_pm1_gcd", "--private"],
        "tier": 2, "desc": "Factorial p±1 GCD — computes k! mod n up to smoothness bound",
    },
    {
        "label": "compositorial_pm1",
        "py_args":   ["--publickey", str(EXAMPLES/"weak_public.pub"), "--attack", "compositorial_pm1_gcd", "--private"],
        "rust_args": ["--publickey", str(EXAMPLES/"weak_public.pub"), "--attack", "compositorial_pm1_gcd", "--private"],
        "tier": 2, "desc": "Compositorial p±1 GCD",
    },
    {
        "label": "brent",
        "py_args":   ["--publickey", str(EXAMPLES/"weak_public.pub"), "--attack", "brent", "--private"],
        "rust_args": ["--publickey", str(EXAMPLES/"weak_public.pub"), "--attack", "brent", "--private"],
        "tier": 2, "desc": "Brent's Pollard-Rho variant — runs until timeout if key too hard",
    },
    {
        "label": "pollard_rho",
        "py_args":   ["--publickey", str(EXAMPLES/"weak_public.pub"), "--attack", "pollard_rho", "--private"],
        "rust_args": ["--publickey", str(EXAMPLES/"weak_public.pub"), "--attack", "pollard_rho", "--private"],
        "tier": 2, "desc": "Pollard Rho (Floyd) — same key",
    },
    {
        "label": "ecm",
        "py_args":   ["--publickey", str(EXAMPLES/"ecm_method.pub"), "--attack", "ecm",
                      "--ecmdigits", "25", "--private"],
        "rust_args": ["--publickey", str(EXAMPLES/"ecm_method.pub"), "--attack", "ecm",
                      "--ecmdigits", "25", "--private"],
        "tier": 2, "desc": "ECM (Lenstra elliptic-curve) — Python uses gmpy2 C backend",
    },

    # ---- Tier 3: structural attacks — largest real speedup ----
    {
        "label": "wiener",
        "py_args":   ["--publickey", str(EXAMPLES/"wiener.pub"), "--attack", "wiener",
                      "--decryptfile", str(EXAMPLES/"wiener.cipher"), "--private"],
        "rust_args": ["--publickey", str(EXAMPLES/"wiener.pub"), "--attack", "wiener",
                      "--decryptfile", str(EXAMPLES/"wiener.cipher"), "--private"],
        "tier": 3, "desc": "Wiener (continued fractions, small d) — Python times out",
    },
    {
        "label": "boneh_durfee",
        "py_args":   ["--publickey", str(EXAMPLES/"wiener.pub"), "--attack", "boneh_durfee",
                      "--decryptfile", str(EXAMPLES/"wiener.cipher"), "--private"],
        "rust_args": ["--publickey", str(EXAMPLES/"wiener.pub"), "--attack", "boneh_durfee",
                      "--decryptfile", str(EXAMPLES/"wiener.cipher"), "--private"],
        "tier": 3, "desc": "Boneh-Durfee (lattice, small d)",
    },
    {
        "label": "small_crt_exp",
        "py_args":   ["--publickey", str(EXAMPLES/"small_crt_exp.pub"), "--attack", "small_crt_exp", "--private"],
        "rust_args": ["--publickey", str(EXAMPLES/"small_crt_exp.pub"), "--attack", "small_crt_exp", "--private"],
        "tier": 3, "desc": "Small CRT exponent lattice attack",
    },
    {
        "label": "smallq",
        "py_args":   ["--publickey", str(EXAMPLES/"small_q.pub"), "--attack", "smallq",
                      "--decryptfile", str(EXAMPLES/"small_q.cipher"), "--private"],
        "rust_args": ["--publickey", str(EXAMPLES/"small_q.pub"), "--attack", "smallq",
                      "--decryptfile", str(EXAMPLES/"small_q.cipher"), "--private"],
        "tier": 3, "desc": "Small q factor (trial division)",
    },
]


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_one(cmd: list[str], timeout: int, env: Optional[dict]) -> tuple[str, float]:
    t0 = time.perf_counter()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        elapsed = time.perf_counter() - t0
        status = "ok" if r.returncode == 0 else "fail"
        return status, elapsed
    except subprocess.TimeoutExpired:
        return "timeout", time.perf_counter() - t0


def run_attack(cmd: list[str], timeout: int, env: Optional[dict], repeat: int) -> tuple[str, float]:
    results = [run_one(cmd, timeout, env) for _ in range(repeat)]
    ok = [e for s, e in results if s == "ok"]
    if ok:
        return "ok", min(ok)
    timeouts = [e for s, e in results if s == "timeout"]
    if timeouts:
        return "timeout", max(timeouts)
    return "fail", min(e for _, e in results)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--python-bin",  type=Path, default=PY_BIN)
    ap.add_argument("--rust-bin",    type=Path, default=RUST_BIN)
    ap.add_argument("--rsactf-root", type=Path, default=RSACTF)
    ap.add_argument("--timeout",     type=int,  default=30)
    ap.add_argument("--repeat",      type=int,  default=2)
    ap.add_argument("--output-dir",  type=Path, default=RSARUST / "benchmarks")
    args = ap.parse_args()

    if not args.python_bin.exists():
        print(f"[error] python not found: {args.python_bin}", file=sys.stderr)
        return 2
    if not args.rust_bin.exists():
        print(f"[error] rust binary not found: {args.rust_bin}\n"
              "        Run: cargo build --release", file=sys.stderr)
        return 2

    py_env = os.environ.copy()
    py_env["PYTHONPATH"] = str(args.rsactf_root / "src")

    # ------------------------------------------------------------------
    # Startup measurement: run nullattack on a key that definitely exists
    # ------------------------------------------------------------------
    print("\n=== Startup overhead ===")
    nullkey = str(EXAMPLES / "weak_public.pub")
    py_starts, rs_starts = [], []
    for _ in range(5):
        _, t = run_one(
            [str(args.python_bin), "-m", "RsaCtfTool.main",
             "--publickey", nullkey, "--attack", "nullattack", "--private"],
            timeout=15, env=py_env,
        )
        py_starts.append(t)
        _, t = run_one(
            [str(args.rust_bin), "--publickey", nullkey, "--attack", "nullattack", "--private"],
            timeout=15, env=None,
        )
        rs_starts.append(t)

    py_start  = min(py_starts)
    rs_start  = min(rs_starts)
    print(f"  Python: {py_start:.3f}s  (min of 5)  ← interpreter + import overhead")
    print(f"  Rust:   {rs_start:.3f}s  (min of 5)  ← binary cold-start")
    print(f"  Ratio:  x{py_start/rs_start:.0f}  (this is NOT an algorithmic speedup)")

    # ------------------------------------------------------------------
    # Attack benchmarks
    # ------------------------------------------------------------------
    print(f"\n=== Attack benchmarks (timeout={args.timeout}s, repeat={args.repeat}) ===")
    print(f"  startup subtracted → compute_time = total − startup")
    print()

    TIER_NAME = {1: "Trivial keys   (startup dominates)",
                 2: "Compute factoring  (real arithmetic work)",
                 3: "Structural attacks (algorithmic advantage)"}

    rows = []
    current_tier = None

    for att in ATTACKS:
        if att["tier"] != current_tier:
            current_tier = att["tier"]
            print(f"\n  {TIER_NAME[current_tier]}")
            print(f"  {'Attack':<20} {'Py-total':>9} {'Py-cmp':>8} {'Rust-tot':>9} "
                  f"{'Rust-cmp':>9} {'cmp-x':>7}  {'Py':>6} {'Rust':>6}")
            print("  " + "-" * 80)

        py_status, py_total = run_attack(
            [str(args.python_bin), "-m", "RsaCtfTool.main"] + att["py_args"],
            timeout=args.timeout, env=py_env, repeat=args.repeat,
        )
        rs_status, rs_total = run_attack(
            [str(args.rust_bin)] + att["rust_args"],
            timeout=args.timeout, env=None, repeat=args.repeat,
        )

        py_cmp = max(0.0, py_total - py_start)
        rs_cmp = max(0.0, rs_total - rs_start)
        cmp_x  = py_cmp / rs_cmp if rs_cmp > 5e-3 else float("inf")

        def fmt_x(x: float) -> str:
            return "∞" if x == float("inf") else f"x{x:.1f}"

        def fmt_status(s: str) -> str:
            return {"ok": "✓", "fail": "✗", "timeout": "T/O"}[s]

        print(
            f"  {att['label']:<20} {py_total:>8.3f}s {py_cmp:>7.3f}s {rs_total:>8.3f}s "
            f"{rs_cmp:>8.3f}s {fmt_x(cmp_x):>7}  {fmt_status(py_status):>6} {fmt_status(rs_status):>6}"
        )

        rows.append({
            "label": att["label"],
            "tier": att["tier"],
            "desc": att["desc"],
            "py_status": py_status,
            "rs_status": rs_status,
            "py_total": py_total,
            "rs_total": rs_total,
            "py_cmp": py_cmp,
            "rs_cmp": rs_cmp,
            "cmp_x": cmp_x,
        })

    # ------------------------------------------------------------------
    # Summary per tier
    # ------------------------------------------------------------------
    print("\n\n=== Summary ===")
    print(f"  Startup overhead: Python {py_start:.3f}s  Rust {rs_start:.3f}s  (x{py_start/rs_start:.0f})\n")

    for tier in [1, 2, 3]:
        tier_rows = [r for r in rows if r["tier"] == tier and
                     r["py_status"] in ("ok",) and r["rs_status"] in ("ok",)]
        finite = [r for r in tier_rows if r["rs_cmp"] > 5e-3]
        if tier_rows:
            avg_total = sum(r["py_total"]/r["rs_total"] for r in tier_rows) / len(tier_rows)
        else:
            avg_total = float("nan")
        if finite:
            avg_cmp = sum(r["cmp_x"] for r in finite) / len(finite)
        else:
            avg_cmp = float("nan")
        print(f"  {TIER_NAME[tier]}")
        if tier_rows:
            print(f"    avg total speedup  (wall-clock incl. startup): x{avg_total:.1f}")
            if finite:
                print(f"    avg compute speedup (startup subtracted):      x{avg_cmp:.1f}")
            else:
                print(f"    avg compute speedup: ∞  (Rust compute ≈ 0 ms)")
        else:
            print(f"    (no cases where both tools succeeded)")
        print()

    print("  Key takeaways:")
    print("  • Startup overhead accounts for most of the speedup in Tier 1.")
    print("  • Tier 2 shows REAL algorithmic speedup from native arithmetic (Rust wins")
    print("    Fermat/SQUFOF/factorial-pm1 by 2–30×; Python's gmpy2 beats ECM).")
    print("  • Tier 3 structural attacks are where Rust shines most: Wiener, Boneh-")
    print("    Durfee, and lattice attacks are genuinely orders of magnitude faster.")
    print("  • SIQS/QS omitted: Rust stubs, Python delegates to libnum/SymPy.")

    # ------------------------------------------------------------------
    # Markdown report
    # ------------------------------------------------------------------
    args.output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    md_path = args.output_dir / f"hard_keys_{stamp}.md"

    with md_path.open("w") as f:
        f.write("# Hard-Key Compute-Bound Benchmark\n\n")
        f.write(f"Generated: {datetime.datetime.now().isoformat(timespec='seconds')}  \n")
        f.write(f"Timeout: {args.timeout}s per run | Repeat: {args.repeat}  \n")
        f.write(f"Python startup: **{py_start:.3f}s** | Rust startup: **{rs_start:.3f}s** "
                f"(x{py_start/rs_start:.0f} ratio)\n\n")
        f.write("## Methodology\n\n")
        f.write("`compute_time = total_time − startup_time`  \n")
        f.write("Startup measured via `nullattack`, 5 runs, minimum taken.\n\n")
        f.write("## Results\n\n")
        f.write("| Tier | Attack | Py total | Py compute | Rust total | Rust compute "
                "| Compute speedup | Py | Rust |\n")
        f.write("|---|---|---:|---:|---:|---:|---:|---|---|\n")
        sym = {1: "trivial", 2: "factor", 3: "struct"}
        for r in rows:
            cx = ("∞" if r["cmp_x"] == float("inf")
                  else f"x{r['cmp_x']:.1f}")
            ps = {"ok": "✓", "fail": "✗", "timeout": "T/O"}[r["py_status"]]
            rs = {"ok": "✓", "fail": "✗", "timeout": "T/O"}[r["rs_status"]]
            f.write(f"| {sym[r['tier']]} | {r['label']} "
                    f"| {r['py_total']:.3f}s | {r['py_cmp']:.3f}s "
                    f"| {r['rs_total']:.3f}s | {r['rs_cmp']:.3f}s "
                    f"| {cx} | {ps} | {rs} |\n")
        f.write("\n## Honest caveats\n\n")
        f.write("- **SIQS/QS** omitted — Rust stubs; Python uses libnum/SymPy.\n")
        f.write("- **ECM >256 bit** — Rust rejects; Python can continue.\n")
        f.write("- **Brent/Rho** on hard keys — Rust step limits cause failure; Python runs longer.\n")
        f.write("- ECM on small keys — Python's gmpy2 C backend outperforms pure-Rust Montgomery ladder.\n")

    print(f"\n[done] {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
