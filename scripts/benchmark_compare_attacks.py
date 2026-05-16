#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import datetime as dt
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple


CUBE_ROOT_CT = "2205316413931134031074603746928247799030155221252519872650101242908540609117693035883827878696406295617513907962419726541451312273821810017858485722109359971259158071688912076249144203043097720816270550387459717116098817458584146690177125"
CUBE_ROOT_N = "29331922499794985782735976045591164936683059380558950386560160105740343201513369939006307531165922708949619162698623675349030430859547825708994708321803705309459438099340427770580064400911431856656901982789948285309956111848686906152664473350940486507451771223435835260168971210087470894448460745593956840586530527915802541450092946574694809584880896601317519794442862977471129319781313161842056501715040555964011899589002863730868679527184420789010551475067862907739054966183120621407246398518098981106431219207697870293412176440482900183550467375190239898455201170831410460483829448603477361305838743852756938687673"

ROCA_N = "5590772118685579117817112787486780348504267507289026685912623973671010394384988015497235515969796783937905129055952167826830196634107346761087047942625347"

HASTADS_CT = (
    "261345950255088824199206969589297492768083568554363001807292202086148198540785875067889853750126065910869378059825972054500409296763768604135988881188967875126819737816598484392562403375391722914907856816865871091726511596620751615512183772327351299941365151995536802718357319233050365556244882929796558270337,"
    "147535246350781145803699087910221608128508531245679654307942476916759248311896958780799558399204686458919290159543753966699893006016413718139713809296129796521671806205375133127498854375392596658549807278970596547851946732056260825231169253750741639904613590541946015782167836188510987545893121474698400398826,"
    "633230627388596886579908367739501184580838393691617645602928172655297372145912724695988151441728614868603479196153916968285656992175356066846340327304330216410957123875304589208458268694616526607064173015876523386638026821701609498528415875970074497028482884675279736968611005756588082906398954547838170886958"
)


def discover_attacks(rsactf_root: Path) -> List[str]:
    names: List[str] = []
    for folder in ("single_key", "multi_keys"):
        for p in sorted((rsactf_root / "src" / "RsaCtfTool" / "attacks" / folder).glob("*.py")):
            if p.name in {"__init__.py", "nullattack.py"}:
                continue
            names.append(p.stem)
    # unique keep order
    seen = set()
    ordered = []
    for n in names:
        if n not in seen:
            seen.add(n)
            ordered.append(n)
    return ordered


@dataclass
class RunResult:
    status: str
    returncode: int
    elapsed_s: float
    stdout_tail: str
    stderr_tail: str


def run_one(cmd: List[str], cwd: Path, env: Dict[str, str], timeout_s: int) -> RunResult:
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd),
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
        elapsed = time.perf_counter() - t0
        status = "ok" if proc.returncode == 0 else "error"
        return RunResult(
            status=status,
            returncode=proc.returncode,
            elapsed_s=elapsed,
            stdout_tail="\n".join(proc.stdout.strip().splitlines()[-4:]),
            stderr_tail="\n".join(proc.stderr.strip().splitlines()[-4:]),
        )
    except subprocess.TimeoutExpired as e:
        elapsed = time.perf_counter() - t0
        out = (e.stdout or "") if isinstance(e.stdout, str) else ""
        err = (e.stderr or "") if isinstance(e.stderr, str) else ""
        return RunResult(
            status="timeout",
            returncode=124,
            elapsed_s=elapsed,
            stdout_tail="\n".join(out.strip().splitlines()[-4:]),
            stderr_tail="\n".join(err.strip().splitlines()[-4:]),
        )


def attack_args(attack: str, ex: Path, tool: str) -> List[str]:
    # tool: "python" or "rust" (only where behavior differs)
    if attack == "cube_root":
        return ["--decrypt", CUBE_ROOT_CT, "-e", "3", "-n", CUBE_ROOT_N, "--attack", attack]

    if attack == "roca":
        return ["--attack", attack, "-n", ROCA_N, "-e", "65537", "--private", "--timeout", "60"]

    if attack == "hastads":
        if tool == "rust":
            pubs = str(ex / "hastads0?.pub")
        else:
            pubs = f"{ex / 'hastads01.pub'},{ex / 'hastads02.pub'},{ex / 'hastads03.pub'}"
        return ["--publickey", pubs, "--decrypt", "".join(HASTADS_CT), "--attack", attack, "--private"]

    if attack == "common_factors":
        return ["--publickey", str(ex / "commonfactor?.pub"), "--attack", attack, "--private"]

    if attack == "common_modulus_related_message":
        if tool == "rust":
            pubs = str(ex / "c3301_?.pub")
        else:
            pubs = f"{ex / 'c3301_1.pub'},{ex / 'c3301_2.pub'}"
        decs = f"{ex / 'cipher1'},{ex / 'cipher2'}"
        return ["--publickey", pubs, "--decryptfile", decs, "--attack", attack, "--private"]

    if attack == "same_n_huge_e":
        # Rust parser expects a single integer for -e, so for consistency use two-key mode for both.
        if tool == "rust":
            pubs = str(ex / "multikey-?.pub")
        else:
            pubs = f"{ex / 'multikey-0.pub'},{ex / 'multikey-1.pub'}"
        return ["--publickey", pubs, "--attack", attack, "--private"]

    # keyed fixtures
    special_pub = {
        "smallq": "small_q.pub",
        "wiener": "wiener.pub",
        "boneh_durfee": "wiener.pub",
        "noveltyprimes": "elite_primes.pub",
        "factordb": "factordb_parse.pub",
        "pastctfprimes": "pastctfprimes.pub",
        "ecm": "ecm_method.pub",
        "ecm2": "ecm_method.pub",
        "siqs": "siqs.pub",
        "qs": "siqs.pub",
        "small_crt_exp": "small_crt_exp.pub",
        "smallfraction": "smallfraction.pub",
        "z3_solver": "z3.pub",
        "factor_2PN": "factor_2PN.pub",
        "SQUFOF": "SQUFOF.pub",
        "fermat_numbers_gcd": "fermat_numbers_gcd.pub",
        "mersenne_pm1_gcd": "mersenne_pm1_gcd.pub",
        "primorial_pm1_gcd": "primorial_pm1_gcd.pub",
        "fibonacci_gcd": "fibonacci_gcd.pub",
        "fermat": "close_primes.pub",
    }

    pubfile = ex / special_pub.get(attack, "weak_public.pub")

    args: List[str] = ["--publickey", str(pubfile), "--attack", attack, "--private"]

    if attack == "smallq":
        args.extend(["--decryptfile", str(ex / "small_q.cipher")])
    elif attack in {"wiener", "boneh_durfee"}:
        args.extend(["--decryptfile", str(ex / "wiener.cipher")])
    elif attack == "fermat":
        args.extend(["--decryptfile", str(ex / "close_primes.cipher")])
    elif attack in {"ecm", "ecm2"}:
        args.extend(["--ecmdigits", "25"])

    return args


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare attack-by-attack benchmark: RsaCtfTool vs RsaRustTool")
    parser.add_argument("--rsactf-root", type=Path, default=Path("/home/abdullaxows/Downloads/RsaCtfTool"))
    parser.add_argument("--rsarust-root", type=Path, default=Path("/home/abdullaxows/Downloads/RsaRustTool"))
    parser.add_argument("--python-bin", type=Path, default=Path("/home/abdullaxows/Downloads/RsaCtfTool/venv/bin/python"))
    parser.add_argument("--rust-bin", type=Path, default=Path("/home/abdullaxows/Downloads/RsaRustTool/target/release/RsaRustTool"))
    parser.add_argument("--timeout", type=int, default=25)
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--attacks", type=str, default="all", help="comma-separated attacks or 'all'")
    parser.add_argument("--output-dir", type=Path, default=Path("/home/abdullaxows/Downloads/RsaRustTool/benchmarks"))
    args = parser.parse_args()

    rsactf_root = args.rsactf_root.resolve()
    rsarust_root = args.rsarust_root.resolve()
    examples = rsactf_root / "examples"

    if not args.python_bin.exists():
        print(f"[error] Python bin not found: {args.python_bin}", file=sys.stderr)
        return 2
    if not args.rust_bin.exists():
        print(f"[error] Rust binary not found: {args.rust_bin}", file=sys.stderr)
        return 2

    available = discover_attacks(rsactf_root)
    if args.attacks == "all":
        attacks = available
    else:
        wanted = [x.strip() for x in args.attacks.split(",") if x.strip()]
        missing = [x for x in wanted if x not in available]
        if missing:
            print(f"[error] unknown attacks: {missing}", file=sys.stderr)
            return 2
        attacks = wanted

    print(f"[info] attacks to benchmark: {len(attacks)}")
    print(f"[info] timeout per run: {args.timeout}s, repeat: {args.repeat}")

    py_env = os.environ.copy()
    py_env["PYTHONPATH"] = str(rsactf_root / "src")

    rows = []
    total = len(attacks)

    for idx, attack in enumerate(attacks, start=1):
        py_times: List[float] = []
        rs_times: List[float] = []
        py_status = "ok"
        rs_status = "ok"
        py_rc = 0
        rs_rc = 0
        py_tail = ""
        rs_tail = ""

        for _ in range(args.repeat):
            py_cmd = [str(args.python_bin), "-m", "RsaCtfTool.main"] + attack_args(attack, examples, "python")
            rs_cmd = [str(args.rust_bin)] + attack_args(attack, examples, "rust")

            py_res = run_one(py_cmd, rsactf_root, py_env, args.timeout)
            rs_res = run_one(rs_cmd, rsarust_root, os.environ.copy(), args.timeout)

            py_times.append(py_res.elapsed_s)
            rs_times.append(rs_res.elapsed_s)
            py_status = py_res.status if py_status == "ok" else py_status
            rs_status = rs_res.status if rs_status == "ok" else rs_status
            py_rc = py_res.returncode
            rs_rc = rs_res.returncode
            py_tail = py_res.stderr_tail or py_res.stdout_tail
            rs_tail = rs_res.stderr_tail or rs_res.stdout_tail

        py_avg = sum(py_times) / len(py_times)
        rs_avg = sum(rs_times) / len(rs_times)
        speedup = (py_avg / rs_avg) if rs_avg > 0 else 0.0

        rows.append({
            "attack": attack,
            "python_status": py_status,
            "python_rc": py_rc,
            "python_s": py_avg,
            "rust_status": rs_status,
            "rust_rc": rs_rc,
            "rust_s": rs_avg,
            "speedup_py_div_rust": speedup,
            "python_tail": py_tail.replace("\n", " | "),
            "rust_tail": rs_tail.replace("\n", " | "),
        })

        print(
            f"[{idx:02d}/{total:02d}] {attack:<32} "
            f"py={py_avg:6.3f}s({py_status})  rs={rs_avg:6.3f}s({rs_status})  "
            f"x{speedup:5.2f}"
        )

    args.output_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = args.output_dir / f"compare_attacks_{stamp}.csv"
    md_path = args.output_dir / f"compare_attacks_{stamp}.md"

    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "attack",
                "python_status",
                "python_rc",
                "python_s",
                "rust_status",
                "rust_rc",
                "rust_s",
                "speedup_py_div_rust",
                "python_tail",
                "rust_tail",
            ],
        )
        w.writeheader()
        w.writerows(rows)

    ok_both = [r for r in rows if r["python_status"] == "ok" and r["rust_status"] == "ok"]
    avg_speedup = sum(r["speedup_py_div_rust"] for r in ok_both) / len(ok_both) if ok_both else 0.0

    with md_path.open("w", encoding="utf-8") as f:
        f.write("# RSA Attack Benchmark Comparison\n\n")
        f.write(f"- Generated: {dt.datetime.now().isoformat(timespec='seconds')}\n")
        f.write(f"- Attacks: {len(rows)}\n")
        f.write(f"- Timeout per run: {args.timeout}s\n")
        f.write(f"- Repeat: {args.repeat}\n")
        f.write(f"- Average speedup (only both-ok rows): x{avg_speedup:.2f}\n\n")
        f.write("| Attack | Python(s) | Rust(s) | Speedup (Py/Rust) | Py status | Rust status |\n")
        f.write("|---|---:|---:|---:|---|---|\n")
        for r in sorted(rows, key=lambda x: x["speedup_py_div_rust"], reverse=True):
            f.write(
                f"| {r['attack']} | {r['python_s']:.3f} | {r['rust_s']:.3f} | {r['speedup_py_div_rust']:.2f} | {r['python_status']} | {r['rust_status']} |\n"
            )

    print(f"\n[done] CSV: {csv_path}")
    print(f"[done] MD : {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
