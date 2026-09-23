#!/usr/bin/env python3
"""
Run the benchmark across detection-layer configurations and publish a
BENCHMARK.md with real, reproducible results.

Usage:
    python benchmarks/run_and_publish.py
    python benchmarks/run_and_publish.py --layers regex,ml

Each configuration is run in a subprocess with the appropriate env vars,
using benchmark.py's --json-out flag. Results are aggregated into a single
Markdown table written to BENCHMARK.md at the repository root.
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parent
OUT = REPO_ROOT / "BENCHMARK.md"
BENCHMARK = ROOT / "benchmark.py"


DEFAULT_CONFIGS = [
    ("regex", "Layer 1 — Regex only"),
    ("regex,ml", "Layer 1+2 — Regex + ML"),
    ("regex,ml,llm", "Layer 1+2+3 — Full stack"),
]


def run_config(layers: str, label: str) -> dict:
    """Run benchmark.py for one layer configuration, return parsed analysis."""
    print(f"\n{'='*70}\n=== Running: {label} (--layers {layers})\n{'='*70}")
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        tmp_path = tmp.name

    cmd = [
        sys.executable, str(BENCHMARK),
        "--layers", layers,
        "--json-out", tmp_path,
    ]
    env = os.environ.copy()
    res = subprocess.run(cmd, capture_output=True, text=True, env=env)
    print(res.stdout)
    if res.returncode not in (0, 1):
        print(res.stderr, file=sys.stderr)

    try:
        with open(tmp_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("analysis", {}).get("summary", {})
    except Exception as e:
        return {"error": f"could not parse results: {e}"}
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def main():
    parser = argparse.ArgumentParser(description="Run benchmark and publish BENCHMARK.md")
    parser.add_argument("--layers", default=None,
                        help="Override configs, e.g. 'regex' or 'regex,ml'")
    args = parser.parse_args()

    if args.layers:
        configs = [(args.layers, f"Layers: {args.layers}")]
    else:
        configs = DEFAULT_CONFIGS

    results = [(label, run_config(layers, label)) for layers, label in configs]

    lines = [
        "# Benchmark Results — Cerbère / AgentGuard",
        "",
        f"_Generated: {datetime.date.today().isoformat()}_",
        "",
        "See [benchmarks/METHODOLOGY.md](benchmarks/METHODOLOGY.md) for methodology.",
        "",
        "| Configuration | Recall | Precision | F1 | FPR | Latency (ms) | Score |",
        "|---|---|---|---|---|---|---|",
    ]
    for label, r in results:
        if "error" in r:
            lines.append(f"| {label} | _run failed: {r['error']}_ | | | | | |")
            continue
        lines.append(
            f"| {label} | {r.get('recall', 0):.1f}% | {r.get('precision', 0):.1f}% | "
            f"{r.get('f1_score', 0):.1f}% | {r.get('false_positive_rate', 0):.1f}% | "
            f"{r.get('avg_latency_ms', 0):.1f} | {r.get('overall_score', 0)}/100 |"
        )

    lines += [
        "",
        "## Reproduction",
        "```bash",
        "python benchmarks/run_and_publish.py",
        "```",
        "",
    ]
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"\n✅ Wrote {OUT}")


if __name__ == "__main__":
    main()
