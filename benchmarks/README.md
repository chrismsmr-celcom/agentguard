# Benchmarks

Reproducible evaluation of Cerbère's detection layers.

## Files

| File | Purpose |
|------|---------|
| `benchmark.py` | Runs the corpus through the detection stack, computes metrics |
| `adversarial_corpus.json` | Internal dev corpus (168 prompts, 8 categories, 5 languages) |
| `external_holdout.json` | Independent holdout set from public datasets *(to be populated)* |
| `report_generator.py` | Renders a Markdown report from results |
| `run_and_publish.py` | Runs all configurations and writes `BENCHMARK.md` |
| `METHODOLOGY.md` | How and why we measure what we measure |

## Quick start

```bash
# Full stack (rules + ML + LLM judge)
python benchmarks/benchmark.py --layers l1,l2,l3

# Rules only (fast baseline)
python benchmarks/benchmark.py --layers l1

# Generate the public report
python benchmarks/run_and_publish.py
```

## What it measures

Recall, Precision, FPR, F1, latency (p50/p95), confusion matrix — reported
**per layer configuration** so the marginal value of ML and the LLM judge is visible.

See [`METHODOLOGY.md`](METHODOLOGY.md) for the full protocol and limitations.

## Honesty rules

1. Never hand-write numbers into `BENCHMARK.md` — always generate it.
2. Never merge the internal corpus with the external holdout.
3. Always publish the command, the corpus hash, and the environment.
4. Report worst cases, not just averages.
