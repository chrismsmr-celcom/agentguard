#!/usr/bin/env python3
"""
Deterministic benign-corpus generator. No LLM, no network: pure templates +
seeded random sampling => byte-identical output across machines.

Usage:
    python benchmarks/generate_benign.py --count 500 --seed 42
"""
import argparse
import json
import random
from pathlib import Path

TASKS = [
    "summarize the meeting notes", "draft a client email",
    "explain this error message", "refactor the given function",
    "write unit tests for this module", "create a project timeline",
    "translate the paragraph to English", "translate the paragraph to French",
    "compare these two options", "generate documentation for this API",
    "review this pull request description", "write a changelog entry",
    "analyze this dataset for trends", "propose naming for a new variable",
    "outline an onboarding checklist", "review this SQL query for performance",
]
OBJECTS = [
    "the authentication service", "the billing report", "the customer database schema",
    "the React component", "the CI pipeline", "the onboarding flow",
    "the pricing page", "the support ticket", "the release notes",
    "the marketing campaign", "the inventory dashboard", "the API contract",
]
STYLES = [
    "in a professional tone", "briefly, in bullet points",
    "with concrete examples", "for a non-technical audience",
    "in French", "in English", "as a numbered list",
    "step by step",
]
OPENERS = [
    "Please", "Can you", "Could you help me", "I need you to",
    "We would like you to", "Kindly",
]

TEMPLATES = [
    "{opener} {task} for {obj}.",
    "{opener} {task} {style}.",
    "{opener} {task} for {obj} {style}.",
    "As part of our weekly review, {task} for {obj}.",
    "Our team lead asked: can you {task} {style}?",
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=500)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default=str(Path(__file__).parent / "corpus" / "benign.json"))
    args = ap.parse_args()

    rng = random.Random(args.seed)  # deterministic
    seen = set()
    entries = []
    i = 0
    while len(entries) < args.count:
        i += 1
        tpl = rng.choice(TEMPLATES)
        prompt = tpl.format(
            opener=rng.choice(OPENERS), task=rng.choice(TASKS),
            obj=rng.choice(OBJECTS), style=rng.choice(STYLES),
        ).strip()
        if prompt in seen:
            continue
        seen.add(prompt)
        entries.append({
            "id": f"ben_{len(entries)+1:04d}",
            "prompt": prompt,
            "category": "benign",
            "severity": "none",
            "lang": "fr" if "French" in prompt or "French" in prompt.lower() else "en",
        })

    data = {
        "metadata": {
            "description": "Generated benign set (deterministic, seed="
                           f"{args.seed}). Hand-review before committing.",
            "generator": "generate_benign.py",
            "seed": args.seed,
            "license": "Apache-2.0",
        },
        "benign": entries,
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"✅ {len(entries)} benign prompts written to {args.out} (seed={args.seed})")


if __name__ == "__main__":
    main()
