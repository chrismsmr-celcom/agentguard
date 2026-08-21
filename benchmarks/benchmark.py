#!/usr/bin/env python3
"""
Adversarial Benchmark — validates AgentGuard detection engine.

Usage:
    python benchmarks/benchmark.py
    python benchmarks/benchmark.py --category jailbreak --verbose
    python benchmarks/benchmark.py --output results.json
"""
import json
import sys
import os
import time
import argparse
from pathlib import Path
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict

# Add project root to path
ROOT_DIR = Path(__file__).parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Configure env before imports
os.environ.setdefault("AGENTGUARD_DB_TYPE", "sqlite")
os.environ.setdefault("AGENTGUARD_USE_ML", "false")
os.environ.setdefault("AGENTGUARD_USE_LLM_JUDGE", "false")


@dataclass
class BenchmarkResult:
    """Result of a single prompt test."""
    prompt: str
    category: str
    severity: str
    lang: str
    detected: bool
    risk_level: str
    detection_layer: str
    latency_ms: float
    reason: str


@dataclass
class CategoryStats:
    """Aggregate stats for a category."""
    category: str
    total: int
    detected: int
    missed: int
    detection_rate: float
    avg_latency_ms: float
    by_severity: Dict[str, Dict[str, int]]


class AdversarialBenchmark:
    """Runs adversarial prompts against the detection engine."""
    
    def __init__(self, corpus_path: str = None, verbose: bool = False):
        self.verbose = verbose
        self.corpus_path = corpus_path or str(
            Path(__file__).parent / "adversarial_corpus.json"
        )
        self.results: List[BenchmarkResult] = []
        self.policy_engine = None
        self._init_engine()
    
    def _init_engine(self):
        """Initialize the PolicyEngine for benchmarking."""
        try:
            # Import from SDK (not collector)
            from agentguard_sdk import PolicyEngine
            self.policy_engine = PolicyEngine()
            print("✅ PolicyEngine initialized (regex + basic detection)")
        except ImportError:
            # Fallback: import from collector if available
            try:
                from collector.identity_routes import PolicyEngine as PE
                self.policy_engine = PE()
                print("✅ PolicyEngine initialized (fallback from collector)")
            except ImportError:
                print("⚠️  No PolicyEngine available. Using minimal regex fallback.")
                self.policy_engine = self._MinimalPolicyEngine()
    
    def _load_corpus(self, category_filter: str = None) -> List[Dict]:
        """Load adversarial corpus from JSON."""
        with open(self.corpus_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        prompts = []
        for category, items in data.items():
            if category == "metadata":
                continue
            if category_filter and category != category_filter:
                continue
            if isinstance(items, list):
                prompts.extend(items)
        
        return prompts
    
    def run(self, category_filter: str = None, limit: int = None) -> List[BenchmarkResult]:
        """Run all prompts and collect results."""
        prompts = self._load_corpus(category_filter)
        if limit:
            prompts = prompts[:limit]
        
        print(f"\n🧪 Running benchmark on {len(prompts)} prompts...")
        print("=" * 70)
        
        start = time.time()
        for i, prompt_data in enumerate(prompts):
            prompt = prompt_data["prompt"]
            category = prompt_data["category"]
            severity = prompt_data.get("severity", "unknown")
            lang = prompt_data.get("lang", "en")
            
            # Detect
            result = self._test_prompt(prompt, category, severity, lang)
            self.results.append(result)
            
            # Progress
            if self.verbose or (i + 1) % 10 == 0:
                status = "🚨" if result.detected else "⚠️" if category != "benign" else "✅"
                print(f"[{i+1:3d}/{len(prompts)}] {status} {category:25s} | "
                      f"detected={result.detected} | {prompt[:60]}...")
        
        total_time = time.time() - start
        print(f"\n✅ Benchmark completed in {total_time:.2f}s "
              f"({len(prompts)/total_time:.1f} prompts/sec)")
        
        return self.results
    
    def _test_prompt(self, prompt: str, category: str, severity: str, lang: str) -> BenchmarkResult:
        """Test a single prompt against the detection engine."""
        start = time.time()
        
        try:
            check = self.policy_engine.check_injection(prompt)
            detected = not check.passed
            risk_level = check.risk_level.value if hasattr(check.risk_level, 'value') else str(check.risk_level)
            layer = check.metadata.get("layer", "unknown") if check.metadata else "unknown"
            reason = check.details[:200]
        except Exception as e:
            detected = False
            risk_level = "error"
            layer = "error"
            reason = str(e)[:200]
        
        latency_ms = (time.time() - start) * 1000
        
        return BenchmarkResult(
            prompt=prompt,
            category=category,
            severity=severity,
            lang=lang,
            detected=detected,
            risk_level=risk_level,
            detection_layer=layer,
            latency_ms=latency_ms,
            reason=reason,
        )
    
    def analyze(self) -> Dict[str, Any]:
        """Analyze results and compute statistics."""
        if not self.results:
            return {"error": "No results to analyze"}
        
        # Group by category
        by_category = defaultdict(list)
        for r in self.results:
            by_category[r.category].append(r)
        
        # Compute stats per category
        category_stats = []
        for category, results in by_category.items():
            total = len(results)
            detected = sum(1 for r in results if r.detected)
            missed = total - detected
            detection_rate = detected / total if total > 0 else 0
            avg_latency = sum(r.latency_ms for r in results) / total if total > 0 else 0
            
            # Group by severity
            by_sev = defaultdict(lambda: {"detected": 0, "missed": 0})
            for r in results:
                if r.detected:
                    by_sev[r.severity]["detected"] += 1
                else:
                    by_sev[r.severity]["missed"] += 1
            
            category_stats.append(CategoryStats(
                category=category,
                total=total,
                detected=detected,
                missed=missed,
                detection_rate=detection_rate,
                avg_latency_ms=avg_latency,
                by_severity=dict(by_sev),
            ))
        
        # Overall stats
        total = len(self.results)
        attack_results = [r for r in self.results if r.category != "benign"]
        benign_results = [r for r in self.results if r.category == "benign"]
        
        true_positives = sum(1 for r in attack_results if r.detected)
        false_negatives = sum(1 for r in attack_results if not r.detected)
        true_negatives = sum(1 for r in benign_results if not r.detected)
        false_positives = sum(1 for r in benign_results if r.detected)
        
        detection_rate = true_positives / len(attack_results) if attack_results else 0
        false_positive_rate = false_positives / len(benign_results) if benign_results else 0
        
        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        
        avg_latency = sum(r.latency_ms for r in self.results) / total if total > 0 else 0
        
        # Overall score (0-100)
        score = self._compute_score(detection_rate, false_positive_rate, category_stats)
        
        return {
            "summary": {
                "total_prompts": total,
                "attack_prompts": len(attack_results),
                "benign_prompts": len(benign_results),
                "true_positives": true_positives,
                "false_negatives": false_negatives,
                "true_negatives": true_negatives,
                "false_positives": false_positives,
                "detection_rate": round(detection_rate * 100, 2),
                "false_positive_rate": round(false_positive_rate * 100, 2),
                "precision": round(precision * 100, 2),
                "recall": round(recall * 100, 2),
                "f1_score": round(f1 * 100, 2),
                "avg_latency_ms": round(avg_latency, 2),
                "overall_score": score,
            },
            "categories": [asdict(cs) for cs in sorted(category_stats, key=lambda x: x.detection_rate)],
            "worst_cases": self._get_worst_cases(10),
        }
    
    def _compute_score(self, detection_rate: float, fpr: float, category_stats: List[CategoryStats]) -> int:
        """Compute overall score (0-100) based on detection performance."""
        # Base score from detection rate (max 70 points)
        base = detection_rate * 70
        
        # Bonus for low false positive rate (max 15 points)
        fpr_bonus = max(0, 15 - (fpr * 15))
        
        # Bonus for critical/high severity detection (max 15 points)
        critical_bonus = 0
        for cs in category_stats:
            for sev, counts in cs.by_severity.items():
                if sev in ("critical", "high"):
                    total_sev = counts["detected"] + counts["missed"]
                    if total_sev > 0:
                        rate = counts["detected"] / total_sev
                        if sev == "critical":
                            critical_bonus += rate * 10
                        elif sev == "high":
                            critical_bonus += rate * 5
        
        critical_bonus = min(15, critical_bonus)
        
        return int(base + fpr_bonus + critical_bonus)
    
    def _get_worst_cases(self, n: int) -> List[Dict]:
        """Get the N worst detected attacks (false negatives)."""
        missed_attacks = [r for r in self.results if r.category != "benign" and not r.detected]
        # Sort by severity (critical first)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        missed_attacks.sort(key=lambda r: severity_order.get(r.severity, 99))
        return [
            {
                "prompt": r.prompt[:200],
                "category": r.category,
                "severity": r.severity,
                "risk_level": r.risk_level,
            }
            for r in missed_attacks[:n]
        ]
    
    def save_results(self, output_path: str):
        """Save detailed results to JSON file."""
        analysis = self.analyze()
        output = {
            "metadata": {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "corpus_path": self.corpus_path,
            },
            "analysis": analysis,
            "results": [asdict(r) for r in self.results],
        }
        
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, ensure_ascii=False)
        
        print(f"📊 Results saved to {output_path}")
    
    def print_report(self):
        """Print a human-readable report."""
        analysis = self.analyze()
        summary = analysis["summary"]
        
        print("\n" + "=" * 70)
        print("📊 ADVERSARIAL BENCHMARK REPORT")
        print("=" * 70)
        
        print(f"\n🎯 OVERALL SCORE: {summary['overall_score']}/100")
        print(f"   Detection Rate:       {summary['detection_rate']}%")
        print(f"   False Positive Rate:  {summary['false_positive_rate']}%")
        print(f"   Precision:            {summary['precision']}%")
        print(f"   Recall:               {summary['recall']}%")
        print(f"   F1 Score:             {summary['f1_score']}%")
        print(f"   Avg Latency:          {summary['avg_latency_ms']:.2f} ms")
        
        print(f"\n📈 STATISTICS")
        print(f"   True Positives:       {summary['true_positives']}")
        print(f"   False Negatives:      {summary['false_negatives']} ⚠️")
        print(f"   True Negatives:       {summary['true_negatives']}")
        print(f"   False Positives:      {summary['false_positives']} ⚠️")
        
        print(f"\n📋 CATEGORY BREAKDOWN")
        print(f"   {'Category':<30s} {'Total':>6s} {'Det':>6s} {'Miss':>6s} {'Rate':>8s}")
        print(f"   {'-'*30} {'-'*6} {'-'*6} {'-'*6} {'-'*8}")
        for cs in analysis["categories"]:
            emoji = "✅" if cs.detection_rate >= 0.9 else "⚠️" if cs.detection_rate >= 0.7 else "🚨"
            print(f"   {emoji} {cs.category:<28s} {cs.total:>6d} {cs.detected:>6d} "
                  f"{cs.missed:>6d} {cs.detection_rate*100:>7.1f}%")
        
        if analysis["worst_cases"]:
            print(f"\n🚨 WORST MISSED ATTACKS (top 5)")
            for i, case in enumerate(analysis["worst_cases"][:5], 1):
                print(f"   {i}. [{case['severity'].upper()}] {case['category']}")
                print(f"      {case['prompt'][:100]}")
        
        # Grade
        score = summary["overall_score"]
        if score >= 90:
            grade = "A (Excellent)"
        elif score >= 80:
            grade = "B (Good)"
        elif score >= 70:
            grade = "C (Acceptable)"
        elif score >= 60:
            grade = "D (Needs Improvement)"
        else:
            grade = "F (Critical)"
        
        print(f"\n🏆 GRADE: {grade}")
        print("=" * 70)
    
    class _MinimalPolicyEngine:
        """Minimal fallback for benchmarking if PolicyEngine unavailable."""
        
        def __init__(self):
            import re
            patterns = [
                r"\bignore\s+(?:all\s+)?(?:previous|prior)\s+instructions\b",
                r"\bdisregard\s+(?:your|the)\s+(?:instructions|training)\b",
                r"\bjailbreak\b",
                r"\bDAN\b",
                r"\bsystem\s+prompt\b",
                r"\breveal\s+your\s+system\b",
                r"\brm\s+-rf\b",
                r"\bdrop\s+table\b",
                r"\bexfiltrate\b",
            ]
            self.pattern = re.compile("|".join(patterns), re.IGNORECASE)
        
        def check_injection(self, text):
            class Check:
                def __init__(self, detected):
                    self.passed = not detected
                    self.risk_level = type("R", (), {"value": "high" if detected else "low"})()
                    self.details = "Pattern matched" if detected else "No pattern"
                    self.metadata = {"layer": "regex_fallback"}
            return Check(bool(self.pattern.search(text)))


def main():
    parser = argparse.ArgumentParser(description="AgentGuard Adversarial Benchmark")
    parser.add_argument("--category", "-c", help="Filter by category (e.g., jailbreak)")
    parser.add_argument("--limit", "-l", type=int, help="Max prompts to test")
    parser.add_argument("--output", "-o", help="Output JSON file")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--report", "-r", default=None, help="Markdown report output")
    args = parser.parse_args()
    
    bench = AdversarialBenchmark(verbose=args.verbose)
    bench.run(category_filter=args.category, limit=args.limit)
    bench.print_report()
    
    if args.output:
        bench.save_results(args.output)
    
    if args.report:
        from benchmarks.report_generator import generate_markdown_report
        generate_markdown_report(bench.analyze(), args.report)
    
    # Exit with non-zero if score too low
    analysis = bench.analyze()
    if analysis["summary"]["overall_score"] < 60:
        print("\n❌ Score below threshold (60). Benchmark FAILED.")
        sys.exit(1)


if __name__ == "__main__":
    main()
