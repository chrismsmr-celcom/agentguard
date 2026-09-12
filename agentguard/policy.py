import os
import json
import hashlib
import re
import requests
import structlog
from typing import Optional, Dict, Any, List

from .models import SecurityCheck, RiskLevel, SecurityAction

logger = structlog.get_logger("agentguard.policy")

# Fallback ML si le module n'est pas dispo
try:
    from agentguard_ml import MLDetector
except ImportError:
    class MLDetector:
        def __init__(self): self.enabled = False
        def predict(self, text): return {"score": 0.0, "risk": "UNKNOWN", "confidence": "low"}

class PolicyEngine:
    _STRONG_PATTERNS = None
    _WEAK_PATTERNS = None

    def __init__(self, policies: Optional[List[Dict[str, Any]]] = None, redis_url: Optional[str] = None):
        self.policies = policies or []
        self._compile_patterns()
        self.ml_detector = MLDetector()
        self.use_llm_judge = os.getenv("AGENTGUARD_USE_LLM_JUDGE", "false").lower() in ("true", "1", "on", "yes")
        self.block_on_ambiguous = os.getenv("AGENTGUARD_BLOCK_ON_AMBIGUOUS", "false").lower() in ("true", "1", "on", "yes")
        self.judge_timeout = max(0.5, float(os.getenv("AGENTGUARD_JUDGE_TIMEOUT", "15.0")))
        
        self._redis_client = None
        if redis_url and self.use_llm_judge:
            try:
                import redis
                self._redis_client = redis.from_url(redis_url)
                self._redis_client.ping()
            except Exception:
                self._redis_client = None

        self._allowed_tools = set()
        for policy in self.policies:
            if policy.get("type") == "tool_whitelist":
                self._allowed_tools.update(policy.get("allowed_tools", []))
        self._triple_judge = None

    def _compile_patterns(self):
        if PolicyEngine._STRONG_PATTERNS is not None:
            return
        strong = [r"\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|rules|prompts)\b", r"\bjailbreak(?:ing)?\b", r"\bsystem\s+override\b", r"\breveal\s+(?:your\s+|the\s+)?system\s+prompt\b", r"\brm\s+-rf\b"]
        weak = [r"\bpretend\s+you\s+are\b", r"\broleplay\s+as\b"]
        PolicyEngine._STRONG_PATTERNS = re.compile("|".join(f"(?:{p})" for p in strong), re.IGNORECASE)
        PolicyEngine._WEAK_PATTERNS = re.compile("|".join(f"(?:{p})" for p in weak), re.IGNORECASE)

    def check_injection(self, text: str) -> SecurityCheck:
        text = str(text or "")
        if not text.strip():
            return SecurityCheck("prompt_injection", True, RiskLevel.LOW, "Empty prompt")
        
        if self._triple_judge is not None:
            try:
                tj_result = self._triple_judge.evaluate(text)
                if tj_result.get("final_verdict") == "DENY":
                    return SecurityCheck("prompt_injection", False, RiskLevel.HIGH, f"[TRIPLE JUDGE] {tj_result.get('reason')}", {"layer": "triple_judge"}, SecurityAction.BLOCK)
            except Exception as e:
                logger.warning("triple_judge_failed", error=str(e))

        if self.ml_detector.enabled:
            ml_result = self.ml_detector.predict(text)
            if ml_result["risk"] == "HIGH" and ml_result["score"] >= 0.85:
                return SecurityCheck("prompt_injection", False, RiskLevel.HIGH, f"ML detected threat ({ml_result['score']:.2%})", {"layer": "ml"}, SecurityAction.BLOCK)

        if PolicyEngine._STRONG_PATTERNS.findall(text):
            return SecurityCheck("prompt_injection", False, RiskLevel.HIGH, "Strong injection pattern detected", {"layer": "regex"}, SecurityAction.BLOCK)

        return SecurityCheck("prompt_injection", True, RiskLevel.LOW, "No injection detected", {"layer": "all_clear"}, SecurityAction.ALLOW)

    def check_pii(self, text: str) -> SecurityCheck:
        return SecurityCheck("pii_detection", True, RiskLevel.LOW, "PII check passed (simplified)")

    def check_tool_policy(self, tool_name: str, params: Dict[str, Any], budget_remaining: float) -> SecurityCheck:
        if self._allowed_tools and tool_name not in self._allowed_tools:
            return SecurityCheck("tool_policy", False, RiskLevel.CRITICAL, f"Tool '{tool_name}' not in whitelist", {}, SecurityAction.BLOCK)
        if budget_remaining < 0:
            return SecurityCheck("budget_policy", False, RiskLevel.HIGH, "Budget exceeded", {}, SecurityAction.BLOCK)
        return SecurityCheck("tool_policy", True, RiskLevel.LOW, "Tool call approved")
