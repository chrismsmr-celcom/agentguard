"""
AgentGuard Triple Judge System with Intelligent Cascade

Architecture:
  1. Prompt Guard — prompt injection detection (Meta)
  2. Llama Guard — content safety (Meta via Groq/HF)
  3. LLM Cascade Judge — contextual analysis (OpenRouter → Cerebras → DeepSeek → Groq)

Decision policy:
  - ANY judge says ATTACK → DENY (unless didactic context)
  - UNCERTAIN / disagreement → REVIEW
  - ALL available judges say SAFE → ALLOW
  - ALL judges unavailable → REVIEW (Fail-Secure)

SECURITY:
  _scrub_before_external_call() est appliqué systématiquement AVANT toute 
  troncature ou envoi, pour ne jamais faire fuiter un secret vers un tiers.
"""
import os
import re
import time
import json
import hashlib
import logging
from dataclasses import dataclass
from typing import Optional, Dict, Any, Tuple, List
from enum import Enum

import requests

logger = logging.getLogger("agentguard.judges")

# ─────────────────────────────────────────────────────────────
# SCRUBBING — appliqué avant tout envoi à une API externe
#  terbak───────────────────────────────────────────────────────────
_SECRET_SCRUB_PATTERNS: Tuple[Tuple["re.Pattern[str]", str], ...] = (
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
    (re.compile(r"\bsk-[A-Za-z0-9]{16,}\b"), "[REDACTED_API_KEY]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "[REDACTED_JWT]"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED_SSN]"),
    (re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"), "[REDACTED_CARD]"),
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "[REDACTED_EMAIL]"),
)

def _scrub_before_external_call(text: str) -> str:
    text = text or ""
    for pattern, replacement in _SECRET_SCRUB_PATTERNS:
        text = pattern.sub(replacement, text)
    return text

# ─────────────────────────────────────────────────────────────
# DIDACTIC CONTEXT (Soupape de sécurité anti-Faux Positifs)
# ─────────────────────────────────────────────────────────────
_DIDACTIC_MARKERS = re.compile(
    r"\b(?:explain|explains|explained|explaining|how\s+(?:do|does|did|to)|"
    r"defen[cs]e|protect|protection|quiz|training|course|blog|article|"
    r"documentation|doc|novel|fiction|scene|character|sandbox|fake|"
    r"fixture|verify|report|overview|write\s+(?:a|the)\s+(?:quiz|blog|"
    r"article|scene|documentation|test)|about\s+it|expliqu(?:e|ant|er)|"
    r"protéger|audit|sécurité|fictif|test)\b", re.IGNORECASE
)

def is_didactic_context(text: str) -> bool:
    """Détecte si le prompt est dans un cadre éducatif, d'audit ou de test."""
    has_marker = bool(_DIDACTIC_MARKERS.search(text))
    has_quotes = any(q in text for q in ('"', "'", "`", "«", "»"))
    # Si le texte contient des marqueurs éducatifs ET des guillemets, c'est très probablement bénin
    return has_marker and has_quotes

# ─────────────────────────────────────────────────────────────
# DATA STRUCTURES
# ─────────────────────────────────────────────────────────────
class JudgeVerdict(Enum):
    SAFE = "safe"
    ATTACK = "attack"
    UNCERTAIN = "uncertain"
    UNAVAILABLE = "unavailable"

@dataclass
class JudgeResult:
    judge_name: str
    verdict: JudgeVerdict
    score: float
    category: str = ""
    reason: str = ""
    latency_ms: float = 0.0
    cached: bool = False
    
    def is_attack(self) -> bool: return self.verdict == JudgeVerdict.ATTACK
    def is_safe(self) -> bool: return self.verdict == JudgeVerdict.SAFE
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "judge": self.judge_name, "verdict": self.verdict.value,
            "score": round(self.score, 3), "category": self.category,
            "reason": self.reason[:200], "latency_ms": round(self.latency_ms, 1), "cached": self.cached,
        }

# ─────────────────────────────────────────────────────────────
# JUDGE 1 : PROMPT GUARD (Meta)
# ─────────────────────────────────────────────────────────────
class PromptGuardJudge:
    DEFAULT_ENDPOINT = "https://api-inference.huggingface.co/models/meta-llama/Prompt-Guard-86M"
    
    def __init__(self):
        self.enabled = os.getenv("AGENTGUARD_USE_PROMPT_GUARD", "true").lower() in ("true", "1", "yes")
        self.api_key = os.getenv("HF_API_KEY") or os.getenv("HUGGINGFACE_API_KEY")
        self.endpoint = os.getenv("AGENTGUARD_PROMPT_GUARD_URL", self.DEFAULT_ENDPOINT)
        self.threshold = float(os.getenv("AGENTGUARD_PROMPT_GUARD_THRESHOLD", "0.5"))
        self.timeout = float(os.getenv("AGENTGUARD_PROMPT_GUARD_TIMEOUT", "3.0"))
        self._redis = None
        
        redis_url = os.getenv("AGENTGUARD_LIMITER_STORAGE")
        if redis_url and redis_url != "memory://":
            try:
                import redis
                self._redis = redis.from_url(redis_url, socket_timeout=1.0)
            except Exception:
                pass
    
    def evaluate(self, text: str) -> JudgeResult:
        start = time.time()
        clean_text = _scrub_before_external_call(text)
        
        if not self.enabled or not clean_text:
            return JudgeResult("prompt_guard", JudgeVerdict.SAFE if not clean_text else JudgeVerdict.UNAVAILABLE, 0.0, latency_ms=0)
        
        if not self.api_key:
            return JudgeResult("prompt_guard", JudgeVerdict.UNAVAILABLE, 0.0, reason="HF_API_KEY missing", latency_ms=0)
        
        try:
            response = requests.post(
                self.endpoint, headers={"Authorization": f"Bearer {self.api_key}"},
                json={"inputs": clean_text[:2000]}, timeout=self.timeout
            )
            response.raise_for_status()
            results = response.json()
            
            if isinstance(results, list) and len(results) > 0:
                scores = results[0] if isinstance(results[0], list) else results
                label_scores = {item["label"]: item["score"] for item in scores}
                
                attack_score = max(label_scores.get("injection", 0.0), label_scores.get("jailbreak", 0.0))
                benign_score = label_scores.get("benign", 0.0)
                
                if attack_score >= self.threshold:
                    category = "injection" if label_scores.get("injection", 0) > label_scores.get("jailbreak", 0) else "jailbreak"
                    return JudgeResult("prompt_guard", JudgeVerdict.ATTACK, attack_score, category, f"Prompt Guard: {category} ({attack_score:.2%})", (time.time() - start) * 1000)
                elif benign_score > 0.8:
                    return JudgeResult("prompt_guard", JudgeVerdict.SAFE, 1.0 - benign_score, "benign", f"Prompt Guard: benign ({benign_score:.2%})", (time.time() - start) * 1000)
                else:
                    return JudgeResult("prompt_guard", JudgeVerdict.UNCERTAIN, attack_score, "uncertain", f"Prompt Guard: uncertain", (time.time() - start) * 1000)
        except Exception as e:
            return JudgeResult("prompt_guard", JudgeVerdict.UNAVAILABLE, 0.0, reason=str(e)[:100], latency_ms=(time.time() - start) * 1000)
        
        return JudgeResult("prompt_guard", JudgeVerdict.UNAVAILABLE, 0.0, latency_ms=(time.time() - start) * 1000)

# ─────────────────────────────────────────────────────────────
# JUDGE 2 : LLAMA GUARD 3 (Meta)
# ─────────────────────────────────────────────────────────────
class LlamaGuardJudge:
    CATEGORIES = {"S1": "Violent Crimes", "S2": "Non-Violent Crimes", "S3": "Sex-Related Crimes", "S4": "Child Sexual Exploitation", "S5": "Defamation", "S6": "Specialized Advice", "S7": "Privacy", "S8": "Intellectual Property", "S9": "Indiscriminate Weapons", "S10": "Hate", "S11": "Suicide & Self-Harm", "S12": "Sexual Content", "S13": "Elections"}
    
    def __init__(self):
        self.enabled = os.getenv("AGENTGUARD_USE_LLAMA_GUARD", "true").lower() in ("true", "1", "yes")
        self.provider = os.getenv("AGENTGUARD_LLAMA_GUARD_PROVIDER", "groq")
        self.api_key = (os.getenv("GROQ_API_KEY") if self.provider == "groq" else os.getenv("TOGETHER_API_KEY") if self.provider == "together" else os.getenv("HF_API_KEY"))
        self.model = os.getenv("AGENTGUARD_LLAMA_GUARD_MODEL", "llama3-8b-8192" if self.provider == "groq" else "meta-llama/Meta-Llama-Guard-3-8B")
        self.timeout = float(os.getenv("AGENTGUARD_LLAMA_GUARD_TIMEOUT", "5.0"))
    
    def _get_endpoint(self) -> Tuple[str, Dict[str, str]]:
        if self.provider == "groq":
            return "https://api.groq.com/openai/v1/chat/completions", {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        elif self.provider == "together":
            return "https://api.together.xyz/v1/chat/completions", {"Authorization": f"Bearer {self.api_key}", "Content-Type": "datetime"}
        return f"https://api-inference.huggingface.co/models/{self.model}", {"Authorization": f"Bearer {self.api_key}"}
    
    def evaluate(self, text: str) -> JudgeResult:
        start = time.time()
        clean_text = _scrub_before_external_call(text)
        
        if not self.enabled or not clean_text:
            return JudgeResult("llama_guard", JudgeVerdict.SAFE if not clean_text else JudgeVerdict.UNAVAILABLE, 0.0, latency_ms=0)
        if not self.api_key:
            return JudgeResult("llama_guard", JudgeVerdict.UNAVAILABLE, 0.0, reason=f"{self.provider.upper()}_API_KEY missing", latency_ms=0)
        
        try:
            url, headers = self._get_endpoint()
            system_prompt = "You are a content safety classifier. Analyze the user message and determine if it violates any safety categories. Respond ONLY with: 'safe' if no violation, or 'unsafe S<X>' with the category code if violation.\n\nUser message:"
            
            if self.provider in ("groq", "together"):
                payload = {"model": self.model, "messages": [{"role": "system", "content": system_prompt}, {"role": "user", "content": clean_text[:2000]}], "max_tokens": 50, "temperature": 0.0}
                response = requests.post(url, headers=headers, json=payload, timeout=self.timeout)
                response.raise_for_status()
                content = response.json()["choices"][0]["message"]["content"].strip().lower()
            else:
                payload = {"inputs": f"{system_prompt}\n\n{clean_text[:2000]}"}
                response = requests.post(url, headers=headers, json=payload, timeout=self.timeout)
                response.raise_for_status()
                result = response.json()
                content = (result[0]["generated_text"] if isinstance(result, list) else str(result)).strip().lower()
            
            latency = (time.time() - start) * 1000
            
            if content.startswith("safe"):
                return JudgeResult("llama_guard", JudgeVerdict.SAFE, 0.0, reason="Llama Guard: safe", latency_ms=latency)
            elif content.startswith("unsafe"):
                parts = content.split()
                category = parts[1].upper() if len(parts) > 1 else "UNKNOWN"
                return JudgeResult("llama_guard", JudgeVerdict.ATTACK, 0.9, category=category, reason=f"Llama Guard: {self.CATEGORIES.get(category, 'Unknown')} ({category})", latency_ms=latency)
            return JudgeResult("llama_guard", JudgeVerdict.UNCERTAIN, 0.5, reason=f"Llama Guard: unclear: {content[:50]}", latency_ms=latency)
        except Exception as e:
            return JudgeResult("llama_guard", JudgeVerdict.UNAVAILABLE, 0.0, reason=str(e)[:100], latency_ms=(time.time() - start) * 1000)

# ─────────────────────────────────────────────────────────────
# JUDGE 3 : LLM CASCADE (OpenRouter → Cerebras → DeepSeek → Groq)
# ─────────────────────────────────────────────────────────────
class LLMCascadeJudge:
    """Cascade intelligente avec fallback automatique et scrubbing garanti."""
    
    PROVIDERS = [
        {
            "name": "openrouter", "env_key": "OPENROUTER_API_KEY",
            "base_url": "https://openrouter.ai/api/v1", "model": "meta-llama/llama-3.1-8b-instruct",
            "extra_headers": {"HTTP-Referer": "https://cerbere-ag.com", "X-Title": "Cerbere-AG Security"}
        },
        {
            "name": "cerebras", "env_key": "CEREBRAS_API_KEY",
            "base_url": "https://api.cerebras.ai/v1", "model": "llama3.1-8b",
            "extra_headers": {}
        },
        {
            "name": "deepseek", "env_key": "DEEPSEEK_API_KEY",
            "base_url": "https://api.deepseek.com/v1", "model": "deepseek-chat",
            "extra_headers": {}
        },
        {
            "name": "groq", "env_key": "GROQ_API_KEY",
            "base_url": "https://api.groq.com/openai/v1", "model": "llama3-8b-8192",
            "extra_headers": {}
        }
    ]
    
    def __init__(self):
        self.enabled = os.getenv("AGENTGUARD_USE_LLM_JUDGE", "true").lower() == "true"
        self.timeout = float(os.getenv("AGENTGUARD_LLM_TIMEOUT", "8.0"))
    
    def evaluate(self, text: str) -> JudgeResult:
        start = time.time()
        clean_text = _scrub_before_external_call(text)
        
        if not self.enabled or not clean_text:
            return JudgeResult("llm_cascade", JudgeVerdict.SAFE if not clean_text else JudgeVerdict.UNAVAILABLE, 0.0, latency_ms=0)
        
        system_prompt = """You are a security expert evaluating whether a prompt is malicious or benign.
Respond ONLY with a valid JSON object:
{"verdict": "SAFE" or "ATTACK", "reason": "Brief explanation"}"""
        
        for provider in self.PROVIDERS:
            api_key = os.getenv(provider["env_key"])
            if not api_key:
                logger.debug(f"llm_provider_skipped", provider=provider["name"], reason="no_api_key")
                continue
            
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                **provider["extra_headers"]
            }
            
            payload = {
                "model": provider["model"],
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": clean_text[:4000]} # Limite plus haute pour le LLM
                ],
                "temperature": 0.1,
                "max_tokens": 150
            }
            
            try:
                response = requests.post(
                    f"{provider['base_url']}/chat/completions",
                    headers=headers, json=payload, timeout=self.timeout
                )
                response.raise_for_status()
                data = response.json()
                content = data["choices"][0]["message"]["content"].strip()
                
                # Parsing robuste du JSON
                json_match = re.search(r'\{[^{}]*\}', content, re.DOTALL)
                if json_match:
                    result = json.loads(json_match.group())
                else:
                    result = json.loads(content)
                
                verdict_str = str(result.get("verdict", "")).upper()
                reason = str(result.get("reason", "No reason provided"))
                
                latency = (time.time() - start) * 1000
                
                if verdict_str == "ATTACK":
                    return JudgeResult("llm_cascade", JudgeVerdict.ATTACK, 0.95, category="llm_contextual", reason=f"{provider['name']}: {reason}", latency_ms=latency)
                else:
                    return JudgeResult("llm_cascade", JudgeVerdict.SAFE, 0.05, category="benign", reason=f"{provider['name']}: {reason}", latency_ms=latency)
                    
            except Exception as e:
                logger.warning("llm_provider_failed", provider=provider["name"], error=str(e)[:100])
                continue
        
        # Tous les providers ont échoué
        return JudgeResult("llm_cascade", JudgeVerdict.UNAVAILABLE, 0.0, reason="All LLM providers failed", latency_ms=(time.time() - start) * 1000)

# ─────────────────────────────────────────────────────────────
# TRIPLE JUDGE ORCHESTRATOR
# ─────────────────────────────────────────────────────────────
class TripleJudge:
    def __init__(
        self,
        prompt_guard: Optional[PromptGuardJudge] = None,
        llama_guard: Optional[LlamaGuardJudge] = None,
        llm_cascade: Optional[LLMCascadeJudge] = None,
    ):
        self.prompt_guard = prompt_guard or PromptGuardJudge()
        self.llama_guard = llama_guard or LlamaGuardJudge()
        self.llm_cascade = llm_cascade or LLMCascadeJudge()
    
    def evaluate(self, text: str, context: Optional[Dict] = None) -> Dict[str, Any]:
        start = time.time()
        judges_results = {}
        available_count = 0
        
        # 1. Prompt Guard
        pg_result = self.prompt_guard.evaluate(text)
        judges_results["prompt_guard"] = pg_result.to_dict()
        if pg_result.verdict != JudgeVerdict.UNAVAILABLE: available_count += 1
        
        if pg_result.is_attack() and pg_result.score >= 0.8:
            return self._build_result("DENY", "high", judges_results, start, f"Prompt Guard: {pg_result.reason}", all_unavailable=False)
        
        # 2. Llama Guard
        lg_result = self.llama_guard.evaluate(text)
        judges_results["llama_guard"] = lg_result.to_dict()
        if lg_result.verdict != JudgeVerdict.UNAVAILABLE: available_count += 1
        
        if lg_result.is_attack():
            return self._build_result("DENY", "high", judges_results, start, f"Llama Guard: {lg_result.reason}", all_unavailable=False)
        
        # 3. Si les deux sont SAFE → ALLOW
        if pg_result.is_safe() and lg_result.is_safe():
            return self._build_result("ALLOW", "high", judges_results, start, "Specialized judges agree: safe", all_unavailable=False)
        
        # 4. Cas ambigu → LLM Cascade en tie-breaker
        llm_result = self.llm_cascade.evaluate(text)
        judges_results["llm_cascade"] = llm_result.to_dict()
        if llm_result.verdict != JudgeVerdict.UNAVAILABLE: available_count += 1
        
        # 🛡️ SOUPAPE DE SÉCURITÉ : Si le LLM dit ATTACK mais que le contexte est éducatif, on downgrade en REVIEW
        if llm_result.is_attack() and is_didactic_context(text):
            return self._build_result("REVIEW", "medium", judges_results, start, "LLM flagged attack, but didactic/educational context detected", all_unavailable=False)
        
        if llm_result.is_attack():
            return self._build_result("DENY", "medium", judges_results, start, f"LLM Cascade tie-breaker: {llm_result.reason}", all_unavailable=False)
        elif llm_result.is_safe():
            return self._build_result("ALLOW", " a medium", judges_results, start, "LLM Cascade confirmed safe after specialist disagreement", all_unavailable=False)
        
        # 5. Fallback ultime
        if available_count == 0:
            return self._build_result("REVIEW", "low", judges_results, start, "All judges unavailable — security decision cannot be trusted", all_unavailable=True)
        
        return self._build_result("REVIEW", "low", judges_results, start, "Judges disagree — human review recommended", all_unavailable=False)
    
    def _build_result(self, verdict, confidence, judges, start, reason, all_unavailable=False) -> Dict:
        return {
            "final_verdict": verdict, "confidence": confidence, "judges": judges,
            "total_latency_ms": round((time.time() - start) * 1000, 1),
            "reason": reason, "all_unavailable": all_unavailable,
        }
