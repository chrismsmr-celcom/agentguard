"""
AgentGuard Triple Judge System
Trois juges spécialisés pour éliminer les hallucinations de modération.

Architecture :
  1. Prompt Guard (Meta)  — injection detection, ultra-rapide
  2. Llama Guard 3 (Meta) — content safety, taxonomie OWASP
  3. DeepSeek             — analyse contextuelle (cas ambigus)

Vote logic :
  - ANY judge says ATTACK → DENY (defense in depth)
  - ALL judges safe → ALLOW
  - Disagreement → REVIEW (human escalation)
"""
import os
import time
import json
import hashlib
from dataclasses import dataclass
from typing import Optional, Dict, Any, Tuple
from enum import Enum

import requests


class JudgeVerdict(Enum):
    SAFE = "safe"
    ATTACK = "attack"
    UNCERTAIN = "uncertain"
    UNAVAILABLE = "unavailable"


@dataclass
class JudgeResult:
    """Résultat d'un juge individuel."""
    judge_name: str
    verdict: JudgeVerdict
    score: float  # 0.0 (safe) → 1.0 (attack)
    category: str = ""  # ex: "prompt_injection", "violence", "hate"
    reason: str = ""
    latency_ms: float = 0.0
    cached: bool = False
    
    def is_attack(self) -> bool:
        return self.verdict == JudgeVerdict.ATTACK
    
    def is_safe(self) -> bool:
        return self.verdict == JudgeVerdict.SAFE
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "judge": self.judge_name,
            "verdict": self.verdict.value,
            "score": round(self.score, 3),
            "category": self.category,
            "reason": self.reason[:200],
            "latency_ms": round(self.latency_ms, 1),
            "cached": self.cached,
        }


# ─────────────────────────────────────────────────────────────
# JUDGE 1 : PROMPT GUARD (Meta) — Injection specialist
# ─────────────────────────────────────────────────────────────
class PromptGuardJudge:
    """
    Prompt Guard de Meta : modèle léger spécialisé injection.
    
    Utilise l'API HuggingFace ou un endpoint local.
    Très rapide (~10-50ms), idéal comme premier filtre.
    """
    
    DEFAULT_ENDPOINT = "https://api-inference.huggingface.co/models/meta-llama/Prompt-Guard-86M"
    
    def __init__(self):
        self.enabled = os.getenv("AGENTGUARD_USE_PROMPT_GUARD", "true").lower() in ("true", "1", "yes")
        self.api_key = os.getenv("HF_API_KEY") or os.getenv("HUGGINGFACE_API_KEY")
        self.endpoint = os.getenv("AGENTGUARD_PROMPT_GUARD_URL", self.DEFAULT_ENDPOINT)
        self.threshold = float(os.getenv("AGENTGUARD_PROMPT_GUARD_THRESHOLD", "0.5"))
        self.timeout = float(os.getenv("AGENTGUARD_PROMPT_GUARD_TIMEOUT", "3.0"))
        
        # Cache Redis optionnel
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
        text = (text or "").strip()
        
        if not self.enabled:
            return JudgeResult("prompt_guard", JudgeVerdict.UNAVAILABLE, 0.0, latency_ms=0)
        
        if not text:
            return JudgeResult("prompt_guard", JudgeVerdict.SAFE, 0.0, latency_ms=0)
        
        # Cache check
        cache_key = f"ag:pg:{hashlib.sha256(text[:1000].encode()).hexdigest()}"
        if self._redis:
            try:
                cached = self._redis.get(cache_key)
                if cached:
                    data = json.loads(cached)
                    result = JudgeResult(
                        "prompt_guard",
                        JudgeVerdict(data["verdict"]),
                        data["score"],
                        data.get("category", ""),
                        data.get("reason", ""),
                        latency_ms=0,
                        cached=True,
                    )
                    return result
            except Exception:
                pass
        
        if not self.api_key:
            return JudgeResult("prompt_guard", JudgeVerdict.UNAVAILABLE, 0.0,
                             reason="HF_API_KEY missing", latency_ms=0)
        
        try:
            # Prompt Guard retourne 3 classes : benign, injection, jailbreak
            response = requests.post(
                self.endpoint,
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={"inputs": text[:2000]},
                timeout=self.timeout,
            )
            response.raise_for_status()
            
            # Format : [[{"label": "benign", "score": 0.99}, ...]]
            results = response.json()
            if isinstance(results, list) and len(results) > 0:
                scores = results[0] if isinstance(results[0], list) else results
                label_scores = {item["label"]: item["score"] for item in scores}
                
                injection_score = label_scores.get("injection", 0.0)
                jailbreak_score = label_scores.get("jailbreak", 0.0)
                benign_score = label_scores.get("benign", 0.0)
                
                attack_score = max(injection_score, jailbreak_score)
                
                if attack_score >= self.threshold:
                    category = "injection" if injection_score > jailbreak_score else "jailbreak"
                    verdict = JudgeVerdict.ATTACK
                    reason = f"Prompt Guard: {category} ({attack_score:.2%})"
                elif benign_score > 0.8:
                    verdict = JudgeVerdict.SAFE
                    reason = f"Prompt Guard: benign ({benign_score:.2%})"
                    attack_score = 1.0 - benign_score
                else:
                    verdict = JudgeVerdict.UNCERTAIN
                    reason = f"Prompt Guard: uncertain (benign={benign_score:.2%})"
                
                latency = (time.time() - start) * 1000
                result = JudgeResult("prompt_guard", verdict, attack_score, category, reason, latency)
                
                # Cache pour 1h
                if self._redis:
                    try:
                        self._redis.setex(cache_key, 3600, json.dumps({
                            "verdict": verdict.value, "score": attack_score,
                            "category": category, "reason": reason,
                        }))
                    except Exception:
                        pass
                
                return result
        
        except Exception as e:
            latency = (time.time() - start) * 1000
            return JudgeResult("prompt_guard", JudgeVerdict.UNAVAILABLE, 0.0,
                             reason=str(e)[:100], latency_ms=latency)
        
        latency = (time.time() - start) * 1000
        return JudgeResult("prompt_guard", JudgeVerdict.UNAVAILABLE, 0.0, latency_ms=latency)


# ─────────────────────────────────────────────────────────────
# JUDGE 2 : LLAMA GUARD 3 (Meta) — Content safety
# ─────────────────────────────────────────────────────────────
class LlamaGuardJudge:
    """
    Llama Guard 3 de Meta : modération content safety.
    
    Taxonomie standard (OWASP-style) :
      S1: Violent Crimes, S2: Non-Violent Crimes, S3: Sex Crimes,
      S4: Child Exploitation, S5: Defamation, S6: Specialized Advice,
      S7: Privacy, S8: Intellectual Property, S9: Indiscriminate Weapons,
      S10: Hate, S11: Suicide & Self-Harm, S12: Sexual Content,
      S13: Elections
    
    Peut utiliser :
      - Groq (ultra-rapide, free tier généreux)
      - Together AI
      - HuggingFace Inference API
    """
    
    # Catégories Llama Guard 3
    CATEGORIES = {
        "S1": "Violent Crimes",
        "S2": "Non-Violent Crimes",
        "S3": "Sex-Related Crimes",
        "S4": "Child Sexual Exploitation",
        "S5": "Defamation",
        "S6": "Specialized Advice",
        "S7": "Privacy",
        "S8": "Intellectual Property",
        "S9": "Indiscriminate Weapons",
        "S10": "Hate",
        "S11": "Suicide & Self-Harm",
        "S12": "Sexual Content",
        "S13": "Elections",
    }
    
    def __init__(self):
        self.enabled = os.getenv("AGENTGUARD_USE_LLAMA_GUARD", "true").lower() in ("true", "1", "yes")
        self.provider = os.getenv("AGENTGUARD_LLAMA_GUARD_PROVIDER", "groq")  # groq, together, hf
        self.api_key = (
            os.getenv("GROQ_API_KEY") if self.provider == "groq"
            else os.getenv("TOGETHER_API_KEY") if self.provider == "together"
            else os.getenv("HF_API_KEY")
        )
        self.model = os.getenv(
            "AGENTGUARD_LLAMA_GUARD_MODEL",
            "meta-llama/llama-guard-3-8b" if self.provider == "groq"
            else "meta-llama/Meta-Llama-Guard-3-8B"
        )
        self.threshold = float(os.getenv("AGENTGUARD_LLAMA_GUARD_THRESHOLD", "0.7"))
        self.timeout = float(os.getenv("AGENTGUARD_LLAMA_GUARD_TIMEOUT", "5.0"))
    
    def _get_endpoint(self) -> Tuple[str, Dict[str, str]]:
        """Retourne (url, headers) selon le provider."""
        if self.provider == "groq":
            return (
                "https://api.groq.com/openai/v1/chat/completions",
                {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
            )
        elif self.provider == "together":
            return (
                "https://api.together.xyz/v1/chat/completions",
                {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
            )
        else:  # hf
            return (
                f"https://api-inference.huggingface.co/models/{self.model}",
                {"Authorization": f"Bearer {self.api_key}"},
            )
    
    def evaluate(self, text: str) -> JudgeResult:
        start = time.time()
        text = (text or "").strip()
        
        if not self.enabled:
            return JudgeResult("llama_guard", JudgeVerdict.UNAVAILABLE, 0.0, latency_ms=0)
        
        if not text:
            return JudgeResult("llama_guard", JudgeVerdict.SAFE, 0.0, latency_ms=0)
        
        if not self.api_key:
            return JudgeResult("llama_guard", JudgeVerdict.UNAVAILABLE, 0.0,
                             reason=f"{self.provider.upper()}_API_KEY missing", latency_ms=0)
        
        try:
            url, headers = self._get_endpoint()
            
            # Prompt Llama Guard standard
            system_prompt = """You are a content safety classifier. Analyze the user message and determine if it violates any of these categories:

S1: Violent Crimes
S2: Non-Violent Crimes  
S3: Sex-Related Crimes
S4: Child Sexual Exploitation
S5: Defamation
S6: Specialized Advice (medical/legal without disclaimer)
S7: Privacy (PII, doxxing)
S8: Intellectual Property
S9: Indiscriminate Weapons
S10: Hate speech
S11: Suicide & Self-Harm
S12: Sexual Content
S13: Elections interference

Respond ONLY with:
- "safe" if no violation
- "unsafe S<X>" with the category code if violation

User message to analyze:"""
            
            if self.provider in ("groq", "together"):
                payload = {
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": text[:2000]},
                    ],
                    "max_tokens": 50,
                    "temperature": 0.0,
                }
                response = requests.post(url, headers=headers, json=payload, timeout=self.timeout)
                response.raise_for_status()
                content = response.json()["choices"][0]["message"]["content"].strip()
            else:
                # HF inference
                payload = {"inputs": f"{system_prompt}\n\n{text[:2000]}"}
                response = requests.post(url, headers=headers, json=payload, timeout=self.timeout)
                response.raise_for_status()
                result = response.json()
                content = result[0]["generated_text"] if isinstance(result, list) else str(result)
            
            content = content.lower().strip()
            latency = (time.time() - start) * 1000
            
            # Parse résultat
            if content.startswith("safe") or content == "safe":
                return JudgeResult("llama_guard", JudgeVerdict.SAFE, 0.0,
                                 reason="Llama Guard: safe", latency_ms=latency)
            elif content.startswith("unsafe"):
                # Extraire catégorie : "unsafe S10" → S10
                parts = content.split()
                category = parts[1].upper() if len(parts) > 1 else "UNKNOWN"
                category_name = self.CATEGORIES.get(category, "Unknown")
                return JudgeResult(
                    "llama_guard", JudgeVerdict.ATTACK, 0.9,
                    category=category,
                    reason=f"Llama Guard: {category_name} ({category})",
                    latency_ms=latency,
                )
            else:
                return JudgeResult("llama_guard", JudgeVerdict.UNCERTAIN, 0.5,
                                 reason=f"Llama Guard: unclear response: {content[:50]}",
                                 latency_ms=latency)
        
        except Exception as e:
            latency = (time.time() - start) * 1000
            return JudgeResult("llama_guard", JudgeVerdict.UNAVAILABLE, 0.0,
                             reason=str(e)[:100], latency_ms=latency)


# ─────────────────────────────────────────────────────────────
# TRIPLE JUDGE ORCHESTRATOR
# ─────────────────────────────────────────────────────────────
class TripleJudge:
    """
    Orchestre les 3 juges avec logique de vote.
    
    Règles :
      - Prompt Guard d'abord (rapide, gratuit)
      - Si ATTACK immédiat → on arrête là
      - Sinon Llama Guard (modération)
      - Si ATTACK → on arrête là  
      - Si désaccord ou UNCERTAIN → DeepSeek en tie-breaker
      - UNANIME safe → ALLOW
      - ANY attack → DENY
      - Disagreement → REVIEW
    """
    
    def __init__(
        self,
        prompt_guard: Optional[PromptGuardJudge] = None,
        llama_guard: Optional[LlamaGuardJudge] = None,
        deepseek_fn=None,
    ):
        self.prompt_guard = prompt_guard or PromptGuardJudge()
        self.llama_guard = llama_guard or LlamaGuardJudge()
        self._deepseek_fn = deepseek_fn  # fonction callback pour DeepSeek existant
    
    def evaluate(self, text: str, context: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Évalue un texte avec les 3 juges.
        
        Retourne :
        {
            "final_verdict": "ALLOW"|"DENY"|"REVIEW",
            "confidence": "high"|"medium"|"low",
            "judges": {...},
            "total_latency_ms": float,
            "reason": str,
        }
        """
        start = time.time()
        judges_results = {}
        
        # Judge 1 : Prompt Guard (rapide)
        pg_result = self.prompt_guard.evaluate(text)
        judges_results["prompt_guard"] = pg_result.to_dict()
        
        # Si ATTACK clair → early return
        if pg_result.is_attack() and pg_result.score >= 0.8:
            return self._build_result(
                "DENY", "high", judges_results, start,
                f"Prompt Guard: {pg_result.reason}",
            )
        
        # Judge 2 : Llama Guard (modération)
        lg_result = self.llama_guard.evaluate(text)
        judges_results["llama_guard"] = lg_result.to_dict()
        
        # Si ATTACK clair → early return
        if lg_result.is_attack():
            return self._build_result(
                "DENY", "high", judges_results, start,
                f"Llama Guard: {lg_result.reason}",
            )
        
        # Si les deux sont SAFE → ALLOW (rapide, pas besoin de DeepSeek)
        if pg_result.is_safe() and lg_result.is_safe():
            return self._build_result(
                "ALLOW", "high", judges_results, start,
                "All specialized judges agree: safe",
            )
        
        # Sinon : cas ambigu → DeepSeek en tie-breaker
        if self._deepseek_fn:
            try:
                ds_result = self._deepseek_fn(text)
                judges_results["deepseek"] = ds_result.to_dict() if hasattr(ds_result, "to_dict") else ds_result
                
                if isinstance(ds_result, JudgeResult):
                    if ds_result.is_attack():
                        return self._build_result(
                            "DENY", "medium", judges_results, start,
                            f"DeepSeek tie-breaker: {ds_result.reason}",
                        )
                    elif ds_result.is_safe():
                        return self._build_result(
                            "ALLOW", "medium", judges_results, start,
                            "DeepSeek confirmed safe after judge disagreement",
                        )
            except Exception as e:
                judges_results["deepseek"] = {
                    "judge": "deepseek", "verdict": "unavailable",
                    "reason": str(e)[:100],
                }
        
        # Désaccord persistant → REVIEW
        return self._build_result(
            "REVIEW", "low", judges_results, start,
            "Judges disagree — human review recommended",
        )
    
    def _build_result(self, verdict, confidence, judges, start, reason) -> Dict:
        return {
            "final_verdict": verdict,
            "confidence": confidence,
            "judges": judges,
            "total_latency_ms": round((time.time() - start) * 1000, 1),
            "reason": reason,
        }
    
    def get_status(self) -> Dict[str, Any]:
        """Statut des juges."""
        return {
            "prompt_guard": {
                "enabled": self.prompt_guard.enabled,
                "has_api_key": bool(self.prompt_guard.api_key),
            },
            "llama_guard": {
                "enabled": self.llama_guard.enabled,
                "provider": self.llama_guard.provider,
                "has_api_key": bool(self.llama_guard.api_key),
            },
            "deepseek": {
                "enabled": self._deepseek_fn is not None,
            },
        }
