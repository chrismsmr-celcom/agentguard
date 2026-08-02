"""
AgentGuard SDK — Observabilité + Sécurité intégrée
Intercepte les appels LLM, scanne les inputs/outputs, applique les policies.
"""

import os
import json
import hashlib
import time
import re
import requests
from typing import Optional, Dict, Any, List, Callable
from dataclasses import dataclass, field
from enum import Enum

class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class SecurityCheck:
    check_name: str
    passed: bool
    risk_level: RiskLevel
    details: str
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class GuardSpan:
    span_id: str
    trace_id: str
    span_type: str
    timestamp: float
    latency_ms: float
    input_data: Dict[str, Any]
    output_data: Dict[str, Any]
    security_checks: List[SecurityCheck] = field(default_factory=list)
    blocked: bool = False
    block_reason: Optional[str] = None
    cost_usd: float = 0.0

class PolicyEngine:
    """DSL minimal pour définir des règles de sécurité."""

    def __init__(self, policies: List[Dict[str, Any]]):
        self.policies = policies
        self._compile_patterns()

    def _compile_patterns(self):
        # Patterns FORTS : indicateurs de contournement sans ambiguïté raisonnable
        # (peu de contextes légitimes les utilisent tels quels). Bloquants seuls.
        self.strong_patterns = [
            r"ignore (all )?(previous|prior|above) (instructions|rules|prompts)",
            r"disregard (your|the|all) (instructions|rules|training)",
            r"you are now (in |entering )?(DAN|developer) mode",
            r"jailbreak(ing)?",
            r"system override",
            r"new instructions?\s*:",
            r"\[system\]", r"\[admin\]", r"\[override\]",
            r"reveal (your |the )?system prompt",
            r"repeat\b.{0,25}\babove\b",
            r"(with|that has|and) no (restrictions|limits|filters)",
            r"do anything now",
            # Équivalents FR — la version originale ne couvrait que l'anglais
            r"ignore (tes|vos|les) instructions (précédentes|pr[ée]c[ée]dentes)",
            r"oublie (tes|vos) instructions",
            r"tu es maintenant en mode (développeur|admin|dan)",
            r"nouvelles? instructions?\s*:",
            r"r[ée]v[èe]le (ton|le) (prompt|invite) syst[èe]me",
            r"ignore (ce )?qui pr[ée]c[èe]de",
        ]
        # Patterns FAIBLES : apparaissent aussi dans des demandes créatives
        # légitimes (écriture, jeu de rôle demandé sciemment). Seuls, ils ne
        # doivent PAS bloquer — juste déclencher une vérification sémantique
        # (llm_judge) si disponible, sinon rester en MEDIUM non-bloquant.
        self.weak_patterns = [
            r"pretend you are",
            r"roleplay as",
            r"act as if you (are|were)",
            r"comme si tu (es|étais)",
            r"joue le r[ôo]le de",
        ]
        self.strong_regex = re.compile(
            r"(" + "|".join(self.strong_patterns) + r")", re.IGNORECASE
        )
        self.weak_regex = re.compile(
            r"(" + "|".join(self.weak_patterns) + r")", re.IGNORECASE
        )

    def check_injection(self, text: str) -> SecurityCheck:
        strong_matches = self.strong_regex.findall(text)
        if strong_matches:
            return SecurityCheck(
                check_name="prompt_injection",
                passed=False,
                risk_level=RiskLevel.HIGH,
                details=f"Strong injection pattern(s): {strong_matches[:3]}",
                metadata={"patterns_found": strong_matches[:5], "confidence": "high"}
            )

        weak_matches = self.weak_regex.findall(text)
        if weak_matches:
            return SecurityCheck(
                check_name="prompt_injection",
                passed=False,
                risk_level=RiskLevel.MEDIUM,
                details=f"Ambiguous pattern(s), needs semantic review: {weak_matches[:3]}",
                metadata={"patterns_found": weak_matches[:5], "confidence": "ambiguous"}
            )

        return SecurityCheck(
            check_name="prompt_injection",
            passed=True,
            risk_level=RiskLevel.LOW,
            details="No injection patterns detected"
        )

    def check_pii(self, text: str) -> SecurityCheck:
        pii_patterns = {
            "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
            "credit_card": r"\b(?:\d{4}[- ]?){3}\d{4}\b",
            "phone": r"\b\+?\d{1,4}?[-.\s]?\(?\d{1,3}?\)?[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}\b",
            "api_key": r"\b(sk-|pk-|Bearer\s)[A-Za-z0-9_-]{20,}\b",
        }
        findings = {}
        for name, pattern in pii_patterns.items():
            matches = re.findall(pattern, text)
            if matches:
                findings[name] = len(matches)

        if findings:
            return SecurityCheck(
                check_name="pii_detection",
                passed=False,
                risk_level=RiskLevel.MEDIUM,
                details=f"PII detected: {findings}",
                metadata={"pii_types": findings}
            )
        return SecurityCheck(
            check_name="pii_detection",
            passed=True,
            risk_level=RiskLevel.LOW,
            details="No PII detected"
        )

    def check_tool_policy(self, tool_name: str, params: Dict[str, Any], 
                          budget_remaining: float) -> SecurityCheck:
        allowed_tools = [p.get("allowed_tools", []) for p in self.policies 
                        if p["type"] == "tool_whitelist"]
        allowed_tools = [t for sublist in allowed_tools for t in sublist]

        if allowed_tools and tool_name not in allowed_tools:
            return SecurityCheck(
                check_name="tool_policy",
                passed=False,
                risk_level=RiskLevel.CRITICAL,
                details=f"Tool '{tool_name}' not in whitelist",
                metadata={"tool": tool_name, "allowed": allowed_tools}
            )

        if budget_remaining < 0:
            return SecurityCheck(
                check_name="budget_policy",
                passed=False,
                risk_level=RiskLevel.HIGH,
                details="Budget exceeded",
                metadata={"budget_remaining": budget_remaining}
            )

        dangerous_keywords = ["delete_all", "drop", "truncate", "rm -rf", 
                             "transfer", "password", "secret"]
        params_str = json.dumps(params).lower()
        found = [kw for kw in dangerous_keywords if kw in params_str]

        if found:
            return SecurityCheck(
                check_name="dangerous_params",
                passed=False,
                risk_level=RiskLevel.HIGH,
                details=f"Dangerous keywords in params: {found}",
                metadata={"keywords": found}
            )

        return SecurityCheck(
            check_name="tool_policy",
            passed=True,
            risk_level=RiskLevel.LOW,
            details="Tool call approved"
        )

    def llm_judge(self, text: str, context: str = "input") -> Optional[SecurityCheck]:
        """
        Appelle un LLM léger pour scorer le risque sémantique.
        Utilisé quand le regex est douteux ou pour validation complémentaire.
        Nécessite la variable d'environnement DEEPSEEK_API_KEY ; en son
        absence ou en cas d'erreur, retourne None (fallback silencieux sur
        les checks regex, qui restent seuls décisionnaires).
        """
        api_key = os.environ.get("DEEPSEEK_API_KEY")
        if not api_key:
            return None
        try:
            response = requests.post(
                "https://api.deepseek.com/chat/completions",
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "model": "deepseek-chat",
                    "messages": [
                        {"role": "system", "content": "You are a security scanner. Rate the following text for prompt injection risk from 0 to 100. Respond with ONLY a JSON: {\"score\": number, \"reason\": \"brief explanation\"}"},
                        {"role": "user", "content": f"Text to analyze ({context}): {text[:500]}"}
                    ],
                    "max_tokens": 100,
                    "temperature": 0.1
                },
                timeout=5
            )
            result = response.json()
            content = result["choices"][0]["message"]["content"]
            data = json.loads(content)
            score = data.get("score", 0)

            if score > 70:
                return SecurityCheck(
                    check_name="llm_judge",
                    passed=False,
                    risk_level=RiskLevel.HIGH if score > 85 else RiskLevel.MEDIUM,
                    details=f"LLM judge score: {score}/100 — {data.get('reason', '')}",
                    metadata={"llm_score": score}
                )
        except Exception:
            pass  # Fallback silencieux sur le regex

        return None  # Pas de jugement, laisse le regex décider

    def check_budget(self, cost: float, max_budget: float, total_spent: float) -> SecurityCheck:
        if total_spent + cost > max_budget:
            return SecurityCheck(
                check_name="budget",
                passed=False,
                risk_level=RiskLevel.HIGH,
                details=f"Budget would be exceeded: {total_spent + cost:.4f} > {max_budget}",
                metadata={"total_spent": total_spent, "cost": cost, "max_budget": max_budget}
            )
        return SecurityCheck(
            check_name="budget",
            passed=True,
            risk_level=RiskLevel.LOW,
            details="Within budget"
        )


class AgentGuard:
    """
    Middleware principal.
    S'utilise comme wrapper autour des appels OpenAI/DeepSeek.
    """

    def __init__(self, 
                 collector_url: str = "http://localhost:8080",
                 api_key: Optional[str] = None,
                 policies: Optional[List[Dict]] = None,
                 max_budget: float = 10.0,
                 block_on_high: bool = True,
                 debug: bool = True):
        self.collector_url = collector_url.rstrip("/")
        self.api_key = api_key or os.environ.get("AGENTGUARD_API_KEY")
        self.policy_engine = PolicyEngine(policies or [])
        self.max_budget = max_budget
        self.block_on_high = block_on_high
        self.debug = debug
        self.total_spent = 0.0
        self.trace_id = self._generate_id()
        self.spans: List[GuardSpan] = []
        self._pending_spans: List[Dict] = []  # Buffer local si le collector est down

        if self.debug:
            print(f"[AgentGuard] Initialisé — collector: {self.collector_url}")
            self._test_connection()

    def _test_connection(self):
        """Vérifie que le collector est accessible."""
        try:
            headers = {"X-API-Key": self.api_key} if self.api_key else {}
            r = requests.get(f"{self.collector_url}/api/metrics", headers=headers, timeout=10)
            if r.status_code == 200:
                print(f"[AgentGuard] ✅ Collector connecté ({r.status_code})")
            elif r.status_code == 401:
                print(f"[AgentGuard] ⚠️ Collector connecté mais clé API manquante/invalide (401) — "
                      f"passe api_key= à AgentGuard() ou fixe AGENTGUARD_API_KEY.")
            else:
                print(f"[AgentGuard] ⚠️ Collector répond mais code {r.status_code}")
        except Exception as e:
            print(f"[AgentGuard] ❌ Collector inaccessible: {e}")
            print(f"[AgentGuard]    URL: {self.collector_url}/api/metrics")
            print(f"[AgentGuard]    Les spans seront bufferisées en local.")

    def _generate_id(self) -> str:
        return hashlib.sha256(str(time.time()).encode()).hexdigest()[:16]

    def _send_to_collector(self, span: GuardSpan):
        """Envoie la span au collector avec retry et logging."""
        payload = {
            "trace_id": span.trace_id,
            "span_id": span.span_id,
            "span_type": span.span_type,
            "timestamp": span.timestamp,
            "latency_ms": span.latency_ms,
            "input_data": span.input_data,
            "output_data": span.output_data,
            "security_checks": [
                {
                    "check_name": c.check_name,
                    "passed": c.passed,
                    "risk_level": c.risk_level.value,
                    "details": c.details,
                    "metadata": c.metadata
                }
                for c in span.security_checks
            ],
            "blocked": span.blocked,
            "block_reason": span.block_reason,
            "cost_usd": span.cost_usd
        }

        # Essai d'envoi
        try:
            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["X-API-Key"] = self.api_key
            r = requests.post(
                f"{self.collector_url}/span",
                json=payload,
                timeout=10,  # Augmenté de 0.5s à 10s
                headers=headers
            )
            if r.status_code == 201:
                if self.debug:
                    print(f"[AgentGuard] 📤 Span envoyée ({span.span_type}, blocked={span.blocked})")
                # Si on avait des spans en attente, on les envoie aussi
                self._flush_pending()
            elif r.status_code == 401:
                if self.debug:
                    print(f"[AgentGuard] 🚨 Span rejetée (401 Unauthorized) — passe api_key= "
                          f"à AgentGuard() ou fixe AGENTGUARD_API_KEY côté agent.")
                self._pending_spans.append(payload)
            else:
                if self.debug:
                    print(f"[AgentGuard] ⚠️ Collector a rejeté la span: HTTP {r.status_code}")
                self._pending_spans.append(payload)
        except Exception as e:
            if self.debug:
                print(f"[AgentGuard] ⚠️ Échec envoi span: {e}")
            self._pending_spans.append(payload)

    def _flush_pending(self):
        """Réessaie d'envoyer les spans en attente."""
        if not self._pending_spans:
            return
        flushed = []
        for payload in self._pending_spans:
            try:
                headers = {"Content-Type": "application/json"}
                if self.api_key:
                    headers["X-API-Key"] = self.api_key
                r = requests.post(
                    f"{self.collector_url}/span",
                    json=payload,
                    timeout=10,
                    headers=headers
                )
                if r.status_code == 201:
                    flushed.append(payload)
            except Exception:
                break
        for p in flushed:
            self._pending_spans.remove(p)
        if flushed and self.debug:
            print(f"[AgentGuard] 🔄 {len(flushed)} spans en attente envoyées")

    def guard_llm_call(self, func: Callable) -> Callable:
        """Décorateur pour wrapper les appels LLM."""
        def wrapper(*args, **kwargs):
            span_id = self._generate_id()
            start = time.time()

            # --- PHASE 1 : SCAN INPUT ---
            input_text = ""
            if "messages" in kwargs:
                input_text = " ".join([
                    m.get("content", "") 
                    for m in kwargs["messages"] 
                    if isinstance(m.get("content"), str)
                ])
            elif args and isinstance(args[0], str):
                input_text = args[0]

            checks = []
            injection_check = self.policy_engine.check_injection(input_text)
            checks.append(injection_check)
            checks.append(self.policy_engine.check_pii(input_text))

            # Le regex seul est bruyant sur les tournures ambiguës (ex: une
            # vraie demande créative de jeu de rôle). On ne sollicite le LLM
            # judge (coût + latence) QUE dans ce cas précis — jamais sur les
            # patterns forts (déjà tranchés) ni sur les textes propres.
            if injection_check.metadata.get("confidence") == "ambiguous":
                judge_check = self.policy_engine.llm_judge(input_text, context="input")
                if judge_check:
                    checks.append(judge_check)

            # Vérifier si on doit bloquer
            high_risk = [c for c in checks if c.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)]
            if high_risk and self.block_on_high:
                latency = (time.time() - start) * 1000
                span = GuardSpan(
                    span_id=span_id,
                    trace_id=self.trace_id,
                    span_type="llm_call",
                    timestamp=start,
                    latency_ms=latency,
                    input_data={"prompt": input_text[:500]},
                    output_data={"blocked": True},
                    security_checks=checks,
                    blocked=True,
                    block_reason=f"HIGH RISK: {[c.check_name for c in high_risk]}"
                )
                self.spans.append(span)
                self._send_to_collector(span)
                raise SecurityException(
                    f"🛡️ AgentGuard BLOCKED: {span.block_reason}"
                )

            # --- PHASE 2 : EXÉCUTION ---
            try:
                result = func(*args, **kwargs)
                latency = (time.time() - start) * 1000

                # Estimer le coût (simplifié)
                cost = self._estimate_cost(kwargs, result)
                self.total_spent += cost

                # Scan output
                output_text = ""
                if hasattr(result, "choices"):
                    output_text = " ".join([
                        c.message.content or "" 
                        for c in result.choices
                    ])
                elif isinstance(result, str):
                    output_text = result

                checks.append(self.policy_engine.check_pii(output_text))
                checks.append(self.policy_engine.check_budget(
                    cost, self.max_budget, self.total_spent - cost
                ))

                # Vérifier output
                high_risk_output = [c for c in checks if not c.passed and c.risk_level == RiskLevel.HIGH]

                span = GuardSpan(
                    span_id=span_id,
                    trace_id=self.trace_id,
                    span_type="llm_call",
                    timestamp=start,
                    latency_ms=latency,
                    input_data={"prompt": input_text[:500]},
                    output_data={"response": output_text[:500]},
                    security_checks=checks,
                    blocked=bool(high_risk_output),
                    block_reason=f"Output risk: {[c.check_name for c in high_risk_output]}" if high_risk_output else None,
                    cost_usd=cost
                )
                self.spans.append(span)
                self._send_to_collector(span)

                if span.blocked:
                    raise SecurityException(f"🛡️ Output blocked: {span.block_reason}")

                return result

            except SecurityException:
                raise
            except Exception as e:
                latency = (time.time() - start) * 1000
                span = GuardSpan(
                    span_id=span_id,
                    trace_id=self.trace_id,
                    span_type="llm_call",
                    timestamp=start,
                    latency_ms=latency,
                    input_data={"prompt": input_text[:500]},
                    output_data={"error": str(e)},
                    security_checks=checks,
                    cost_usd=0.0
                )
                self.spans.append(span)
                self._send_to_collector(span)
                raise

        return wrapper

    def guard_tool_call(self, tool_name: str, params: Dict[str, Any], 
                        func: Callable) -> Any:
        """Wrapper pour les appels d'outils."""
        span_id = self._generate_id()
        start = time.time()

        budget_remaining = self.max_budget - self.total_spent
        check = self.policy_engine.check_tool_policy(tool_name, params, budget_remaining)

        if not check.passed and self.block_on_high:
            latency = (time.time() - start) * 1000
            span = GuardSpan(
                span_id=span_id,
                trace_id=self.trace_id,
                span_type="tool_call",
                timestamp=start,
                latency_ms=latency,
                input_data={"tool": tool_name, "params": params},
                output_data={"blocked": True},
                security_checks=[check],
                blocked=True,
                block_reason=check.details
            )
            self.spans.append(span)
            self._send_to_collector(span)
            raise SecurityException(f"🛡️ Tool blocked: {check.details}")

        result = func(**params)
        latency = (time.time() - start) * 1000

        span = GuardSpan(
            span_id=span_id,
            trace_id=self.trace_id,
            span_type="tool_call",
            timestamp=start,
            latency_ms=latency,
            input_data={"tool": tool_name, "params": params},
            output_data={"result": str(result)[:500]},
            security_checks=[check],
            cost_usd=0.0
        )
        self.spans.append(span)
        self._send_to_collector(span)
        return result

    def _estimate_cost(self, kwargs, result) -> float:
        """Estimation simplifiée du coût LLM."""
        model = kwargs.get("model", "gpt-4o")
        messages = kwargs.get("messages", [])
        input_tokens = sum(len(m.get("content", "").split()) * 1.3 for m in messages)

        output_tokens = 0
        if hasattr(result, "choices"):
            output_tokens = sum(
                len(c.message.content.split()) * 1.3 
                for c in result.choices if c.message.content
            )

        pricing = {
            "gpt-4o": (2.5e-6, 1.0e-5),
            "gpt-4o-mini": (1.5e-7, 6.0e-7),
            "gpt-3.5-turbo": (5.0e-7, 1.5e-6),
            "deepseek-chat": (1.4e-7, 2.8e-7),
            "deepseek-reasoner": (5.5e-7, 2.19e-6),
        }
        inp_p, out_p = pricing.get(model, (2.5e-6, 1.0e-5))
        return (input_tokens * inp_p) + (output_tokens * out_p)

    def get_report(self) -> Dict:
        """Génère un rapport de sécurité pour la session."""
        total_checks = sum(len(s.security_checks) for s in self.spans)
        failed_checks = sum(
            1 for s in self.spans for c in s.security_checks if not c.passed
        )
        blocked = sum(1 for s in self.spans if s.blocked)

        return {
            "trace_id": self.trace_id,
            "total_spans": len(self.spans),
            "total_checks": total_checks,
            "failed_checks": failed_checks,
            "blocked_operations": blocked,
            "total_cost_usd": round(self.total_spent, 6),
            "budget_remaining": round(self.max_budget - self.total_spent, 6),
            "pending_spans": len(self._pending_spans),
            "risk_summary": self._risk_summary()
        }

    def _risk_summary(self) -> Dict[str, int]:
        summary = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for span in self.spans:
            for check in span.security_checks:
                summary[check.risk_level.value] += 1
        return summary

class SecurityException(Exception):
    pass
