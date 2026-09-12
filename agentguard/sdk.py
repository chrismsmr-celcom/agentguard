import os
import time
import hashlib
import requests
import structlog
from functools import wraps
from typing import Optional, Dict, Any, List, Callable, Tuple

from .models import (
    SecurityCheck, RiskLevel, SecurityAction, SecurityException,
    GuardSpan, SpanPayload, RuntimeRiskDecision
)
from .policy import PolicyEngine
from .runtime import TrajectoryAnalyzer, RuntimeRiskEngine

logger = structlog.get_logger("agentguard.sdk")

class AgentGuard:
     def __init__(
        self,
        collector_url: str = "http://localhost:8080",
        api_key: Optional[str] = None,
        policies: Optional[List[Dict[str, Any]]] = None,
        max_budget: float = 10.0,
        block_on_high: bool = True,
        debug: bool = False,          # ← AJOUTE CETTE LIGNE
        use_ml: Optional[bool] = None,
        use_llm_judge: Optional[bool] = None,
        redis_url: Optional[str] = None,
        fail_open: bool = False,
        agent_id: Optional[str] = None,
    ):
        self.collector_url = collector_url.rstrip("/")
        self.debug = debug  
        self.api_key = api_key or os.getenv("AGENTGUARD_API_KEY")
        self.agent_id = agent_id or os.getenv("AGENTGUARD_AGENT_ID", "default")
        self.max_budget = max(0.0, float(max_budget))
        self.block_on_high = block_on_high
        self.total_spent = 0.0
        self.trace_id = hashlib.sha256(f"{time.time_ns()}:{id(self)}".encode()).hexdigest()[:16]
        self.spans: List[GuardSpan] = []
        self.collector_timeout = max(0.5, float(os.getenv("AGENTGUARD_COLLECTOR_TIMEOUT", "5.0")))

        self.policy_engine = PolicyEngine(policies or [], redis_url)
        self._verifier = None # À implémenter avec ton module de signing
        
        self._runtime_enabled = os.getenv("AGENTGUARD_RUNTIME_RISK_ENABLED", "true").lower() == "true"
        self._runtime_fail_closed = os.getenv("AGENTGUARD_RUNTIME_FAIL_CLOSED", "true").lower() == "true"
        self._trajectory = TrajectoryAnalyzer(max_events=100) if self._runtime_enabled else None
        self._runtime_risk = RuntimeRiskEngine(fail_closed=self._runtime_fail_closed) if self._runtime_enabled else None

        logger.info("agentguard_initialized", agent_id=self.agent_id, runtime_risk=self._runtime_enabled)

    def _headers(self):
        h = {"Content-Type": "application/json"}
        if self.api_key: h["X-API-Key"] = self.api_key
        return h

    def _send_to_collector(self, span: GuardSpan):
        try:
            payload = SpanPayload(
                trace_id=span.trace_id, span_id=span.span_id, span_type=span.span_type,
                timestamp=span.timestamp, latency_ms=span.latency_ms,
                input_data=span.input_data, output_data=span.output_data,
                security_checks=[c.to_model() for c in span.security_checks],
                blocked=span.blocked, block_reason=span.block_reason,
                cost_usd=span.cost_usd, input_tokens=span.input_tokens, output_tokens=span.output_tokens,
            ).model_dump()
            requests.post(f"{self.collector_url}/span", json=payload, headers=self._headers(), timeout=self.collector_timeout)
        except Exception as e:
            logger.warning("collector_send_failed", error=str(e))

    def _request_signed_decision(self, tool_name: str, params: Dict[str, Any]) -> Optional[Dict]:
        # Placeholder pour ta logique de signature Ed25519
        return None

    def _record_trajectory_tool(self, tool_name: str, decision: RuntimeRiskDecision):
        if self._trajectory:
            self._trajectory.record(self.agent_id, TrajectoryEvent(
                timestamp=time.time(), event_type="tool_call", tool_name=tool_name,
                risk_score=decision.risk_score, metadata=decision.metadata
            ))

    def guard_tool_call(self, tool_name: str, params: Optional[Dict[str, Any]] = None, func: Optional[Callable] = None):
        """Vérifie une tool call avant exécution. (BUG D'INDENTATION CORRIGÉ ICI)"""
        if params is None or func is None:
            raise TypeError("params et func doivent être fournis ensemble")

        span_id = hashlib.sha256(f"{time.time_ns()}".encode()).hexdigest()[:16]
        start = time.time()
        budget_remaining = self.max_budget - self.total_spent

        check = self.policy_engine.check_tool_policy(tool_name, params, budget_remaining)
        runtime_decision = self._runtime_risk.evaluate(tool_name, params) if self._runtime_enabled else RuntimeRiskDecision("ALLOW", 0.0, RiskLevel.LOW)
        
        runtime_check = SecurityCheck("runtime_risk", runtime_decision.allowed, runtime_decision.risk_level, "; ".join(runtime_decision.reasons[:5]))

        if not runtime_decision.allowed:
            span = GuardSpan(span_id, self.trace_id, "tool_call", start, (time.time()-start)*1000,
                {"tool": tool_name, "params": params}, {"blocked": True}, [check, runtime_check], True,
                f"[RUNTIME {runtime_decision.action}] {runtime_decision.reasons[0] if runtime_decision.reasons else 'blocked'}")
            self.spans.append(span)
            self._send_to_collector(span)
            self._record_trajectory_tool(tool_name, runtime_decision)
            raise SecurityException(f"🛡️ Runtime risk {runtime_decision.action}")

        # ✅ CORRECTION : Logique fail-closed proprement indentée à l'intérieur de la méthode
        signed_decision = None
        if self._verifier:
            signed_decision = self._request_signed_decision(tool_name, params or {})
            
            # Fail-closed : si le collector ne répond pas, on bloque par sécurité
            if signed_decision is None:
                span = GuardSpan(span_id, self.trace_id, "tool_call", start, (time.time()-start)*1000,
                    {"tool": tool_name, "params": params}, {"blocked": True, "reason": "signed_decision_unavailable"},
                    [check, runtime_check], True, "[SECURITY] Signed server decision unavailable")
                self.spans.append(span)
                self._send_to_collector(span)
                self._record_trajectory_tool(tool_name, RuntimeRiskDecision("DENY", 100.0, RiskLevel.CRITICAL, ["signed server decision unavailable"]))
                raise SecurityException("🛡️ AgentGuard DENY: server security decision unavailable")

            # Un DENY signé gagne toujours
            if signed_decision.get("action") == "DENY":
                raise SecurityException(f"🛡️ Signed DENY: {signed_decision.get('reason', 'policy violation')}")
            
            # REQUIRE_APPROVAL doit aussi empêcher l'exécution
            if signed_decision.get("action") == "REQUIRE_APPROVAL":
                raise SecurityException("🛡️ AgentGuard: human approval required")

        # Check local (fallback si pas de décision signée ou si elle est ALLOW)
        if not check.passed and check.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL) and self.block_on_high:
            raise SecurityException(f"🛡️ Tool blocked: {check.details}")

        # Exécution de la fonction
        try:
            result = func(**params)
        except Exception as exc:
            raise

        span = GuardSpan(span_id, self.trace_id, "tool_call", start, (time.time()-start)*1000,
            {"tool": tool_name, "params": params}, {"result": str(result)[:500]}, [check, runtime_check])
        self.spans.append(span)
        self._send_to_collector(span)
        self._record_trajectory_tool(tool_name, runtime_decision)
        return result

    def get_report(self) -> Dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "total_spans": len(self.spans),
            "blocked_operations": sum(1 for s in self.spans if s.blocked),
            "total_cost_usd": round(self.total_spent, 6),
            "runtime_risk_enabled": self._runtime_enabled,
        }
