import os
import time
import hashlib
import requests
import structlog
import tiktoken
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
        debug: bool = False,
        use_ml: Optional[bool] = None,
        use_llm_judge: Optional[bool] = None,
        redis_url: Optional[str] = None,
        fail_open: bool = False,
        agent_id: Optional[str] = None,
    ):
        self.collector_url = collector_url.rstrip("/")
        self.api_key = api_key or os.getenv("AGENTGUARD_API_KEY")
        self.agent_id = agent_id or os.getenv("AGENTGUARD_AGENT_ID", "default")
        self.max_budget = max(0.0, float(max_budget))
        self.block_on_high = block_on_high
        self.debug = debug
        self.total_spent = 0.0
        self.trace_id = hashlib.sha256(f"{time.time_ns()}:{id(self)}".encode()).hexdigest()[:16]
        self.spans: List[GuardSpan] = []
        self.collector_timeout = max(0.5, float(os.getenv("AGENTGUARD_COLLECTOR_TIMEOUT", "5.0")))

        self.policy_engine = PolicyEngine(policies or [], redis_url)
        self._verifier = None
        
        self._runtime_enabled = os.getenv("AGENTGUARD_RUNTIME_RISK_ENABLED", "true").lower() == "true"
        self._runtime_fail_closed = os.getenv("AGENTGUARD_RUNTIME_FAIL_CLOSED", "true").lower() == "true"
        self._trajectory = TrajectoryAnalyzer(max_events=100) if self._runtime_enabled else None
        self._runtime_risk = RuntimeRiskEngine(fail_closed=self._runtime_fail_closed) if self._runtime_enabled else None

        logger.info("agentguard_initialized", agent_id=self.agent_id, runtime_risk=self._runtime_enabled)

    def _headers(self):
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["X-API-Key"] = self.api_key
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
        if not self._verifier:
            return None
        try:
            r = requests.post(
                f"{self.collector_url}/api/decide",
                json={"tool_name": tool_name, "params": params or {}, "agent_id": self.agent_id},
                headers=self._headers(), timeout=self.collector_timeout,
            )
            if r.status_code == 200:
                return r.json()
        except Exception as e:
            logger.warning("signed_decision_request_failed", error=str(e))
        return None

    def _record_trajectory_tool(self, tool_name: str, decision: RuntimeRiskDecision):
        if self._trajectory:
            self._trajectory.record(self.agent_id, TrajectoryEvent(
                timestamp=time.time(), event_type="tool_call", tool_name=tool_name,
                risk_score=decision.risk_score, metadata=decision.metadata
            ))

    @staticmethod
    def _extract_input(args, kwargs):
        messages = kwargs.get("messages")
        if isinstance(messages, list):
            return "\n".join(m.get("content", "") for m in messages if isinstance(m, dict) and isinstance(m.get("content"), str))
        if args and isinstance(args[0], str):
            return args[0]
        return ""

    @staticmethod
    def _extract_output(result):
        if isinstance(result, str):
            return result
        choices = getattr(result, "choices", None)
        if choices:
            parts = []
            for choice in choices:
                msg = getattr(choice, "message", None)
                content = getattr(msg, "content", None) if msg else None
                if isinstance(content, str):
                    parts.append(content)
            return "\n".join(parts)
        return ""

    def _count_tokens(self, kwargs, result) -> Tuple[int, int]:
        model = str(kwargs.get("model", "gpt-4o"))
        input_text = self._extract_input([], kwargs) or ""
        output_text = self._extract_output(result) or ""
        try:
            encoding = tiktoken.encoding_for_model(model)
        except KeyError:
            encoding = tiktoken.get_encoding("cl100k_base")
        try:
            input_tokens = len(encoding.encode(input_text))
        except Exception:
            input_tokens = 0
        try:
            output_tokens = len(encoding.encode(output_text))
        except Exception:
            output_tokens = 0
        return input_tokens, output_tokens

    def _estimate_cost(self, kwargs, result) -> Tuple[float, int, int]:
        model = str(kwargs.get("model", "gpt-4o"))
        input_tokens, output_tokens = self._count_tokens(kwargs, result)
        pricing = {
            "gpt-4o": (2.5e-6, 1.0e-5), "gpt-4o-mini": (1.5e-7, 6.0e-7),
            "gpt-3.5-turbo": (5.0e-7, 1.5e-6), "deepseek-chat": (1.4e-7, 2.8e-7),
        }
        in_p, out_p = pricing.get(model, (2.5e-6, 1.0e-5))
        cost = max(0.0, input_tokens * in_p + output_tokens * out_p)
        return cost, input_tokens, output_tokens

    def guard_llm_call(self, func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            span_id = hashlib.sha256(f"{time.time_ns()}".encode()).hexdigest()[:16]
            start = time.time()
            input_text = self._extract_input(args, kwargs)

            checks = [
                self.policy_engine.check_injection(input_text),
                self.policy_engine.check_pii(input_text),
            ]
            high_risk = [c for c in checks if not c.passed and c.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)]

            if high_risk and self.block_on_high:
                span = GuardSpan(span_id, self.trace_id, "llm_call", start, (time.time()-start)*1000,
                    {"prompt": input_text[:500], "model": kwargs.get("model", "unknown")},
                    {"blocked": True}, checks, True, f"HIGH RISK: {[c.check_name for c in high_risk]}")
                self.spans.append(span)
                self._send_to_collector(span)
                raise SecurityException(f"🛡️ AgentGuard BLOCKED: {span.block_reason}")

            try:
                result = func(*args, **kwargs)
            except Exception as exc:
                span = GuardSpan(span_id, self.trace_id, "llm_call", start, (time.time()-start)*1000,
                    {"prompt": input_text[:500]}, {"error": str(exc)[:1000]}, checks)
                self.spans.append(span)
                self._send_to_collector(span)
                raise

            latency = (time.time() - start) * 1000
            cost, input_tokens, output_tokens = self._estimate_cost(kwargs, result)
            self.total_spent += cost

            output_pii = self.policy_engine.check_pii(self._extract_output(result))
            budget_check = self.policy_engine.check_budget(cost, self.max_budget, self.total_spent - cost)
            checks.extend([output_pii, budget_check])

            blocking_output = [c for c in checks if not c.passed and c.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)]
            blocked = bool(blocking_output) and self.block_on_high

            span = GuardSpan(span_id, self.trace_id, "llm_call", start, latency,
                {"prompt": input_text[:500], "model": kwargs.get("model", "unknown")},
                {"response": self._extract_output(result)[:500]}, checks, blocked,
                f"Output risk: {[c.check_name for c in blocking_output]}" if blocked else None,
                cost_usd=cost, input_tokens=input_tokens, output_tokens=output_tokens)
            self.spans.append(span)
            self._send_to_collector(span)

            if blocked:
                raise SecurityException(f"🛡️ Output blocked: {span.block_reason}")
            return result
        return wrapper

    def guard_tool_call(self, tool_name: str, params: Optional[Dict[str, Any]] = None, func: Optional[Callable] = None):
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

        # ✅ CORRECTION : Logique fail-closed proprement indentée
        signed_decision = None
        if self._verifier:
            signed_decision = self._request_signed_decision(tool_name, params or {})
            
            if signed_decision is None:
                span = GuardSpan(span_id, self.trace_id, "tool_call", start, (time.time()-start)*1000,
                    {"tool": tool_name, "params": params}, {"blocked": True, "reason": "signed_decision_unavailable"},
                    [check, runtime_check], True, "[SECURITY] Signed server decision unavailable")
                self.spans.append(span)
                self._send_to_collector(span)
                self._record_trajectory_tool(tool_name, RuntimeRiskDecision("DENY", 100.0, RiskLevel.CRITICAL, ["signed server decision unavailable"]))
                raise SecurityException("🛡️ AgentGuard DENY: server security decision unavailable")

            if signed_decision.get("action") == "DENY":
                raise SecurityException(f"🛡️ Signed DENY: {signed_decision.get('reason', 'policy violation')}")
            
            if signed_decision.get("action") == "REQUIRE_APPROVAL":
                raise SecurityException("🛡️ AgentGuard: human approval required")

        if not check.passed and check.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL) and self.block_on_high:
            raise SecurityException(f"🛡️ Tool blocked: {check.details}")

        try:
            result = func(**params)
        except Exception as exc:
            span = GuardSpan(span_id, self.trace_id, "tool_call", start, (time.time()-start)*1000,
                {"tool": tool_name, "params": params}, {"error": str(exc)[:1000]}, [check, runtime_check])
            self.spans.append(span)
            self._send_to_collector(span)
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
