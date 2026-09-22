import os
import time
import hashlib
import requests
import structlog
import tiktoken
import logging
from functools import wraps
from typing import Optional, Dict, Any, List, Callable, Tuple

import json
from .models import SecurityCheck, RiskLevel, SecurityAction, SecurityException, ApprovalRequiredException, ApprovalRejectedException, AgentDisconnectedException, GuardSpan, SpanPayload, RuntimeRiskDecision, TrajectoryEvent
from .policy import PolicyEngine
from .runtime import TrajectoryAnalyzer, RuntimeRiskEngine

logger = structlog.get_logger("agentguard.sdk")

SDK_VERSION = "0.4.2"


class AgentGuard:
    def __init__(self, collector_url: Optional[str] = None, api_key: Optional[str] = None, policies: Optional[List[Dict[str, Any]]] = None, max_budget: float = 10.0, block_on_high: bool = True, debug: bool = False, use_ml: Optional[bool] = None, use_llm_judge: Optional[bool] = None, redis_url: Optional[str] = None, fail_open: bool = False, agent_id: Optional[str] = None, wait_for_approval: Optional[bool] = None, approval_timeout: Optional[float] = None):
        self.collector_url = (collector_url or os.getenv("AGENTGUARD_COLLECTOR_URL") or "http://localhost:8080").rstrip("/")
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

        # Kill switch : l'agent peut être déconnecté depuis le dashboard, sans toucher au code.
        self._auth_warned = False
        self._conn_state = "connected"
        self._conn_checked_at = 0.0
        self._status_ttl = max(1.0, float(os.getenv("AGENTGUARD_STATUS_TTL", "5")))
        self._status_check = bool(self.api_key) and os.getenv("AGENTGUARD_STATUS_CHECK", "true").lower() == "true"

        # HITL : par défaut, une action en attente lève ApprovalRequiredException (mode "async") ;
        # avec wait_for_approval=True (ici ou par appel), le SDK PATIENTE que l'humain décide, puis
        # exécute l'outil lui-même : c'est ce qui manquait pour que l'approbation débloque réellement l'agent.
        self.wait_for_approval = (wait_for_approval if wait_for_approval is not None
                                  else os.getenv("AGENTGUARD_WAIT_FOR_APPROVAL", "false").lower() == "true")
        self.approval_timeout = (float(approval_timeout) if approval_timeout is not None
                                 else float(os.getenv("AGENTGUARD_APPROVAL_TIMEOUT", "300")))
        self.approval_poll_interval = max(1.0, float(os.getenv("AGENTGUARD_APPROVAL_POLL_INTERVAL", "3")))
        
        self._runtime_enabled = os.getenv("AGENTGUARD_RUNTIME_RISK_ENABLED", "true").lower() == "true"
        self._runtime_fail_closed = os.getenv("AGENTGUARD_RUNTIME_FAIL_CLOSED", "true").lower() == "true"
        self._trajectory = TrajectoryAnalyzer(max_events=100) if self._runtime_enabled else None
        self._runtime_risk = RuntimeRiskEngine(fail_closed=self._runtime_fail_closed) if self._runtime_enabled else None

        logger.info("agentguard_initialized", agent_id=self.agent_id, runtime_risk=self._runtime_enabled)

    def _headers(self):
        h = {"Content-Type": "application/json", "X-Agent-Id": str(self.agent_id), "X-Agent-Sdk": SDK_VERSION}
        if self.api_key: h["X-API-Key"] = self.api_key
        return h

    def _warn_key_rejected(self):
        """Une clé refusée ne doit jamais échouer en silence : sinon rien n'apparaît dans le dashboard."""
        if self._auth_warned:
            return
        self._auth_warned = True
        import warnings
        warnings.warn(
            f"[Cerbere] {self.collector_url} rejected your API key (HTTP 401): events are NOT being recorded. "
            "Check AGENTGUARD_API_KEY and that the collector URL is correct.",
            RuntimeWarning, stacklevel=3)

    @staticmethod
    def _stable_approval_id(agent_id: str, tool_name: str, params: Dict[str, Any]) -> str:
        """ID déterministe pour UNE action (même agent + même outil + mêmes paramètres).

        Avant : chaque appel générait un ID basé sur time.time(), donc un agent qui réessaie la
        MÊME action après une approbation créait une NOUVELLE demande "pending" au lieu de voir
        que l'humain avait déjà décidé -> l'approbation ne débloquait jamais rien."""
        try:
            canon = json.dumps(params or {}, sort_keys=True, default=str)
        except TypeError:
            canon = str(params)
        digest = hashlib.sha256(f"{agent_id}|{tool_name}|{canon}".encode("utf-8")).hexdigest()[:16]
        return f"req_{digest}"

    def _fetch_approval_status(self, approval_id: str) -> Tuple[Optional[str], Optional[str]]:
        """(status, resolved_by). status est 'approved' | 'rejected' | 'pending' | None (demande
        inconnue du collecteur, clé refusée, ou collecteur injoignable)."""
        try:
            r = requests.get(f"{self.collector_url}/api/approvals/{approval_id}",
                             headers=self._headers(), timeout=min(5.0, self.collector_timeout))
            if r.status_code == 401:
                self._warn_key_rejected()
            elif r.status_code == 200:
                data = r.json()
                return data.get("status"), data.get("resolved_by")
        except Exception as e:
            logger.warning("approval_status_check_failed", approval_id=approval_id, error=str(e))
        return None, None

    def _create_approval_request(self, approval_id: str, tool_name: str, params: Dict[str, Any], reason: str):
        try:
            resp = requests.post(
                f"{self.collector_url}/api/approvals",
                json={"approval_id": approval_id, "agent_id": self.agent_id, "tool_name": tool_name,
                     "params": params, "reason": reason},
                headers=self._headers(), timeout=5)
            if resp.status_code == 401:
                self._warn_key_rejected()
            elif resp.status_code >= 400:
                logger.warning("collector_rejected_approval", status_code=resp.status_code, body=resp.text[:300])
        except Exception as e:
            logger.warning("failed_to_notify_collector_of_approval", error=str(e))

    def _resolve_approval(self, approval_id, tool_name, params, reason, wait, timeout):
        """Retourne (status, resolved_by). Crée la demande si elle n'existe pas encore ; si `wait`,
        patiente jusqu'à `timeout` secondes qu'un humain décide (poll toutes les
        `self.approval_poll_interval` secondes) au lieu de bloquer l'agent immédiatement."""
        status, resolved_by = self._fetch_approval_status(approval_id)
        if status is None:
            self._create_approval_request(approval_id, tool_name, params, reason)
            status = "pending"
        if status == "pending" and wait:
            deadline = time.time() + max(0.0, timeout)
            while time.time() < deadline:
                time.sleep(min(self.approval_poll_interval, max(0.1, deadline - time.time())))
                status, resolved_by = self._fetch_approval_status(approval_id)
                if status is None:
                    status = "pending"
                if status != "pending":
                    break
        return status, resolved_by

    def _ensure_connected(self):
        """Bloque l'agent s'il a été déconnecté depuis le dashboard.

        Vérifie l'état auprès du collecteur au plus toutes les AGENTGUARD_STATUS_TTL secondes.
        Un collecteur injoignable ne bloque pas l'agent (les autres protections restent actives)."""
        if not self._status_check:
            return
        now = time.time()
        if now - self._conn_checked_at >= self._status_ttl:
            self._conn_checked_at = now
            try:
                r = requests.get(f"{self.collector_url}/api/agent/status", headers=self._headers(),
                                 timeout=min(2.0, self.collector_timeout))
                if r.status_code == 401:
                    self._warn_key_rejected()
                if r.status_code == 200:
                    self._conn_state = r.json().get("status", "connected")
                elif r.status_code == 403 and "agent_disconnected" in r.text:
                    self._conn_state = "disconnected"
            except Exception as exc:
                self._conn_checked_at = now + 25  # collecteur injoignable : on réessaie plus tard
                logger.debug("agent_status_check_failed", error=str(exc))
        if self._conn_state == "disconnected":
            raise AgentDisconnectedException(
                f"Agent '{self.agent_id}' was disconnected from the Cerbere dashboard. Reconnect it there to resume.")

    def _send_to_collector(self, span: GuardSpan):
        try:
            payload = SpanPayload(trace_id=span.trace_id, span_id=span.span_id, span_type=span.span_type, timestamp=span.timestamp, latency_ms=span.latency_ms, input_data=span.input_data, output_data=span.output_data, security_checks=[c.to_model() for c in span.security_checks], blocked=span.blocked, block_reason=span.block_reason, cost_usd=span.cost_usd, input_tokens=span.input_tokens, output_tokens=span.output_tokens).model_dump()
            resp = requests.post(f"{self.collector_url}/span", json=payload, headers=self._headers(), timeout=self.collector_timeout)
            if resp.status_code == 401:
                self._warn_key_rejected()
            if resp.status_code == 403 and "agent_disconnected" in resp.text:
                self._conn_state = "disconnected"
            if resp.status_code >= 400:
                logger.warning("collector_rejected_span", status_code=resp.status_code, body=resp.text[:300], collector_url=self.collector_url)
        except Exception as e: 
            logger.warning("collector_send_failed", error=str(e))

    def _request_signed_decision(self, tool_name: str, params: Dict[str, Any]) -> Optional[Dict]:
        if not self._verifier: return None
        try:
            r = requests.post(f"{self.collector_url}/api/decide", json={"tool_name": tool_name, "params": params or {}, "agent_id": self.agent_id}, headers=self._headers(), timeout=self.collector_timeout)
            if r.status_code == 200: return r.json()
        except Exception as e: 
            logger.warning("signed_decision_request_failed", error=str(e))
        return None

    def _record_trajectory_tool(self, tool_name: str, decision: RuntimeRiskDecision):
        if self._trajectory:
            self._trajectory.record(self.agent_id, TrajectoryEvent(timestamp=time.time(), event_type="tool_call", tool_name=tool_name, risk_score=decision.risk_score, metadata=decision.metadata))

    def track_input(self, value: Any, source: str = "user") -> Any: return value

    @staticmethod
    def _extract_input(args, kwargs):
        messages = kwargs.get("messages")
        if isinstance(messages, list): return "\n".join(m.get("content", "") for m in messages if isinstance(m, dict) and isinstance(m.get("content"), str))
        if args and isinstance(args[0], str): return args[0]
        return ""

    @staticmethod
    def _extract_output(result):
        if isinstance(result, str): return result
        choices = getattr(result, "choices", None)
        if choices:
            parts = []
            for choice in choices:
                msg = getattr(choice, "message", None)
                content = getattr(msg, "content", None) if msg else None
                if isinstance(content, str): parts.append(content)
            return "\n".join(parts)
        return ""

    def _count_tokens(self, kwargs, result) -> Tuple[int, int]:
        model = str(kwargs.get("model", "gpt-4o"))
        input_text = self._extract_input([], kwargs) or ""
        output_text = self._extract_output(result) or ""
        try: encoding = tiktoken.encoding_for_model(model)
        except KeyError: encoding = tiktoken.get_encoding("cl100k_base")
        try: input_tokens = len(encoding.encode(input_text))
        except Exception: input_tokens = 0
        try: output_tokens = len(encoding.encode(output_text))
        except Exception: output_tokens = 0
        return input_tokens, output_tokens

    def _estimate_cost(self, kwargs, result) -> Tuple[float, int, int]:
        model = str(kwargs.get("model", "gpt-4o"))
        input_tokens, output_tokens = self._count_tokens(kwargs, result)
        pricing = {"gpt-4o": (2.5e-6, 1.0e-5), "gpt-4o-mini": (1.5e-7, 6.0e-7), "gpt-3.5-turbo": (5.0e-7, 1.5e-6), "deepseek-chat": (1.4e-7, 2.8e-7)}
        in_p, out_p = pricing.get(model, (2.5e-6, 1.0e-5))
        return max(0.0, input_tokens * in_p + output_tokens * out_p), input_tokens, output_tokens

    def guard_llm_call(self, func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            self._ensure_connected()
            span_id = hashlib.sha256(f"{time.time_ns()}".encode()).hexdigest()[:16]
            start = time.time()
            input_text = self._extract_input(args, kwargs)
            checks = [self.policy_engine.check_injection(input_text), self.policy_engine.check_pii(input_text)]
            high_risk = [c for c in checks if not c.passed and c.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)]

            if high_risk and self.block_on_high:
                span = GuardSpan(span_id, self.trace_id, "llm_call", start, (time.time()-start)*1000, {"prompt": input_text[:500], "model": kwargs.get("model", "unknown")}, {"blocked": True}, checks, True, f"HIGH RISK: {[c.check_name for c in high_risk]}")
                self.spans.append(span); self._send_to_collector(span)
                raise SecurityException(f"🛡️ AgentGuard BLOCKED: {span.block_reason}")

            try: result = func(*args, **kwargs)
            except Exception as exc:
                span = GuardSpan(span_id, self.trace_id, "llm_call", start, (time.time()-start)*1000, {"prompt": input_text[:500]}, {"error": str(exc)[:1000]}, checks)
                self.spans.append(span); self._send_to_collector(span)
                raise

            latency = (time.time() - start) * 1000
            cost, input_tokens, output_tokens = self._estimate_cost(kwargs, result)
            
            budget_check = self.policy_engine.check_budget(cost, self.max_budget, self.total_spent)
            output_pii = self.policy_engine.check_pii(self._extract_output(result))
            checks.extend([output_pii, budget_check])
            
            blocking_output = [c for c in checks if not c.passed and c.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)]
            blocked = bool(blocking_output) and self.block_on_high

            span = GuardSpan(span_id, self.trace_id, "llm_call", start, latency, {"prompt": input_text[:500], "model": kwargs.get("model", "unknown")}, {"response": self._extract_output(result)[:500]}, checks, blocked, f"Output risk: {[c.check_name for c in blocking_output]}" if blocked else None, cost_usd=cost, input_tokens=input_tokens, output_tokens=output_tokens)
            self.spans.append(span); self._send_to_collector(span)
            
            if blocked: raise SecurityException(f"🛡️ Output blocked: {span.block_reason}")
            
            self.total_spent += cost
            return result
        return wrapper

    def guard_tool_call(self, tool_name: Optional[str] = None, params: Optional[Dict[str, Any]] = None, func: Optional[Callable] = None, wait_for_approval: Optional[bool] = None, approval_timeout: Optional[float] = None):
        if callable(tool_name):
            actual_func = tool_name
            actual_tool_name = actual_func.__name__
            @wraps(actual_func)
            def wrapper(*args, **kwargs):
                return self._execute_guarded_tool(actual_tool_name, kwargs, actual_func)
            return wrapper
            
        if params is None and func is None and isinstance(tool_name, str):
            def decorator(wrapped: Callable):
                @wraps(wrapped)
                def wrapper(*args, **kwargs):
                    return self._execute_guarded_tool(tool_name, kwargs, wrapped)
                return wrapper
            return decorator
            
        if func is not None and isinstance(tool_name, str):
            return self._execute_guarded_tool(tool_name, params or {}, func, wait_for_approval, approval_timeout)
            
        raise TypeError("Usage invalide de guard_tool_call. Utilisez @guard.guard_tool_call ou @guard.guard_tool_call('nom')")

    def _execute_guarded_tool(self, tool_name: str, params: Dict[str, Any], func: Callable):
    self._ensure_connected()
    span_id = hashlib.sha256(f"{time.time_ns()}".encode()).hexdigest()[:16]
    start = time.time()
    budget_remaining = self.max_budget - self.total_spent
    
    check = self.policy_engine.check_tool_policy(tool_name, params, budget_remaining)
    runtime_decision = self._runtime_risk.evaluate(tool_name, params) if self._runtime_enabled else RuntimeRiskDecision("ALLOW", 0.0, RiskLevel.LOW)
    runtime_check = SecurityCheck("runtime_risk", runtime_decision.allowed, runtime_decision.risk_level, "; ".join(runtime_decision.reasons[:5]))

    if not runtime_decision.allowed:
        span = GuardSpan(span_id, self.trace_id, "tool_call", start, (time.time()-start)*1000, {"tool": tool_name, "params": params}, {"blocked": True}, [check, runtime_check], True, f"[RUNTIME {runtime_decision.action}] {runtime_decision.reasons[0] if runtime_decision.reasons else 'blocked'}")
        self.spans.append(span); self._send_to_collector(span); self._record_trajectory_tool(tool_name, runtime_decision)
        raise SecurityException(f"🛡️ Runtime risk {runtime_decision.action}: {runtime_decision.reasons[0] if runtime_decision.reasons else 'blocked'}")

    signed_decision = None
    if self._verifier:
        signed_decision = self._request_signed_decision(tool_name, params or {})
        if signed_decision is None:
            span = GuardSpan(span_id, self.trace_id, "tool_call", start, (time.time()-start)*1000, {"tool": tool_name, "params": params}, {"blocked": True, "reason": "signed_decision_unavailable"}, [check, runtime_check], True, "[SECURITY] Signed server decision unavailable")
            self.spans.append(span); self._send_to_collector(span)
            self._record_trajectory_tool(tool_name, RuntimeRiskDecision("DENY", 100.0, RiskLevel.CRITICAL, ["signed server decision unavailable"]))
            raise SecurityException("️ AgentGuard DENY: server security decision unavailable")
        if signed_decision.get("action") == "DENY": raise SecurityException(f"🛡️ Signed DENY: {signed_decision.get('reason', 'policy violation')}")
        if signed_decision.get("action") == "REQUIRE_APPROVAL": raise SecurityException("🛡️ AgentGuard: human approval required")

    # --- GESTION DE L'APPROBATION HUMAINE (HITL) avec auto-retry ---
    if not check.passed:
        if check.metadata.get("requires_approval"):
            approval_id = f"req_{hashlib.sha256(f'{time.time()}'.encode()).hexdigest()[:8]}"
            
            # 1. Créer la demande d'approbation côté serveur
            try:
                requests.post(
                    f"{self.collector_url}/api/approvals",
                    json={
                        "approval_id": approval_id,
                        "agent_id": self.agent_id,
                        "tool_name": tool_name,
                        "params": params,
                        "reason": check.details
                    },
                    headers=self._headers(),
                    timeout=5
                )
            except Exception as e:
                logger.warning("failed_to_notify_collector_of_approval", error=str(e))

            # 2. POLLER jusqu'à ce que l'humain approuve (timeout 5 min)
            logger.info("waiting_for_human_approval", approval_id=approval_id, tool=tool_name)
            max_wait = 300  # 5 minutes
            poll_interval = 2  # secondes
            elapsed = 0
            
            while elapsed < max_wait:
                time.sleep(poll_interval)
                elapsed += poll_interval
                
                try:
                    r = requests.get(
                        f"{self.collector_url}/api/approvals/{approval_id}",
                        headers=self._headers(),
                        timeout=3
                    )
                    if r.status_code == 200:
                        status = r.json().get("status")
                        if status == "approved":
                            logger.info("approval_granted_executing_tool", approval_id=approval_id, tool=tool_name)
                            # L'humain a approuvé → exécuter l'outil
                            break
                        elif status == "rejected":
                            raise ApprovalRequiredException(
                                f"Action rejetée par l'administrateur. (ID: {approval_id})",
                                approval_id=approval_id,
                                details=check.metadata
                            )
                except Exception as e:
                    logger.debug("poll_failed", error=str(e))
            
            if elapsed >= max_wait:
                raise ApprovalRequiredException(
                    f"Approbation expirée après {max_wait}s. (ID: {approval_id})",
                    approval_id=approval_id,
                    details=check.metadata
                )
                
            # 3. L'outil va maintenant s'exécuter normalement (on sort du bloc if)
            logger.info("proceeding_with_tool_execution", tool=tool_name)
        else:
            if check.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL) and self.block_on_high:
                span = GuardSpan(span_id, self.trace_id, "tool_call", start, (time.time()-start)*1000, {"tool": tool_name, "params": params}, {"blocked": True, "reason": "policy_block_on_high"}, [check, runtime_check], True, f"[POLICY] {check.details}")
                self.spans.append(span); self._send_to_collector(span); self._record_trajectory_tool(tool_name, runtime_decision)
                raise SecurityException(f"🛡️ Tool blocked: {check.details}")

    try: 
        result = func(**params)
    except Exception as exc:
        span = GuardSpan(span_id, self.trace_id, "tool_call", start, (time.time()-start)*1000, {"tool": tool_name, "params": params}, {"error": str(exc)[:1000]}, [check, runtime_check])
        self.spans.append(span); self._send_to_collector(span)
        raise

    span = GuardSpan(span_id, self.trace_id, "tool_call", start, (time.time()-start)*1000, {"tool": tool_name, "params": params}, {"result": str(result)[:500]}, [check, runtime_check])
    self.spans.append(span); self._send_to_collector(span); self._record_trajectory_tool(tool_name, runtime_decision)
    return result

    def get_report(self) -> Dict[str, Any]:
        return {"trace_id": self.trace_id, "total_spans": len(self.spans), "blocked_operations": sum(1 for s in self.spans if s.blocked), "total_cost_usd": round(self.total_spent, 6), "runtime_risk_enabled": self._runtime_enabled}

def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    logger.info("Starting CerbereAG MCP Server (v1.x) on stdio...")
    from mcp.server.fastmcp import FastMCP


