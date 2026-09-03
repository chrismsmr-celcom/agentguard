AgentGuard Cyber Judge v1.0
Deterministic cybersecurity judge for AI-agent runtime decisions.

Design goals:
- No external LLM dependency for the default judge.
- Deterministic, explainable decisions.
- Bounded latency and bounded memory.
- Uses cybersecurity concepts without pretending to be a complete MITRE/CWE validator.
- Can optionally consume an existing ML score as a signal.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class JudgeVerdict(str, Enum):
    ALLOW = "ALLOW"
    ALERT = "ALERT"
    BLOCK = "BLOCK"
    BLOCK_IMMEDIATE = "BLOCK_IMMEDIATE"


class AttackType(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    SYSTEM_EXTRACTION = "system_extraction"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    COMMAND_INJECTION = "command_injection"
    CREDENTIAL_EXPOSURE = "credential_exposure"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    SUPPLY_CHAIN = "supply_chain"
    UNKNOWN = "unknown"


@dataclass
class CyberVerdict:
    verdict: JudgeVerdict
    risk_score: int
    reasoning: List[str] = field(default_factory=list)
    confidence: float = 0.0
    attack_type: Optional[AttackType] = None
    mitre_tactic: Optional[str] = None
    cwe_id: Optional[str] = None
    exploitability: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "risk_score": self.risk_score,
            "reasoning": list(self.reasoning),
            "confidence": self.confidence,
            "attack_type": self.attack_type.value if self.attack_type else None,
            "mitre_tactic": self.mitre_tactic,
            "cwe_id": self.cwe_id,
            "exploitability": dict(self.exploitability),
            "metadata": dict(self.metadata),
        }


class CyberJudge:
    """
    Deterministic cyber-security judge.

    Important:
    This is a risk engine, not a formal MITRE/CWE compliance oracle.
    Framework identifiers are contextual mappings used for telemetry and
    explainability; the primary enforcement decision comes from explicit rules.
    """

    TOOL_RISK: Dict[str, int] = {
        "send_email": 55,
        "send_message": 55,
        "webhook": 60,
        "http_request": 55,
        "fetch": 55,
        "upload_file": 70,
        "publish": 75,
        "delete_file": 85,
        "delete_all": 95,
        "drop_database": 100,
        "drop_table": 95,
        "execute_command": 100,
        "run_shell": 100,
        "subprocess": 100,
        "sudo": 100,
        "grant_access": 90,
        "change_permissions": 90,
        "access_secrets": 95,
        "query_database": 65,
        "access_database": 75,
        "transfer_funds": 100,
        "create_user": 70,
        "modify_config": 80,
        "modify_logs": 75,
        "write_file": 50,
        "append_file": 45,
    }

    EXTERNAL_TOOLS = {
        "http_request", "fetch", "webhook", "send_email", "send_message",
        "upload_file", "publish", "post_message", "browser_navigate",
    }

    PRIVILEGED_TOOLS = {
        "execute_command", "run_shell", "subprocess", "sudo",
        "admin_action", "grant_access", "change_permissions", "delete_all",
    }

    IRREVERSIBLE_TOOLS = {
        "delete", "delete_file", "delete_all", "drop_database", "drop_table",
        "execute_command", "run_shell", "subprocess", "transfer_funds",
        "send_email", "publish", "upload_file",
    }

    # These patterns are intentionally high-signal. Generic words such as
    # "export" or "send" alone are not enough to block.
    ATTACK_SIGNATURES: Tuple[Tuple[AttackType, Tuple[str, ...], int, str, str], ...] = (
        (
            AttackType.PROMPT_INJECTION,
            (
                r"\bignore\s+(all\s+)?previous\s+instructions\b",
                r"\bdisregard\s+(all\s+)?previous\s+instructions\b",
                r"\boverride\s+(the\s+)?system\b",
                r"\bforget\s+(all\s+)?previous\s+instructions\b",
                r"\bdo\s+not\s+follow\s+(the\s+)?system\b",
                r"\breveal\s+hidden\s+instructions\b",
            ),
            75,
            "execution",
            "CWE-94",
        ),
        (
            AttackType.JAILBREAK,
            (
                r"\bdeveloper\s+mode\b",
                r"\bdo\s+anything\s+now\b",
                r"\buncensored\s+mode\b",
                r"\bunrestricted\s+mode\b",
                r"\bbypass\s+(your\s+)?safety\b",
            ),
            80,
            "privilege_escalation",
            "CWE-269",
        ),
        (
            AttackType.SYSTEM_EXTRACTION,
            (
                r"\bsystem\s+prompt\b",
                r"\bhidden\s+instructions\b",
                r"\binitial\s+prompt\b",
                r"\bshow\s+your\s+instructions\b",
                r"\breveal\s+your\s+prompt\b",
            ),
            60,
            "discovery",
            "CWE-200",
        ),
        (
            AttackType.DATA_EXFILTRATION,
            (
                r"\b(send|upload|transfer|leak|exfiltrate)\b.{0,80}\b(secret|password|token|api[_ -]?key|private[_ -]?key|credential)s?\b",
                r"\bexport\b.{0,80}\b(all|customer|user|private|confidential|secret)\b",
            ),
            90,
            "exfiltration",
            "CWE-359",
        ),
        (
            AttackType.COMMAND_INJECTION,
            (
                r"\brm\s+-rf\b",
                r"\bdrop\s+table\b",
                r"\bchmod\s+777\b",
                r"\bcurl\b.{0,100}\|\s*(sh|bash)\b",
                r"\bwget\b.{0,100}\|\s*(sh|bash)\b",
                r";\s*(rm|curl|wget|bash|sh)\b",
            ),
            100,
            "execution",
            "CWE-78",
        ),
        (
            AttackType.CREDENTIAL_EXPOSURE,
            (
                r"\b(api[_ -]?key|access[_ -]?token|private[_ -]?key|password)\b.{0,60}\b(send|post|upload|publish|webhook)\b",
                r"\b(send|post|upload|publish|webhook)\b.{0,60}\b(api[_ -]?key|access[_ -]?token|private[_ -]?key|password)\b",
            ),
            90,
            "credential_access",
            "CWE-200",
        ),
        (
            AttackType.RESOURCE_EXHAUSTION,
            (
                r"\b(infinite|unbounded)\s+(loop|recursion|requests)\b",
                r"\bmillions?\s+of\s+(requests|emails|records)\b",
                r"\bmax(?:imum)?\s*=\s*(?:999999|1000000)\b",
            ),
            80,
            "impact",
            "CWE-400",
        ),
    )

    SENSITIVE_PARAM_NAMES = {
        "api_key", "apikey", "access_token", "auth_token", "password",
        "passwd", "secret", "private_key", "client_secret", "refresh_token",
        "authorization", "credential", "credentials",
    }

    def __init__(
        self,
        allow_threshold: int = 29,
        alert_threshold: int = 40,
        block_threshold: int = 60,
        immediate_threshold: int = 85,
    ):
        self.allow_threshold = int(allow_threshold)
        self.alert_threshold = int(alert_threshold)
        self.block_threshold = int(block_threshold)
        self.immediate_threshold = int(immediate_threshold)
        self._baseline: Dict[str, Dict[str, int]] = {}

    @staticmethod
    def _serialize(value: Any, limit: int = 8000) -> str:
        try:
            text = json.dumps(value, default=str, ensure_ascii=False)
        except Exception:
            text = str(value)
        return text[:limit]

    def _detect_attack(self, text: str) -> Tuple[Optional[AttackType], int, Optional[str], Optional[str], List[str]]:
        lowered = text.lower()
        for attack_type, patterns, base_risk, tactic, cwe in self.ATTACK_SIGNATURES:
            for pattern in patterns:
                if re.search(pattern, lowered, flags=re.IGNORECASE | re.DOTALL):
                    return (
                        attack_type,
                        base_risk,
                        tactic,
                        cwe,
                        [f"high-signal pattern: {attack_type.value}"],
                    )
        return None, 0, None, None, []

    def _tool_risk(self, tool_name: str) -> Tuple[int, List[str]]:
        tool = (tool_name or "unknown").lower()
        risk = self.TOOL_RISK.get(tool, 15)
        reasons: List[str] = []
        if tool in self.PRIVILEGED_TOOLS:
            reasons.append(f"privileged tool: {tool}")
        if tool in self.IRREVERSIBLE_TOOLS:
            reasons.append(f"irreversible side effect: {tool}")
        if tool in self.EXTERNAL_TOOLS:
            reasons.append(f"external side effect: {tool}")
        if risk >= 90:
            reasons.append(f"critical-impact tool: {tool}")
        return risk, reasons

    def _param_risk(self, params: Dict[str, Any], external: bool) -> Tuple[int, List[str]]:
        if not params:
            return 0, []

        reasons: List[str] = []
        risk = 0

        keys = {str(k).lower() for k in params}
        sensitive_keys = keys & self.SENSITIVE_PARAM_NAMES

        if sensitive_keys and external:
            risk += 45
            reasons.append("credential-like parameter reaches external tool")

        serialized = self._serialize(params).lower()
        if external and re.search(
            r"\b(sk-[a-z0-9_-]{12,}|ghp_[a-z0-9]{20,}|bearer\s+[a-z0-9._-]{12,})\b",
            serialized,
        ):
            risk += 45
            reasons.append("credential/token-like value detected in external tool parameters")

        if re.search(r"\b(all|everything|entire|whole)\b", serialized):
            risk += 15
            reasons.append("broad-scope parameter detected")

        return min(risk, 70), reasons

    def _context_risk(self, span_data: Dict[str, Any]) -> Tuple[int, List[str]]:
        context = span_data.get("context") or {}
        risk = 0
        reasons: List[str] = []

        role = str(span_data.get("agent_role") or context.get("agent_role") or "user").lower()
        if role == "admin":
            risk += 10
            reasons.append("admin execution context")
        elif role == "system":
            risk += 15
            reasons.append("system execution context")

        if context.get("is_production"):
            risk += 10
            reasons.append("production environment")
        if context.get("has_network_access"):
            risk += 5
            reasons.append("network-capable context")

        return risk, reasons

    def _ml_signal(self, span_data: Dict[str, Any]) -> Tuple[int, List[str]]:
        ml = span_data.get("ml_result") or {}
        if not isinstance(ml, dict):
            return 0, []

        raw_score = ml.get("score")
        if raw_score is None:
            return 0, []

        try:
            score = float(raw_score)
        except (TypeError, ValueError):
            return 0, []

        # Normalize classifiers that expose 0..1 probabilities.
        if 0 <= score <= 1:
            score *= 100

        confidence = str(ml.get("confidence", "")).lower()
        if confidence not in {"high", "0.9", "0.95", "0.99"} and score < 85:
            return int(score * 0.15), []

        return int(min(score, 100) * 0.25), [f"ML signal contributes {int(score)} risk"]

    def _baseline_signal(self, span_data: Dict[str, Any]) -> Tuple[int, List[str]]:
        agent_id = str(span_data.get("agent_id") or "default")
        tool = str(span_data.get("tool_name") or "unknown")
        key = f"{agent_id}:{tool}"

        entry = self._baseline.setdefault(key, {"count": 0})
        previous = entry["count"]
        entry["count"] = min(previous + 1, 1000000)

        # First occurrence is not anomalous. After a baseline exists, a brand-new
        # tool can be supplied through context["known_tools"] for stronger evidence.
        context = span_data.get("context") or {}
        known_tools = set(context.get("known_tools") or [])
        if known_tools and tool not in known_tools:
            return 15, ["tool is outside declared historical/allowed baseline"]

        return 0, []

    def _confidence(self, reasons: List[str], hard_attack: bool) -> float:
        if hard_attack:
            return 0.98
        if len(reasons) >= 4:
            return 0.90
        if len(reasons) >= 2:
            return 0.80
        if len(reasons) == 1:
            return 0.70
        return 0.60

    def judge(self, span_data: Dict[str, Any]) -> CyberVerdict:
        start = time.perf_counter()

        tool_name = str(
            span_data.get("tool_name")
            or span_data.get("tool")
            or (span_data.get("input_data") or {}).get("tool")
            or "unknown"
        )
        params = span_data.get("params") or {}
        input_data = span_data.get("input_data") or {}
        output_data = span_data.get("output_data") or {}

        text = " ".join(
            [
                self._serialize(input_data),
                self._serialize(params),
                self._serialize(output_data),
            ]
        )

        attack_type, attack_risk, tactic, cwe_id, reasons = self._detect_attack(text)

        tool_risk, tool_reasons = self._tool_risk(tool_name)
        context_risk, context_reasons = self._context_risk(span_data)
        external = tool_name.lower() in self.EXTERNAL_TOOLS
        param_risk, param_reasons = self._param_risk(params, external)
        ml_risk, ml_reasons = self._ml_signal(span_data)
        baseline_risk, baseline_reasons = self._baseline_signal(span_data)

        reasons.extend(tool_reasons)
        reasons.extend(context_reasons)
        reasons.extend(param_reasons)
        reasons.extend(ml_reasons)
        reasons.extend(baseline_reasons)

        # Hard security rules take precedence over aggregate scoring.
        hard_block_reason: Optional[str] = None
        taint = str(span_data.get("taint_level") or "").upper()

        if taint == "MALICIOUS" and (external or tool_name.lower() in self.PRIVILEGED_TOOLS):
            hard_block_reason = "MALICIOUS taint reaches a high-impact sink"
        elif taint == "SECRET" and external:
            hard_block_reason = "SECRET taint reaches an external sink"

        if hard_block_reason:
            reasons.append(f"hard rule: {hard_block_reason}")
            score = 100
            verdict = JudgeVerdict.BLOCK_IMMEDIATE
        else:
            # Tool risk is a baseline, not an automatic block. This avoids the
            # common mistake where every send_email call becomes malicious.
            score = max(
                0,
                min(
                    100,
                    int(
                        (attack_risk * 0.65)
                        + (tool_risk * 0.25)
                        + param_risk
                        + context_risk
                        + ml_risk
                        + baseline_risk
                    ),
                ),
            )

            if attack_type == AttackType.COMMAND_INJECTION:
                score = max(score, 95)
            elif attack_type in {
                AttackType.DATA_EXFILTRATION,
                AttackType.CREDENTIAL_EXPOSURE,
                AttackType.JAILBREAK,
            }:
                score = max(score, 75)

            if score >= self.immediate_threshold:
                verdict = JudgeVerdict.BLOCK_IMMEDIATE
            elif score >= self.block_threshold:
                verdict = JudgeVerdict.BLOCK
            elif score >= self.alert_threshold:
                verdict = JudgeVerdict.ALERT
            else:
                verdict = JudgeVerdict.ALLOW

        elapsed_ms = (time.perf_counter() - start) * 1000

        return CyberVerdict(
            verdict=verdict,
            risk_score=int(score),
            reasoning=reasons or ["no high-risk cyber indicators detected"],
            confidence=self._confidence(reasons, hard_block_reason is not None),
            attack_type=attack_type,
            mitre_tactic=tactic,
            cwe_id=cwe_id,
            exploitability={
                "complexity": "low" if attack_type else "unknown",
                "privileges_required": "none",
                "accessibility": "runtime",
            },
            metadata={
                "tool": tool_name,
                "external": external,
                "privileged": tool_name.lower() in self.PRIVILEGED_TOOLS,
                "irreversible": tool_name.lower() in self.IRREVERSIBLE_TOOLS,
                "latency_ms": round(elapsed_ms, 3),
                "deterministic": True,
            },
        )

    def get_status(self) -> Dict[str, Any]:
        return {
            "enabled": True,
            "type": "deterministic_cyber_judge",
            "baseline_entries": len(self._baseline),
        }


class HybridCyberJudge:
    """
    Optional hybrid wrapper.

    Deterministic CyberJudge always runs first. An optional callback can be used
    for ambiguous cases. The callback is deliberately generic so AgentGuard can
    connect a local model, an enterprise model, or another classifier later.

    No external LLM is required by default.
    """

    def __init__(
        self,
        deterministic: Optional[CyberJudge] = None,
        ambiguous_callback: Optional[Any] = None,
        ambiguous_min: int = 30,
        ambiguous_max: int = 59,
    ):
        self.deterministic = deterministic or CyberJudge()
        self.ambiguous_callback = ambiguous_callback
        self.ambiguous_min = int(ambiguous_min)
        self.ambiguous_max = int(ambiguous_max)

    def judge(self, span_data: Dict[str, Any]) -> CyberVerdict:
        result = self.deterministic.judge(span_data)

        if (
            self.ambiguous_callback is None
            or result.risk_score < self.ambiguous_min
            or result.risk_score > self.ambiguous_max
        ):
            return result

        try:
            external = self.ambiguous_callback(span_data, result)
        except TypeError:
            external = self.ambiguous_callback(span_data)
        except Exception as exc:
            # Security-first fallback: keep the deterministic verdict.
            result.metadata["ambiguous_callback_error"] = str(exc)[:200]
            return result

        if not isinstance(external, dict):
            return result

        try:
            external_score = int(max(0, min(100, float(external.get("risk_score", result.risk_score)))))
        except (TypeError, ValueError):
            external_score = result.risk_score

        if external.get("verdict") in {"BLOCK", "BLOCK_IMMEDIATE"}:
            result.verdict = JudgeVerdict(external["verdict"])
        elif external.get("verdict") == "ALERT":
            result.verdict = JudgeVerdict.ALERT
        elif external.get("verdict") == "ALLOW":
            result.verdict = JudgeVerdict.ALLOW

        result.risk_score = max(result.risk_score, external_score)
        result.reasoning.append("ambiguous-case secondary judge consulted")
        result.metadata["secondary_judge"] = external
        return result
