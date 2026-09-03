"""
Cerbere / AgentGuard — Unified Runtime Decision Engine

Single authoritative decision point for agent actions.

Flow:
    identity
        ↓
    trajectory
        ↓
    detection
        ↓
    risk
        ↓
    policy
        ↓
    ALLOW / BLOCK / REQUIRE_APPROVAL

The LLM is never the final authority.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional

from risk_engine import RiskEngine, RiskInput, RiskDecision


class Decision(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    REQUIRE_APPROVAL = "require_approval"


class DecisionReason(str, Enum):
    POLICY = "policy"
    RISK = "risk"
    IDENTITY = "identity"
    TRAJECTORY = "trajectory"
    DETECTION = "detection"
    TAINT = "taint"
    TOOL = "tool"
    APPROVAL = "approval"


@dataclass
class PolicyRule:
    """
    Runtime policy attached to an action/tool.
    """

    name: str

    allowed_tools: Optional[set[str]] = None

    blocked_tools: set[str] = field(default_factory=set)

    require_approval_for: set[str] = field(default_factory=set)

    max_risk_score: float = 79.0

    block_risk_score: float = 80.0

    deny_untrusted_external_side_effect: bool = True

    deny_secret_external_side_effect: bool = True

    deny_malicious_taint: bool = True

    allow_unknown_tools: bool = False


@dataclass
class DecisionRequest:
    """
    Complete security context for one agent action.
    """

    agent_id: str

    tool_name: str

    tool_category: str = "read"

    identity_trusted: bool = False

    model_score: float = 0.0

    anomaly_score: float = 0.0

    taint_level: str = "PUBLIC"

    trajectory_length: int = 0

    previous_risky_actions: int = 0

    external_side_effect: bool = False

    irreversible: bool = False

    tool_registered: bool = True

    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DecisionResult:
    decision: Decision

    risk_score: float

    risk_level: str

    reasons: List[str]

    reason_codes: List[str]

    policy: str

    factors: Dict[str, float]

    enforcement: str

    audit: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision.value,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "reasons": self.reasons,
            "reason_codes": self.reason_codes,
            "policy": self.policy,
            "factors": self.factors,
            "enforcement": self.enforcement,
            "audit": self.audit,
        }


class DecisionEngine:
    """
    The single security authority for runtime actions.

    Important:
    - Detection proposes signals.
    - RiskEngine calculates risk.
    - Policy decides what is allowed.
    - This engine produces the final enforcement decision.
    """

    def __init__(
        self,
        policies: Optional[Iterable[PolicyRule]] = None,
        risk_engine: Optional[RiskEngine] = None,
    ):
        self.risk_engine = risk_engine or RiskEngine()

        self.policies: Dict[str, PolicyRule] = {
            policy.name: policy
            for policy in (policies or [])
        }

        if "default" not in self.policies:
            self.policies["default"] = PolicyRule(
                name="default"
            )

    def register_policy(self, policy: PolicyRule) -> None:
        self.policies[policy.name] = policy

    def _select_policy(
        self,
        request: DecisionRequest,
    ) -> PolicyRule:
        requested_policy = request.metadata.get("policy")

        if requested_policy:
            policy = self.policies.get(str(requested_policy))
            if policy:
                return policy

        return self.policies["default"]

    @staticmethod
    def _result(
        decision: Decision,
        risk_score: float,
        risk_level: str,
        reasons: List[str],
        reason_codes: List[str],
        policy: PolicyRule,
        factors: Dict[str, float],
        request: DecisionRequest,
    ) -> DecisionResult:

        return DecisionResult(
            decision=decision,
            risk_score=round(float(risk_score), 2),
            risk_level=risk_level,
            reasons=reasons,
            reason_codes=reason_codes,
            policy=policy.name,
            factors=factors,
            enforcement=decision.value,
            audit={
                "agent_id": request.agent_id,
                "tool_name": request.tool_name,
                "tool_category": request.tool_category,
                "taint_level": request.taint_level.upper(),
                "identity_trusted": request.identity_trusted,
                "external_side_effect": request.external_side_effect,
                "irreversible": request.irreversible,
                "trajectory_length": request.trajectory_length,
                "previous_risky_actions": request.previous_risky_actions,
            },
        )

    def evaluate(
        self,
        request: DecisionRequest,
    ) -> DecisionResult:

        policy = self._select_policy(request)

        reasons: List[str] = []
        reason_codes: List[str] = []

        # ---------------------------------------------------------
        # 1. Identity
        # ---------------------------------------------------------

        if not request.identity_trusted:

            return self._result(
                Decision.BLOCK,
                100,
                "critical",
                ["Agent identity is not trusted"],
                [DecisionReason.IDENTITY.value],
                policy,
                {"identity_risk": 100.0},
                request,
            )

        # ---------------------------------------------------------
        # 2. Tool registration
        # ---------------------------------------------------------

        if not request.tool_registered and not policy.allow_unknown_tools:

            return self._result(
                Decision.BLOCK,
                100,
                "critical",
                ["Tool is not registered in runtime policy"],
                [DecisionReason.TOOL.value],
                policy,
                {"tool_risk": 100.0},
                request,
            )

        # ---------------------------------------------------------
        # 3. Explicit blocked tool
        # ---------------------------------------------------------

        if request.tool_name in policy.blocked_tools:

            return self._result(
                Decision.BLOCK,
                100,
                "critical",
                [f"Tool '{request.tool_name}' is explicitly blocked"],
                [DecisionReason.POLICY.value],
                policy,
                {"policy_risk": 100.0},
                request,
            )

        # ---------------------------------------------------------
        # 4. Allowlist
        # ---------------------------------------------------------

        if (
            policy.allowed_tools is not None
            and request.tool_name not in policy.allowed_tools
        ):

            return self._result(
                Decision.BLOCK,
                100,
                "critical",
                [f"Tool '{request.tool_name}' is not allowlisted"],
                [DecisionReason.POLICY.value],
                policy,
                {"policy_risk": 100.0},
                request,
            )

        # ---------------------------------------------------------
        # 5. Hard taint rules
        # ---------------------------------------------------------

        taint = request.taint_level.upper()

        if policy.deny_malicious_taint and taint == "MALICIOUS":

            return self._result(
                Decision.BLOCK,
                100,
                "critical",
                ["MALICIOUS data cannot reach an executable tool"],
                [DecisionReason.TAINT.value],
                policy,
                {"taint_risk": 100.0},
                request,
            )

        if (
            policy.deny_secret_external_side_effect
            and taint == "SECRET"
            and request.external_side_effect
        ):

            return self._result(
                Decision.BLOCK,
                100,
                "critical",
                ["SECRET data cannot reach an external side-effect"],
                [DecisionReason.TAINT.value],
                policy,
                {"taint_risk": 100.0},
                request,
            )

        if (
            policy.deny_untrusted_external_side_effect
            and taint == "UNTRUSTED"
            and request.external_side_effect
        ):

            return self._result(
                Decision.BLOCK,
                100,
                "critical",
                ["UNTRUSTED data cannot directly trigger an external side-effect"],
                [DecisionReason.TAINT.value],
                policy,
                {"taint_risk": 100.0},
                request,
            )

        # ---------------------------------------------------------
        # 6. Risk calculation
        # ---------------------------------------------------------

        risk = self.risk_engine.evaluate(
            RiskInput(
                tool_name=request.tool_name,
                tool_category=request.tool_category,
                model_score=request.model_score,
                taint_level=taint,
                trajectory_length=request.trajectory_length,
                previous_risky_actions=request.previous_risky_actions,
                identity_trusted=request.identity_trusted,
                external_side_effect=request.external_side_effect,
                irreversible=request.irreversible,
                anomaly_score=request.anomaly_score,
                metadata=request.metadata,
            )
        )

        reasons.extend(risk.reasons)

        if risk.reasons:
            reason_codes.append(DecisionReason.RISK.value)

        # ---------------------------------------------------------
        # 7. Explicit approval policy
        # ---------------------------------------------------------

        if request.tool_name in policy.require_approval_for:

            reasons.append(
                f"Tool '{request.tool_name}' requires human approval"
            )

            reason_codes.append(
                DecisionReason.APPROVAL.value
            )

            return self._result(
                Decision.REQUIRE_APPROVAL,
                max(risk.score, 60),
                "high",
                reasons,
                reason_codes,
                policy,
                risk.factors,
                request,
            )

        # ---------------------------------------------------------
        # 8. Risk-based BLOCK
        # ---------------------------------------------------------

        if risk.score >= policy.block_risk_score:

            reasons.append(
                f"Risk score {risk.score} exceeds block threshold "
                f"{policy.block_risk_score}"
            )

            reason_codes.append(
                DecisionReason.RISK.value
            )

            return self._result(
                Decision.BLOCK,
                risk.score,
                risk.level.value,
                reasons,
                reason_codes,
                policy,
                risk.factors,
                request,
            )

        # ---------------------------------------------------------
        # 9. Risk-based REVIEW
        # ---------------------------------------------------------

        if risk.score > policy.max_risk_score:

            reasons.append(
                f"Risk score {risk.score} requires approval"
            )

            reason_codes.append(
                DecisionReason.APPROVAL.value
            )

            return self._result(
                Decision.REQUIRE_APPROVAL,
                risk.score,
                risk.level.value,
                reasons,
                reason_codes,
                policy,
                risk.factors,
                request,
            )

        # ---------------------------------------------------------
        # 10. Allow
        # ---------------------------------------------------------

        reasons.append(
            "Action passed identity, policy, taint and risk checks"
        )

        return self._result(
            Decision.ALLOW,
            risk.score,
            risk.level.value,
            reasons,
            reason_codes or ["allow"],
            policy,
            risk.factors,
            request,
        )
