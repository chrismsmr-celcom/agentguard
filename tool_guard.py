"""
AgentGuard Tool Guard
---------------------
Zero-trust authorization layer for AI agent tool calls.

Le LLM ne peut jamais décider seul:
    "j'ai le droit d'appeler cet outil."

AgentGuard décide.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Set

from risk_engine import (
    RiskEngine,
    RiskInput,
    RiskDecision,
)


class ToolBlocked(Exception):
    pass


class ApprovalRequired(Exception):
    pass


@dataclass
class ToolPolicy:
    name: str

    # Permission explicite.
    allowed_identities: Set[str] = field(default_factory=set)

    # Classification.
    category: str = "read"

    # Restrictions.
    read_only: bool = True

    # Effets.
    external_side_effect: bool = False
    irreversible: bool = False

    # Require approval for risky operations.
    require_approval: bool = False

    # Maximum arguments size.
    max_argument_bytes: int = 50_000


@dataclass
class ToolRequest:
    tool_name: str
    identity: str
    arguments: Dict[str, Any]

    model_score: float = 0.0
    taint_level: str = "PUBLIC"

    trajectory_length: int = 0
    previous_risky_actions: int = 0


@dataclass
class ToolDecision:
    allowed: bool
    decision: str
    reason: str
    risk_score: float
    metadata: Dict[str, Any] = field(default_factory=dict)


class ToolGuard:

    def __init__(self, policies=None):
        self.policies: Dict[str, ToolPolicy] = {
            p.name: p for p in (policies or [])
        }

        self.risk_engine = RiskEngine()

    def register(self, policy: ToolPolicy):
        self.policies[policy.name] = policy

    def authorize(self, request: ToolRequest) -> ToolDecision:

        policy = self.policies.get(request.tool_name)

        # ---------------------------------------------------------
        # Unknown tools = DENY
        # ---------------------------------------------------------

        if policy is None:
            return ToolDecision(
                allowed=False,
                decision="block",
                reason="Tool is not registered in AgentGuard policy",
                risk_score=100,
            )

        # ---------------------------------------------------------
        # Identity authorization
        # ---------------------------------------------------------

        if request.identity not in policy.allowed_identities:
            return ToolDecision(
                allowed=False,
                decision="block",
                reason="Agent identity is not authorized for this tool",
                risk_score=100,
                metadata={
                    "tool": request.tool_name,
                    "identity": request.identity,
                },
            )

        # ---------------------------------------------------------
        # Argument size
        # ---------------------------------------------------------

        import json

        try:
            size = len(
                json.dumps(
                    request.arguments,
                    default=str,
                ).encode("utf-8")
            )
        except Exception:
            return ToolDecision(
                allowed=False,
                decision="block",
                reason="Tool arguments could not be serialized safely",
                risk_score=100,
            )

        if size > policy.max_argument_bytes:
            return ToolDecision(
                allowed=False,
                decision="block",
                reason="Tool argument size exceeds policy limit",
                risk_score=90,
            )

        # ---------------------------------------------------------
        # Risk engine
        # ---------------------------------------------------------

        risk = self.risk_engine.evaluate(
            RiskInput(
                tool_name=request.tool_name,
                tool_category=policy.category,
                model_score=request.model_score,
                taint_level=request.taint_level,
                trajectory_length=request.trajectory_length,
                previous_risky_actions=request.previous_risky_actions,
                identity_trusted=True,
                external_side_effect=policy.external_side_effect,
                irreversible=policy.irreversible,
            )
        )

        # ---------------------------------------------------------
        # Hard security rules
        # ---------------------------------------------------------

        if request.taint_level.upper() == "MALICIOUS":
            return ToolDecision(
                allowed=False,
                decision="block",
                reason="MALICIOUS data cannot reach a tool",
                risk_score=100,
                metadata=risk.to_dict(),
            )

        if (
            request.taint_level.upper() == "SECRET"
            and policy.external_side_effect
        ):
            return ToolDecision(
                allowed=False,
                decision="block",
                reason="SECRET data cannot reach external side-effect tools",
                risk_score=100,
                metadata=risk.to_dict(),
            )

        # ---------------------------------------------------------
        # Explicit approval
        # ---------------------------------------------------------

        if policy.require_approval:
            return ToolDecision(
                allowed=False,
                decision="review",
                reason="Human approval required by tool policy",
                risk_score=max(risk.score, 60),
                metadata=risk.to_dict(),
            )

        # ---------------------------------------------------------
        # Risk decision
        # ---------------------------------------------------------

        if risk.decision == RiskDecision.BLOCK:
            return ToolDecision(
                allowed=False,
                decision="block",
                reason="Risk engine blocked the tool call",
                risk_score=risk.score,
                metadata=risk.to_dict(),
            )

        if risk.decision == RiskDecision.REVIEW:
            return ToolDecision(
                allowed=False,
                decision="review",
                reason="Risk engine requires human approval",
                risk_score=risk.score,
                metadata=risk.to_dict(),
            )

        return ToolDecision(
            allowed=True,
            decision="allow",
            reason="Tool call authorized",
            risk_score=risk.score,
            metadata=risk.to_dict(),
        )
