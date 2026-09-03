"""
Cerbere / AgentGuard — Zero Trust Tool Guard

All tool execution passes through DecisionEngine.

Unknown tool:
    BLOCK

Unauthorized identity:
    BLOCK

Malicious taint:
    BLOCK

High-risk:
    BLOCK

Policy requiring approval:
    REQUIRE_APPROVAL

Safe:
    ALLOW
"""

from __future__ import annotations

import json

from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Set

from decision_engine import (
    Decision,
    DecisionEngine,
    DecisionRequest,
    PolicyRule,
)


class ToolBlocked(Exception):
    """Raised when AgentGuard blocks a tool call."""


class ApprovalRequired(Exception):
    """Raised when human approval is required."""


@dataclass
class ToolPolicy:
    name: str

    allowed_identities: Set[str] = field(
        default_factory=set
    )

    category: str = "read"

    read_only: bool = True

    external_side_effect: bool = False

    irreversible: bool = False

    require_approval: bool = False

    max_argument_bytes: int = 50_000

    blocked: bool = False


@dataclass
class ToolRequest:
    tool_name: str

    identity: str

    arguments: Dict[str, Any]

    model_score: float = 0.0

    anomaly_score: float = 0.0

    taint_level: str = "PUBLIC"

    trajectory_length: int = 0

    previous_risky_actions: int = 0

    agent_id: str = ""

    session_id: str = ""

    metadata: Dict[str, Any] = field(
        default_factory=dict
    )


@dataclass
class ToolDecision:
    allowed: bool

    decision: str

    reason: str

    risk_score: float

    metadata: Dict[str, Any] = field(
        default_factory=dict
    )

    @property
    def requires_approval(self) -> bool:
        return self.decision == "require_approval"


class ToolGuard:

    def __init__(
        self,
        policies=None,
    ):

        self.policies: Dict[str, ToolPolicy] = {
            policy.name: policy
            for policy in (
                policies or []
            )
        }

        self.decision_engine = DecisionEngine()

        self._sync_engine_policies()

    # -------------------------------------------------------------
    # Policy registration
    # -------------------------------------------------------------

    def _sync_engine_policies(self):

        allowed_tools = set(
            self.policies.keys()
        )

        blocked_tools = {
            name
            for name, policy
            in self.policies.items()
            if policy.blocked
        }

        approval_tools = {
            name
            for name, policy
            in self.policies.items()
            if policy.require_approval
        }

        self.decision_engine.register_policy(
            PolicyRule(
                name="tool_guard",
                allowed_tools=allowed_tools,
                blocked_tools=blocked_tools,
                require_approval_for=approval_tools,
                allow_unknown_tools=False,
            )
        )

    def register(
        self,
        policy: ToolPolicy,
    ) -> None:

        self.policies[policy.name] = policy

        self._sync_engine_policies()

    # -------------------------------------------------------------
    # Authorization
    # -------------------------------------------------------------

    def authorize(
        self,
        request: ToolRequest,
    ) -> ToolDecision:

        policy = self.policies.get(
            request.tool_name
        )

        # ---------------------------------------------------------
        # Unknown tool
        # ---------------------------------------------------------

        if policy is None:

            return ToolDecision(
                allowed=False,
                decision="block",
                reason=(
                    "Tool is not registered "
                    "in AgentGuard policy"
                ),
                risk_score=100,
                metadata={
                    "reason_code": "tool",
                    "tool": request.tool_name,
                },
            )

        # ---------------------------------------------------------
        # Identity
        # ---------------------------------------------------------

        if (
            policy.allowed_identities
            and request.identity
            not in policy.allowed_identities
        ):

            return ToolDecision(
                allowed=False,
                decision="block",
                reason=(
                    "Agent identity is not "
                    "authorized for this tool"
                ),
                risk_score=100,
                metadata={
                    "reason_code": "identity",
                    "tool": request.tool_name,
                    "identity": request.identity,
                },
            )

        # ---------------------------------------------------------
        # Serialize arguments safely
        # ---------------------------------------------------------

        try:

            serialized = json.dumps(
                request.arguments,
                default=str,
                ensure_ascii=False,
            )

            argument_size = len(
                serialized.encode("utf-8")
            )

        except Exception:

            return ToolDecision(
                allowed=False,
                decision="block",
                reason=(
                    "Tool arguments could not "
                    "be serialized safely"
                ),
                risk_score=100,
                metadata={
                    "reason_code": "validation"
                },
            )

        # ---------------------------------------------------------
        # Argument size
        # ---------------------------------------------------------

        if (
            argument_size
            > policy.max_argument_bytes
        ):

            return ToolDecision(
                allowed=False,
                decision="block",
                reason=(
                    "Tool argument size exceeds "
                    "policy limit"
                ),
                risk_score=90,
                metadata={
                    "reason_code": "argument_size",
                    "argument_bytes": argument_size,
                    "limit": policy.max_argument_bytes,
                },
            )

        # ---------------------------------------------------------
        # Unified decision engine
        # ---------------------------------------------------------

        metadata = dict(
            request.metadata
        )

        metadata.update(
            {
                "tool_category": policy.category,
                "session_id": request.session_id,
            }
        )

        result = (
            self.decision_engine.evaluate(
                DecisionRequest(
                    agent_id=(
                        request.agent_id
                        or request.identity
                    ),
                    tool_name=request.tool_name,
                    tool_category=policy.category,
                    identity_trusted=True,
                    model_score=request.model_score,
                    anomaly_score=request.anomaly_score,
                    taint_level=request.taint_level,
                    trajectory_length=(
                        request.trajectory_length
                    ),
                    previous_risky_actions=(
                        request.previous_risky_actions
                    ),
                    external_side_effect=(
                        policy.external_side_effect
                    ),
                    irreversible=(
                        policy.irreversible
                    ),
                    tool_registered=True,
                    metadata=metadata,
                )
            )
        )

        # ---------------------------------------------------------
        # Convert decision
        # ---------------------------------------------------------

        if result.decision == Decision.BLOCK:

            return ToolDecision(
                allowed=False,
                decision="block",
                reason="; ".join(
                    result.reasons
                ),
                risk_score=result.risk_score,
                metadata=result.to_dict(),
            )

        if (
            result.decision
            == Decision.REQUIRE_APPROVAL
        ):

            return ToolDecision(
                allowed=False,
                decision="require_approval",
                reason="; ".join(
                    result.reasons
                ),
                risk_score=result.risk_score,
                metadata=result.to_dict(),
            )

        return ToolDecision(
            allowed=True,
            decision="allow",
            reason="Tool call authorized",
            risk_score=result.risk_score,
            metadata=result.to_dict(),
        )

    # -------------------------------------------------------------
    # Enforcement helper
    # -------------------------------------------------------------

    def enforce(
        self,
        request: ToolRequest,
    ) -> ToolDecision:

        decision = self.authorize(
            request
        )

        if decision.decision == "block":

            raise ToolBlocked(
                decision.reason
            )

        if (
            decision.decision
            == "require_approval"
        ):

            raise ApprovalRequired(
                decision.reason
            )

        return decision
