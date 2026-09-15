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

HITL lifecycle:
    REQUIRE_APPROVAL -> persisted approval request -> human decision
    -> APPROVED retry -> ALLOW

The guard never executes a tool itself. It only authorizes or rejects
execution before the caller performs the actual side effect.
"""

from __future__ import annotations

import hashlib
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

    def __init__(self, reason: str, approval_id: Optional[str] = None):
        super().__init__(reason)
        self.reason = reason
        self.approval_id = approval_id


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

    org_id: str = ""

    tenant_id: str = ""

    trace_id: str = ""

    span_id: str = ""

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


def _arguments_hash(arguments: Any) -> str:
    """
    Create a deterministic hash of tool arguments.

    The hash binds an approval to the exact arguments that were reviewed.
    """

    payload = json.dumps(
        arguments if arguments is not None else {},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")

    return hashlib.sha256(payload).hexdigest()


def _approval_matches_request(
    approval: dict[str, Any],
    request: ToolRequest,
) -> bool:
    """
    Ensure an approval cannot be replayed for another action.
    """

    if approval.get("status") != "approved":
        return False

    if approval.get("tool_name") != request.tool_name:
        return False

    expected_agent = request.agent_id or request.identity

    if (
        approval.get("agent_id")
        and approval.get("agent_id") != expected_agent
    ):
        return False

    if (
        approval.get("session_id")
        and approval.get("session_id") != request.session_id
    ):
        return False

    approved_hash = approval.get("arguments_hash")

    if (
        approved_hash
        and approved_hash != _arguments_hash(request.arguments)
    ):
        return False

    return True


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
    # Approved retry
    # -------------------------------------------------------------

    def _approved_retry(
        self,
        request: ToolRequest,
    ) -> Optional[ToolDecision]:
        """
        Validate a previously approved request.

        The approval is bound to:
        - organization
        - tool
        - agent
        - session
        - exact arguments
        """

        approval_id = request.metadata.get(
            "approval_id"
        )

        if not approval_id:
            return None

        from collector.approvals import get_approval

        approval = get_approval(
            str(approval_id),
            org_id=request.org_id or None,
        )

        if approval is None:

            return ToolDecision(
                allowed=False,
                decision="block",
                reason="Approval request was not found",
                risk_score=100,
                metadata={
                    "reason_code": "approval_not_found",
                    "approval_id": approval_id,
                },
            )

        if not _approval_matches_request(
            approval,
            request,
        ):

            return ToolDecision(
                allowed=False,
                decision="block",
                reason="Approval does not match this tool request",
                risk_score=100,
                metadata={
                    "reason_code": "approval_mismatch",
                    "approval_id": approval_id,
                },
            )

        return ToolDecision(
            allowed=True,
            decision="allow",
            reason="Human approval granted",
            risk_score=0.0,
            metadata={
                "reason_code": "human_approval",
                "approval_id": approval_id,
                "approved_by": approval.get(
                    "decided_by"
                ),
            },
        )

    # -------------------------------------------------------------
    # Approval persistence
    # -------------------------------------------------------------

    def _create_or_reuse_approval(
        self,
        request: ToolRequest,
        decision: ToolDecision,
    ) -> ToolDecision:
        """
        Persist a pending approval.

        If the same request is already pending, reuse its approval ID
        instead of creating duplicate approval requests.
        """

        from collector.approvals import (
            create_approval,
            list_approvals,
        )

        argument_hash = _arguments_hash(
            request.arguments
        )

        agent_id = (
            request.agent_id
            or request.identity
        )

        # Avoid approval spam when an agent retries while
        # the human is still deciding.
        try:

            pending = list_approvals(
                org_id=request.org_id or None,
                status="pending",
                limit=200,
            )

            for approval in pending:

                if (
                    approval.get("tool_name")
                    == request.tool_name
                    and approval.get("agent_id")
                    == agent_id
                    and approval.get("session_id")
                    == request.session_id
                    and approval.get("arguments_hash")
                    == argument_hash
                ):

                    approval_id = approval.get(
                        "approval_id"
                    )

                    return ToolDecision(
                        allowed=False,
                        decision="require_approval",
                        reason=decision.reason,
                        risk_score=decision.risk_score,
                        metadata={
                            **decision.metadata,
                            "approval_id": approval_id,
                            "approval_status": "pending",
                            "arguments_hash": argument_hash,
                        },
                    )

        except Exception:
            # Persistence errors are handled below.
            pass

        approval = create_approval(
            tool_name=request.tool_name,
            arguments=request.arguments,
            org_id=request.org_id or None,
            tenant_id=request.tenant_id or None,
            agent_id=agent_id,
            session_id=request.session_id or None,
            trace_id=request.trace_id or None,
            span_id=request.span_id or None,
            risk_score=decision.risk_score,
            reason=decision.reason,
            policy_name=request.tool_name,
        )

        approval_id = approval[
            "approval_id"
        ]

        return ToolDecision(
            allowed=False,
            decision="require_approval",
            reason=decision.reason,
            risk_score=decision.risk_score,
            metadata={
                **decision.metadata,
                "approval_id": approval_id,
                "approval_status": "pending",
                "arguments_hash": argument_hash,
            },
        )

    # -------------------------------------------------------------
    # Authorization
    # -------------------------------------------------------------

    def authorize(
        self,
        request: ToolRequest,
    ) -> ToolDecision:

        # A previously approved action can be retried.
        #
        # This check happens before the normal policy evaluation so
        # the human approval becomes the explicit authorization for
        # this exact action.
        if request.metadata.get(
            "approval_id"
        ):

            return self._approved_retry(
                request
            )

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
                "policy": "tool_guard",
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
        # BLOCK
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

        # ---------------------------------------------------------
        # REQUIRE APPROVAL
        # ---------------------------------------------------------

        if (
            result.decision
            == Decision.REQUIRE_APPROVAL
        ):

            base_decision = ToolDecision(
                allowed=False,
                decision="require_approval",
                reason="; ".join(
                    result.reasons
                ),
                risk_score=result.risk_score,
                metadata=result.to_dict(),
            )

            try:

                return (
                    self._create_or_reuse_approval(
                        request,
                        base_decision,
                    )
                )

            except Exception as exc:

                # Fail closed:
                # if the approval cannot be persisted,
                # the side effect must not happen.
                return ToolDecision(
                    allowed=False,
                    decision="block",
                    reason=(
                        "Approval could not be "
                        "persisted; action blocked"
                    ),
                    risk_score=100,
                    metadata={
                        "reason_code": (
                            "approval_persistence_failure"
                        ),
                        "error": str(exc)[:200],
                    },
                )

        # ---------------------------------------------------------
        # ALLOW
        # ---------------------------------------------------------

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
                decision.reason,
                approval_id=decision.metadata.get(
                    "approval_id"
                ),
            )

        return decision
