"""
Cerbere / AgentGuard — Runtime Agent Trajectory

Tracks the complete execution trajectory of an AI agent.

Security model:

    INPUT
      ↓
    TOOL CALL
      ↓
    DATA FLOW
      ↓
    RISK
      ↓
    DECISION
      ↓
    SIDE EFFECT

The trajectory is used as security context, not just observability.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class TrajectoryEvent:
    event_type: str

    tool_name: str = ""

    agent_id: str = ""

    session_id: str = ""

    trace_id: str = ""

    span_id: str = ""

    taint_level: str = "PUBLIC"

    risk_score: float = 0.0

    decision: str = "allow"

    blocked: bool = False

    external_side_effect: bool = False

    irreversible: bool = False

    timestamp: str = field(
        default_factory=lambda: datetime.now(
            timezone.utc
        ).isoformat()
    )

    metadata: Dict[str, Any] = field(default_factory=dict)


class TrajectoryAnalyzer:
    """
    Stateful analyzer for one agent/session trajectory.

    The analyzer intentionally keeps only security metadata.
    Raw secrets should never be stored here.
    """

    def __init__(
        self,
        agent_id: str = "",
        session_id: str = "",
        max_events: int = 500,
    ):
        self.agent_id = agent_id
        self.session_id = session_id
        self.max_events = max(1, max_events)

        self.events: List[TrajectoryEvent] = []

    # -------------------------------------------------------------
    # Event management
    # -------------------------------------------------------------

    def add(
        self,
        event: TrajectoryEvent,
    ) -> None:

        if not event.agent_id:
            event.agent_id = self.agent_id

        if not event.session_id:
            event.session_id = self.session_id

        self.events.append(event)

        # Prevent unbounded memory growth.
        if len(self.events) > self.max_events:
            self.events = self.events[-self.max_events:]

    @property
    def length(self) -> int:
        return len(self.events)

    @property
    def last_event(self) -> Optional[TrajectoryEvent]:
        if not self.events:
            return None

        return self.events[-1]

    # -------------------------------------------------------------
    # Security signals
    # -------------------------------------------------------------

    def risky_actions(self) -> List[TrajectoryEvent]:

        return [
            event
            for event in self.events
            if event.risk_score >= 50
            or event.blocked
            or event.decision in {
                "block",
                "review",
                "require_approval",
            }
        ]

    def blocked_actions(self) -> List[TrajectoryEvent]:

        return [
            event
            for event in self.events
            if event.blocked
            or event.decision == "block"
        ]

    def approval_actions(self) -> List[TrajectoryEvent]:

        return [
            event
            for event in self.events
            if event.decision
            in {
                "review",
                "require_approval",
            }
        ]

    def has_external_input(self) -> bool:

        return any(
            event.taint_level.upper()
            in {
                "UNTRUSTED",
                "MALICIOUS",
            }
            for event in self.events
        )

    def has_sensitive_data(self) -> bool:

        return any(
            event.taint_level.upper()
            in {
                "CONFIDENTIAL",
                "SECRET",
                "MALICIOUS",
            }
            for event in self.events
        )

    # -------------------------------------------------------------
    # Escalation detection
    # -------------------------------------------------------------

    def detect_escalation(self) -> bool:
        """
        Detect:

            untrusted input
                ↓
            sensitive data
                ↓
            external side effect

        This is significantly more dangerous than
        any individual event alone.
        """

        untrusted_seen = False
        sensitive_seen = False

        for event in self.events:

            taint = event.taint_level.upper()

            if taint in {
                "UNTRUSTED",
                "MALICIOUS",
            }:
                untrusted_seen = True

            if (
                untrusted_seen
                and taint in {
                    "CONFIDENTIAL",
                    "SECRET",
                }
            ):
                sensitive_seen = True

            if (
                sensitive_seen
                and event.external_side_effect
            ):
                return True

        return False

    # -------------------------------------------------------------
    # Cross-step privilege escalation
    # -------------------------------------------------------------

    def detect_privilege_escalation(self) -> bool:
        """
        Detect suspicious transition:

            low-risk/read
                ↓
            privileged/admin operation

        after risky input or risky action.
        """

        risky_seen = False

        privileged_categories = {
            "admin",
            "shell",
            "delete",
            "payment",
            "database_write",
        }

        for event in self.events:

            if event.risk_score >= 50:
                risky_seen = True

            category = str(
                event.metadata.get(
                    "tool_category",
                    "",
                )
            ).lower()

            if (
                risky_seen
                and category in privileged_categories
            ):
                return True

        return False

    # -------------------------------------------------------------
    # Repeated risky behavior
    # -------------------------------------------------------------

    def repeated_risky_behavior(
        self,
        minimum: int = 3,
    ) -> bool:

        minimum = max(1, minimum)

        return len(self.risky_actions()) >= minimum

    # -------------------------------------------------------------
    # Trajectory risk
    # -------------------------------------------------------------

    def calculate_risk(self) -> int:

        risky = self.risky_actions()

        score = 0

        # Multiple risky actions.
        score += min(
            30,
            len(risky) * 10,
        )

        if self.has_external_input():
            score += 15

        if self.has_sensitive_data():
            score += 20

        if self.detect_escalation():
            score += 40

        if self.detect_privilege_escalation():
            score += 30

        if self.repeated_risky_behavior(4):
            score += 20

        if self.blocked_actions():
            score += 10

        return min(100, score)

    # -------------------------------------------------------------
    # Final trajectory analysis
    # -------------------------------------------------------------

    def analyze(self) -> Dict[str, Any]:

        risky = self.risky_actions()

        escalation = self.detect_escalation()

        privilege_escalation = (
            self.detect_privilege_escalation()
        )

        score = self.calculate_risk()

        if (
            escalation
            or privilege_escalation
            or score >= 80
        ):
            decision = "block"

        elif score >= 50:
            decision = "require_approval"

        else:
            decision = "allow"

        return {
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "trajectory_length": self.length,
            "risky_actions": len(risky),
            "blocked_actions": len(
                self.blocked_actions()
            ),
            "approval_actions": len(
                self.approval_actions()
            ),
            "external_input": self.has_external_input(),
            "sensitive_data": self.has_sensitive_data(),
            "privilege_escalation": privilege_escalation,
            "trajectory_escalation": escalation,
            "trajectory_risk_score": score,
            "decision": decision,
        }

    # -------------------------------------------------------------
    # Serialization
    # -------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:

        return {
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "events": [
                {
                    "event_type": event.event_type,
                    "tool_name": event.tool_name,
                    "agent_id": event.agent_id,
                    "session_id": event.session_id,
                    "trace_id": event.trace_id,
                    "span_id": event.span_id,
                    "taint_level": event.taint_level,
                    "risk_score": event.risk_score,
                    "decision": event.decision,
                    "blocked": event.blocked,
                    "external_side_effect": event.external_side_effect,
                    "irreversible": event.irreversible,
                    "timestamp": event.timestamp,
                    "metadata": event.metadata,
                }
                for event in self.events
            ],
            "analysis": self.analyze(),
        }
