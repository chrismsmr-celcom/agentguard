"""
AgentGuard Trajectory Security

Analyse la trajectoire complète d'un agent.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any


@dataclass
class TrajectoryEvent:
    event_type: str
    tool_name: str = ""
    taint_level: str = "PUBLIC"
    risk_score: float = 0.0
    blocked: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


class TrajectoryAnalyzer:

    def __init__(self):
        self.events: List[TrajectoryEvent] = []

    def add(self, event: TrajectoryEvent):
        self.events.append(event)

    @property
    def length(self):
        return len(self.events)

    def risky_actions(self):

        return [
            event
            for event in self.events
            if event.risk_score >= 50
            or event.blocked
        ]

    def has_external_input(self):

        return any(
            event.taint_level.upper() == "UNTRUSTED"
            for event in self.events
        )

    def has_sensitive_data(self):

        return any(
            event.taint_level.upper()
            in {"CONFIDENTIAL", "SECRET", "MALICIOUS"}
            for event in self.events
        )

    def detect_escalation(self) -> bool:
        """
        Détecte un pattern classique:

        untrusted input
            ↓
        tool call
            ↓
        sensitive data
            ↓
        external side effect
        """

        untrusted_seen = False
        sensitive_seen = False

        for event in self.events:

            if event.taint_level.upper() == "UNTRUSTED":
                untrusted_seen = True

            if (
                untrusted_seen
                and event.taint_level.upper()
                in {"CONFIDENTIAL", "SECRET"}
            ):
                sensitive_seen = True

            if (
                sensitive_seen
                and event.metadata.get("external_side_effect")
            ):
                return True

        return False

    def analyze(self):

        risky = self.risky_actions()

        escalation = self.detect_escalation()

        score = 0

        score += min(
            30,
            len(risky) * 10,
        )

        if self.has_external_input():
            score += 15

        if self.has_sensitive_data():
            score += 20

        if escalation:
            score += 40

        score = min(100, score)

        if escalation or score >= 80:
            decision = "block"

        elif score >= 50:
            decision = "review"

        else:
            decision = "allow"

        return {
            "trajectory_length": self.length,
            "risky_actions": len(risky),
            "external_input": self.has_external_input(),
            "sensitive_data": self.has_sensitive_data(),
            "privilege_escalation": escalation,
            "trajectory_risk_score": score,
            "decision": decision,
        }
