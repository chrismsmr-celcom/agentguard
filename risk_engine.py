"""
AgentGuard Risk Engine
----------------------
Calcul déterministe du risque d'une action agentique.

Principe:
    risk = model_signal
         + tool_risk
         + taint_risk
         + trajectory_risk
         + identity_risk
         + anomaly_risk

Le modèle n'est JAMAIS l'autorité finale.
Le RiskEngine produit une décision indépendante.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List


class RiskDecision(str, Enum):
    ALLOW = "allow"
    REVIEW = "review"
    BLOCK = "block"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class RiskInput:
    tool_name: str = ""
    tool_category: str = "read"

    # Score venant du moteur ML / Triple Judge.
    model_score: float = 0.0

    # Taint maximum des données utilisées par l'action.
    taint_level: str = "PUBLIC"

    # Nombre d'actions effectuées dans la trajectoire.
    trajectory_length: int = 0

    # Actions dangereuses précédentes.
    previous_risky_actions: int = 0

    # Identité / privilèges.
    identity_trusted: bool = False

    # Action externe: email, payment, API externe, etc.
    external_side_effect: bool = False

    # Action irréversible.
    irreversible: bool = False

    # Détection d'anomalie comportementale.
    anomaly_score: float = 0.0

    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RiskResult:
    score: float
    level: RiskLevel
    decision: RiskDecision
    reasons: List[str]
    factors: Dict[str, float]

    def to_dict(self):
        return {
            "score": self.score,
            "level": self.level.value,
            "decision": self.decision.value,
            "reasons": self.reasons,
            "factors": self.factors,
        }


class RiskEngine:
    """
    Moteur de décision indépendant du LLM.

    IMPORTANT:
    Un LLM peut proposer une action.
    Le RiskEngine décide si cette action est autorisée.
    """

    TOOL_RISK = {
        "read": 5,
        "search": 5,
        "database_read": 10,
        "write": 30,
        "database_write": 45,
        "filesystem_write": 45,
        "network": 35,
        "email": 55,
        "delete": 70,
        "shell": 85,
        "admin": 90,
        "payment": 95,
    }

    TAINT_RISK = {
        "PUBLIC": 0,
        "INTERNAL": 10,
        "CONFIDENTIAL": 25,
        "SECRET": 50,
        "UNTRUSTED": 55,
        "MALICIOUS": 100,
    }

    def evaluate(self, data: RiskInput) -> RiskResult:
        score = 0.0
        reasons = []
        factors = {}

        # ---------------------------------------------------------
        # 1. Tool risk
        # ---------------------------------------------------------

        tool_risk = self.TOOL_RISK.get(
            data.tool_category.lower(),
            50,
        )

        factors["tool_risk"] = tool_risk
        score += tool_risk * 0.30

        if tool_risk >= 70:
            reasons.append(
                f"High-risk tool category: {data.tool_category}"
            )

        # ---------------------------------------------------------
        # 2. Model / detection signal
        # ---------------------------------------------------------

        model_score = max(
            0.0,
            min(100.0, data.model_score),
        )

        factors["model_score"] = model_score
        score += model_score * 0.25

        if model_score >= 70:
            reasons.append("Security model detected elevated risk")

        # ---------------------------------------------------------
        # 3. Taint
        # ---------------------------------------------------------

        taint = data.taint_level.upper()

        taint_score = self.TAINT_RISK.get(
            taint,
            50,
        )

        factors["taint_risk"] = taint_score
        score += taint_score * 0.20

        if taint in {"SECRET", "UNTRUSTED", "MALICIOUS"}:
            reasons.append(
                f"Sensitive/untrusted data classification: {taint}"
            )

        # ---------------------------------------------------------
        # 4. Trajectory
        # ---------------------------------------------------------

        trajectory_score = min(
            100,
            data.trajectory_length * 3
            + data.previous_risky_actions * 12,
        )

        factors["trajectory_risk"] = trajectory_score
        score += trajectory_score * 0.10

        if data.previous_risky_actions >= 2:
            reasons.append(
                "Multiple risky actions detected in trajectory"
            )

        # ---------------------------------------------------------
        # 5. External side effect
        # ---------------------------------------------------------

        if data.external_side_effect:
            factors["external_side_effect"] = 80
            score += 80 * 0.10

            reasons.append(
                "Action produces an external side effect"
            )
        else:
            factors["external_side_effect"] = 0

        # ---------------------------------------------------------
        # 6. Irreversible operation
        # ---------------------------------------------------------

        if data.irreversible:
            factors["irreversible"] = 100
            score += 100 * 0.15

            reasons.append(
                "Action is irreversible"
            )
        else:
            factors["irreversible"] = 0

        # ---------------------------------------------------------
        # 7. Identity
        # ---------------------------------------------------------

        if not data.identity_trusted:
            factors["identity_risk"] = 50
            score += 50 * 0.10

            reasons.append(
                "Agent identity is not trusted"
            )
        else:
            factors["identity_risk"] = 0

        # ---------------------------------------------------------
        # 8. Anomaly
        # ---------------------------------------------------------

        anomaly = max(
            0,
            min(100, data.anomaly_score),
        )

        factors["anomaly_risk"] = anomaly
        score += anomaly * 0.10

        if anomaly >= 70:
            reasons.append(
                "Behavioral anomaly detected"
            )

        score = min(100.0, round(score, 2))

        # ---------------------------------------------------------
        # FINAL DECISION
        # ---------------------------------------------------------

        if taint == "MALICIOUS":
            decision = RiskDecision.BLOCK
            level = RiskLevel.CRITICAL

        elif data.irreversible and score >= 45:
            decision = RiskDecision.REVIEW
            level = RiskLevel.HIGH

        elif data.external_side_effect and score >= 65:
            decision = RiskDecision.REVIEW
            level = RiskLevel.HIGH

        elif score >= 80:
            decision = RiskDecision.BLOCK
            level = RiskLevel.CRITICAL

        elif score >= 60:
            decision = RiskDecision.REVIEW
            level = RiskLevel.HIGH

        elif score >= 35:
            decision = RiskDecision.REVIEW
            level = RiskLevel.MEDIUM

        else:
            decision = RiskDecision.ALLOW
            level = RiskLevel.LOW

        return RiskResult(
            score=score,
            level=level,
            decision=decision,
            reasons=reasons,
            factors=factors,
        )
