from .models import (
    RiskLevel, SecurityAction, DetectionConfidence,
    SecurityCheck, SecurityException, ApprovalRequiredException,
    GuardSpan, RuntimeRiskDecision, TrajectoryEvent
)
from .policy import PolicyEngine
from .sdk import AgentGuard


# NOUVEAU : Exception pour le workflow d'approbation humaine
class ApprovalRequiredException(Exception):
    def __init__(self, message: str, approval_id: str, details: dict):
        super().__init__(message)
        self.approval_id = approval_id
        self.details = details

__all__ = [
    "RiskLevel", "SecurityAction", "DetectionConfidence",
    "SecurityCheck", "SecurityException", "ApprovalRequiredException",
    "GuardSpan", "RuntimeRiskDecision", "TrajectoryEvent",
    "PolicyEngine", "AgentGuard"
]
