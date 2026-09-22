from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field

# ==============================================================================
# ENUMS
# ==============================================================================

class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class SecurityAction(Enum):
    ALLOW = "allow"
    BLOCK = "block"
    REDACT = "redact"
    REVIEW = "review"

class DetectionConfidence(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

# ==============================================================================
# PYDANTIC MODELS (Pour la sérialisation vers le Collector)
# ==============================================================================

class SecurityCheckModel(BaseModel):
    check_name: str
    passed: bool
    risk_level: str
    details: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    action: str = "allow"

class SpanPayload(BaseModel):
    trace_id: str = Field(..., max_length=64)
    span_id: str = Field(..., max_length=64)
    span_type: str
    timestamp: float
    latency_ms: float = Field(..., ge=0)
    input_data: Dict[str, Any]
    output_data: Dict[str, Any]
    security_checks: List[SecurityCheckModel]
    blocked: bool = False
    block_reason: Optional[str] = None
    cost_usd: float = Field(..., ge=0)
    input_tokens: int = Field(0, ge=0)
    output_tokens: int = Field(0, ge=0)

# ==============================================================================
# DATACLASSES (Pour la logique interne du SDK)
# ==============================================================================

@dataclass
class SecurityCheck:
    check_name: str
    passed: bool
    risk_level: RiskLevel
    details: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    action: SecurityAction = SecurityAction.ALLOW

    def to_model(self) -> SecurityCheckModel:
        return SecurityCheckModel(
            check_name=self.check_name, 
            passed=self.passed,
            risk_level=self.risk_level.value, 
            details=self.details,
            metadata=self.metadata, 
            action=self.action.value,
        )

@dataclass
class RuntimeRiskDecision:
    action: str
    risk_score: float
    risk_level: RiskLevel
    reasons: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.action == "ALLOW"

@dataclass
class TrajectoryEvent:
    timestamp: float
    event_type: str
    tool_name: Optional[str] = None
    taint_level: Optional[str] = None
    external: bool = False
    irreversible: bool = False
    risk_score: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class GuardSpan:
    span_id: str
    trace_id: str
    span_type: str
    timestamp: float
    latency_ms: float
    input_data: Dict[str, Any]
    output_data: Dict[str, Any]
    security_checks: List[SecurityCheck] = field(default_factory=list)
    blocked: bool = False
    block_reason: Optional[str] = None
    cost_usd: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0

# ==============================================================================
# EXCEPTIONS
# ==============================================================================

class SecurityException(Exception):
    """Exception levée lorsqu'une opération est bloquée par AgentGuard."""
    pass

class AgentDisconnectedException(SecurityException):
    """Levée quand l'agent a été déconnecté depuis le dashboard Cerbere (kill switch)."""
    pass

class ApprovalRequiredException(Exception):
    """
    Exception levée lorsqu'une opération nécessite une approbation humaine (Human-in-the-Loop).
    Utilisé pour les cas de DLP (Data Loss Prevention) où l'action n'est ni bloquée brutalement, 
    ni autorisée aveuglément.
    """
    def __init__(self, message: str, approval_id: str, details: Dict[str, Any], timed_out: bool = False):
        super().__init__(message)
        self.approval_id = approval_id
        self.details = details
        self.timed_out = timed_out  # True si guard_tool_call(..., wait_for_approval=True) a expiré sans décision


class ApprovalRejectedException(SecurityException):
    """Levée quand un humain a explicitement REJETÉ la demande (pas juste "en attente")."""
    def __init__(self, message: str, approval_id: str, resolved_by: Optional[str] = None):
        super().__init__(message)
        self.approval_id = approval_id
        self.resolved_by = resolved_by


