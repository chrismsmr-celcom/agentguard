from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field

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
            check_name=self.check_name, passed=self.passed,
            risk_level=self.risk_level.value, details=self.details,
            metadata=self.metadata, action=self.action.value,
        )

class SecurityException(Exception):
    """Exception levée lorsqu'une opération est bloquée par AgentGuard."""
    pass

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
