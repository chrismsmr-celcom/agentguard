"""Pydantic schemas for strict input validation."""
from decimal import Decimal, InvalidOperation
from typing import Optional
from pydantic import BaseModel, Field, field_validator


class AgentCreateRequest(BaseModel):
    """Validation stricte pour création d'agent."""
    name: str = Field(..., min_length=2, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    max_budget_per_day: float = Field(100.0, ge=0, le=10000)
    org_id: Optional[str] = None
    
    @field_validator("max_budget_per_day")
    @classmethod
    def validate_budget(cls, v):
        # Reject NaN, Infinity, subnormal
        d = Decimal(str(v))
        if not d.is_finite():
            raise ValueError("max_budget_per_day must be finite (no NaN/Infinity)")
        if d < 0 or d > 10000:
            raise ValueError("max_budget_per_day must be between 0 and 10000")
        return float(d)
    
    @field_validator("name")
    @classmethod
    def validate_name(cls, v):
        # Prevent injection via name
        if any(c in v for c in ['<', '>', '"', "'", ';', '`', '$']):
            raise ValueError("name contains forbidden characters")
        return v.strip()


class UserCreateRequest(BaseModel):
    """Validation stricte pour création d'utilisateur."""
    email: str = Field(..., min_length=3, max_length=255)
    display_name: Optional[str] = Field(None, max_length=100)
    role: str = Field("viewer")
    org_id: Optional[str] = None
    
    @field_validator("email")
    @classmethod
    def validate_email(cls, v):
        v = v.lower().strip()
        if "@" not in v or "." not in v.split("@")[-1]:
            raise ValueError("invalid email format")
        if len(v) > 255:
            raise ValueError("email too long")
        return v
    
    @field_validator("role")
    @classmethod
    def validate_role(cls, v):
        from identity import Role
        try:
            Role(v)
        except ValueError:
            raise ValueError(f"invalid role: must be one of {[r.value for r in Role]}")
        return v


class OrgCreateRequest(BaseModel):
    """Validation pour création d'org."""
    name: str = Field(..., min_length=2, max_length=64)
    tenant_id: Optional[str] = None
    
    @field_validator("name")
    @classmethod
    def validate_name(cls, v):
        if any(c in v for c in ['<', '>', '"', "'", ';', '`']):
            raise ValueError("name contains forbidden characters")
        return v.strip()


class SpanIngestRequest(BaseModel):
    """Validation du payload /span — rejette les payloads malformés."""
    trace_id: str = Field(..., min_length=1, max_length=64)
    span_id: str = Field(..., min_length=1, max_length=64)
    span_type: str = Field(..., min_length=1, max_length=64)
    timestamp: float
    latency_ms: float = Field(..., ge=0, le=3600000)
    cost_usd: float = Field(0.0, ge=0, le=1000000)
    input_tokens: int = Field(0, ge=0, le=1000000000)
    output_tokens: int = Field(0, ge=0, le=1000000000)
    
    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, v):
        d = Decimal(str(v))
        if not d.is_finite():
            raise ValueError("timestamp must be finite")
        return float(d)
    
    @field_validator("latency_ms", "cost_usd")
    @classmethod
    def validate_finite(cls, v):
        d = Decimal(str(v))
        if not d.is_finite():
            raise ValueError("numeric fields must be finite")
        return float(d)
