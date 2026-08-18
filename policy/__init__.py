"""
AgentGuard Policy Engine — Zero-Trust authorization for AI agents.

Usage:
    from policy import PolicyEngine
    
    engine = PolicyEngine(policies_dir="./policies")
    decision = engine.evaluate_tool_call(
        agent_id="finance-agent",
        tool_name="send_email",
        params={"to": "client@acme.com", "body": "Hello"},
    )
    
    if decision.is_allowed():
        # execute tool
        pass
    elif decision.is_denied():
        raise SecurityException(decision.reason)
"""

from .models import (
    Policy,
    PolicyDecision,
    Decision,
    Capabilities,
    ToolCapabilities,
    FilesystemCapabilities,
    NetworkCapabilities,
    BudgetLimits,
    Rule,
    FailureMode,
)
from .loader import PolicyLoader
from .engine import PolicyEngine

__all__ = [
    "Policy",
    "PolicyDecision",
    "Decision",
    "Capabilities",
    "ToolCapabilities",
    "FilesystemCapabilities",
    "NetworkCapabilities",
    "BudgetLimits",
    "Rule",
    "FailureMode",
    "PolicyLoader",
    "PolicyEngine",
]
