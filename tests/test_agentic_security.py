import pytest

from tool_guard import ToolGuard, ToolPolicy, ToolRequest
from trajectory import (
    TrajectoryAnalyzer,
    TrajectoryEvent,
)


def test_unknown_tool_is_denied():

    guard = ToolGuard([])

    result = guard.authorize(
        ToolRequest(
            tool_name="unknown_tool",
            identity="agent",
            arguments={},
        )
    )

    assert result.allowed is False
    assert result.decision == "block"


def test_identity_cannot_use_unauthorized_tool():

    guard = ToolGuard([
        ToolPolicy(
            name="database_write",
            category="database_write",
            allowed_identities={"admin-agent"},
        )
    ])

    result = guard.authorize(
        ToolRequest(
            tool_name="database_write",
            identity="research-agent",
            arguments={},
        )
    )

    assert result.allowed is False
    assert result.decision == "block"


def test_malicious_data_cannot_reach_tool():

    guard = ToolGuard([
        ToolPolicy(
            name="send_email",
            category="email",
            allowed_identities={"support-agent"},
            external_side_effect=True,
        )
    ])

    result = guard.authorize(
        ToolRequest(
            tool_name="send_email",
            identity="support-agent",
            arguments={
                "to": "attacker@example.com"
            },
            taint_level="MALICIOUS",
        )
    )

    assert result.allowed is False
    assert result.decision == "block"


def test_sensitive_external_action_requires_review():

    guard = ToolGuard([
        ToolPolicy(
            name="send_email",
            category="email",
            allowed_identities={"support-agent"},
            external_side_effect=True,
            require_approval=True,
        )
    ])

    result = guard.authorize(
        ToolRequest(
            tool_name="send_email",
            identity="support-agent",
            arguments={
                "body": "confidential information"
            },
            taint_level="CONFIDENTIAL",
        )
    )

    assert result.allowed is False
    assert result.decision == "review"


def test_trajectory_detects_exfiltration_pattern():

    trajectory = TrajectoryAnalyzer()

    trajectory.add(
        TrajectoryEvent(
            event_type="user_input",
            taint_level="UNTRUSTED",
        )
    )

    trajectory.add(
        TrajectoryEvent(
            event_type="tool_call",
            tool_name="read_database",
            taint_level="CONFIDENTIAL",
        )
    )

    trajectory.add(
        TrajectoryEvent(
            event_type="tool_call",
            tool_name="send_email",
            taint_level="CONFIDENTIAL",
            metadata={
                "external_side_effect": True,
            },
        )
    )

    result = trajectory.analyze()

    assert result["privilege_escalation"] is True
    assert result["decision"] == "block"
