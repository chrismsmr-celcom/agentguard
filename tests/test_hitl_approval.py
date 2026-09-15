import os

import pytest

from collector.approvals import (
    APPROVED,
    PENDING,
    REJECTED,
    approve_approval,
    create_approval,
    get_approval,
    reject_approval,
)

from tool_guard import (
    ApprovalRequired,
    ToolGuard,
    ToolPolicy,
    ToolRequest,
)


@pytest.fixture
def approval_db(tmp_path, monkeypatch):
    db_path = tmp_path / "hitl.db"

    monkeypatch.setenv(
        "AGENTGUARD_DB_PATH",
        str(db_path),
    )

    monkeypatch.setenv(
        "AGENTGUARD_DB_TYPE",
        "sqlite",
    )

    return db_path


def test_create_approval_is_pending(
    approval_db,
):

    approval = create_approval(
        tool_name="send_email",
        arguments={
            "to": "user@example.com",
            "subject": "Test",
        },
        org_id="org-1",
        agent_id="agent-1",
        session_id="session-1",
        reason="External side effect requires approval",
    )

    assert approval["approval_id"].startswith(
        "apr_"
    )

    assert approval["status"] == PENDING

    assert approval["tool_name"] == (
        "send_email"
    )


def test_approval_can_be_approved(
    approval_db,
):

    approval = create_approval(
        tool_name="payment",
        arguments={
            "amount": 1000,
        },
        org_id="org-1",
        agent_id="agent-1",
    )

    result = approve_approval(
        approval["approval_id"],
        org_id="org-1",
        decided_by="user-123",
        decision_reason="Approved by finance",
    )

    assert result["status"] == APPROVED

    assert result["decided_by"] == (
        "user-123"
    )


def test_approval_can_be_rejected(
    approval_db,
):

    approval = create_approval(
        tool_name="delete_database",
        arguments={},
        org_id="org-1",
        agent_id="agent-1",
    )

    result = reject_approval(
        approval["approval_id"],
        org_id="org-1",
        decided_by="user-123",
        decision_reason="Not authorized",
    )

    assert result["status"] == REJECTED


def test_tool_guard_creates_pending_approval(
    approval_db,
):

    guard = ToolGuard(
        policies=[
            ToolPolicy(
                name="send_email",
                allowed_identities={
                    "agent-1"
                },
                category="email",
                external_side_effect=True,
                require_approval=True,
            )
        ]
    )

    request = ToolRequest(
        tool_name="send_email",
        identity="agent-1",
        agent_id="agent-1",
        session_id="session-1",
        org_id="org-1",
        arguments={
            "to": "user@example.com",
        },
    )

    decision = guard.authorize(
        request
    )

    assert decision.allowed is False

    assert (
        decision.decision
        == "require_approval"
    )

    approval_id = decision.metadata.get(
        "approval_id"
    )

    assert approval_id

    approval = get_approval(
        approval_id,
        org_id="org-1",
    )

    assert approval is not None

    assert approval["status"] == PENDING


def test_approved_action_can_be_retried(
    approval_db,
):

    guard = ToolGuard(
        policies=[
            ToolPolicy(
                name="payment",
                allowed_identities={
                    "agent-1"
                },
                category="payment",
                external_side_effect=True,
                require_approval=True,
            )
        ]
    )

    original_request = ToolRequest(
        tool_name="payment",
        identity="agent-1",
        agent_id="agent-1",
        session_id="session-1",
        org_id="org-1",
        arguments={
            "amount": 100,
        },
    )

    first = guard.authorize(
        original_request
    )

    assert (
        first.decision
        == "require_approval"
    )

    approval_id = first.metadata[
        "approval_id"
    ]

    approve_approval(
        approval_id,
        org_id="org-1",
        decided_by="user-123",
    )

    retry_request = ToolRequest(
        tool_name="payment",
        identity="agent-1",
        agent_id="agent-1",
        session_id="session-1",
        org_id="org-1",
        arguments={
            "amount": 100,
        },
        metadata={
            "approval_id": approval_id,
        },
    )

    second = guard.authorize(
        retry_request
    )

    assert second.allowed is True

    assert second.decision == "allow"

    assert (
        second.metadata["reason_code"]
        == "human_approval"
    )


def test_approved_action_cannot_change_arguments(
    approval_db,
):

    guard = ToolGuard(
        policies=[
            ToolPolicy(
                name="payment",
                allowed_identities={
                    "agent-1"
                },
                category="payment",
                external_side_effect=True,
                require_approval=True,
            )
        ]
    )

    original_request = ToolRequest(
        tool_name="payment",
        identity="agent-1",
        agent_id="agent-1",
        session_id="session-1",
        org_id="org-1",
        arguments={
            "amount": 100,
        },
    )

    first = guard.authorize(
        original_request
    )

    approval_id = first.metadata[
        "approval_id"
    ]

    approve_approval(
        approval_id,
        org_id="org-1",
        decided_by="user-123",
    )

    modified_request = ToolRequest(
        tool_name="payment",
        identity="agent-1",
        agent_id="agent-1",
        session_id="session-1",
        org_id="org-1",
        arguments={
            "amount": 10000,
        },
        metadata={
            "approval_id": approval_id,
        },
    )

    decision = guard.authorize(
        modified_request
    )

    assert decision.allowed is False

    assert decision.decision == "block"

    assert (
        decision.metadata["reason_code"]
        == "approval_mismatch"
    )


def test_approval_is_single_use_decision(
    approval_db,
):

    approval = create_approval(
        tool_name="send_email",
        arguments={},
        org_id="org-1",
        agent_id="agent-1",
    )

    approve_approval(
        approval["approval_id"],
        org_id="org-1",
        decided_by="user-123",
    )

    with pytest.raises(ValueError):
        reject_approval(
            approval["approval_id"],
            org_id="org-1",
            decided_by="user-456",
        )
