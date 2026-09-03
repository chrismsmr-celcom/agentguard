from tool_guard import (
    ApprovalRequired,
    ToolBlocked,
    ToolGuard,
    ToolPolicy,
    ToolRequest,
)


def test_unknown_tool_is_blocked():

    guard = ToolGuard()

    decision = guard.authorize(
        ToolRequest(
            tool_name="unknown",
            identity="agent-1",
            arguments={},
        )
    )

    assert decision.allowed is False
    assert decision.decision == "block"


def test_allowed_tool_can_execute():

    guard = ToolGuard(
        policies=[
            ToolPolicy(
                name="search",
                allowed_identities={
                    "agent-1"
                },
                category="search",
            )
        ]
    )

    decision = guard.authorize(
        ToolRequest(
            tool_name="search",
            identity="agent-1",
            arguments={
                "query": "AI security"
            },
            agent_id="agent-1",
        )
    )

    assert decision.allowed is True
    assert decision.decision == "allow"


def test_wrong_identity_is_blocked():

    guard = ToolGuard(
        policies=[
            ToolPolicy(
                name="search",
                allowed_identities={
                    "agent-1"
                },
            )
        ]
    )

    decision = guard.authorize(
        ToolRequest(
            tool_name="search",
            identity="agent-2",
            arguments={},
        )
    )

    assert decision.allowed is False
    assert decision.decision == "block"


def test_secret_email_is_blocked():

    guard = ToolGuard(
        policies=[
            ToolPolicy(
                name="send_email",
                allowed_identities={
                    "agent-1"
                },
                category="email",
                external_side_effect=True,
            )
        ]
    )

    decision = guard.authorize(
        ToolRequest(
            tool_name="send_email",
            identity="agent-1",
            arguments={
                "to": "user@example.com"
            },
            taint_level="SECRET",
            agent_id="agent-1",
        )
    )

    assert decision.allowed is False
    assert decision.decision == "block"


def test_approval_is_enforced():

    guard = ToolGuard(
        policies=[
            ToolPolicy(
                name="send_email",
                allowed_identities={
                    "agent-1"
                },
                category="email",
                require_approval=True,
            )
        ]
    )

    decision = guard.authorize(
        ToolRequest(
            tool_name="send_email",
            identity="agent-1",
            arguments={},
            agent_id="agent-1",
        )
    )

    assert decision.allowed is False
    assert (
        decision.decision
        == "require_approval"
    )

    assert decision.requires_approval is True


def test_argument_limit_is_enforced():

    guard = ToolGuard(
        policies=[
            ToolPolicy(
                name="search",
                allowed_identities={
                    "agent-1"
                },
                max_argument_bytes=10,
            )
        ]
    )

    decision = guard.authorize(
        ToolRequest(
            tool_name="search",
            identity="agent-1",
            arguments={
                "query": "this is too long"
            },
        )
    )

    assert decision.allowed is False
    assert decision.decision == "block"


def test_enforce_raises_on_block():

    guard = ToolGuard()

    try:
        guard.enforce(
            ToolRequest(
                tool_name="unknown",
                identity="agent-1",
                arguments={},
            )
        )

        assert False, "Expected ToolBlocked"

    except ToolBlocked:
        pass


def test_enforce_raises_on_approval():

    guard = ToolGuard(
        policies=[
            ToolPolicy(
                name="payment",
                allowed_identities={
                    "agent-1"
                },
                category="payment",
                require_approval=True,
            )
        ]
    )

    try:
        guard.enforce(
            ToolRequest(
                tool_name="payment",
                identity="agent-1",
                arguments={},
            )
        )

        assert False, (
            "Expected ApprovalRequired"
        )

    except ApprovalRequired:
        pass
