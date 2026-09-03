import pytest

from decision_engine import (
    Decision,
    DecisionEngine,
    DecisionRequest,
    PolicyRule,
)


def test_safe_action_is_allowed():

    engine = DecisionEngine()

    result = engine.evaluate(
        DecisionRequest(
            agent_id="agent-1",
            tool_name="search",
            tool_category="search",
            identity_trusted=True,
            model_score=0,
            taint_level="PUBLIC",
        )
    )

    assert result.decision == Decision.ALLOW
    assert result.risk_score < 35


def test_untrusted_identity_is_blocked():

    engine = DecisionEngine()

    result = engine.evaluate(
        DecisionRequest(
            agent_id="agent-1",
            tool_name="search",
            identity_trusted=False,
        )
    )

    assert result.decision == Decision.BLOCK
    assert "identity" in result.reason_codes


def test_malicious_taint_is_blocked():

    engine = DecisionEngine()

    result = engine.evaluate(
        DecisionRequest(
            agent_id="agent-1",
            tool_name="send_email",
            tool_category="email",
            identity_trusted=True,
            taint_level="MALICIOUS",
            external_side_effect=True,
        )
    )

    assert result.decision == Decision.BLOCK
    assert result.risk_score == 100


def test_secret_cannot_trigger_external_side_effect():

    engine = DecisionEngine()

    result = engine.evaluate(
        DecisionRequest(
            agent_id="agent-1",
            tool_name="send_email",
            tool_category="email",
            identity_trusted=True,
            taint_level="SECRET",
            external_side_effect=True,
        )
    )

    assert result.decision == Decision.BLOCK


def test_explicit_approval_policy():

    engine = DecisionEngine(
        policies=[
            PolicyRule(
                name="default",
                require_approval_for={
                    "send_email"
                },
            )
        ]
    )

    result = engine.evaluate(
        DecisionRequest(
            agent_id="agent-1",
            tool_name="send_email",
            tool_category="email",
            identity_trusted=True,
            taint_level="PUBLIC",
        )
    )

    assert (
        result.decision
        == Decision.REQUIRE_APPROVAL
    )


def test_unknown_tool_is_blocked():

    engine = DecisionEngine()

    result = engine.evaluate(
        DecisionRequest(
            agent_id="agent-1",
            tool_name="unknown_tool",
            identity_trusted=True,
            tool_registered=False,
        )
    )

    assert result.decision == Decision.BLOCK


def test_high_risk_operation_is_blocked():

    engine = DecisionEngine()

    result = engine.evaluate(
        DecisionRequest(
            agent_id="agent-1",
            tool_name="payment",
            tool_category="payment",
            identity_trusted=True,
            model_score=95,
            taint_level="PUBLIC",
            external_side_effect=True,
            irreversible=True,
        )
    )

    assert result.decision == Decision.BLOCK
    assert result.risk_score >= 80


def test_allowlist_blocks_unlisted_tool():

    engine = DecisionEngine(
        policies=[
            PolicyRule(
                name="default",
                allowed_tools={
                    "search",
                    "read_database",
                },
            )
        ]
    )

    result = engine.evaluate(
        DecisionRequest(
            agent_id="agent-1",
            tool_name="send_email",
            tool_category="email",
            identity_trusted=True,
        )
    )

    assert result.decision == Decision.BLOCK
    assert "policy" in result.reason_codes


def test_result_is_auditable():

    engine = DecisionEngine()

    result = engine.evaluate(
        DecisionRequest(
            agent_id="agent-42",
            tool_name="search",
            tool_category="search",
            identity_trusted=True,
        )
    )

    payload = result.to_dict()

    assert payload["decision"] == "allow"
    assert payload["audit"]["agent_id"] == "agent-42"
    assert payload["audit"]["tool_name"] == "search"
    assert "factors" in payload
    assert "reasons" in payload
