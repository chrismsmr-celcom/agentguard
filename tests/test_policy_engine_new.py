"""Tests du nouveau Policy Engine (Phase 1)."""
import os
import pytest
from policy import PolicyEngine, Policy, PolicyDecision, Decision


@pytest.fixture
def engine(tmp_path):
    """Policy Engine avec policies temporaires."""
    # Crée une policy de test
    policy_content = """
version: 1
name: test-policy
description: "Test policy"
agents:
  - test-agent
capabilities:
  tools:
    allow:
      - search_*
      - get_*
    deny:
      - delete_*
  filesystem:
    read:
      - /workspace/data/**
    write:
      - /workspace/output/**
    deny:
      - /etc/**
  network:
    default: deny
    allow:
      - api.example.com
rules:
  - name: large-amount-approval
    when:
      tool: send_payment
      params.amount: "> 10000"
    decision: REQUIRE_APPROVAL
    reason: "Large payment needs approval"
budget:
  max_per_session: 5.0
  max_per_day: 50.0
"""
    policies_dir = tmp_path / "policies"
    policies_dir.mkdir()
    (policies_dir / "test.yaml").write_text(policy_content)
    
    return PolicyEngine(policies_dir=str(policies_dir))


class TestPolicyLoading:
    """Tests de chargement des policies."""
    
    def test_load_from_directory(self, engine):
        policies = engine.list_policies()
        assert len(policies) == 1
        assert policies[0].name == "test-policy"
    
    def test_load_from_string(self, engine):
        yaml_str = """
version: 1
name: inline-policy
agents: [agent-x]
capabilities:
  tools:
    allow: [tool_a]
"""
        policy = engine.load_policy_string(yaml_str)
        assert policy is not None
        assert policy.name == "inline-policy"


class TestToolCapabilities:
    """Tests des capacités d'outils."""
    
    def test_allowed_tool(self, engine):
        decision = engine.evaluate_tool_call(
            agent_id="test-agent",
            tool_name="search_transactions",
            params={},
        )
        assert decision.is_allowed()
    
    def test_denied_tool(self, engine):
        decision = engine.evaluate_tool_call(
            agent_id="test-agent",
            tool_name="delete_database",
            params={},
        )
        assert decision.is_denied()
        assert "not allowed" in decision.reason
    
    def test_unknown_tool_no_whitelist(self, tmp_path):
        """Sans whitelist, outils inconnus autorisés."""
        policy = """
version: 1
name: open
agents: [agent-x]
capabilities:
  tools:
    deny: [bad_tool]
"""
        policies_dir = tmp_path / "policies"
        policies_dir.mkdir()
        (policies_dir / "open.yaml").write_text(policy)
        engine = PolicyEngine(policies_dir=str(policies_dir))
        
        decision = engine.evaluate_tool_call("agent-x", "any_tool", {})
        assert decision.is_allowed()


class TestFilesystemCapabilities:
    """Tests des capacités filesystem."""
    
    def test_allowed_read(self, engine):
        decision = engine.evaluate_tool_call(
            agent_id="test-agent",
            tool_name="read_file",
            params={"path": "/workspace/data/file.txt"},
        )
        assert decision.is_allowed()
    
    def test_denied_read(self, engine):
        decision = engine.evaluate_tool_call(
            agent_id="test-agent",
            tool_name="read_file",
            params={"path": "/etc/passwd"},
        )
        assert decision.is_denied()
    
    def test_recursive_pattern(self, engine):
        decision = engine.evaluate_tool_call(
            agent_id="test-agent",
            tool_name="read_file",
            params={"path": "/workspace/data/subdir/deep/file.txt"},
        )
        assert decision.is_allowed()


class TestNetworkCapabilities:
    """Tests des capacités réseau + SSRF protection."""
    
    def test_allowed_network(self, engine):
        decision = engine.evaluate_tool_call(
            agent_id="test-agent",
            tool_name="http_request",
            params={"url": "https://api.example.com/data"},
        )
        assert decision.is_allowed()
    
    def test_denied_network(self, engine):
        decision = engine.evaluate_tool_call(
            agent_id="test-agent",
            tool_name="http_request",
            params={"url": "https://evil.com/steal"},
        )
        assert decision.is_denied()
    
    def test_ssrf_localhost_blocked(self, engine):
        """SSRF : localhost toujours bloqué."""
        decision = engine.evaluate_tool_call(
            agent_id="test-agent",
            tool_name="http_request",
            params={"url": "http://localhost:8080/admin"},
        )
        assert decision.is_denied()
    
    def test_ssrf_aws_metadata_blocked(self, engine):
        """SSRF : AWS metadata endpoint toujours bloqué."""
        decision = engine.evaluate_tool_call(
            agent_id="test-agent",
            tool_name="http_request",
            params={"url": "http://169.254.169.254/latest/meta-data/"},
        )
        assert decision.is_denied()


class TestRules:
    """Tests d'évaluation des règles."""
    
    def test_rule_requires_approval(self, engine):
        decision = engine.evaluate_tool_call(
            agent_id="test-agent",
            tool_name="send_payment",
            params={"amount": 50000},
        )
        assert decision.requires_approval()
        assert "approval" in decision.reason.lower()
    
    def test_rule_not_triggered_small_amount(self, engine):
        decision = engine.evaluate_tool_call(
            agent_id="test-agent",
            tool_name="send_payment",
            params={"amount": 100},
        )
        # Devrait être ALLOW (si send_payment dans allow list, sinon DENY tool)
        # Ici tool pas dans whitelist donc DENY tool
        assert decision.is_denied()


class TestNoPolicy:
    """Tests du comportement sans policy."""
    
    def test_no_policy_fail_closed(self, tmp_path):
        """Sans policy, fail_closed = DENY."""
        policies_dir = tmp_path / "empty_policies"
        policies_dir.mkdir()
        engine = PolicyEngine(policies_dir=str(policies_dir))
        
        decision = engine.evaluate_tool_call(
            agent_id="unknown-agent",
            tool_name="any_tool",
            params={},
        )
        assert decision.is_denied()
        assert "No policy" in decision.reason


class TestPolicyDecision:
    """Tests du modèle PolicyDecision."""
    
    def test_to_dict(self):
        decision = PolicyDecision(
            action=Decision.ALLOW,
            reason="Test reason",
            policy_name="test",
            policy_version=1,
            matched_rules=["rule1"],
            risk_score=20,
        )
        d = decision.to_dict()
        assert d["action"] == "ALLOW"
        assert d["reason"] == "Test reason"
        assert d["policy_name"] == "test"
