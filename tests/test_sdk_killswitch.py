"""Kill switch côté SDK : un agent déconnecté depuis le dashboard cesse d'exécuter ses outils."""
import pytest

import agentguard.sdk as sdk_mod
from agentguard import AgentGuard, AgentDisconnectedException, SecurityException


class FakeResp:
    def __init__(self, status=200, body=None, text=""):
        self.status_code, self._body, self.text = status, body or {}, text

    def json(self):
        return self._body


@pytest.fixture
def guard(monkeypatch):
    monkeypatch.setattr(sdk_mod.requests, "post", lambda *a, **k: FakeResp(201))
    return AgentGuard(collector_url="http://collector.test", api_key="k", agent_id="finance-bot")


def test_sends_agent_identity_headers(guard):
    h = guard._headers()
    assert h["X-Agent-Id"] == "finance-bot" and h["X-Agent-Sdk"] and h["X-API-Key"] == "k"


def test_connected_agent_runs_tool(guard, monkeypatch):
    monkeypatch.setattr(sdk_mod.requests, "get", lambda *a, **k: FakeResp(200, {"status": "connected"}))
    assert guard.guard_tool_call("read_doc", {"id": 1}, func=lambda **kw: "ok") == "ok"


def test_disconnected_agent_is_blocked(guard, monkeypatch):
    monkeypatch.setattr(sdk_mod.requests, "get", lambda *a, **k: FakeResp(200, {"status": "disconnected"}))
    ran = []
    with pytest.raises(AgentDisconnectedException):
        guard.guard_tool_call("read_doc", {"id": 1}, func=lambda **kw: ran.append(1))
    assert ran == []
    assert issubclass(AgentDisconnectedException, SecurityException)


def test_span_403_marks_agent_disconnected(guard, monkeypatch):
    monkeypatch.setattr(sdk_mod.requests, "get", lambda *a, **k: FakeResp(200, {"status": "connected"}))
    guard._ensure_connected()
    monkeypatch.setattr(sdk_mod.requests, "post",
                        lambda *a, **k: FakeResp(403, text='{"error":"agent_disconnected"}'))
    guard._conn_checked_at = 1e18   # évite un nouveau contrôle : on teste la voie 403
    guard._send_to_collector(sdk_mod.GuardSpan("s", "t", "tool_call", 0.0, 1.0, {}, {}, []))
    with pytest.raises(AgentDisconnectedException):
        guard._ensure_connected()


def test_unreachable_collector_does_not_block_agent(guard, monkeypatch):
    def boom(*a, **k):
        raise sdk_mod.requests.ConnectionError("down")
    monkeypatch.setattr(sdk_mod.requests, "get", boom)
    assert guard.guard_tool_call("read_doc", {"id": 1}, func=lambda **kw: "ok") == "ok"
