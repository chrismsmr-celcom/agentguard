"""
Régression du 21/09 : « Approvals = 0, Agents = 0 ».

Cause réelle : les clés générées dans le dashboard sont stockées dans `user_api_keys`, mais le
collecteur n'authentifiait les agents que contre `api_keys` -> 401 sur /span et /api/approvals,
donc rien n'atteignait jamais le dashboard. Ici la résolution des clés est le VRAI code (aucun stub).
"""
import time

import pytest


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTGUARD_DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setenv("AGENTGUARD_DB_TYPE", "sqlite")
    monkeypatch.delenv("DATABASE_URL", raising=False)

    import collector.auth as auth
    import collector.api as api
    # seul le login humain est simulé (cookie "HUMAN") ; les clés API passent par le vrai code
    monkeypatch.setattr(auth, "_resolve_human_session",
                        lambda tok: ("u1", "org-real", "t1", "me@acme.io", "Me", "admin", True) if tok == "HUMAN" else None)
    api._AGENT_SEEN.clear()
    api._AGENT_STATUS.clear()

    from collector.db import init_db
    from collector.app import create_app
    init_db()
    app = create_app()
    app.config["TESTING"] = True
    cookie = app.config.get("AUTH_COOKIE", auth.MAGIC_LINK_COOKIE)
    agent = app.test_client()          # un agent : clé API seulement, aucun cookie
    human = app.test_client()          # un humain connecté au dashboard : cookie de session
    human.set_cookie(cookie, "HUMAN")
    yield agent, human


SPAN = {"trace_id": "t1", "span_id": "s1", "span_type": "tool_call", "timestamp": time.time(),
        "latency_ms": 5, "input_data": {}, "output_data": {}, "security_checks": []}


def new_key(human, name="support bot key"):
    r = human.post("/api/keys", json={"name": name})
    assert r.status_code == 201, r.get_data(as_text=True)
    return r.get_json()["key"], r.get_json()["key_id"]


def test_dashboard_generated_key_authenticates_an_agent(env):
    c, h = env
    key, _ = new_key(h)

    assert c.post("/span", json=SPAN, headers={"X-API-Key": key, "X-Agent-Id": "bot-1"}).status_code == 201
    r = c.post("/api/approvals", headers={"X-API-Key": key, "X-Agent-Id": "bot-1"},
               json={"approval_id": "r1", "tool_name": "send_email", "params": {}})
    assert r.status_code == 201

    pending = h.get("/api/approvals?status=pending").get_json()
    assert [a["id"] for a in pending["approvals"]] == ["r1"]
    agents = h.get("/api/agents").get_json()
    assert [a["agent_id"] for a in agents["agents"]] == ["bot-1"]


def test_revoked_dashboard_key_stops_working(env):
    c, h = env
    key, key_id = new_key(h)
    assert c.post("/span", json=SPAN, headers={"X-API-Key": key}).status_code == 201
    assert h.delete(f"/api/keys/{key_id}").status_code in (200, 204)
    assert c.post("/span", json={**SPAN, "span_id": "s2"}, headers={"X-API-Key": key}).status_code == 401


def test_unknown_key_is_still_rejected(env):
    c, _ = env
    assert c.post("/span", json=SPAN, headers={"X-API-Key": "ag_live_not_a_real_key"}).status_code == 401


def test_old_sdk_without_agent_header_still_shows_up_and_can_be_disconnected(env):
    c, h = env
    key, _ = new_key(h, name="Kloyya prod")
    assert c.post("/span", json=SPAN, headers={"X-API-Key": key}).status_code == 201        # SDK < 0.4.1

    agents = h.get("/api/agents").get_json()["agents"]
    assert len(agents) == 1 and agents[0]["agent_id"] == "key:Kloyya prod"
    assert agents[0]["name"] == "Kloyya prod" and agents[0]["sdk_version"] is None

    assert h.post("/api/agents/key:Kloyya prod/disconnect").status_code == 200
    r = c.post("/span", json={**SPAN, "span_id": "s2"}, headers={"X-API-Key": key})
    assert r.status_code == 403 and r.get_json()["error"] == "agent_disconnected"


def test_test_buttons_create_data_and_are_human_only(env):
    c, h = env
    key, _ = new_key(h)
    assert c.post("/api/approvals/test", headers={"X-API-Key": key}).status_code == 401
    assert c.post("/api/agents/test", headers={"X-API-Key": key}).status_code == 401

    assert h.post("/api/approvals/test").status_code == 201
    pending = h.get("/api/approvals?status=pending").get_json()["approvals"]
    assert len(pending) == 1 and pending[0]["agent_id"] == "cerbere-test-agent"
    assert [a["agent_id"] for a in h.get("/api/agents").get_json()["agents"]] == ["cerbere-test-agent"]
    assert h.post(f"/api/approvals/{pending[0]['id']}/approve").status_code == 200


# ── SDK ───────────────────────────────────────────────────────────────────────
class FakeResp:
    def __init__(self, status=200, body=None, text=""):
        self.status_code, self._body, self.text = status, body or {}, text

    def json(self):
        return self._body


def test_sdk_warns_loudly_when_the_key_is_rejected(monkeypatch):
    import agentguard.sdk as sdk_mod
    from agentguard import AgentGuard
    monkeypatch.setattr(sdk_mod.requests, "post", lambda *a, **k: FakeResp(401, text="Unauthorized"))
    monkeypatch.setattr(sdk_mod.requests, "get", lambda *a, **k: FakeResp(401))
    g = AgentGuard(collector_url="http://collector.test", api_key="bad", agent_id="a")
    with pytest.warns(RuntimeWarning, match="rejected your API key"):
        g.guard_tool_call("search_kb", {"q": "x"}, func=lambda **k: "ok")


def test_sdk_reads_collector_url_from_environment(monkeypatch):
    from agentguard import AgentGuard
    monkeypatch.setenv("AGENTGUARD_COLLECTOR_URL", "https://app.cerbereag.site/")
    assert AgentGuard(api_key="k").collector_url == "https://app.cerbereag.site"
    assert AgentGuard(collector_url="http://x.test", api_key="k").collector_url == "http://x.test"
