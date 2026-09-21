"""
Registre d'agents + kill switch + décisions HITL réservées aux humains.

- un SDK qui envoie X-Agent-Id apparaît dans GET /api/agents
- déconnecter un agent depuis le dashboard bloque ses requêtes (403) ; reconnecter les rétablit
- une clé API (donc un agent) ne peut PAS approuver / rejeter / déconnecter
"""
import time

import pytest

KEYS = {"key-a": "org-a", "key-b": "org-b"}
SPAN = {"trace_id": "t1", "span_id": "s1", "span_type": "tool_call",
        "timestamp": time.time(), "latency_ms": 12, "cost_usd": 0.01,
        "input_data": {"tool": "send_email"}, "output_data": {}, "security_checks": []}


def hdr(key="key-a", agent="finance-bot"):
    return {"X-API-Key": key, "X-Agent-Id": agent}


@pytest.fixture
def app_client(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTGUARD_DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setenv("AGENTGUARD_DB_TYPE", "sqlite")
    monkeypatch.delenv("DATABASE_URL", raising=False)

    import collector.auth as auth
    import collector.api as api
    monkeypatch.setattr(auth, "resolve_org_id", lambda key: KEYS.get(key))
    api._AGENT_SEEN.clear()
    api._AGENT_STATUS.clear()

    from collector.db import init_db
    from collector.app import create_app
    init_db()
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c, api, monkeypatch


def _as_human(api, monkeypatch, org="org-a", email="ciso@acme.io"):
    def fake():
        from flask import g
        g.org_id, g.human_email = org, email
        return True
    monkeypatch.setattr(api, "require_human_auth", fake)


def test_agent_registers_on_first_request(app_client):
    c, api, _ = app_client
    assert c.post("/span", json=SPAN, headers=hdr()).status_code in (200, 201)

    agents = c.get("/api/agents", headers={"X-API-Key": "key-a"}).get_json()
    assert agents["total"] == 1
    a = agents["agents"][0]
    assert a["agent_id"] == "finance-bot" and a["state"] == "connected"
    assert a["calls"] == 1


def test_agents_are_isolated_per_org(app_client):
    c, api, _ = app_client
    c.post("/span", json=SPAN, headers=hdr("key-a", "bot-a"))
    other = c.get("/api/agents", headers={"X-API-Key": "key-b"}).get_json()
    assert other["total"] == 0


def test_api_key_cannot_disconnect_or_approve(app_client):
    c, api, _ = app_client
    c.post("/span", json=SPAN, headers=hdr())
    c.post("/api/approvals", headers=hdr(),
           json={"approval_id": "req-1", "tool_name": "send_email", "params": {}})

    assert c.post("/api/agents/finance-bot/disconnect", headers=hdr()).status_code == 401
    assert c.post("/api/approvals/req-1/approve", headers=hdr()).status_code == 401
    assert c.post("/api/approvals/req-1/reject", headers=hdr()).status_code == 401

    pending = c.get("/api/approvals?status=pending", headers=hdr()).get_json()
    assert [a["id"] for a in pending["approvals"]] == ["req-1"]


def test_disconnect_blocks_agent_then_reconnect_restores(app_client):
    c, api, mp = app_client
    c.post("/span", json=SPAN, headers=hdr())
    _as_human(api, mp)

    assert c.post("/api/agents/finance-bot/disconnect").status_code == 200
    r = c.post("/span", json={**SPAN, "span_id": "s2"}, headers=hdr())
    assert r.status_code == 403 and r.get_json()["error"] == "agent_disconnected"
    assert c.get("/api/agent/status", headers=hdr()).get_json()["status"] == "disconnected"
    assert c.post("/api/decide", json={"tool_name": "x"}, headers=hdr()).status_code == 403
    assert c.post("/api/approvals", headers=hdr(),
                  json={"approval_id": "r9", "tool_name": "x"}).status_code == 403
    # un autre agent de la même org n'est pas touché
    assert c.post("/span", json={**SPAN, "span_id": "s3"}, headers=hdr(agent="other-bot")).status_code in (200, 201)

    listed = c.get("/api/agents", headers={"X-API-Key": "key-a"}).get_json()
    fb = next(a for a in listed["agents"] if a["agent_id"] == "finance-bot")
    assert fb["state"] == "disconnected" and fb["disconnected_by"] == "ciso@acme.io"

    assert c.post("/api/agents/finance-bot/reconnect").status_code == 200
    assert c.post("/span", json={**SPAN, "span_id": "s4"}, headers=hdr()).status_code in (200, 201)
    assert c.get("/api/agent/status", headers=hdr()).get_json()["status"] == "connected"


def test_unknown_agent_returns_404(app_client):
    c, api, mp = app_client
    _as_human(api, mp)
    assert c.post("/api/agents/ghost/disconnect").status_code == 404


def test_human_approves_and_history_records_who(app_client):
    c, api, mp = app_client
    c.post("/api/approvals", headers=hdr(), json={"approval_id": "req-1", "tool_name": "send_email",
                                                   "params": {"to": "x@gmail.com"}, "reason": "DLP"})
    c.post("/api/approvals", headers=hdr(), json={"approval_id": "req-2", "tool_name": "wire_transfer"})
    _as_human(api, mp)
    assert c.post("/api/approvals/req-1/approve").status_code == 200
    assert c.post("/api/approvals/req-2/reject").status_code == 200
    assert c.post("/api/approvals/req-1/approve").status_code == 404      # déjà décidée

    hist = c.get("/api/approvals?status=history", headers=hdr()).get_json()
    by_id = {a["id"]: a for a in hist["approvals"]}
    assert by_id["req-1"]["status"] == "approved" and by_id["req-1"]["resolved_by"] == "ciso@acme.io"
    assert by_id["req-2"]["status"] == "rejected"
    assert hist["counts"] == {"pending": 0, "approved": 1, "rejected": 1}
    # le SDK peut interroger le statut pour reprendre l'action
    assert c.get("/api/approvals/req-1", headers=hdr()).get_json()["status"] == "approved"


def test_as_json_handles_jsonb_dicts_and_text():
    from collector.api import _as_json
    assert _as_json({"a": 1}, {}) == {"a": 1}       # PostgreSQL JSONB -> dict
    assert _as_json('{"a": 1}', {}) == {"a": 1}     # SQLite -> texte
    assert _as_json(None, []) == [] and _as_json("not json", {}) == {}
