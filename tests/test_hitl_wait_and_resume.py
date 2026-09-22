"""
"L'approbation qui ne libère pas l'action" (21/09) — la corriger et la GARDER corrigée.

Deux façons d'utiliser guard_tool_call sur une action qui demande une approbation :

  A) wait_for_approval=True  : l'appel BLOQUE jusqu'à la décision, puis exécute l'outil lui-même.
  B) par défaut (async)      : ApprovalRequiredException immédiate ; un NOUVEL appel avec les
                                MÊMES paramètres, après approbation, exécute l'outil sans relancer
                                une nouvelle demande (id déterministe = même agent + outil + params).

Tests contre un vrai serveur Flask qui tourne (pas de mock du collecteur) : c'est la jointure
SDK <-> collecteur qui posait problème, un mock l'aurait masquée.
"""
import threading
import time

import pytest
import requests
from werkzeug.serving import make_server

from agentguard import AgentGuard, ApprovalRequiredException, ApprovalRejectedException


@pytest.fixture
def server(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTGUARD_DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setenv("AGENTGUARD_DB_TYPE", "sqlite")
    monkeypatch.delenv("DATABASE_URL", raising=False)

    import collector.auth as auth
    monkeypatch.setattr(auth, "resolve_org_id", lambda key: {"key-a": "org-a"}.get(key))
    monkeypatch.setattr(auth, "_resolve_human_session",
                        lambda tok: ("u1", "org-a", "t1", "ciso@acme.io", "CISO", "admin", True) if tok == "HUMAN" else None)

    from collector.db import init_db
    from collector.app import create_app
    init_db()
    app = create_app()
    cookie = app.config.get("AUTH_COOKIE", auth.MAGIC_LINK_COOKIE)

    srv = make_server("127.0.0.1", 0, app, threaded=True)
    port = srv.server_port
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    time.sleep(0.15)
    yield f"http://127.0.0.1:{port}", cookie
    srv.shutdown()
    t.join(timeout=2)


def _approve(url, cookie, approval_id, deadline=5.0, delay=0.0):
    """Simule le CISO : attend que la demande existe, puis clique Approve depuis le dashboard."""
    if delay:
        time.sleep(delay)
    start = time.time()
    while time.time() - start < deadline:
        r = requests.get(f"{url}/api/approvals?status=pending", cookies={cookie: "HUMAN"})
        if any(a["id"] == approval_id for a in r.json().get("approvals", [])):
            return requests.post(f"{url}/api/approvals/{approval_id}/approve", cookies={cookie: "HUMAN"})
        time.sleep(0.1)
    raise TimeoutError("approval never showed up in the queue")


EMAIL = {"to": "j.martin@gmail.com", "subject": "customer export"}


def test_wait_for_approval_blocks_then_executes_the_tool(server):
    """C'est le cœur du bug : approuver doit vraiment débloquer l'action, sans nouvel appel."""
    url, cookie = server
    g = AgentGuard(collector_url=url, api_key="key-a", agent_id="finance-bot", wait_for_approval=True)
    approval_id = g._stable_approval_id("finance-bot", "send_email", EMAIL)
    calls = []

    approver = threading.Thread(target=lambda: _approve(url, cookie, approval_id, delay=0.4))
    approver.start()

    result = g.guard_tool_call("send_email", EMAIL, func=lambda **kw: calls.append(kw) or "SENT")
    approver.join(timeout=5)

    assert result == "SENT"
    assert calls == [EMAIL]                       # l'outil a vraiment tourné, une seule fois
    hist = requests.get(f"{url}/api/approvals?status=history", cookies={cookie: "HUMAN"}).json()
    assert hist["approvals"][0]["resolved_by"] == "ciso@acme.io"


def test_wait_for_approval_raises_on_rejection(server):
    url, cookie = server
    g = AgentGuard(collector_url=url, api_key="key-a", agent_id="finance-bot", wait_for_approval=True)
    REJECT_EMAIL = {"to": "reject-me@gmail.com"}
    approval_id = g._stable_approval_id("finance-bot", "send_email", REJECT_EMAIL)

    def reject_it():
        deadline = time.time() + 5
        while time.time() < deadline:
            r = requests.get(f"{url}/api/approvals?status=pending", cookies={cookie: "HUMAN"})
            if any(a["id"] == approval_id for a in r.json()["approvals"]):
                requests.post(f"{url}/api/approvals/{approval_id}/reject", cookies={cookie: "HUMAN"})
                return
            time.sleep(0.1)
    t = threading.Thread(target=reject_it); t.start()

    with pytest.raises(ApprovalRejectedException) as exc:
        g.guard_tool_call("send_email", REJECT_EMAIL, func=lambda **kw: "done")
    t.join(timeout=5)
    assert exc.value.resolved_by == "ciso@acme.io"


def test_wait_for_approval_times_out_if_nobody_decides(server):
    url, _ = server
    g = AgentGuard(collector_url=url, api_key="key-a", agent_id="finance-bot",
                   wait_for_approval=True, approval_timeout=0.5)
    g.approval_poll_interval = 0.1
    with pytest.raises(ApprovalRequiredException) as exc:
        g.guard_tool_call("send_email", {"to": "nobody-decides@gmail.com"}, func=lambda **kw: "SENT")
    assert exc.value.timed_out is True


def test_async_mode_retry_after_approval_runs_the_tool_without_a_new_request(server):
    """Le mode par défaut (pas de thread bloqué) : c'est le pattern le plus courant côté agent."""
    url, cookie = server
    g = AgentGuard(collector_url=url, api_key="key-a", agent_id="finance-bot")   # wait_for_approval=False

    with pytest.raises(ApprovalRequiredException) as exc:
        g.guard_tool_call("send_email", EMAIL, func=lambda **kw: "SENT")
    approval_id = exc.value.approval_id
    assert exc.value.timed_out is False

    requests.post(f"{url}/api/approvals/{approval_id}/approve", cookies={cookie: "HUMAN"})

    # même agent, même outil, MÊMES paramètres -> reconnu comme la même demande, déjà approuvée
    calls = []
    result = g.guard_tool_call("send_email", EMAIL, func=lambda **kw: calls.append(1) or "SENT")
    assert result == "SENT" and calls == [1]

    pending = requests.get(f"{url}/api/approvals?status=pending", cookies={cookie: "HUMAN"}).json()
    assert pending["approvals"] == []   # aucune demande fantôme en double


def test_async_mode_retry_still_blocked_while_pending(server):
    url, _ = server
    g = AgentGuard(collector_url=url, api_key="key-a", agent_id="finance-bot")
    with pytest.raises(ApprovalRequiredException):
        g.guard_tool_call("send_email", EMAIL, func=lambda **kw: "SENT")
    with pytest.raises(ApprovalRequiredException) as exc2:
        g.guard_tool_call("send_email", EMAIL, func=lambda **kw: "SENT")
    assert exc2.value.timed_out is False   # toujours en attente, pas un timeout


def test_different_params_get_different_approval_ids(server):
    url, _ = server
    g = AgentGuard(collector_url=url, api_key="key-a", agent_id="finance-bot")
    ids = set()
    for to in ("a@gmail.com", "b@gmail.com"):
        try:
            g.guard_tool_call("send_email", {"to": to}, func=lambda **kw: "x")
        except ApprovalRequiredException as e:
            ids.add(e.approval_id)
    assert len(ids) == 2   # pas la même demande pour deux actions différentes


def test_decorator_form_respects_env_wait_flag(server, monkeypatch):
    """@guard.guard_tool_call doit aussi pouvoir attendre, via AGENTGUARD_WAIT_FOR_APPROVAL."""
    url, cookie = server
    monkeypatch.setenv("AGENTGUARD_WAIT_FOR_APPROVAL", "true")
    monkeypatch.setenv("AGENTGUARD_APPROVAL_TIMEOUT", "5")
    g = AgentGuard(collector_url=url, api_key="key-a", agent_id="finance-bot")
    assert g.wait_for_approval is True

    @g.guard_tool_call
    def send_email(to):
        return "SENT to " + to

    approval_id = g._stable_approval_id("finance-bot", "send_email", {"to": "c@gmail.com"})
    t = threading.Thread(target=lambda: _approve(url, cookie, approval_id, delay=0.3)); t.start()
    assert send_email(to="c@gmail.com") == "SENT to c@gmail.com"
    t.join(timeout=5)
