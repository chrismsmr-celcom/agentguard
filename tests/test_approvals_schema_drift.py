"""
Régression prod (19/09) : GET/POST /api/approvals renvoyaient HTTP 500.

La table `approval_requests` a été créée le 18/09 SANS la colonne `org_id`.
Le 19/09 le CREATE TABLE a gagné `org_id`, mais `CREATE TABLE IF NOT EXISTS`
ne modifie jamais une table existante : la base de prod a gardé l'ancien
schéma et toutes les requêtes `WHERE org_id = ...` échouaient.

Ce test recrée l'ancien schéma AVANT init_db() et vérifie la migration.
"""
import sqlite3

import pytest

KEYS = {"key-a": "org-a"}

OLD_SCHEMA = """
CREATE TABLE approval_requests (
    id TEXT PRIMARY KEY,
    agent_id TEXT,
    tool_name TEXT,
    params TEXT,
    reason TEXT,
    status TEXT DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP NULL,
    resolved_by TEXT NULL
)
"""


@pytest.fixture
def client(tmp_path, monkeypatch):
    db_path = tmp_path / "old.db"
    monkeypatch.setenv("AGENTGUARD_DB_PATH", str(db_path))
    monkeypatch.setenv("AGENTGUARD_DB_TYPE", "sqlite")
    monkeypatch.delenv("DATABASE_URL", raising=False)

    conn = sqlite3.connect(db_path)
    conn.execute(OLD_SCHEMA)
    conn.execute("INSERT INTO approval_requests (id, agent_id, tool_name, params, reason) "
                 "VALUES ('legacy-1', 'a1', 'send_email', '{}', 'ancienne demande')")
    conn.commit()
    conn.close()

    import collector.auth as auth
    monkeypatch.setattr(auth, "resolve_org_id", lambda key: KEYS.get(key))

    from collector.db import init_db
    from collector.app import create_app

    init_db()
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_old_table_gets_org_id_column(client):
    r = client.post("/api/approvals", headers={"X-API-Key": "key-a"},
                    json={"approval_id": "req-1", "agent_id": "a1",
                          "tool_name": "send_email", "params": {"to": "x@gmail.com"},
                          "reason": "domaine personnel"})
    assert r.status_code == 201, r.get_data(as_text=True)

    r = client.get("/api/approvals?status=pending", headers={"X-API-Key": "key-a"})
    assert r.status_code == 200, r.get_data(as_text=True)
    ids = [a["id"] for a in r.get_json()["approvals"]]
    assert "req-1" in ids


def test_legacy_rows_are_kept_in_default_org(client):
    conn = sqlite3.connect(client.application.config.get("DB_PATH") or
                           __import__("os").environ["AGENTGUARD_DB_PATH"])
    row = conn.execute("SELECT org_id FROM approval_requests WHERE id='legacy-1'").fetchone()
    conn.close()
    assert row[0] == "default"


# ─────────────────────────────────────────────────────────────────────────────
# Cas réellement observé en prod le 21/09 :
#   column "id" does not exist  (SELECT id, agent_id, tool_name, params ...)
# La table avait le schéma de l'ancien module approvals.py (approval_id, arguments...).
# ─────────────────────────────────────────────────────────────────────────────
HITL_MODULE_SCHEMA = """
CREATE TABLE approval_requests (
    approval_id TEXT PRIMARY KEY, org_id TEXT, tenant_id TEXT, agent_id TEXT, session_id TEXT,
    trace_id TEXT, span_id TEXT, tool_name TEXT NOT NULL, arguments TEXT NOT NULL, arguments_hash TEXT,
    risk_score REAL, reason TEXT, policy_name TEXT, status TEXT NOT NULL, requested_at TEXT NOT NULL,
    expires_at TEXT NOT NULL, decided_at TEXT, decided_by TEXT, decision_reason TEXT
)
"""


@pytest.fixture
def client_wrong_schema(tmp_path, monkeypatch):
    db_path = tmp_path / "wrong.db"
    monkeypatch.setenv("AGENTGUARD_DB_PATH", str(db_path))
    monkeypatch.setenv("AGENTGUARD_DB_TYPE", "sqlite")
    monkeypatch.delenv("DATABASE_URL", raising=False)

    conn = sqlite3.connect(db_path)
    conn.execute(HITL_MODULE_SCHEMA)
    conn.execute("INSERT INTO approval_requests (approval_id, org_id, tool_name, arguments, status, requested_at, expires_at) "
                 "VALUES ('old-1', 'org-a', 'send_email', '{}', 'pending', '2026-09-19', '2026-09-20')")
    conn.commit()
    conn.close()

    import collector.auth as auth
    monkeypatch.setattr(auth, "resolve_org_id", lambda key: KEYS.get(key))

    from collector.db import init_db
    from collector.app import create_app
    init_db()
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c, db_path


def test_wrong_schema_table_is_renamed_kept_and_recreated(client_wrong_schema):
    c, db_path = client_wrong_schema

    r = c.get("/api/approvals?status=pending", headers={"X-API-Key": "key-a"})
    assert r.status_code == 200, r.get_data(as_text=True)          # plus de HTTP 500
    assert r.get_json()["approvals"] == []

    r = c.post("/api/approvals", headers={"X-API-Key": "key-a"},
               json={"approval_id": "req-1", "tool_name": "send_email", "params": {}})
    assert r.status_code == 201
    assert [a["id"] for a in c.get("/api/approvals?status=pending",
                                   headers={"X-API-Key": "key-a"}).get_json()["approvals"]] == ["req-1"]

    conn = sqlite3.connect(db_path)
    legacy = [t[0] for t in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'approval_requests_legacy_%'")]
    assert len(legacy) == 1                                          # données anciennes conservées
    assert conn.execute(f"SELECT COUNT(*) FROM {legacy[0]}").fetchone()[0] == 1
    conn.close()


def test_hitl_module_never_touches_the_api_table(client_wrong_schema):
    """Avant : approvals.ensure_approval_schema() supprimait la table des routes API (et inversement)."""
    c, db_path = client_wrong_schema
    c.post("/api/approvals", headers={"X-API-Key": "key-a"},
           json={"approval_id": "req-9", "tool_name": "wire_transfer", "params": {}})

    from collector.approvals import ensure_approval_schema
    ensure_approval_schema()
    ensure_approval_schema()

    listed = c.get("/api/approvals?status=pending", headers={"X-API-Key": "key-a"})
    assert listed.status_code == 200
    assert [a["id"] for a in listed.get_json()["approvals"]] == ["req-9"]

