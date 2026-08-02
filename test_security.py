"""
Tests de sécurité — verrouille les comportements critiques du collector :
auth sur les routes sensibles, redaction PII avant stockage, secret admin
sans valeur par défaut, rate-limit sur /span.

Lancer : pytest test_security.py -v
"""
import os
import importlib

import pytest

TEST_API_KEY = "ag-test-key-for-pytest"


@pytest.fixture
def client(tmp_path, monkeypatch):
    """Recharge le module collector avec une config de test isolée."""
    monkeypatch.setenv("AGENTGUARD_API_KEY", TEST_API_KEY)
    monkeypatch.setenv("AGENTGUARD_DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.delenv("AGENTGUARD_ADMIN_SECRET", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("AGENTGUARD_DB_TYPE", "sqlite")

    import collector
    importlib.reload(collector)
    collector.init_db()
    collector.app.config["TESTING"] = True
    with collector.app.test_client() as c:
        yield c


def _span_payload(prompt="hello", trace_id="t1"):
    return {
        "trace_id": trace_id, "span_id": "s1", "span_type": "llm_call",
        "timestamp": 1.0, "latency_ms": 10, "cost_usd": 0.0, "blocked": False,
        "input_data": {"prompt": prompt}, "output_data": {"response": "ok"},
        "security_checks": [],
    }


# ── AUTH : routes GET protégées ──

@pytest.mark.parametrize("path", ["/api/metrics", "/api/traces", "/api/traces/x", "/"])
def test_get_routes_require_auth(client, path):
    r = client.get(path)
    assert r.status_code == 401


@pytest.mark.parametrize("path", ["/api/metrics", "/api/traces"])
def test_get_routes_reject_wrong_key(client, path):
    r = client.get(path, query_string={"key": "wrong-key"})
    assert r.status_code == 401


@pytest.mark.parametrize("path", ["/api/metrics", "/api/traces"])
def test_get_routes_accept_correct_key(client, path):
    r = client.get(path, query_string={"key": TEST_API_KEY})
    assert r.status_code == 200


def test_dashboard_sets_cookie_then_works_without_key_param(client):
    r1 = client.get("/", query_string={"key": TEST_API_KEY})
    assert r1.status_code == 200
    r2 = client.get("/")  # même client = cookie envoyé automatiquement
    assert r2.status_code == 200


# ── AUTH : /span (POST) ──

def test_span_post_requires_auth(client):
    r = client.post("/span", json=_span_payload())
    assert r.status_code == 401


def test_span_post_accepts_header_key(client):
    r = client.post("/span", json=_span_payload(),
                     headers={"X-API-Key": TEST_API_KEY})
    assert r.status_code == 201


# ── PII : redaction avant stockage ──

def test_pii_is_redacted_before_storage(client):
    payload = _span_payload(prompt="mon email test@example.com et carte 4111-1111-1111-1111")
    r = client.post("/span", json=payload, headers={"X-API-Key": TEST_API_KEY})
    assert r.status_code == 201

    got = client.get("/api/traces/t1", query_string={"key": TEST_API_KEY})
    stored_prompt = got.get_json()[0]["input_data"]["prompt"]
    assert "test@example.com" not in stored_prompt
    assert "4111-1111-1111-1111" not in stored_prompt
    assert "REDACTED" in stored_prompt


# ── /api/key : pas de secret par défaut ──

def test_api_key_endpoint_disabled_without_admin_secret(client):
    r = client.get("/api/key", query_string={"admin": "changeme"})
    assert r.status_code == 404


def test_api_key_endpoint_works_with_configured_secret(client, monkeypatch):
    monkeypatch.setenv("AGENTGUARD_ADMIN_SECRET", "real-secret")
    import collector
    importlib.reload(collector)
    with collector.app.test_client() as c:
        wrong = c.get("/api/key", query_string={"admin": "changeme"})
        right = c.get("/api/key", query_string={"admin": "real-secret"})
    assert wrong.status_code == 403
    assert right.status_code == 200


# ── RATE LIMIT ──

# Au lieu de 35 requêtes, utiliser la limite actuelle + 10%
def test_span_rate_limit_kicks_in(client):
    headers = {"X-API-Key": TEST_API_KEY}
    limit = 60  # Limite actuelle configurée dans collector.py
    responses = [
        client.post("/span", json=_span_payload(trace_id=f"t{i}"), headers=headers)
        for i in range(limit + 10)  # 70 requêtes (60 + 10)
    ]
    codes = [r.status_code for r in responses]
    assert 429 in codes, "le rate-limit ne s'est pas déclenché"
    # Vérifier que les 60 premières sont passées (201)
    assert all(r.status_code == 201 for r in responses[:limit]), "les requêtes autorisées devraient passer"
