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

@pytest.mark.parametrize("path", ["/api/metrics", "/api/traces", "/api/traces/x"])
def test_get_routes_require_auth_json(client, path):
    """Les routes API renvoient un 401 JSON propre sans clé."""
    r = client.get(path)
    assert r.status_code == 401


def test_dashboard_redirects_to_login_without_auth(client):
    """Le dashboard redirige vers /login plutôt qu'un 401 brut — c'est le
    nouveau comportement voulu, pas une régression : /?key=... exposait la
    clé API dans l'URL (logs serveur, historique navigateur, referrer...),
    remplacé par un vrai formulaire de connexion en POST."""
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


def test_query_string_key_no_longer_grants_auth(client):
    """L'ancien ?key=... dans l'URL ne doit plus jamais authentifier —
    c'est le changement délibéré que ce test verrouille."""
    r = client.get("/api/metrics", query_string={"key": TEST_API_KEY})
    assert r.status_code == 401


def test_login_with_wrong_key_rejected(client):
    r = client.post("/login", data={"api_key": "wrong-key"})
    assert r.status_code == 401


def test_login_then_dashboard_and_api_work_via_session_cookie(client):
    r1 = client.post("/login", data={"api_key": TEST_API_KEY}, follow_redirects=False)
    assert r1.status_code == 302  # redirige vers le dashboard après succès

    r2 = client.get("/")  # même client de test = cookie de session envoyé automatiquement
    assert r2.status_code == 200

    r3 = client.get("/api/metrics")
    assert r3.status_code == 200


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

    got = client.get("/api/traces/t1", headers={"X-API-Key": TEST_API_KEY})
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
    limit = 30  # Doit rester synchronisé avec @limiter.limit(...) sur /span dans collector.py
    responses = [
        client.post("/span", json=_span_payload(trace_id=f"t{i}"), headers=headers)
        for i in range(limit + 10)  # 40 requêtes (30 + 10)
    ]
    codes = [r.status_code for r in responses]
    assert 429 in codes, "le rate-limit ne s'est pas déclenché"
    # Vérifier que les 60 premières sont passées (201)
    assert all(r.status_code == 201 for r in responses[:limit]), "les requêtes autorisées devraient passer"
