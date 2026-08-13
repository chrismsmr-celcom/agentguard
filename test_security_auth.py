"""
Tests de sécurité — collector.

Contrat d'authentification :
- API : X-API-Key
- Dashboard : /login + session cookie
- Aucun secret dans les query params
- /healthz public
"""

import importlib
import os

import pytest

TEST_API_KEY = "ag-test-key-for-pytest"


@pytest.fixture
def client(tmp_path, monkeypatch):
    """Recharge collector avec une configuration SQLite isolée."""
    monkeypatch.setenv("AGENTGUARD_API_KEY", TEST_API_KEY)
    monkeypatch.setenv("AGENTGUARD_DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.delenv("AGENTGUARD_ADMIN_SECRET", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("AGENTGUARD_DB_TYPE", "sqlite")
    monkeypatch.setenv("AGENTGUARD_COOKIE_SECURE", "false")

    import collector

    importlib.reload(collector)
    collector.init_db()
    collector.app.config["TESTING"] = True

    with collector.app.test_client() as c:
        yield c


def _span_payload(prompt="hello", trace_id="t1"):
    return {
        "trace_id": trace_id,
        "span_id": "s1",
        "span_type": "llm_call",
        "timestamp": 1.0,
        "latency_ms": 10,
        "cost_usd": 0.0,
        "blocked": False,
        "input_data": {"prompt": prompt},
        "output_data": {"response": "ok"},
        "security_checks": [],
    }


# ── AUTH : routes GET protégées ──

@pytest.mark.parametrize(
    "path",
    ["/api/metrics", "/api/traces", "/api/traces/x"],
)
def test_get_routes_require_auth(client, path):
    r = client.get(path)
    assert r.status_code == 401


def test_dashboard_requires_login(client):
    r = client.get("/")

    assert r.status_code == 302
    assert r.headers["Location"].endswith("/login")


@pytest.mark.parametrize(
    "path",
    ["/api/metrics", "/api/traces"],
)
def test_get_routes_reject_wrong_key(client, path):
    r = client.get(
        path,
        headers={"X-API-Key": "wrong-key"},
    )
    assert r.status_code == 401


@pytest.mark.parametrize(
    "path",
    ["/api/metrics", "/api/traces"],
)
def test_get_routes_accept_correct_key(client, path):
    r = client.get(
        path,
        headers={"X-API-Key": TEST_API_KEY},
    )
    assert r.status_code == 200


def test_query_key_is_never_an_authentication_mechanism(client):
    r = client.get(
        "/api/metrics",
        query_string={"key": TEST_API_KEY},
    )

    assert r.status_code == 401


def test_dashboard_login_creates_session(client):
    r1 = client.post(
        "/login",
        data={"api_key": TEST_API_KEY},
        follow_redirects=False,
    )

    assert r1.status_code == 302
    assert r1.headers["Location"].endswith("/")

    cookie = r1.headers.get("Set-Cookie", "")
    assert "ag_auth=" in cookie
    assert "HttpOnly" in cookie

    r2 = client.get("/")
    assert r2.status_code == 200


def test_dashboard_login_rejects_invalid_key(client):
    r = client.post(
        "/login",
        data={"api_key": "wrong-key"},
    )

    assert r.status_code == 401
    assert "Invalid API key" in r.get_data(as_text=True)


def test_dashboard_logout_invalidates_session(client):
    login = client.post(
        "/login",
        data={"api_key": TEST_API_KEY},
        follow_redirects=False,
    )
    assert login.status_code == 302

    before = client.get("/")
    assert before.status_code == 200

    logout = client.post("/logout", follow_redirects=False)
    assert logout.status_code == 302
    assert logout.headers["Location"].endswith("/login")

    # Le cookie supprimé ne doit plus permettre l'accès.
    after = client.get("/")
    assert after.status_code == 302
    assert after.headers["Location"].endswith("/login")


def test_healthz_is_public(client):
    r = client.get("/healthz")
    assert r.status_code in (200, 503)


# ── AUTH : /span (POST) ──

def test_span_post_requires_auth(client):
    r = client.post(
        "/span",
        json=_span_payload(),
    )
    assert r.status_code == 401


def test_span_post_accepts_header_key(client):
    r = client.post(
        "/span",
        json=_span_payload(),
        headers={"X-API-Key": TEST_API_KEY},
    )
    assert r.status_code == 201


# ── PII : redaction avant stockage ──

def test_pii_is_redacted_before_storage(client):
    payload = _span_payload(
        prompt="mon email test@example.com et carte 4111-1111-1111-1111"
    )

    r = client.post(
        "/span",
        json=payload,
        headers={"X-API-Key": TEST_API_KEY},
    )
    assert r.status_code == 201

    got = client.get(
        "/api/traces/t1",
        headers={"X-API-Key": TEST_API_KEY},
    )

    assert got.status_code == 200

    rows = got.get_json()
    assert isinstance(rows, list)
    assert rows

    stored_prompt = rows[0]["input_data"]["prompt"]

    assert "test@example.com" not in stored_prompt
    assert "4111-1111-1111-1111" not in stored_prompt
    assert "REDACTED" in stored_prompt


# ── /api/key : ne doit jamais exposer la clé maître ──

def test_api_key_endpoint_is_removed_or_disabled(client):
    r = client.get(
        "/api/key",
        query_string={"admin": "anything"},
    )

    assert r.status_code in (404, 403)


def test_api_key_endpoint_never_returns_master_key(client, monkeypatch):
    monkeypatch.setenv("AGENTGUARD_ADMIN_SECRET", "real-secret")

    import collector

    importlib.reload(collector)

    with collector.app.test_client() as c:
        r = c.get(
            "/api/key",
            headers={"X-Admin-Secret": "real-secret"},
        )

    assert r.status_code in (404, 403)

    if r.is_json:
        body = r.get_json()
        assert "api_key" not in body


# ── ADMIN AUTH : secret uniquement en header ──

def test_admin_query_secret_is_rejected(client, monkeypatch):
    monkeypatch.setenv("AGENTGUARD_ADMIN_SECRET", "real-secret")

    import collector

    importlib.reload(collector)

    with collector.app.test_client() as c:
        r = c.post(
            "/admin/customers",
            json={"org_name": "Test Org"},
            query_string={"admin": "real-secret"},
        )

    assert r.status_code in (403, 404)


def test_admin_header_secret_works(client, monkeypatch):
    monkeypatch.setenv("AGENTGUARD_ADMIN_SECRET", "real-secret")

    import collector

    importlib.reload(collector)
    collector.init_db()

    with collector.app.test_client() as c:
        r = c.post(
            "/admin/customers",
            json={
                "org_name": "Test Org",
                "plan": "free",
            },
            headers={"X-Admin-Secret": "real-secret"},
        )

    assert r.status_code == 201

    body = r.get_json()
    assert body["org_name"] == "Test Org"
    assert body["plan"] == "free"
    assert body["api_key"].startswith("ag_")


# ── RATE LIMIT ──

def test_span_rate_limit_kicks_in(client):
    headers = {"X-API-Key": TEST_API_KEY}
    limit = 30

    responses = [
        client.post(
            "/span",
            json=_span_payload(trace_id=f"t{i}"),
            headers=headers,
        )
        for i in range(limit + 10)
    ]

    codes = [r.status_code for r in responses]

    assert 429 in codes
    assert all(
        r.status_code == 201
        for r in responses[:limit]
    )
