"""
Vérifie l'isolation multi-tenant : deux clients hébergés ne doivent JAMAIS
voir les données l'un de l'autre, la clé maître (self-host) reste isolée
dans l'org 'default', et la révocation coupe l'accès immédiatement.

Lancer : pytest test_multitenancy.py -v
"""
import os
import importlib

import pytest

MASTER_KEY = "ag-master-key-pytest"
ADMIN_SECRET = "admin-secret-pytest"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTGUARD_API_KEY", MASTER_KEY)
    monkeypatch.setenv("AGENTGUARD_ADMIN_SECRET", ADMIN_SECRET)
    monkeypatch.setenv("AGENTGUARD_DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("AGENTGUARD_DB_TYPE", "sqlite")

    import collector
    importlib.reload(collector)
    collector.init_db()
    collector.app.config["TESTING"] = True
    with collector.app.test_client() as c:
        yield c, collector


def _create_customer(c, org_name, plan="pro"):
    r = c.post("/admin/customers", headers={"X-Admin-Secret": ADMIN_SECRET},
               json={"org_name": org_name, "plan": plan})
    assert r.status_code == 201
    data = r.get_json()
    return data["api_key"], data["org_id"]


def _span(trace_id, prompt="hello"):
    return {
        "trace_id": trace_id, "span_id": trace_id + "-s1", "span_type": "llm_call",
        "timestamp": 1.0, "latency_ms": 1, "input_data": {"prompt": prompt},
        "output_data": {}, "security_checks": [], "blocked": False, "cost_usd": 0.0,
    }


def test_two_customers_are_fully_isolated(client):
    c, _ = client
    key_a, org_a = _create_customer(c, "Client A")
    key_b, org_b = _create_customer(c, "Client B")

    for i in range(5):
        c.post("/span", headers={"X-API-Key": key_a}, json=_span(f"tA{i}"))
    for i in range(3):
        c.post("/span", headers={"X-API-Key": key_b}, json=_span(f"tB{i}"))

    metrics_a = c.get("/api/metrics", headers={"X-API-Key": key_a}).get_json()
    metrics_b = c.get("/api/metrics", headers={"X-API-Key": key_b}).get_json()

    assert metrics_a["total_spans"] == 5
    assert metrics_b["total_spans"] == 3


def test_customer_cannot_read_another_customers_trace(client):
    c, _ = client
    key_a, _ = _create_customer(c, "Client A")
    key_b, _ = _create_customer(c, "Client B")

    c.post("/span", headers={"X-API-Key": key_a}, json=_span("secret-trace"))

    leaked = c.get("/api/traces/secret-trace", headers={"X-API-Key": key_b}).get_json()
    assert leaked == [], "FUITE: un client peut lire les traces d'un autre client"

    owner_view = c.get("/api/traces/secret-trace", headers={"X-API-Key": key_a}).get_json()
    assert len(owner_view) == 1


def test_master_key_stays_isolated_from_customers(client):
    c, _ = client
    key_a, _ = _create_customer(c, "Client A")

    c.post("/span", headers={"X-API-Key": MASTER_KEY}, json=_span("default-trace"))
    c.post("/span", headers={"X-API-Key": key_a}, json=_span("customer-trace"))

    default_metrics = c.get("/api/metrics", headers={"X-API-Key": MASTER_KEY}).get_json()
    assert default_metrics["total_spans"] == 1


def test_invalid_key_rejected_cleanly_even_with_weird_input(client):
    c, _ = client
    # Une clé farfelue (non-ASCII) ne doit jamais faire planter l'auth en 500
    r = c.get("/api/metrics", headers={"X-API-Key": "ag-clé-invéntée-€"})
    assert r.status_code == 401


def test_revoked_customer_loses_access_immediately(client):
    c, _ = client
    key_a, org_a = _create_customer(c, "Client A")

    assert c.get("/api/metrics", headers={"X-API-Key": key_a}).status_code == 200

    rev = c.post(f"/admin/customers/{org_a}/revoke", headers={"X-Admin-Secret": ADMIN_SECRET})
    assert rev.status_code == 200
    assert rev.get_json()["keys_revoked"] == 1

    assert c.get("/api/metrics", headers={"X-API-Key": key_a}).status_code == 401


def test_customer_provisioning_requires_admin_secret(client):
    c, _ = client
    r = c.post("/admin/customers", json={"org_name": "Sans droit"})
    assert r.status_code == 403
