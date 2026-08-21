"""
Authorization matrix tests — validates SYSTEM / Tenant Admin / Developer isolation.

This is the fundamental security matrix of AgentGuard:

    Actor                → Target Tenant → Target Org → Result
    ─────────────────────────────────────────────────────────────
    SYSTEM               → Any           → Any       → ALLOW
    Tenant A Admin       → Tenant A      → Org A1    → ALLOW
    Tenant A Admin       → Tenant A      → Org A2    → ALLOW
    Tenant A Admin       → Tenant B      → Any       → DENY (403)
    Org A1 Developer     → Tenant A      → Org A1    → ALLOW
    Org A1 Developer     → Tenant A      → Org A2    → DENY (403)
    Org A1 Developer     → Tenant B      → Any       → DENY (403)
"""
import os
import sys
import pytest
from pathlib import Path

ROOT_DIR = Path(__file__).parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

os.environ.setdefault("AGENTGUARD_API_KEY", "ag-test-key-for-ci-only")
os.environ.setdefault("AGENTGUARD_ADMIN_SECRET", "test-admin-secret")
os.environ.setdefault("AGENTGUARD_DB_TYPE", "sqlite")
os.environ.setdefault("AGENTGUARD_FLASK_SECRET", "test-flask-secret-ci")


@pytest.fixture
def client_with_identity(tmp_path):
    """Client with DB + tenant + org initialized."""
    db_path = tmp_path / "test.db"
    os.environ["AGENTGUARD_DB_PATH"] = str(db_path)
    
    from collector.db import init_db
    from collector.app import create_app
    
    init_db()
    app = create_app()
    app.config["TESTING"] = True
    
    with app.test_client() as client:
        api_key = os.environ.get("AGENTGUARD_API_KEY", "ag-test-key-for-ci-only")
        
        # Create a tenant
        resp = client.post("/api/identity/tenants",
            json={"name": "Acme Corp"},
            headers={"X-API-Key": api_key})
        assert resp.status_code == 201
        tenant_id = resp.json["tenant_id"]
        
        # Create an org
        resp = client.post("/api/identity/orgs",
            json={"name": "Engineering", "tenant_id": tenant_id},
            headers={"X-API-Key": api_key})
        assert resp.status_code == 201
        org_id = resp.json["org_id"]
        
        yield client, {"tenant_id": tenant_id, "org_id": org_id, "api_key": api_key}
    
    if db_path.exists():
        try:
            db_path.unlink()
        except Exception:
            pass


def _admin_headers(api_key: str):
    return {
        "X-API-Key": api_key,
        "Content-Type": "application/json",
    }


# ═══════════════════════════════════════════════════════════════
# MATRIX TESTS
# ═══════════════════════════════════════════════════════════════

class TestAuthorizationMatrix:
    """Validates the fundamental authorization matrix."""
    
    def test_system_can_create_org_in_any_tenant(self, client_with_identity):
        """SYSTEM identity → any tenant = ALLOW (legacy behavior)."""
        client, ctx = client_with_identity
        
        # Create tenant B
        resp = client.post("/api/identity/tenants",
            json={"name": "Other Corp"},
            headers=_admin_headers(ctx["api_key"]))
        assert resp.status_code == 201
        tenant_b = resp.json["tenant_id"]
        
        # SYSTEM can create org in tenant B (legacy global access)
        resp = client.post("/api/identity/orgs",
            json={"name": "Spy Org", "tenant_id": tenant_b},
            headers=_admin_headers(ctx["api_key"]))
        assert resp.status_code == 201
    
    def test_developer_cannot_create_agent_in_other_org_same_tenant(self, client_with_identity):
        """Developer A → Org B (same tenant) = DENY (403)."""
        client, ctx = client_with_identity
        
        # Create developer agent
        resp = client.post("/api/identity/agents",
            json={"name": "Dev Agent", "org_id": ctx["org_id"]},
            headers=_admin_headers(ctx["api_key"]))
        assert resp.status_code == 201
        dev_key = resp.json["api_key"]
        
        # Create Org B in same tenant
        resp = client.post("/api/identity/orgs",
            json={"name": "Other Org", "tenant_id": ctx["tenant_id"]},
            headers=_admin_headers(ctx["api_key"]))
        assert resp.status_code == 201
        org_b = resp.json["org_id"]
        
        # Developer cannot create agent in Org B
        resp = client.post("/api/identity/agents",
            json={"name": "Spy Agent", "org_id": org_b},
            headers=_admin_headers(dev_key))
        assert resp.status_code == 403
        assert "denied" in resp.json.get("error", "").lower()
    
    def test_developer_cannot_create_agent_in_other_tenant(self, client_with_identity):
        """Developer A → Tenant B = DENY (403)."""
        client, ctx = client_with_identity
        
        # Create developer agent
        resp = client.post("/api/identity/agents",
            json={"name": "Dev Agent", "org_id": ctx["org_id"]},
            headers=_admin_headers(ctx["api_key"]))
        assert resp.status_code == 201
        dev_key = resp.json["api_key"]
        
        # Create tenant B
        resp = client.post("/api/identity/tenants",
            json={"name": "Evil Corp"},
            headers=_admin_headers(ctx["api_key"]))
        tenant_b = resp.json["tenant_id"]
        
        # Create org in tenant B
        resp = client.post("/api/identity/orgs",
            json={"name": "Spy Org", "tenant_id": tenant_b},
            headers=_admin_headers(ctx["api_key"]))
        spy_org = resp.json["org_id"]
        
        # Developer cannot create agent in spy_org (different tenant)
        resp = client.post("/api/identity/agents",
            json={"name": "Spy Agent", "org_id": spy_org},
            headers=_admin_headers(dev_key))
        assert resp.status_code == 403
        assert "denied" in resp.json.get("error", "").lower()
    
    def test_developer_cannot_create_user(self, client_with_identity):
        """Developer → user:create = DENY (permission missing)."""
        client, ctx = client_with_identity
        
        resp = client.post("/api/identity/agents",
            json={"name": "Dev", "org_id": ctx["org_id"]},
            headers=_admin_headers(ctx["api_key"]))
        dev_key = resp.json["api_key"]
        
        resp = client.post("/api/identity/users",
            json={"email": "x@test.com", "org_id": ctx["org_id"]},
            headers=_admin_headers(dev_key))
        assert resp.status_code == 403
    
    def test_developer_can_list_agents_in_own_org(self, client_with_identity):
        """Developer → agent:list in own org = ALLOW."""
        client, ctx = client_with_identity
        
        # Create 2 agents in ctx["org_id"]
        resp1 = client.post("/api/identity/agents",
            json={"name": "Agent1", "org_id": ctx["org_id"]},
            headers=_admin_headers(ctx["api_key"]))
        resp2 = client.post("/api/identity/agents",
            json={"name": "Agent2", "org_id": ctx["org_id"]},
            headers=_admin_headers(ctx["api_key"]))
        dev_key = resp1.json["api_key"]
        
        # Developer can list their own org's agents
        resp = client.get("/api/identity/agents",
            headers=_admin_headers(dev_key))
        assert resp.status_code == 200
        assert resp.json["count"] == 2


class TestInputValidation:
    """Tests for strict Pydantic input validation."""
    
    def test_nan_budget_rejected(self, client_with_identity):
        """NaN budget → 400."""
        client, ctx = client_with_identity
        resp = client.post("/api/identity/agents",
            json={"name": "Bot", "org_id": ctx["org_id"], "max_budget_per_day": float("nan")},
            headers=_admin_headers(ctx["api_key"]))
        assert resp.status_code == 400
        assert "validation" in resp.json.get("error", "").lower()
    
    def test_infinity_budget_rejected(self, client_with_identity):
        """Infinity budget → 400."""
        client, ctx = client_with_identity
        resp = client.post("/api/identity/agents",
            json={"name": "Bot", "org_id": ctx["org_id"], "max_budget_per_day": float("inf")},
            headers=_admin_headers(ctx["api_key"]))
        assert resp.status_code == 400
    
    def test_negative_budget_rejected(self, client_with_identity):
        """Negative budget → 400."""
        client, ctx = client_with_identity
        resp = client.post("/api/identity/agents",
            json={"name": "Bot", "org_id": ctx["org_id"], "max_budget_per_day": -10.0},
            headers=_admin_headers(ctx["api_key"]))
        assert resp.status_code == 400
    
    def test_oversized_budget_rejected(self, client_with_identity):
        """Budget > 10000 → 400."""
        client, ctx = client_with_identity
        resp = client.post("/api/identity/agents",
            json={"name": "Bot", "org_id": ctx["org_id"], "max_budget_per_day": 999999},
            headers=_admin_headers(ctx["api_key"]))
        assert resp.status_code == 400
    
    def test_injection_in_name_rejected(self, client_with_identity):
        """Injection chars in name → 400."""
        client, ctx = client_with_identity
        resp = client.post("/api/identity/agents",
            json={"name": "Bot<script>", "org_id": ctx["org_id"]},
            headers=_admin_headers(ctx["api_key"]))
        assert resp.status_code == 400
    
    def test_valid_budget_accepted(self, client_with_identity):
        """Valid budget (42.5) → 201."""
        client, ctx = client_with_identity
        resp = client.post("/api/identity/agents",
            json={"name": "Valid Bot", "org_id": ctx["org_id"], "max_budget_per_day": 42.5},
            headers=_admin_headers(ctx["api_key"]))
        assert resp.status_code == 201
        assert resp.json["agent_id"].startswith("agent_")
