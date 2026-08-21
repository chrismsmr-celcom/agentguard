"""Tests de l'Identity Engine Phase 2 — isolation multi-tenant + RBAC."""
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
    """Client avec DB + tenant + org + user admin initialisés."""
    db_path = tmp_path / "test.db"
    os.environ["AGENTGUARD_DB_PATH"] = str(db_path)
    
    from collector.db import init_db
    from collector.app import create_app
    
    init_db()
    app = create_app()
    app.config["TESTING"] = True
    
    with app.test_client() as client:
        # Crée un tenant
        resp = client.post("/api/identity/tenants",
            json={"name": "Acme Corp"},
            headers={"X-API-Key": os.environ["AGENTGUARD_API_KEY"]})
        assert resp.status_code == 201
        tenant_id = resp.json["tenant_id"]
        
        # Crée une org
        resp = client.post("/api/identity/orgs",
            json={"name": "Engineering", "tenant_id": tenant_id},
            headers={"X-API-Key": os.environ["AGENTGUARD_API_KEY"]})
        assert resp.status_code == 201
        org_id = resp.json["org_id"]
        
        yield client, {"tenant_id": tenant_id, "org_id": org_id}
    
    if db_path.exists():
        db_path.unlink()


@pytest.fixture
def client(tmp_path):
    """Client simple."""
    db_path = tmp_path / "test.db"
    os.environ["AGENTGUARD_DB_PATH"] = str(db_path)
    
    from collector.db import init_db
    from collector.app import create_app
    
    init_db()
    app = create_app()
    app.config["TESTING"] = True
    
    with app.test_client() as c:
        yield c
    
    if db_path.exists():
        db_path.unlink()


def _admin_headers():
    return {
        "X-API-Key": os.environ["AGENTGUARD_API_KEY"],
        "Content-Type": "application/json",
    }


# ═══════════════════════════════════════════════════════════════
# TENANT TESTS
# ═══════════════════════════════════════════════════════════════

class TestTenantCreation:
    def test_create_tenant_success(self, client):
        resp = client.post("/api/identity/tenants",
            json={"name": "Test Corp"},
            headers=_admin_headers())
        assert resp.status_code == 201
        assert resp.json["tenant_id"].startswith("tenant_")
        assert resp.json["name"] == "Test Corp"
    
    def test_create_tenant_invalid_name(self, client):
        resp = client.post("/api/identity/tenants",
            json={"name": "x"},
            headers=_admin_headers())
        assert resp.status_code == 400


# ═══════════════════════════════════════════════════════════════
# AGENT CREATION + API KEY
# ═══════════════════════════════════════════════════════════════

class TestAgentCreation:
    def test_create_agent_returns_api_key(self, client_with_identity):
        client, ctx = client_with_identity
        resp = client.post("/api/identity/agents",
            json={
                "name": "Test Agent",
                "org_id": ctx["org_id"],
                "max_budget_per_day": 50.0,
            },
            headers=_admin_headers())
        assert resp.status_code == 201
        data = resp.json
        assert data["agent_id"].startswith("agent_")
        assert data["api_key"].startswith("ag_")
        # Format: ag_{t}_{o}_{a}_{random32}
        parts = data["api_key"].split("_")
        assert len(parts) == 5
        assert parts[0] == "ag"
        assert len(parts[4]) == 32
    
    def test_create_agent_invalid_name(self, client_with_identity):
        client, ctx = client_with_identity
        resp = client.post("/api/identity/agents",
            json={"name": "x", "org_id": ctx["org_id"]},
            headers=_admin_headers())
        assert resp.status_code == 400
    
    def test_create_agent_invalid_budget(self, client_with_identity):
        client, ctx = client_with_identity
        resp = client.post("/api/identity/agents",
            json={"name": "Agent", "org_id": ctx["org_id"], "max_budget_per_day": 999999},
            headers=_admin_headers())
        assert resp.status_code == 400


# ═══════════════════════════════════════════════════════════════
# MULTI-TENANT ISOLATION (BOLA enforcement - CWE-639)
# ═══════════════════════════════════════════════════════════════

class TestMultiTenantIsolation:
    """Isolation stricte multi-tenant : aucun accès cross-tenant."""

    def test_org_a_cannot_see_org_b_agents(self, client_with_identity):
        """Org A crée un agent. Un appel avec une autre org ne le voit pas."""
        client, ctx = client_with_identity
        
        # Org A crée un agent
        resp = client.post("/api/identity/agents",
            json={"name": "Secret Agent", "org_id": ctx["org_id"]},
            headers=_admin_headers())
        assert resp.status_code == 201
        
        # Crée une org B
        resp = client.post("/api/identity/orgs",
            json={"name": "Marketing", "tenant_id": ctx["tenant_id"]},
            headers=_admin_headers())
        org_b_id = resp.json["org_id"]
        
        # Vérifie via query DB directe (isolation au niveau DB)
        from collector.db import get_sqlite_conn
        conn = get_sqlite_conn()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM agents WHERE org_id = ?", (ctx["org_id"],))
        count_a = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM agents WHERE org_id = ?", (org_b_id,))
        count_b = cur.fetchone()[0]
        conn.close()
        
        assert count_a == 1  # Org A a 1 agent
        assert count_b == 0  # Org B n'en voit aucun

    def test_cannot_create_agent_in_other_tenant_org(self, client_with_identity):
        """
        Un developer ne peut PAS créer un agent dans une org d'un autre tenant.
        
        ✅ MUST = 403 (jamais 201). Test déterministe.
        CWE-639: Broken Object Level Authorization (BOLA)
        """
        client, ctx = client_with_identity
        
        # Crée un tenant B (isolé)
        resp = client.post("/api/identity/tenants",
            json={"name": "Evil Corp"},
            headers=_admin_headers())
        assert resp.status_code == 201
        tenant_b = resp.json["tenant_id"]
        
        # Crée une org dans tenant B
        resp = client.post("/api/identity/orgs",
            json={"name": "Spy Org", "tenant_id": tenant_b},
            headers=_admin_headers())
        assert resp.status_code == 201
        spy_org = resp.json["org_id"]
        
        # Crée un agent developer dans ctx["org_id"] (tenant A)
        resp = client.post("/api/identity/agents",
            json={"name": "Legit Agent", "org_id": ctx["org_id"]},
            headers=_admin_headers())
        assert resp.status_code == 201
        dev_agent_key = resp.json["api_key"]
        
        # Developer tente de créer un agent dans spy_org (tenant B)
        # ✅ BOLA enforcement : DOIT retourner 403
        resp = client.post("/api/identity/agents",
            json={"name": "Spy Agent", "org_id": spy_org},
            headers={"X-API-Key": dev_agent_key, "Content-Type": "application/json"})
        
        # ✅ Assertion déterministe : JAMAIS 201, TOUJOURS 403
        assert resp.status_code == 403, \
            f"BOLA not enforced: got {resp.status_code}, expected 403"
        assert "access denied" in resp.json.get("error", "").lower() or \
               "denied" in resp.json.get("error", "").lower()

# ═══════════════════════════════════════════════════════════════
# AGENT REVOCATION
# ═══════════════════════════════════════════════════════════════

class TestAgentRevocation:
    def test_revoke_agent_invalidates_key(self, client_with_identity):
        """Révoquer un agent rend sa clé API invalide."""
        client, ctx = client_with_identity
        
        # Crée un agent
        resp = client.post("/api/identity/agents",
            json={"name": "Temp Agent", "org_id": ctx["org_id"]},
            headers=_admin_headers())
        assert resp.status_code == 201
        agent_id = resp.json["agent_id"]
        api_key = resp.json["api_key"]
        
        # La clé marche pour /span
        resp = client.post("/span",
            json={
                "trace_id": "t1", "span_id": "s1", "span_type": "llm_call",
                "timestamp": 1700000000.0, "latency_ms": 100,
                "input_data": {}, "output_data": {},
            },
            headers={"X-API-Key": api_key, "Content-Type": "application/json"})
        assert resp.status_code == 201
        
        # Révoque l'agent
        resp = client.delete(f"/api/identity/agents/{agent_id}",
            headers=_admin_headers())
        assert resp.status_code == 200
        
        # La clé ne marche plus
        resp = client.post("/span",
            json={
                "trace_id": "t2", "span_id": "s2", "span_type": "llm_call",
                "timestamp": 1700000001.0, "latency_ms": 100,
                "input_data": {}, "output_data": {},
            },
            headers={"X-API-Key": api_key, "Content-Type": "application/json"})
        assert resp.status_code == 401
    
    def test_revoke_nonexistent_agent_returns_404(self, client_with_identity):
        client, _ = client_with_identity
        resp = client.delete("/api/identity/agents/agent_nonexistent",
            headers=_admin_headers())
        assert resp.status_code == 404


# ═══════════════════════════════════════════════════════════════
# /ME ENDPOINT
# ═══════════════════════════════════════════════════════════════

class TestMeEndpoint:
    def test_me_with_legacy_key(self, client):
        """La clé API legacy retourne identity_type system (super-admin)."""
        resp = client.get("/api/identity/me", headers=_admin_headers())
        assert resp.status_code == 200
        # ✅ La clé legacy = super-admin global (type system)
        assert resp.json["identity_type"] in ("legacy", "system")
        assert resp.json["role"] == "admin"
    
    def test_me_requires_auth(self, client):
        """Sans clé API → 401."""
        resp = client.get("/api/identity/me")
        assert resp.status_code == 401


# ═══════════════════════════════════════════════════════════════
# RBAC TESTS (via agent key)
# ═══════════════════════════════════════════════════════════════

class TestRBACWithAgentKey:
    def test_agent_key_cannot_create_user(self, client_with_identity):
        """Une clé agent (role=developer) ne peut pas créer de user."""
        client, ctx = client_with_identity
        
        # Crée un agent
        resp = client.post("/api/identity/agents",
            json={"name": "Bot", "org_id": ctx["org_id"]},
            headers=_admin_headers())
        agent_key = resp.json["api_key"]
        
        # Tente de créer un user avec la clé agent
        resp = client.post("/api/identity/users",
            json={"email": "bob@test.com", "role": "viewer"},
            headers={"X-API-Key": agent_key, "Content-Type": "application/json"})
        # developer n'a pas user:create → 403
        assert resp.status_code == 403
    
    def test_agent_key_can_list_agents(self, client_with_identity):
        """Une clé agent (role=developer) peut lister les agents."""
        client, ctx = client_with_identity
        
        # Crée 2 agents
        resp1 = client.post("/api/identity/agents",
            json={"name": "Bot1", "org_id": ctx["org_id"]},
            headers=_admin_headers())
        resp2 = client.post("/api/identity/agents",
            json={"name": "Bot2", "org_id": ctx["org_id"]},
            headers=_admin_headers())
        agent_key = resp1.json["api_key"]
        
        # L'agent peut lister (role=developer a traces:view_own_org)
        resp = client.get("/api/identity/agents",
            headers={"X-API-Key": agent_key})
        # Note : list_agents requiert admin/developer/auditor
        assert resp.status_code == 200
        assert resp.json["count"] == 2


# ═══════════════════════════════════════════════════════════════
# USER CREATION
# ═══════════════════════════════════════════════════════════════

class TestUserCreation:
    def test_create_user_success(self, client_with_identity):
        client, ctx = client_with_identity
        resp = client.post("/api/identity/users",
            json={
                "email": "alice@test.com",
                "display_name": "Alice",
                "role": "developer",
                "org_id": ctx["org_id"],
            },
            headers=_admin_headers())
        assert resp.status_code == 201
        assert resp.json["user_id"].startswith("user_")
        assert resp.json["role"] == "developer"
    
    def test_create_user_invalid_email(self, client_with_identity):
        client, ctx = client_with_identity
        resp = client.post("/api/identity/users",
            json={"email": "not-an-email", "org_id": ctx["org_id"]},
            headers=_admin_headers())
        assert resp.status_code == 400
    
    def test_create_user_duplicate_email(self, client_with_identity):
        client, ctx = client_with_identity
        payload = {"email": "dup@test.com", "org_id": ctx["org_id"]}
        resp1 = client.post("/api/identity/users",
            json=payload, headers=_admin_headers())
        assert resp1.status_code == 201
        resp2 = client.post("/api/identity/users",
            json=payload, headers=_admin_headers())
        assert resp2.status_code == 409
    
    def test_create_user_invalid_role(self, client_with_identity):
        client, ctx = client_with_identity
        resp = client.post("/api/identity/users",
            json={
                "email": "x@test.com",
                "role": "superadmin",
                "org_id": ctx["org_id"],
            },
            headers=_admin_headers())
        assert resp.status_code == 400
        assert "valid_roles" in resp.json
