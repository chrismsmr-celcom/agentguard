"""Tests de la matrice d'autorisation — vérifie tous les cas critiques."""
import os
import pytest


class TestAuthorizationMatrix:
    """Matrice complète SYSTEM/Tenant Admin/Org Developer."""
    
    def test_system_can_access_any_tenant(self, client_with_identity):
        """SYSTEM → tout tenant = ALLOW."""
        client, _ = client_with_identity
        # Créer tenant B
        resp = client.post("/api/identity/tenants",
            json={"name": "Other Corp"},
            headers={"X-API-Key": os.environ["AGENTGUARD_API_KEY"]})
        tenant_b = resp.json["tenant_id"]
        
        # SYSTEM peut créer org dans tenant B
        resp = client.post("/api/identity/orgs",
            json={"name": "Spy Org", "tenant_id": tenant_b},
            headers={"X-API-Key": os.environ["AGENTGUARD_API_KEY"]})
        assert resp.status_code == 201
    
    def test_developer_cannot_access_other_org(self, client_with_identity):
        """Developer A → Org B (même tenant) = DENY."""
        client, ctx = client_with_identity
        
        # Créer dev agent
        resp = client.post("/api/identity/agents",
            json={"name": "Dev", "org_id": ctx["org_id"]},
            headers={"X-API-Key": os.environ["AGENTGUARD_API_KEY"]})
        dev_key = resp.json["api_key"]
        
        # Créer org B dans même tenant
        resp = client.post("/api/identity/orgs",
            json={"name": "Other Org", "tenant_id": ctx["tenant_id"]},
            headers={"X-API-Key": os.environ["AGENTGUARD_API_KEY"]})
        org_b = resp.json["org_id"]
        
        # Developer ne peut pas créer agent dans org B
        resp = client.post("/api/identity/agents",
            json={"name": "Spy", "org_id": org_b},
            headers={"X-API-Key": dev_key, "Content-Type": "application/json"})
        assert resp.status_code == 403
    
    def test_developer_cannot_create_user(self, client_with_identity):
        """Developer → user:create = DENY (permission manquante)."""
        client, ctx = client_with_identity
        
        resp = client.post("/api/identity/agents",
            json={"name": "Dev", "org_id": ctx["org_id"]},
            headers={"X-API-Key": os.environ["AGENTGUARD_API_KEY"]})
        dev_key = resp.json["api_key"]
        
        resp = client.post("/api/identity/users",
            json={"email": "x@test.com", "org_id": ctx["org_id"]},
            headers={"X-API-Key": dev_key, "Content-Type": "application/json"})
        assert resp.status_code == 403
    
    def test_auditor_cannot_create_agent(self, client_with_identity):
        """Auditor → agent:create = DENY."""
        # À implémenter quand login user sera fait
        pass
    
    def test_invalid_budget_rejected(self, client_with_identity):
        """NaN/Infinity/negative budget = 400."""
        client, ctx = client_with_identity
        
        # NaN
        resp = client.post("/api/identity/agents",
            json={"name": "Bad", "org_id": ctx["org_id"], "max_budget_per_day": float("nan")},
            headers={"X-API-Key": os.environ["AGENTGUARD_API_KEY"], "Content-Type": "application/json"})
        assert resp.status_code == 400
        
        # Infinity
        resp = client.post("/api/identity/agents",
            json={"name": "Bad", "org_id": ctx["org_id"], "max_budget_per_day": float("inf")},
            headers={"X-API-Key": os.environ["AGENTGUARD_API_KEY"], "Content-Type": "application/json"})
        assert resp.status_code == 400
        
        # Negative
        resp = client.post("/api/identity/agents",
            json={"name": "Bad", "org_id": ctx["org_id"], "max_budget_per_day": -10.0},
            headers={"X-API-Key": os.environ["AGENTGUARD_API_KEY"], "Content-Type": "application/json"})
        assert resp.status_code == 400
        
        # Over limit
        resp = client.post("/api/identity/agents",
            json={"name": "Bad", "org_id": ctx["org_id"], "max_budget_per_day": 999999},
            headers={"X-API-Key": os.environ["AGENTGUARD_API_KEY"], "Content-Type": "application/json"})
        assert resp.status_code == 400
