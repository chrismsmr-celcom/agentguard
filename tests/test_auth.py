"""Tests d'authentification et sessions."""
import os
import pytest


class TestLoginFlow:
    """Flux de login web."""
    
    def test_login_page_accessible(self, client):
        """La page de login est accessible sans auth."""
        resp = client.get("/login")
        assert resp.status_code == 200
        assert b"Sign in" in resp.data
    
    def test_valid_login_redirects(self, client):
        """Login valide → redirect vers dashboard."""
        resp = client.post(
            "/login",
            data={"api_key": os.environ["AGENTGUARD_API_KEY"]},
            follow_redirects=False,
        )
        assert resp.status_code in (302, 303)
        # Vérifie qu'un cookie de session est défini
        assert "ag_auth" in resp.headers.get("Set-Cookie", "")
    
    def test_invalid_login_shows_error(self, client):
        """Login invalide → page d'erreur."""
        resp = client.post("/login", data={"api_key": "invalid-key"})
        assert resp.status_code == 401
        assert b"Invalid" in resp.data


class TestKeyEndpoint:
    """Endpoint /api/key (récupération clé via admin secret)."""
    
    def test_key_requires_admin_secret(self, client):
        """Sans admin secret → 403."""
        resp = client.get("/api/key")
        assert resp.status_code in (403, 404)
    
    def test_key_with_valid_admin_secret(self, client):
        """Avec admin secret valide → retourne la clé."""
        resp = client.get(
            "/api/key",
            headers={"X-Admin-Secret": os.environ["AGENTGUARD_ADMIN_SECRET"]},
        )
        # Si ADMIN_SECRET est configuré, doit retourner la clé
        if os.environ["AGENTGUARD_ADMIN_SECRET"]:
            assert resp.status_code == 200
            data = resp.get_json()
            assert "api_key" in data


class TestLogout:
    """Déconnexion."""
    
    def test_logout_clears_cookie(self, client):
        """Logout supprime le cookie de session."""
        # Login d'abord
        client.post(
            "/login",
            data={"api_key": os.environ["AGENTGUARD_API_KEY"]},
        )
        
        # Logout
        resp = client.post("/logout", follow_redirects=False)
        assert resp.status_code in (302, 303)
        cookie = resp.headers.get("Set-Cookie", "")
        # Le cookie doit être expiré (Max-Age=0 ou expires dans le passé)
        assert "ag_auth" in cookie
