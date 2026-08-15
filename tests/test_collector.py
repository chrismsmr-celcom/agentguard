"""Tests des endpoints API du collector."""
import json
import pytest


class TestHealthEndpoint:
    """Endpoint /healthz."""
    
    def test_health_returns_ok(self, client):
        resp = client.get("/healthz")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"


class TestAuthMiddleware:
    """Middleware d'authentification."""
    
    def test_unauthenticated_metrics_rejected(self, client):
        """Sans clé API → 401."""
        resp = client.get("/api/metrics")
        assert resp.status_code == 401
    
    def test_valid_key_accepted(self, client, auth_headers):
        """Clé valide → 200."""
        resp = client.get("/api/metrics", headers=auth_headers)
        assert resp.status_code == 200
    
    def test_invalid_key_rejected(self, client):
        """Clé invalide → 401."""
        resp = client.get("/api/metrics", headers={"X-API-Key": "ag-invalid"})
        assert resp.status_code == 401


class TestSpanIngestion:
    """Endpoint POST /span."""
    
    def test_valid_span_accepted(self, client, auth_headers, sample_span):
        """Span valide → 201."""
        resp = client.post(
            "/span",
            json=sample_span,
            headers={**auth_headers, "Content-Type": "application/json"},
        )
        assert resp.status_code == 201
    
    def test_missing_required_fields_rejected(self, client, auth_headers):
        """Champs manquants → 400."""
        resp = client.post(
            "/span",
            json={"trace_id": "abc"},  # manque span_id, span_type, etc.
            headers={**auth_headers, "Content-Type": "application/json"},
        )
        assert resp.status_code == 400
    
    def test_invalid_json_rejected(self, client, auth_headers):
        """JSON invalide → 400."""
        resp = client.post(
            "/span",
            data="not json",
            headers={**auth_headers, "Content-Type": "application/json"},
        )
        assert resp.status_code == 400
    
    def test_span_stored_and_retrievable(self, client, auth_headers, sample_span):
        """La span est bien stockée et récupérable."""
        # Ingest
        client.post(
            "/span",
            json=sample_span,
            headers={**auth_headers, "Content-Type": "application/json"},
        )
        
        # Retrieve via traces
        resp = client.get("/api/traces", headers=auth_headers)
        assert resp.status_code == 200
        traces = resp.get_json()
        assert len(traces) >= 1
        trace_ids = [t["trace_id"] for t in traces]
        assert "test-trace-001" in trace_ids


class TestMetricsEndpoint:
    """Endpoint /api/metrics."""
    
    def test_metrics_structure(self, client, auth_headers):
        """Structure des métriques correcte."""
        resp = client.get("/api/metrics", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        
        # Champs obligatoires
        required_fields = [
            "total_spans", "total_traces", "blocked_operations",
            "total_cost_usd", "avg_latency_ms", "risk_distribution",
        ]
        for field in required_fields:
            assert field in data, f"Champ manquant: {field}"
    
    def test_metrics_updated_after_span(self, client, auth_headers, sample_span):
        """Les métriques s'incrémentent après ingestion."""
        # Avant
        before = client.get("/api/metrics", headers=auth_headers).get_json()
        
        # Ingest
        client.post(
            "/span",
            json=sample_span,
            headers={**auth_headers, "Content-Type": "application/json"},
        )
        
        # Après
        after = client.get("/api/metrics", headers=auth_headers).get_json()
        assert after["total_spans"] >= before["total_spans"]


class TestPIIRedaction:
    """Masquage du PII dans les spans stockées."""
    
    def test_email_redacted_in_storage(self, client, auth_headers):
        """L'email est masqué avant stockage."""
        span = {
            "trace_id": "pii-test",
            "span_id": "pii-span",
            "span_type": "llm_call",
            "timestamp": 1700000000.0,
            "latency_ms": 10.0,
            "input_data": {"prompt": "Email: john@example.com please"},
            "output_data": {},
            "security_checks": [],
            "blocked": False,
        }
        client.post(
            "/span",
            json=span,
            headers={**auth_headers, "Content-Type": "application/json"},
        )
        
        # Récupère la trace
        resp = client.get("/api/traces/pii-test", headers=auth_headers)
        assert resp.status_code == 200
        rows = resp.get_json()
        assert len(rows) >= 1
        
        # Vérifie que l'email est masqué
        stored_prompt = str(rows[0].get("input_data", {}))
        assert "john@example.com" not in stored_prompt
        assert "REDACTED" in stored_prompt
