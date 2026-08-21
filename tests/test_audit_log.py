"""Tests de l'Immutable Audit Log (v3.6)."""
import os
import json
import tempfile
import pytest

try:
    from audit import ImmutableAuditLog, AuditEventType
    AUDIT_AVAILABLE = True
except ImportError:
    AUDIT_AVAILABLE = False


@pytest.mark.skipif(not AUDIT_AVAILABLE, reason="audit module not installed")
class TestAuditLogBasic:
    """Tests de base du audit log."""
    
    def test_log_event_creates_entry(self, tmp_path):
        """Logger un event crée une entrée."""
        backup = str(tmp_path / "audit.jsonl")
        log = ImmutableAuditLog(backup_file=backup)
        
        entry = log.log_event(
            event_type=AuditEventType.PROMPT_BLOCKED,
            org_id="org1",
            actor="agent1",
            resource="span:abc",
            action="blocked",
            details={"reason": "injection"},
            risk_level="critical",
        )
        
        assert entry.event_id
        assert entry.entry_hash
        assert entry.prev_hash == "GENESIS"
        assert entry.event_type == "prompt_blocked"
    
    def test_chain_hashes_linked(self, tmp_path):
        """Chaque entrée référence le hash de la précédente."""
        backup = str(tmp_path / "audit.jsonl")
        log = ImmutableAuditLog(backup_file=backup)
        
        e1 = log.log_event(
            event_type=AuditEventType.LLM_CALL,
            org_id="org1", actor="a", resource="r1", action="a",
        )
        e2 = log.log_event(
            event_type=AuditEventType.LLM_CALL,
            org_id="org1", actor="a", resource="r2", action="a",
        )
        e3 = log.log_event(
            event_type=AuditEventType.LLM_CALL,
            org_id="org1", actor="a", resource="r3", action="a",
        )
        
        assert e1.prev_hash == "GENESIS"
        assert e2.prev_hash == e1.entry_hash
        assert e3.prev_hash == e2.entry_hash
    
    def test_verify_chain_valid(self, tmp_path):
        """Une chaîne non modifiée est valide."""
        backup = str(tmp_path / "audit.jsonl")
        log = ImmutableAuditLog(backup_file=backup)
        
        for i in range(10):
            log.log_event(
                event_type=AuditEventType.SPAN_INGESTED,
                org_id="org1", actor="a",
                resource=f"span:{i}", action="ingested",
            )
        
        is_valid, report = log.verify_chain()
        assert is_valid is True
        assert report["entries_checked"] == 10
        assert report["violations"] == []


@pytest.mark.skipif(not AUDIT_AVAILABLE, reason="audit module not installed")
class TestAuditLogTampering:
    """Tests de détection de tampering."""
    
    def test_tampered_entry_detected(self, tmp_path):
        """Modifier une entrée casse la chaîne."""
        backup = str(tmp_path / "audit.jsonl")
        log = ImmutableAuditLog(backup_file=backup)
        
        for i in range(5):
            log.log_event(
                event_type=AuditEventType.LLM_CALL,
                org_id="org1", actor="a",
                resource=f"r{i}", action="a",
            )
        
        # Tamper : modifier la 3e entrée
        with open(backup, "r") as f:
            lines = f.readlines()
        
        entry = json.loads(lines[2])
        entry["action"] = "TAMPERED"
        lines[2] = json.dumps(entry) + "\n"
        
        with open(backup, "w") as f:
            f.writelines(lines)
        
        # Vérifie : doit détecter le tampering
        is_valid, report = log.verify_chain()
        assert is_valid is False
        assert len(report["violations"]) >= 1
        # Soit hash_mismatch, soit chain_break
        violation_types = [v["type"] for v in report["violations"]]
        assert "hash_mismatch" in violation_types or "chain_break" in violation_types
    
    def test_deleted_entry_detected(self, tmp_path):
        """Supprimer une entrée casse la chaîne."""
        backup = str(tmp_path / "audit.jsonl")
        log = ImmutableAuditLog(backup_file=backup)
        
        for i in range(5):
            log.log_event(
                event_type=AuditEventType.LLM_CALL,
                org_id="org1", actor="a",
                resource=f"r{i}", action="a",
            )
        
        # Supprime la 3e entrée
        with open(backup, "r") as f:
            lines = f.readlines()
        del lines[2]
        with open(backup, "w") as f:
            f.writelines(lines)
        
        # La 4e entrée (maintenant 3e) pointe vers un prev_hash qui n'existe plus
        is_valid, report = log.verify_chain()
        assert is_valid is False
        assert any(v["type"] == "chain_break" for v in report["violations"])
    
    def test_inserted_entry_detected(self, tmp_path):
        """Insérer une entrée au milieu casse la chaîne."""
        backup = str(tmp_path / "audit.jsonl")
        log = ImmutableAuditLog(backup_file=backup)
        
        for i in range(3):
            log.log_event(
                event_type=AuditEventType.LLM_CALL,
                org_id="org1", actor="a",
                resource=f"r{i}", action="a",
            )
        
        # Insère une fausse entrée entre 1 et 2
        with open(backup, "r") as f:
            lines = f.readlines()
        
        fake_entry = {
            "event_id": "fake",
            "timestamp": 9999999999,
            "event_type": "injected",
            "org_id": "org1",
            "actor": "attacker",
            "resource": "fake",
            "action": "injected",
            "details": {},
            "risk_level": "critical",
            "prev_hash": "fake_prev",
            "entry_hash": "fake_hash",
        }
        lines.insert(1, json.dumps(fake_entry) + "\n")
        
        with open(backup, "w") as f:
            f.writelines(lines)
        
        is_valid, report = log.verify_chain()
        assert is_valid is False


@pytest.mark.skipif(not AUDIT_AVAILABLE, reason="audit module not installed")
class TestAuditLogQuery:
    """Tests des requêtes sur l'audit log."""
    
    def test_query_by_org(self, tmp_path):
        """Requête par org retourne seulement les events de cet org."""
        backup = str(tmp_path / "audit.jsonl")
        log = ImmutableAuditLog(backup_file=backup)
        
        log.log_event(AuditEventType.LLM_CALL, "org1", "a", "r1", "a")
        log.log_event(AuditEventType.LLM_CALL, "org2", "a", "r2", "a")
        log.log_event(AuditEventType.LLM_CALL, "org1", "a", "r3", "a")
        
        results = log.query(org_id="org1")
        assert len(results) == 2
        assert all(r["org_id"] == "org1" for r in results)
    
    def test_query_by_event_type(self, tmp_path):
        """Requête par type d'événement."""
        backup = str(tmp_path / "audit.jsonl")
        log = ImmutableAuditLog(backup_file=backup)
        
        log.log_event(AuditEventType.PROMPT_BLOCKED, "org1", "a", "r1", "blocked")
        log.log_event(AuditEventType.LLM_CALL, "org1", "a", "r2", "allowed")
        log.log_event(AuditEventType.PROMPT_BLOCKED, "org1", "a", "r3", "blocked")
        
        results = log.query(event_type="prompt_blocked")
        assert len(results) == 2
    
    def test_get_stats(self, tmp_path):
        """get_stats retourne des statistiques correctes."""
        backup = str(tmp_path / "audit.jsonl")
        log = ImmutableAuditLog(backup_file=backup)
        
        log.log_event(AuditEventType.PROMPT_BLOCKED, "org1", "a", "r1", "blocked", risk_level="critical")
        log.log_event(AuditEventType.PROMPT_BLOCKED, "org1", "a", "r2", "blocked", risk_level="critical")
        log.log_event(AuditEventType.LLM_CALL, "org1", "a", "r3", "ok", risk_level="info")
        
        stats = log.get_stats()
        assert stats["total_entries"] == 3
        assert stats["chain_intact"] is True
    
    def test_details_size_limit(self, tmp_path):
        """Les détails trop gros sont tronqués (protection anti-DoS)."""
        backup = str(tmp_path / "audit.jsonl")
        log = ImmutableAuditLog(backup_file=backup)
        
        # Détails de 50KB
        big_details = {"data": "x" * 50_000}
        entry = log.log_event(
            AuditEventType.LLM_CALL, "org1", "a", "r1", "a",
            details=big_details,
        )
        
        # Devrait être tronqué
        assert entry.details.get("_truncated") is True
        assert entry.details.get("_original_size") > 10_000
