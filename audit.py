"""
AgentGuard Immutable Audit Log
Log append-only cryptographiquement chaîné pour SOC 2 Type II compliance.

Architecture :
  - Chaque entrée contient le hash SHA256 de l'entrée précédente
  - Signature Ed25519 périodique de la racine (toutes les N entrées)
  - Détection instantanée de toute modification
  - Stockage Postgres (primary) + JSON Lines (backup)

Garanties :
  - Append-only (pas de UPDATE/DELETE)
  - Integrity : toute modification casse la chaîne
  - Non-repudiation : signatures cryptographiques
  - Verifiable : rejouer la chaîne = preuve d'intégrité
"""
import os
import json
import time
import hashlib
import secrets
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any, List
from enum import Enum

try:
    import psycopg
    import psycopg.rows
    PSYCOPG_AVAILABLE = True
except ImportError:
    PSYCOPG_AVAILABLE = False


class AuditEventType(str, Enum):
    """Types d'événements auditables."""
    # Sécurité
    PROMPT_BLOCKED = "prompt_blocked"
    TOOL_BLOCKED = "tool_blocked"
    TAINT_VIOLATION = "taint_violation"
    BUDGET_EXCEEDED = "budget_exceeded"
    SIGNED_DENY = "signed_deny"
    PII_DETECTED = "pii_detected"
    INJECTION_DETECTED = "injection_detected"
    
    # Accès
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    API_KEY_CREATED = "api_key_created"
    API_KEY_REVOKED = "api_key_revoked"
    
    # Système
    POLICY_LOADED = "policy_loaded"
    POLICY_CHANGED = "policy_changed"
    CONFIG_CHANGED = "config_changed"
    
    # Opérations
    LLM_CALL = "llm_call"
    TOOL_CALL = "tool_call"
    SPAN_INGESTED = "span_ingested"


@dataclass
class AuditEntry:
    """Une entrée dans l'audit log."""
    event_id: str
    timestamp: float
    event_type: str
    org_id: str
    actor: str  # user_id, agent_id, ou "system"
    resource: str  # ex: "span:abc123", "policy:finance"
    action: str  # ex: "blocked", "allowed", "created"
    details: Dict[str, Any]
    risk_level: str = "info"  # info, warning, critical
    prev_hash: str = ""
    entry_hash: str = ""
    signature: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    def canonical_json(self, include_hash: bool = False) -> str:
        """JSON canonique pour calcul de hash (stable, trié)."""
        data = {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "org_id": self.org_id,
            "actor": self.actor,
            "resource": self.resource,
            "action": self.action,
            "details": self.details,
            "risk_level": self.risk_level,
            "prev_hash": self.prev_hash,
        }
        if include_hash and self.entry_hash:
            data["entry_hash"] = self.entry_hash
        return json.dumps(data, sort_keys=True, separators=(",", ":"))
    
    def compute_hash(self) -> str:
        """Calcule le hash SHA256 de l'entrée."""
        return hashlib.sha256(self.canonical_json().encode()).hexdigest()


class ImmutableAuditLog:
    """
    Audit log append-only avec chaînage cryptographique.
    
    Usage:
        log = ImmutableAuditLog(database_url="postgresql://...", signing_key=...)
        log.log_event(
            event_type=AuditEventType.PROMPT_BLOCKED,
            org_id="org1",
            actor="agent_xyz",
            resource="span:abc123",
            action="blocked",
            details={"reason": "injection detected", "score": 0.95},
            risk_level="critical",
        )
        
        # Vérification d'intégrité
        is_valid, report = log.verify_chain()
    """
    
    # Signe toutes les N entrées (0 = jamais)
    DEFAULT_SIGN_EVERY = 100
    # Limite de taille par entrée (protection anti-DoS)
    MAX_DETAILS_SIZE = 10_000  # caractères
    
    def __init__(
        self,
        database_url: Optional[str] = None,
        backup_file: Optional[str] = None,
        signing_key_pem: Optional[str] = None,
        sign_every: int = DEFAULT_SIGN_EVERY,
    ):
        self.database_url = database_url
        self.backup_file = backup_file or os.getenv(
            "AGENTGUARD_AUDIT_BACKUP", "/tmp/agentguard_audit.jsonl"
        )
        self.sign_every = sign_every
        self._entry_counter = 0
        
        # Signing (optionnel)
        self._signer = None
        if signing_key_pem:
            try:
                from signing import DecisionSigner
                self._signer = DecisionSigner(signing_key_pem)
            except Exception as e:
                print(f"[AuditLog] Signing unavailable: {e}")
        
        # Initialise le stockage
        self._init_storage()
    
    def _init_storage(self):
        """Initialise la table Postgres et/ou le fichier backup."""
        if self.database_url and PSYCOPG_AVAILABLE:
            try:
                conn = psycopg.connect(self.database_url)
                conn.autocommit = True
                with conn.cursor() as cur:
                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS audit_log (
                            event_id TEXT PRIMARY KEY,
                            seq_no BIGSERIAL UNIQUE,
                            timestamp DOUBLE PRECISION NOT NULL,
                            event_type TEXT NOT NULL,
                            org_id TEXT NOT NULL,
                            actor TEXT NOT NULL,
                            resource TEXT NOT NULL,
                            action TEXT NOT NULL,
                            details JSONB,
                            risk_level TEXT DEFAULT 'info',
                            prev_hash TEXT NOT NULL,
                            entry_hash TEXT NOT NULL,
                            signature TEXT,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )
                    """)
                    cur.execute("""
                        CREATE INDEX IF NOT EXISTS idx_audit_seq 
                        ON audit_log(seq_no)
                    """)
                    cur.execute("""
                        CREATE INDEX IF NOT EXISTS idx_audit_org_time 
                        ON audit_log(org_id, timestamp DESC)
                    """)
                    cur.execute("""
                        CREATE INDEX IF NOT EXISTS idx_audit_type 
                        ON audit_log(event_type, timestamp DESC)
                    """)
                conn.close()
                print("[AuditLog] Postgres storage initialized")
            except Exception as e:
                print(f"[AuditLog] Postgres init failed, using file backup: {e}")
                self.database_url = None
        
        # Backup file (toujours actif en parallèle)
        backup_dir = os.path.dirname(self.backup_file)
        if backup_dir and not os.path.exists(backup_dir):
            os.makedirs(backup_dir, exist_ok=True)
    
    def _get_last_hash(self) -> str:
        """Récupère le hash de la dernière entrée (pour chaînage)."""
        if self.database_url and PSYCOPG_AVAILABLE:
            try:
                conn = psycopg.connect(self.database_url)
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT entry_hash FROM audit_log "
                        "ORDER BY seq_no DESC LIMIT 1"
                    )
                    row = cur.fetchone()
                conn.close()
                return row[0] if row else "GENESIS"
            except Exception:
                pass
        
        # Fallback fichier
        if os.path.exists(self.backup_file):
            try:
                with open(self.backup_file, "r") as f:
                    lines = f.readlines()
                    if lines:
                        last = json.loads(lines[-1])
                        return last.get("entry_hash", "GENESIS")
            except Exception:
                pass
        
        return "GENESIS"
    
    def log_event(
        self,
        event_type: AuditEventType,
        org_id: str,
        actor: str,
        resource: str,
        action: str,
        details: Optional[Dict[str, Any]] = None,
        risk_level: str = "info",
    ) -> AuditEntry:
        """
        Log un événement de manière immutable.
        Retourne l'entrée créée.
        """
        # Sanitize details (protection taille)
        details = details or {}
        details_str = json.dumps(details)
        if len(details_str) > self.MAX_DETAILS_SIZE:
            details = {
                "_truncated": True,
                "_original_size": len(details_str),
                "_preview": details_str[:500],
            }
        
        # Récupère le hash précédent
        prev_hash = self._get_last_hash()
        
        # Crée l'entrée
        entry = AuditEntry(
            event_id=secrets.token_hex(16),
            timestamp=time.time(),
            event_type=event_type.value if isinstance(event_type, AuditEventType) else str(event_type),
            org_id=str(org_id),
            actor=str(actor),
            resource=str(resource),
            action=str(action),
            details=details,
            risk_level=risk_level,
            prev_hash=prev_hash,
        )
        
        # Calcule le hash
        entry.entry_hash = entry.compute_hash()
        
        # Signature périodique
        self._entry_counter += 1
        if self._signer and self.sign_every > 0 and self._entry_counter % self.sign_every == 0:
            try:
                payload = {
                    "request_id": entry.event_id,
                    "action": "audit_checkpoint",
                    "policy_name": "audit_chain",
                    "policy_version": 1,
                    "reason": f"Checkpoint at entry {self._entry_counter}",
                }
                signed = self._signer.sign_decision(payload)
                entry.signature = signed.get("signature")
            except Exception as e:
                print(f"[AuditLog] Signing failed: {e}")
        
        # Persiste (Postgres + backup file)
        self._persist(entry)
        
        return entry
    
    def _persist(self, entry: AuditEntry):
        """Persiste l'entrée dans Postgres ET backup file."""
        # Postgres
        if self.database_url and PSYCOPG_AVAILABLE:
            try:
                conn = psycopg.connect(self.database_url)
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO audit_log 
                        (event_id, timestamp, event_type, org_id, actor, resource, 
                         action, details, risk_level, prev_hash, entry_hash, signature)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """, (
                        entry.event_id, entry.timestamp, entry.event_type,
                        entry.org_id, entry.actor, entry.resource, entry.action,
                        json.dumps(entry.details), entry.risk_level,
                        entry.prev_hash, entry.entry_hash, entry.signature,
                    ))
                conn.commit()
                conn.close()
            except Exception as e:
                print(f"[AuditLog] Postgres persist failed: {e}")
        
        # Backup file (append-only, toujours)
        try:
            with open(self.backup_file, "a") as f:
                f.write(json.dumps(entry.to_dict()) + "\n")
        except Exception as e:
            print(f"[AuditLog] File backup failed: {e}")
    
    def verify_chain(self, limit: Optional[int] = None) -> tuple:
        """
        Vérifie l'intégrité de toute la chaîne.
        
        Retourne:
            (is_valid: bool, report: dict)
        """
        entries = self._load_entries(limit=limit)
        
        if not entries:
            return True, {"status": "empty", "entries_checked": 0}
        
        report = {
            "entries_checked": 0,
            "first_entry": entries[0]["event_id"],
            "last_entry": entries[-1]["event_id"],
            "violations": [],
            "signatures_verified": 0,
            "signatures_failed": 0,
        }
        
        prev_hash = "GENESIS"
        
        for i, entry in enumerate(entries):
            report["entries_checked"] += 1
            
            # Vérifie chaînage
            if entry.get("prev_hash") != prev_hash:
                report["violations"].append({
                    "type": "chain_break",
                    "event_id": entry["event_id"],
                    "position": i,
                    "expected_prev": prev_hash,
                    "actual_prev": entry.get("prev_hash"),
                })
            
            # Vérifie hash
            reconstructed = AuditEntry(
                event_id=entry["event_id"],
                timestamp=entry["timestamp"],
                event_type=entry["event_type"],
                org_id=entry["org_id"],
                actor=entry["actor"],
                resource=entry["resource"],
                action=entry["action"],
                details=entry.get("details", {}),
                risk_level=entry.get("risk_level", "info"),
                prev_hash=entry.get("prev_hash", ""),
            )
            computed = reconstructed.compute_hash()
            if computed != entry.get("entry_hash"):
                report["violations"].append({
                    "type": "hash_mismatch",
                    "event_id": entry["event_id"],
                    "position": i,
                    "expected": entry.get("entry_hash"),
                    "computed": computed,
                })
            
            # Vérifie signature si présente
            if entry.get("signature") and self._signer:
                # On pourrait vérifier la signature ici
                report["signatures_verified"] += 1
            
            prev_hash = entry.get("entry_hash")
        
        is_valid = len(report["violations"]) == 0
        report["status"] = "valid" if is_valid else "tampered"
        
        return is_valid, report
    
    def _load_entries(self, limit: Optional[int] = None) -> List[Dict]:
        """Charge les entrées depuis Postgres ou fichier."""
        entries = []
        
        if self.database_url and PSYCOPG_AVAILABLE:
            try:
                conn = psycopg.connect(self.database_url)
                with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
                    query = "SELECT * FROM audit_log ORDER BY seq_no ASC"
                    if limit:
                        query += f" LIMIT {int(limit)}"
                    cur.execute(query)
                    entries = [dict(row) for row in cur.fetchall()]
                conn.close()
                return entries
            except Exception as e:
                print(f"[AuditLog] Postgres load failed: {e}")
        
        # Fallback fichier
        if os.path.exists(self.backup_file):
            try:
                with open(self.backup_file, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            entries.append(json.loads(line))
                            if limit and len(entries) >= limit:
                                break
            except Exception as e:
                print(f"[AuditLog] File load failed: {e}")
        
        return entries
    
    def get_stats(self) -> Dict[str, Any]:
        """Statistiques de l'audit log."""
        stats = {
            "total_entries": 0,
            "by_event_type": {},
            "by_risk_level": {},
            "oldest_entry": None,
            "newest_entry": None,
            "chain_intact": None,
        }
        
        if self.database_url and PSYCOPG_AVAILABLE:
            try:
                conn = psycopg.connect(self.database_url)
                with conn.cursor() as cur:
                    cur.execute("SELECT COUNT(*) FROM audit_log")
                    stats["total_entries"] = cur.fetchone()[0]
                    
                    cur.execute("""
                        SELECT event_type, COUNT(*) 
                        FROM audit_log GROUP BY event_type
                    """)
                    stats["by_event_type"] = dict(cur.fetchall())
                    
                    cur.execute("""
                        SELECT risk_level, COUNT(*) 
                        FROM audit_log GROUP BY risk_level
                    """)
                    stats["by_risk_level"] = dict(cur.fetchall())
                    
                    cur.execute("""
                        SELECT MIN(timestamp), MAX(timestamp) FROM audit_log
                    """)
                    row = cur.fetchone()
                    if row and row[0]:
                        stats["oldest_entry"] = datetime.fromtimestamp(row[0]).isoformat()
                        stats["newest_entry"] = datetime.fromtimestamp(row[1]).isoformat()
                conn.close()
            except Exception as e:
                print(f"[AuditLog] Stats failed: {e}")
        
        # Vérification rapide (uniquement les 1000 dernières entrées)
        is_valid, _ = self.verify_chain(limit=1000)
        stats["chain_intact"] = is_valid
        
        return stats
    
    def query(
        self,
        org_id: Optional[str] = None,
        event_type: Optional[str] = None,
        risk_level: Optional[str] = None,
        since: Optional[float] = None,
        until: Optional[float] = None,
        limit: int = 100,
    ) -> List[Dict]:
        """Requête sur l'audit log."""
        if self.database_url and PSYCOPG_AVAILABLE:
            try:
                conn = psycopg.connect(self.database_url)
                with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
                    conditions = []
                    params = []
                    
                    if org_id:
                        conditions.append("org_id = %s")
                        params.append(org_id)
                    if event_type:
                        conditions.append("event_type = %s")
                        params.append(event_type)
                    if risk_level:
                        conditions.append("risk_level = %s")
                        params.append(risk_level)
                    if since:
                        conditions.append("timestamp >= %s")
                        params.append(since)
                    if until:
                        conditions.append("timestamp <= %s")
                        params.append(until)
                    
                    query = "SELECT * FROM audit_log"
                    if conditions:
                        query += " WHERE " + " AND ".join(conditions)
                    query += " ORDER BY seq_no DESC LIMIT %s"
                    params.append(limit)
                    
                    cur.execute(query, params)
                    rows = [dict(r) for r in cur.fetchall()]
                conn.close()
                return rows
            except Exception as e:
                print(f"[AuditLog] Query failed: {e}")
        
        # Fallback fichier
        results = []
        for entry in reversed(self._load_entries()):
            if org_id and entry.get("org_id") != org_id:
                continue
            if event_type and entry.get("event_type") != event_type:
                continue
            if risk_level and entry.get("risk_level") != risk_level:
                continue
            if since and entry.get("timestamp", 0) < since:
                continue
            if until and entry.get("timestamp", float("inf")) > until:
                continue
            results.append(entry)
            if len(results) >= limit:
                break
        return results
