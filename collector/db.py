"""Database connection helpers — supports SQLite and PostgreSQL."""
import os
import sqlite3
import structlog
from typing import Tuple, Optional

logger = structlog.get_logger("agentguard.db")


def _get_db_config() -> Tuple[str, str]:
    """Get database type and URL from environment."""
    db_type = os.environ.get("AGENTGUARD_DB_TYPE", "sqlite")
    database_url = os.environ.get("DATABASE_URL", "")
    return db_type, database_url


def _get_db_path() -> str:
    """Get SQLite DB path dynamically (reads env at call time, not import time).
    
    IMPORTANT: This function MUST be called instead of using DB_SQLITE_PATH
    directly, because pytest tests change AGENTGUARD_DB_PATH after module import.
    """
    return os.environ.get("AGENTGUARD_DB_PATH", "/tmp/agentguard.db")


def is_postgres() -> bool:
    """Check if we're using PostgreSQL."""
    db_type, _ = _get_db_config()
    return db_type == "postgres"


def get_pg_conn():
    """Get a PostgreSQL connection."""
    import psycopg
    _, database_url = _get_db_config()
    if not database_url:
        raise RuntimeError("DATABASE_URL not configured for PostgreSQL")
    return psycopg.connect(database_url)


def get_sqlite_conn():
    """Get a SQLite connection with dynamic path lookup."""
    return sqlite3.connect(_get_db_path())


def get_conn():
    """Get a DB connection (SQLite or PostgreSQL)."""
    if is_postgres():
        return get_pg_conn()
    return get_sqlite_conn()


# Backward compat (deprecated — use _get_db_path() in new code)
DB_SQLITE_PATH = "/tmp/agentguard.db"


def init_db():
    """Initialize all database tables.
    
    Creates: spans, api_keys, tenants, orgs, users, agents, identity_events, audit_events
    """
    if is_postgres():
        conn = get_pg_conn()
        cur = conn.cursor()
        cur.execute("SELECT pg_advisory_lock(727271)")
        try:
            # Spans table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS spans (
                    id SERIAL PRIMARY KEY,
                    trace_id TEXT, span_id TEXT, span_type TEXT,
                    timestamp DOUBLE PRECISION, latency_ms DOUBLE PRECISION,
                    input_data JSONB, output_data JSONB, security_checks JSONB,
                    blocked BOOLEAN DEFAULT FALSE, block_reason TEXT,
                    cost_usd DOUBLE PRECISION DEFAULT 0.0,
                    input_tokens BIGINT DEFAULT 0, output_tokens BIGINT DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    detection_layer TEXT, ml_score DOUBLE PRECISION,
                    llm_score DOUBLE PRECISION, llm_reason TEXT,
                    org_id TEXT DEFAULT 'default', model TEXT
                )
            """)
            for idx in [
                "CREATE INDEX IF NOT EXISTS idx_trace_pg ON spans(trace_id)",
                "CREATE INDEX IF NOT EXISTS idx_created_pg ON spans(created_at)",
                "CREATE INDEX IF NOT EXISTS idx_blocked_pg ON spans(blocked)",
                "CREATE INDEX IF NOT EXISTS idx_detection_layer_pg ON spans(detection_layer)",
                "CREATE INDEX IF NOT EXISTS idx_llm_score_pg ON spans(llm_score)",
                "CREATE INDEX IF NOT EXISTS idx_org_pg ON spans(org_id)",
                "CREATE INDEX IF NOT EXISTS idx_audit_pg ON spans(org_id, created_at DESC)",
                "CREATE INDEX IF NOT EXISTS idx_cost_pg ON spans(cost_usd)",
            ]:
                cur.execute(idx)

            for col, dtype in [
                ("org_id", "TEXT DEFAULT 'default'"),
                ("model", "TEXT"),
                ("input_tokens", "BIGINT DEFAULT 0"),
                ("output_tokens", "BIGINT DEFAULT 0"),
            ]:
                try:
                    cur.execute(f"ALTER TABLE spans ADD COLUMN IF NOT EXISTS {col} {dtype}")
                except Exception:
                    conn.rollback()

            # API keys table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    id SERIAL PRIMARY KEY, key_hash TEXT UNIQUE NOT NULL,
                    org_id TEXT NOT NULL, org_name TEXT, plan TEXT DEFAULT 'free',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    active BOOLEAN DEFAULT TRUE
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_hash_pg ON api_keys(key_hash)")
            conn.commit()
        finally:
            cur.execute("SELECT pg_advisory_unlock(727271)")
            conn.close()
        logger.info("postgres_initialized", version="v6.1")
    else:
        # ✅ CRITICAL: use _get_db_path() for dynamic lookup
        db_path = _get_db_path()
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        try:
            # Spans table
            c.execute("""
                CREATE TABLE IF NOT EXISTS spans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    trace_id TEXT, span_id TEXT, span_type TEXT,
                    timestamp REAL, latency_ms REAL,
                    input_data TEXT, output_data TEXT, security_checks TEXT,
                    blocked INTEGER, block_reason TEXT, cost_usd REAL,
                    input_tokens INTEGER DEFAULT 0, output_tokens INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    detection_layer TEXT, ml_score REAL, llm_score REAL, llm_reason TEXT,
                    org_id TEXT DEFAULT 'default', model TEXT
                )
            """)
            for idx in [
                "CREATE INDEX IF NOT EXISTS idx_trace ON spans(trace_id)",
                "CREATE INDEX IF NOT EXISTS idx_created ON spans(created_at)",
                "CREATE INDEX IF NOT EXISTS idx_blocked ON spans(blocked)",
                "CREATE INDEX IF NOT EXISTS idx_detection_layer ON spans(detection_layer)",
                "CREATE INDEX IF NOT EXISTS idx_llm_score ON spans(llm_score)",
                "CREATE INDEX IF NOT EXISTS idx_org ON spans(org_id)",
                "CREATE INDEX IF NOT EXISTS idx_audit ON spans(org_id, created_at)",
                "CREATE INDEX IF NOT EXISTS idx_cost ON spans(cost_usd)",
            ]:
                try:
                    c.execute(idx)
                except sqlite3.OperationalError:
                    pass
            
            for col, dtype in [
                ("org_id", "TEXT DEFAULT 'default'"),
                ("model", "TEXT"),
                ("input_tokens", "INTEGER DEFAULT 0"),
                ("output_tokens", "INTEGER DEFAULT 0"),
            ]:
                try:
                    c.execute(f"ALTER TABLE spans ADD COLUMN {col} {dtype}")
                except sqlite3.OperationalError:
                    pass
            
            # API keys table
            c.execute("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key_hash TEXT UNIQUE NOT NULL,
                    org_id TEXT NOT NULL, org_name TEXT, plan TEXT DEFAULT 'free',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    active INTEGER DEFAULT 1
                )
            """)
            try:
                c.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash)")
            except sqlite3.OperationalError:
                pass
            
            conn.commit()
            logger.info("sqlite_initialized", version="v6.1", db_path=db_path)
        except Exception as e:
            logger.error("sqlite_init_failed", error=str(e), db_path=db_path)
            raise
        finally:
            conn.close()

    # Initialize identity tables (Phase 1)
    try:
        init_identity_tables()
    except Exception as e:
        logger.warning("identity_tables_init_failed", error=str(e))


def init_identity_tables():
    """Initialize identity tables (tenants, orgs, users, agents, identity_events)."""
    if is_postgres():
        conn = get_pg_conn()
        cur = conn.cursor()
        try:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS tenants (
                    tenant_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS orgs (
                    org_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
                    name TEXT NOT NULL,
                    active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL REFERENCES orgs(org_id),
                    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
                    email TEXT NOT NULL,
                    display_name TEXT,
                    role TEXT NOT NULL DEFAULT 'viewer',
                    active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS agents (
                    agent_id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL REFERENCES orgs(org_id),
                    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
                    name TEXT NOT NULL,
                    description TEXT,
                    key_hash TEXT UNIQUE NOT NULL,
                    key_prefix TEXT,
                    max_budget_per_day DOUBLE PRECISION DEFAULT 100.0,
                    active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen_at TIMESTAMP
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS identity_events (
                    event_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    org_id TEXT,
                    actor_user_id TEXT,
                    actor_agent_id TEXT,
                    event_type TEXT NOT NULL,
                    resource_type TEXT,
                    resource_id TEXT,
                    action TEXT NOT NULL,
                    details JSONB,
                    ip_address TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_identity_events_tenant ON identity_events(tenant_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_identity_events_created ON identity_events(created_at)")
            conn.commit()
        finally:
            conn.close()
    else:
        # ✅ CRITICAL: use _get_db_path() for dynamic lookup
        db_path = _get_db_path()
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        try:
            c.execute("""
                CREATE TABLE IF NOT EXISTS tenants (
                    tenant_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    active INTEGER DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS orgs (
                    org_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
                    name TEXT NOT NULL,
                    active INTEGER DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL REFERENCES orgs(org_id),
                    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
                    email TEXT NOT NULL,
                    display_name TEXT,
                    role TEXT NOT NULL DEFAULT 'viewer',
                    active INTEGER DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS agents (
                    agent_id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL REFERENCES orgs(org_id),
                    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
                    name TEXT NOT NULL,
                    description TEXT,
                    key_hash TEXT UNIQUE NOT NULL,
                    key_prefix TEXT,
                    max_budget_per_day REAL DEFAULT 100.0,
                    active INTEGER DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen_at TIMESTAMP
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS identity_events (
                    event_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    org_id TEXT,
                    actor_user_id TEXT,
                    actor_agent_id TEXT,
                    event_type TEXT NOT NULL,
                    resource_type TEXT,
                    resource_id TEXT,
                    action TEXT NOT NULL,
                    details TEXT,
                    ip_address TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            try:
                c.execute("CREATE INDEX IF NOT EXISTS idx_identity_events_tenant ON identity_events(tenant_id)")
                c.execute("CREATE INDEX IF NOT EXISTS idx_identity_events_created ON identity_events(created_at)")
            except sqlite3.OperationalError:
                pass
            
            conn.commit()
            logger.info("identity_tables_initialized", db="sqlite")
        finally:
            conn.close()


# ═══════════════════════════════════════════════════════════════
# AGENT KEY RESOLUTION (Phase 2)
# ═══════════════════════════════════════════════════════════════

def resolve_agent_identity(api_key: str) -> Optional[dict]:
    """
    Resolve an agent's API key to its identity.
    
    Returns dict with {agent_id, org_id, tenant_id, agent_name} or None if invalid.
    
    Agent API keys have format: ag_{tenant}_{org}_{agent}_{random}
    """
    if not api_key or not api_key.startswith("ag_"):
        return None
    
    parts = api_key.split("_")
    if len(parts) != 5:
        return None
    
    _, tenant_id, org_id, agent_id, _ = parts
    key_prefix = "_".join(parts[:4])
    key_hash = _hash_key(api_key)
    
    try:
        if is_postgres():
            conn = get_pg_conn()
            cur = conn.cursor()
            try:
                cur.execute("""
                    SELECT agent_id, org_id, tenant_id, name
                    FROM agents
                    WHERE key_hash = %s AND active = TRUE
                """, (key_hash,))
                row = cur.fetchone()
            finally:
                conn.close()
        else:
            # ✅ CRITICAL: use _get_db_path() for dynamic lookup
            conn = sqlite3.connect(_get_db_path())
            cur = conn.cursor()
            try:
                cur.execute("""
                    SELECT agent_id, org_id, tenant_id, name
                    FROM agents
                    WHERE key_hash = ? AND active = 1
                """, (key_hash,))
                row = cur.fetchone()
            finally:
                conn.close()
        
        if not row:
            return None
        
        return {
            "agent_id": row[0],
            "org_id": row[1],
            "tenant_id": row[2],
            "agent_name": row[3],
        }
    except Exception as e:
        logger.debug("agent_key_resolution_failed", error=str(e))
        return None


def _hash_key(key: str) -> str:
    """Hash an API key with SHA-256."""
    import hashlib
    return hashlib.sha256(key.encode()).hexdigest()

# ═══════════════════════════════════════════════════════════════
# BACKWARD COMPATIBILITY ALIASES
# ═══════════════════════════════════════════════════════════════

def get_db():
    """Backward compatibility alias for get_conn().
    
    Used by collector/__init__.py and other legacy code.
    """
    return get_conn()


def redact_pii(text: str) -> str:
    """Redact PII from text (basic implementation).
    
    Used by collector/__init__.py for backward compatibility.
    """
    import re
    if not text or not isinstance(text, str):
        return text
    
    # Email
    text = re.sub(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b",
        "[REDACTED_EMAIL]",
        text,
    )
    # SSN
    text = re.sub(r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_SSN]", text)
    # Credit card (16 digits)
    text = re.sub(r"\b\d{16}\b", "[REDACTED_CC]", text)
    # API keys (ag_...)
    text = re.sub(r"\bag_[a-zA-Z0-9_]{20,}", "[REDACTED_KEY]", text)
    
    return text
