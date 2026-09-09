"""Database connection helpers — supports SQLite and PostgreSQL."""

import hashlib
import os
import re
import sqlite3
import threading
import uuid
import structlog
from typing import Tuple, Optional, Any

logger = structlog.get_logger("agentguard.db")

# ═══════════════════════════════════════════════════════════════
# POSTGRES CONNECTION POOL
# ═══════════════════════════════════════════════════════════════

_PG_POOL = None
_PG_POOL_LOCK = threading.Lock()


def _get_pg_pool():
    global _PG_POOL
    if _PG_POOL is None:
        with _PG_POOL_LOCK:
            if _PG_POOL is None:
                from psycopg_pool import ConnectionPool

                _, database_url = _get_db_config()
                if not database_url:
                    raise RuntimeError("DATABASE_URL not configured for PostgreSQL")

                _PG_POOL = ConnectionPool(
                    database_url,
                    min_size=1,
                    max_size=int(os.environ.get("AGENTGUARD_DB_POOL_MAX", "5")),
                    timeout=10,
                    open=True,
                )
                logger.info(
                    "pg_pool_initialized",
                    max_size=int(os.environ.get("AGENTGUARD_DB_POOL_MAX", "5")),
                )
    return _PG_POOL


class _PooledConnProxy:
    """Proxy d'une connexion psycopg provenant d'un pool."""

    __slots__ = ("_conn", "_pool", "_returned")

    def __init__(self, conn, pool):
        object.__setattr__(self, "_conn", conn)
        object.__setattr__(self, "_pool", pool)
        object.__setattr__(self, "_returned", False)

    def close(self):
        if self._returned:
            return

        try:
            if not self._conn.closed:
                try:
                    self._conn.rollback()
                except Exception:
                    logger.warning("pg_connection_rollback_failed", exc_info=True)

            self._pool.putconn(self._conn)

        except Exception:
            logger.warning("pg_pool_putconn_failed", exc_info=True)
            try:
                if not self._conn.closed:
                    self._conn.close()
            except Exception:
                logger.warning("pg_connection_close_failed", exc_info=True)

        finally:
            object.__setattr__(self, "_returned", True)

    def __getattr__(self, name):
        return getattr(self._conn, name)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is not None:
            try:
                self._conn.rollback()
            except Exception:
                logger.warning("pg_connection_context_rollback_failed", exc_info=True)

        self.close()
        return False


# ═══════════════════════════════════════════════════════════════
# CONFIG + CONNECTION HELPERS
# ═══════════════════════════════════════════════════════════════

def _get_db_config() -> Tuple[str, str]:
    """Get database type and URL from environment."""
    db_type = os.environ.get("AGENTGUARD_DB_TYPE", "sqlite")
    database_url = os.environ.get("DATABASE_URL", "")
    return db_type, database_url


def _get_db_path() -> str:
    """Get SQLite DB path dynamically."""
    return os.environ.get("AGENTGUARD_DB_PATH", "/tmp/agentguard.db")


def is_postgres() -> bool:
    """Check if we're using PostgreSQL."""
    db_type, _ = _get_db_config()
    return db_type == "postgres"


def get_pg_conn():
    """Get a clean PostgreSQL connection from the pool."""
    pool = _get_pg_pool()
    conn = pool.getconn(timeout=10)

    try:
        conn.rollback()
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
        raise

    return _PooledConnProxy(conn, pool)


def get_sqlite_conn():
    """Get a SQLite connection with dynamic path lookup."""
    conn = sqlite3.connect(_get_db_path())
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def get_conn():
    """Get a DB connection (SQLite or PostgreSQL)."""
    if is_postgres():
        return get_pg_conn()
    return get_sqlite_conn()


def get_db():
    """Backward compatibility alias for get_conn()."""
    return get_conn()


DB_SQLITE_PATH = "/tmp/agentguard.db"


# ═══════════════════════════════════════════════════════════════
# SQL HELPERS
# ═══════════════════════════════════════════════════════════════

def sql_true() -> str:
    return "TRUE" if is_postgres() else "1"


def sql_false() -> str:
    return "FALSE" if is_postgres() else "0"


def sql_placeholder() -> str:
    return "%s" if is_postgres() else "?"


# ═══════════════════════════════════════════════════════════════
# PII + SECRETS REDACTION
# ═══════════════════════════════════════════════════════════════

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", re.IGNORECASE)
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CC_RE = re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{16}\b")
_PHONE_RE = re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?[0-9]{3}\)?[-.\s]?)[0-9]{3}[-.\s]?[0-9]{4}\b")
_API_KEY_RE = re.compile(r"\bag_[a-zA-Z0-9_]{20,}\b")
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")

_AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_AWS_SECRET_RE = re.compile(r"(?:aws_secret_access_key|secret_access_key|aws_secret)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?", re.IGNORECASE)
_GITHUB_PAT_RE = re.compile(r"\bghp_[A-Za-z0-9]{36}\b")
_GITHUB_PAT_FG_RE = re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}_[A-Za-z0-9]{59}\b")
_GITHUB_OAUTH_RE = re.compile(r"\bgho_[A-Za-z0-9]{36}\b")
_GITHUB_TOKEN_RE = re.compile(r"\bgh[us]_[A-Za-z0-9]{36}\b")
_GOOGLE_KEY_RE = re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")
_SLACK_TOKEN_RE = re.compile(r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,34}\b")
_SLACK_WEBHOOK_RE = re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+")
_STRIPE_SECRET_RE = re.compile(r"\bsk_(?:live|test)_[0-9A-Za-z]{24,}\b")
_STRIPE_PUB_RE = re.compile(r"\bpk_(?:live|test)_[0-9A-Za-z]{24,}\b")
_STRIPE_WEBHOOK_RE = re.compile(r"\bwhsec_[A-Za-z0-9]{32,}\b")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,200}\.[A-Za-z0-9_-]{10,200}\.[A-Za-z0-9_-]{10,200}\b")
_BEARER_RE = re.compile(r"(?<=Bearer\s)[A-Za-z0-9._\-+/=]{32,}")
_PEM_KEY_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----")
_DB_URL_RE = re.compile(r"\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|rediss|amqp|amqps)://[^\s'\"<>]+")
_OPENAI_KEY_RE = re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{32,}\b")
_ANTHROPIC_KEY_RE = re.compile(r"\bsk-ant-[A-Za-z0-9\-]{40,}\b")
_GENERIC_SECRET_RE = re.compile(r"\b(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|secret[_-]?key|client[_-]?secret|private[_-]?key|password|passwd|pwd|credentials?)\s*[=:]\s*['\"]?([A-Za-z0-9_\-+/=]{20,})['\"]?", re.IGNORECASE)


def _redact_string(text: str) -> str:
    text = _EMAIL_RE.sub("[REDACTED_EMAIL]", text)
    text = _SSN_RE.sub("[REDACTED_SSN]", text)
    text = _CC_RE.sub("[REDACTED_CC]", text)
    text = _PHONE_RE.sub("[REDACTED_PHONE]", text)
    text = _API_KEY_RE.sub("[REDACTED_KEY]", text)
    text = _IPV4_RE.sub("[REDACTED_IP]", text)

    text = _AWS_KEY_RE.sub("[REDACTED_AWS_KEY]", text)
    text = _AWS_SECRET_RE.sub("[REDACTED_AWS_SECRET]", text)
    text = _GITHUB_PAT_RE.sub("[REDACTED_GITHUB_PAT]", text)
    text = _GITHUB_PAT_FG_RE.sub("[REDACTED_GITHUB_PAT]", text)
    text = _GITHUB_OAUTH_RE.sub("[REDACTED_GITHUB_OAUTH]", text)
    text = _GITHUB_TOKEN_RE.sub("[REDACTED_GITHUB_TOKEN]", text)
    text = _GOOGLE_KEY_RE.sub("[REDACTED_GOOGLE_KEY]", text)
    text = _SLACK_TOKEN_RE.sub("[REDACTED_SLACK_TOKEN]", text)
    text = _SLACK_WEBHOOK_RE.sub("[REDACTED_SLACK_WEBHOOK]", text)
    text = _STRIPE_SECRET_RE.sub("[REDACTED_STRIPE_SECRET]", text)
    text = _STRIPE_PUB_RE.sub("[REDACTED_STRIPE_KEY]", text)
    text = _STRIPE_WEBHOOK_RE.sub("[REDACTED_STRIPE_WEBHOOK]", text)
    text = _JWT_RE.sub("[REDACTED_JWT]", text)
    text = _BEARER_RE.sub("[REDACTED_BEARER]", text)
    text = _PEM_KEY_RE.sub("[REDACTED_PRIVATE_KEY]", text)
    text = _DB_URL_RE.sub("[REDACTED_DB_URL]", text)
    text = _OPENAI_KEY_RE.sub("[REDACTED_OPENAI_KEY]", text)
    text = _ANTHROPIC_KEY_RE.sub("[REDACTED_ANTHROPIC_KEY]", text)
    text = _GENERIC_SECRET_RE.sub("[REDACTED_GENERIC_SECRET]", text)

    return text


def redact_pii(data: Any) -> Any:
    if data is None:
        return None
    if isinstance(data, str):
        return _redact_string(data)
    if isinstance(data, dict):
        return {key: redact_pii(value) for key, value in data.items()}
    if isinstance(data, (list, tuple)):
        redacted = [redact_pii(item) for item in data]
        return tuple(redacted) if isinstance(data, tuple) else redacted
    return data


# ═══════════════════════════════════════════════════════════════
# API KEYS MIGRATION & INITIALIZATION
# ═══════════════════════════════════════════════════════════════

def _migrate_api_keys_table():
    """
    Ensures the api_keys table matches the canonical schema.
    Migrates legacy data (org_name, plan) to the new schema (name) safely.
    """
    if is_postgres():
        conn = get_pg_conn()
        cur = conn.cursor()
        try:
            # 1. Check if table exists
            cur.execute("SELECT 1 FROM information_schema.tables WHERE table_name = 'api_keys'")
            table_exists = cur.fetchone() is not None

            if not table_exists:
                # Case A: Create canonical directly
                cur.execute("""
                    CREATE TABLE api_keys (
                        id TEXT PRIMARY KEY,
                        org_id TEXT NOT NULL,
                        key_hash TEXT NOT NULL UNIQUE,
                        name TEXT NOT NULL,
                        active BOOLEAN NOT NULL DEFAULT TRUE,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                """)
            else:
                # Check columns to detect legacy schema
                cur.execute("""
                    SELECT column_name FROM information_schema.columns 
                    WHERE table_name = 'api_keys' AND column_name IN ('org_name', 'plan', 'name')
                """)
                cols = [row[0] for row in cur.fetchall()]

                if 'org_name' in cols or 'plan' in cols:
                    # Case C: Legacy schema detected. Migrate.
                    logger.info("migrating_legacy_api_keys_to_canonical_schema")
                    
                    # Fetch legacy data
                    cur.execute("SELECT id, key_hash, org_id, org_name, active, created_at FROM api_keys")
                    legacy_rows = cur.fetchall()

                    # Rename old table
                    cur.execute("ALTER TABLE api_keys RENAME TO api_keys_legacy")

                    # Create canonical table
                    cur.execute("""
                        CREATE TABLE api_keys (
                            id TEXT PRIMARY KEY,
                            org_id TEXT NOT NULL,
                            key_hash TEXT NOT NULL UNIQUE,
                            name TEXT NOT NULL,
                            active BOOLEAN NOT NULL DEFAULT TRUE,
                            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                        )
                    """)

                    # Migrate data
                    for row in legacy_rows:
                        old_id, key_hash, org_id, org_name, active, created_at = row
                        new_id = str(old_id) if old_id else str(uuid.uuid4())
                        name = (org_name or "").strip() or "Legacy API Key"
                        
                        cur.execute("""
                            INSERT INTO api_keys (id, org_id, key_hash, name, active, created_at)
                            VALUES (%s, %s, %s, %s, %s, %s)
                        """, (new_id, org_id, key_hash, name, active, created_at))

                    # Drop legacy table
                    cur.execute("DROP TABLE api_keys_legacy")
                    logger.info("api_keys_migration_completed_successfully")

            # Ensure indexes exist (Case B & Post-migration)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_org_id ON api_keys(org_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash)")
            
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error("api_keys_migration_failed", error=str(e))
            raise
        finally:
            conn.close()

    else:
        # SQLite
        db_path = _get_db_path()
        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA foreign_keys = ON")
        c = conn.cursor()
        try:
            # 1. Check if table exists
            c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='api_keys'")
            table_exists = c.fetchone() is not None

            if not table_exists:
                # Case A: Create canonical directly
                c.execute("""
                    CREATE TABLE api_keys (
                        id TEXT PRIMARY KEY,
                        org_id TEXT NOT NULL,
                        key_hash TEXT NOT NULL UNIQUE,
                        name TEXT NOT NULL,
                        active INTEGER NOT NULL DEFAULT 1,
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                """)
            else:
                # Check columns
                c.execute("PRAGMA table_info(api_keys)")
                cols = [row[1] for row in c.fetchall()]

                if 'org_name' in cols or 'plan' in cols:
                    # Case C: Legacy schema detected. Migrate.
                    logger.info("migrating_legacy_api_keys_to_canonical_schema_sqlite")
                    
                    c.execute("SELECT id, key_hash, org_id, org_name, active, created_at FROM api_keys")
                    legacy_rows = c.fetchall()

                    c.execute("ALTER TABLE api_keys RENAME TO api_keys_legacy")

                    c.execute("""
                        CREATE TABLE api_keys (
                            id TEXT PRIMARY KEY,
                            org_id TEXT NOT NULL,
                            key_hash TEXT NOT NULL UNIQUE,
                            name TEXT NOT NULL,
                            active INTEGER NOT NULL DEFAULT 1,
                            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                        )
                    """)

                    for row in legacy_rows:
                        old_id, key_hash, org_id, org_name, active, created_at = row
                        new_id = str(old_id) if old_id else str(uuid.uuid4())
                        name = (org_name or "").strip() or "Legacy API Key"
                        # Ensure active is strictly 0 or 1 for SQLite
                        active_int = 1 if active else 0
                        
                        c.execute("""
                            INSERT INTO api_keys (id, org_id, key_hash, name, active, created_at)
                            VALUES (?, ?, ?, ?, ?, ?)
                        """, (new_id, org_id, key_hash, name, active_int, created_at))

                    c.execute("DROP TABLE api_keys_legacy")
                    logger.info("api_keys_migration_completed_successfully_sqlite")

            # Ensure indexes
            try:
                c.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_org_id ON api_keys(org_id)")
                c.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash)")
            except sqlite3.OperationalError:
                pass
            
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error("api_keys_migration_failed_sqlite", error=str(e), db_path=db_path)
            raise
        finally:
            conn.close()


# ═══════════════════════════════════════════════════════════════
# DB INITIALIZATION
# ═══════════════════════════════════════════════════════════════

def init_db():
    """Initialize all database tables in correct dependency order."""
    
    # 1. Core independent tables & API Keys Migration
    if is_postgres():
        conn = get_pg_conn()
        cur = conn.cursor()
        cur.execute("SELECT pg_advisory_lock(727271)")
        try:
            # SPANS
            cur.execute("""
                CREATE TABLE IF NOT EXISTS spans (
                    id SERIAL PRIMARY KEY,
                    trace_id TEXT,
                    span_id TEXT,
                    span_type TEXT,
                    timestamp DOUBLE PRECISION,
                    latency_ms DOUBLE PRECISION,
                    input_data JSONB,
                    output_data JSONB,
                    security_checks JSONB,
                    blocked BOOLEAN DEFAULT FALSE,
                    block_reason TEXT,
                    cost_usd DOUBLE PRECISION DEFAULT 0.0,
                    input_tokens BIGINT DEFAULT 0,
                    output_tokens BIGINT DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    detection_layer TEXT,
                    ml_score DOUBLE PRECISION,
                    llm_score DOUBLE PRECISION,
                    llm_reason TEXT,
                    org_id TEXT DEFAULT 'default',
                    model TEXT
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

            conn.commit()
        finally:
            cur.execute("SELECT pg_advisory_unlock(727271)")
            conn.close()
    else:
        db_path = _get_db_path()
        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA foreign_keys = ON")
        c = conn.cursor()
        try:
            c.execute("""
                CREATE TABLE IF NOT EXISTS spans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    trace_id TEXT,
                    span_id TEXT,
                    span_type TEXT,
                    timestamp REAL,
                    latency_ms REAL,
                    input_data TEXT,
                    output_data TEXT,
                    security_checks TEXT,
                    blocked INTEGER,
                    block_reason TEXT,
                    cost_usd REAL,
                    input_tokens INTEGER DEFAULT 0,
                    output_tokens INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    detection_layer TEXT,
                    ml_score REAL,
                    llm_score REAL,
                    llm_reason TEXT,
                    org_id TEXT DEFAULT 'default',
                    model TEXT
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

            conn.commit()
        finally:
            conn.close()

    # 2. Migrate / Initialize API Keys (Source of Truth)
    _migrate_api_keys_table()

    # 3. Identity Tables (Creates tenants, orgs, users, agents, identity_events)
    try:
        init_identity_tables()
    except Exception as e:
        logger.warning("identity_tables_init_failed", error=str(e))

    # 4. Magic Link Tokens (Depends on 'users' table existing)
    if is_postgres():
        conn = get_pg_conn()
        cur = conn.cursor()
        try:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS magic_link_tokens (
                    token_hash TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                    expires_at TIMESTAMP NOT NULL,
                    used_at TIMESTAMP NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    requested_ip TEXT
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_magic_link_user_pg ON magic_link_tokens(user_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_magic_link_expiry_pg ON magic_link_tokens(expires_at)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_magic_link_active_pg ON magic_link_tokens(user_id, used_at, expires_at)")
            conn.commit()
        finally:
            conn.close()
    else:
        db_path = _get_db_path()
        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA foreign_keys = ON")
        c = conn.cursor()
        try:
            c.execute("""
                CREATE TABLE IF NOT EXISTS magic_link_tokens (
                    token_hash TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    used_at TIMESTAMP NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    requested_ip TEXT,
                    FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE
                )
            """)
            try:
                c.execute("CREATE INDEX IF NOT EXISTS idx_magic_link_user ON magic_link_tokens(user_id)")
                c.execute("CREATE INDEX IF NOT EXISTS idx_magic_link_expiry ON magic_link_tokens(expires_at)")
                c.execute("CREATE INDEX IF NOT EXISTS idx_magic_link_active ON magic_link_tokens(user_id, used_at, expires_at)")
            except sqlite3.OperationalError:
                pass
            conn.commit()
        finally:
            conn.close()

    logger.info("database_initialization_completed")


# ═══════════════════════════════════════════════════════════════
# IDENTITY TABLES
# ═══════════════════════════════════════════════════════════════

def init_identity_tables():
    """Initialize identity tables."""
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
        db_path = _get_db_path()
        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA foreign_keys = ON")
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
        finally:
            conn.close()


# ═══════════════════════════════════════════════════════════════
# AGENT KEY RESOLUTION
# ═══════════════════════════════════════════════════════════════

def resolve_agent_identity(api_key: str) -> Optional[dict]:
    """Resolve an agent API key to its identity."""
    if not api_key or not api_key.startswith("ag_"):
        return None

    parts = api_key.split("_")
    if len(parts) != 5:
        return None

    _, tenant_id, org_id, agent_id, _ = parts
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
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


# ═══════════════════════════════════════════════════════════════
# DATABASE ROW UTILITIES
# ═══════════════════════════════════════════════════════════════

def dict_from_row(row, cursor=None) -> dict:
    """Convert a database row to a dict."""
    if row is None:
        return None
    if hasattr(row, "_asdict"):
        return row._asdict()
    if hasattr(row, "_fields"):
        return dict(zip(row._fields, row))
    if hasattr(row, "keys"):
        return {key: row[key] for key in row.keys()}
    if cursor is not None and hasattr(cursor, "description"):
        return {col[0]: value for col, value in zip(cursor.description, row)}
    if isinstance(row, dict):
        return row
    return row


# ═══════════════════════════════════════════════════════════════
# POSTGRES / PSYCOPG COMPATIBILITY
# ═══════════════════════════════════════════════════════════════

try:
    import psycopg2
except ImportError:
    try:
        import psycopg as psycopg2  # type: ignore
    except ImportError:
        psycopg2 = None  # type: ignore


# ═══════════════════════════════════════════════════════════════
# EXPORTS
# ═══════════════════════════════════════════════════════════════

__all__ = [
    "_get_db_config",
    "_get_db_path",
    "is_postgres",
    "get_pg_conn",
    "get_sqlite_conn",
    "get_conn",
    "get_db",
    "DB_SQLITE_PATH",
    "init_db",
    "init_identity_tables",
    "_migrate_api_keys_table",
    "resolve_agent_identity",
    "_hash_key",
    "dict_from_row",
    "redact_pii",
    "psycopg2",
    "sql_true",
    "sql_false",
    "sql_placeholder",
]
