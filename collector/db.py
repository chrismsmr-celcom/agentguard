"""Database connection helpers — supports SQLite and PostgreSQL."""

import hashlib
import os
import re
import sqlite3
import structlog
from typing import Tuple, Optional, Any

logger = structlog.get_logger("agentguard.db")


# ═══════════════════════════════════════════════════════════════
# CONFIG + CONNECTION HELPERS
# ═══════════════════════════════════════════════════════════════


def _get_db_config() -> Tuple[str, str]:
    """Get database type and URL from environment."""
    db_type = os.environ.get("AGENTGUARD_DB_TYPE", "sqlite")
    database_url = os.environ.get("DATABASE_URL", "")
    return db_type, database_url


def _get_db_path() -> str:
    """Get SQLite DB path dynamically.

    IMPORTANT:
    This function MUST be called instead of using DB_SQLITE_PATH
    directly, because pytest tests can change AGENTGUARD_DB_PATH
    after module import.
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


# Backward compatibility.
# Deprecated — use _get_db_path() in new code.
DB_SQLITE_PATH = "/tmp/agentguard.db"


# ═══════════════════════════════════════════════════════════════
# PII + SECRETS REDACTION
# ═══════════════════════════════════════════════════════════════

_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    re.IGNORECASE,
)

_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

_CC_RE = re.compile(
    r"\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{16}\b"
)

_PHONE_RE = re.compile(
    r"\b(?:\+?1[-.\s]?)?"
    r"(?:\(?[0-9]{3}\)?[-.\s]?)"
    r"[0-9]{3}[-.\s]?[0-9]{4}\b"
)

_API_KEY_RE = re.compile(r"\bag_[a-zA-Z0-9_]{20,}\b")

_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)


# ═══════════════════════════════════════════════════════════════
# SECRET PATTERNS
# ═══════════════════════════════════════════════════════════════

_AWS_KEY_RE = re.compile(
    r"\bAKIA[0-9A-Z]{16}\b"
)

_AWS_SECRET_RE = re.compile(
    r"(?:aws_secret_access_key|secret_access_key|aws_secret)"
    r"\s*[=:]\s*['\"]?"
    r"([A-Za-z0-9/+=]{40})['\"]?",
    re.IGNORECASE,
)

_GITHUB_PAT_RE = re.compile(
    r"\bghp_[A-Za-z0-9]{36}\b"
)

_GITHUB_PAT_FG_RE = re.compile(
    r"\bgithub_pat_[A-Za-z0-9_]{22,}_[A-Za-z0-9]{59}\b"
)

_GITHUB_OAUTH_RE = re.compile(
    r"\bgho_[A-Za-z0-9]{36}\b"
)

_GITHUB_TOKEN_RE = re.compile(
    r"\bgh[us]_[A-Za-z0-9]{36}\b"
)

_GOOGLE_KEY_RE = re.compile(
    r"\bAIza[0-9A-Za-z\-_]{35}\b"
)

_SLACK_TOKEN_RE = re.compile(
    r"\bxox[baprs]-"
    r"[0-9]{10,13}-"
    r"[0-9]{10,13}-"
    r"[A-Za-z0-9]{24,34}\b"
)

_SLACK_WEBHOOK_RE = re.compile(
    r"https://hooks\.slack\.com/services/"
    r"T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"
)

_STRIPE_SECRET_RE = re.compile(
    r"\bsk_(?:live|test)_[0-9A-Za-z]{24,}\b"
)

_STRIPE_PUB_RE = re.compile(
    r"\bpk_(?:live|test)_[0-9A-Za-z]{24,}\b"
)

_STRIPE_WEBHOOK_RE = re.compile(
    r"\bwhsec_[A-Za-z0-9]{32,}\b"
)

_JWT_RE = re.compile(
    r"\beyJ[A-Za-z0-9_-]{10,200}"
    r"\.[A-Za-z0-9_-]{10,200}"
    r"\.[A-Za-z0-9_-]{10,200}\b"
)

_BEARER_RE = re.compile(
    r"(?<=Bearer\s)[A-Za-z0-9._\-+/=]{32,}"
)

_PEM_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"
    r"[\s\S]*?"
    r"-----END [A-Z0-9 ]*PRIVATE KEY-----"
)

_DB_URL_RE = re.compile(
    r"\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|"
    r"redis|rediss|amqp|amqps)://"
    r"[^\s'\"<>]+"
)

_OPENAI_KEY_RE = re.compile(
    r"\bsk-(?:proj-)?[A-Za-z0-9]{32,}\b"
)

_ANTHROPIC_KEY_RE = re.compile(
    r"\bsk-ant-[A-Za-z0-9\-]{40,}\b"
)

_GENERIC_SECRET_RE = re.compile(
    r"\b(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|"
    r"secret[_-]?key|client[_-]?secret|private[_-]?key|"
    r"password|passwd|pwd|credentials?)"
    r"\s*[=:]\s*['\"]?"
    r"([A-Za-z0-9_\-+/=]{20,})['\"]?",
    re.IGNORECASE,
)


def _redact_string(text: str) -> str:
    """Redact PII and secrets from a single string."""

    # PII
    text = _EMAIL_RE.sub("[REDACTED_EMAIL]", text)
    text = _SSN_RE.sub("[REDACTED_SSN]", text)
    text = _CC_RE.sub("[REDACTED_CC]", text)
    text = _PHONE_RE.sub("[REDACTED_PHONE]", text)
    text = _API_KEY_RE.sub("[REDACTED_KEY]", text)
    text = _IPV4_RE.sub("[REDACTED_IP]", text)

    # Secrets
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
    text = _GENERIC_SECRET_RE.sub(
        "[REDACTED_GENERIC_SECRET]",
        text,
    )

    return text


def redact_pii(data: Any) -> Any:
    """Redact PII and secrets recursively.

    Handles:
    - dict: recursively redacts all string values
    - list/tuple: recursively redacts all elements
    - str: redacts emails, SSN, credit cards, API keys,
      phone numbers, IPs, JWT, AWS keys, GitHub tokens,
      Google keys, private keys, DB URLs, etc.
    - other types: returns as-is
    """

    if data is None:
        return None

    if isinstance(data, str):
        return _redact_string(data)

    if isinstance(data, dict):
        return {
            key: redact_pii(value)
            for key, value in data.items()
        }

    if isinstance(data, (list, tuple)):
        redacted = [
            redact_pii(item)
            for item in data
        ]

        if isinstance(data, tuple):
            return tuple(redacted)

        return redacted

    return data


# ═══════════════════════════════════════════════════════════════
# DB INITIALIZATION
# ═══════════════════════════════════════════════════════════════


def init_db():
    """Initialize all database tables.

    Creates:
    - spans
    - api_keys
    - tenants
    - orgs
    - users
    - agents
    - identity_events
    - magic_link_tokens
    """

    if is_postgres():
        conn = get_pg_conn()
        cur = conn.cursor()

        cur.execute("SELECT pg_advisory_lock(727271)")

        try:
            # ────────────────────────────────────────────────
            # SPANS
            # ────────────────────────────────────────────────
            cur.execute(
                """
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
                """
            )

            for idx in [
                """
                CREATE INDEX IF NOT EXISTS idx_trace_pg
                ON spans(trace_id)
                """,
                """
                CREATE INDEX IF NOT EXISTS idx_created_pg
                ON spans(created_at)
                """,
                """
                CREATE INDEX IF NOT EXISTS idx_blocked_pg
                ON spans(blocked)
                """,
                """
                CREATE INDEX IF NOT EXISTS idx_detection_layer_pg
                ON spans(detection_layer)
                """,
                """
                CREATE INDEX IF NOT EXISTS idx_llm_score_pg
                ON spans(llm_score)
                """,
                """
                CREATE INDEX IF NOT EXISTS idx_org_pg
                ON spans(org_id)
                """,
                """
                CREATE INDEX IF NOT EXISTS idx_audit_pg
                ON spans(org_id, created_at DESC)
                """,
                """
                CREATE INDEX IF NOT EXISTS idx_cost_pg
                ON spans(cost_usd)
                """,
            ]:
                cur.execute(idx)

            for col, dtype in [
                ("org_id", "TEXT DEFAULT 'default'"),
                ("model", "TEXT"),
                ("input_tokens", "BIGINT DEFAULT 0"),
                ("output_tokens", "BIGINT DEFAULT 0"),
            ]:
                try:
                    cur.execute(
                        f"""
                        ALTER TABLE spans
                        ADD COLUMN IF NOT EXISTS {col} {dtype}
                        """
                    )
                except Exception:
                    conn.rollback()

            # ────────────────────────────────────────────────
            # LEGACY API KEYS
            # ────────────────────────────────────────────────
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS api_keys (
                    id SERIAL PRIMARY KEY,
                    key_hash TEXT UNIQUE NOT NULL,
                    org_id TEXT NOT NULL,
                    org_name TEXT,
                    plan TEXT DEFAULT 'free',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    active BOOLEAN DEFAULT TRUE
                )
                """
            )

            cur.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_api_keys_hash_pg
                ON api_keys(key_hash)
                """
            )

            # ────────────────────────────────────────────────
            # MAGIC LINK TOKENS
            # ────────────────────────────────────────────────
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS magic_link_tokens (
                    token_hash TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL
                        REFERENCES users(user_id)
                        ON DELETE CASCADE,
                    expires_at TIMESTAMP NOT NULL,
                    used_at TIMESTAMP NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    requested_ip TEXT
                )
                """
            )

            cur.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_magic_link_user_pg
                ON magic_link_tokens(user_id)
                """
            )

            cur.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_magic_link_expiry_pg
                ON magic_link_tokens(expires_at)
                """
            )

            cur.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_magic_link_active_pg
                ON magic_link_tokens(user_id, used_at, expires_at)
                """
            )

            conn.commit()

        finally:
            cur.execute("SELECT pg_advisory_unlock(727271)")
            conn.close()

        logger.info(
            "postgres_initialized",
            version="v6.2",
        )

    else:
        # ────────────────────────────────────────────────────
        # SQLITE
        # ────────────────────────────────────────────────────
        db_path = _get_db_path()

        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA foreign_keys = ON")

        c = conn.cursor()

        try:
            # ────────────────────────────────────────────────
            # SPANS
            # ────────────────────────────────────────────────
            c.execute(
                """
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
                """
            )

            for idx in [
                """
                CREATE INDEX IF NOT EXISTS idx_trace
                ON spans(trace_id)
                """,
                """
                CREATE INDEX IF NOT EXISTS idx_created
                ON spans(created_at)
                """,
                """
                CREATE INDEX IF NOT EXISTS idx_blocked
                ON spans(blocked)
                """,
                """
                CREATE INDEX IF NOT EXISTS idx_detection_layer
                ON spans(detection_layer)
                """,
                """
                CREATE INDEX IF NOT EXISTS idx_llm_score
                ON spans(llm_score)
                """,
                """
                CREATE INDEX IF NOT EXISTS idx_org
                ON spans(org_id)
                """,
                """
                CREATE INDEX IF NOT EXISTS idx_audit
                ON spans(org_id, created_at)
                """,
                """
                CREATE INDEX IF NOT EXISTS idx_cost
                ON spans(cost_usd)
                """,
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
                    c.execute(
                        f"""
                        ALTER TABLE spans
                        ADD COLUMN {col} {dtype}
                        """
                    )
                except sqlite3.OperationalError:
                    pass

            # ────────────────────────────────────────────────
            # LEGACY API KEYS
            # ────────────────────────────────────────────────
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS api_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key_hash TEXT UNIQUE NOT NULL,
                    org_id TEXT NOT NULL,
                    org_name TEXT,
                    plan TEXT DEFAULT 'free',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    active INTEGER DEFAULT 1
                )
                """
            )

            try:
                c.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_api_keys_hash
                    ON api_keys(key_hash)
                    """
                )
            except sqlite3.OperationalError:
                pass

            # ────────────────────────────────────────────────
            # MAGIC LINK TOKENS
            # ────────────────────────────────────────────────
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS magic_link_tokens (
                    token_hash TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    used_at TIMESTAMP NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    requested_ip TEXT,
                    FOREIGN KEY(user_id)
                        REFERENCES users(user_id)
                        ON DELETE CASCADE
                )
                """
            )

            try:
                c.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_magic_link_user
                    ON magic_link_tokens(user_id)
                    """
                )

                c.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_magic_link_expiry
                    ON magic_link_tokens(expires_at)
                    """
                )

                c.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_magic_link_active
                    ON magic_link_tokens(
                        user_id,
                        used_at,
                        expires_at
                    )
                    """
                )
            except sqlite3.OperationalError:
                pass

            conn.commit()

            logger.info(
                "sqlite_initialized",
                version="v6.2",
                db_path=db_path,
            )

        except Exception as e:
            logger.error(
                "sqlite_init_failed",
                error=str(e),
                db_path=db_path,
            )
            raise

        finally:
            conn.close()

    # Identity tables are initialized after the core tables.
    try:
        init_identity_tables()
    except Exception as e:
        logger.warning(
            "identity_tables_init_failed",
            error=str(e),
        )


# ═══════════════════════════════════════════════════════════════
# IDENTITY TABLES
# ═══════════════════════════════════════════════════════════════


def init_identity_tables():
    """Initialize identity tables.

    Creates:
    - tenants
    - orgs
    - users
    - agents
    - identity_events
    """

    if is_postgres():
        conn = get_pg_conn()
        cur = conn.cursor()

        try:
            # ────────────────────────────────────────────────
            # TENANTS
            # ────────────────────────────────────────────────
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS tenants (
                    tenant_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

            # ────────────────────────────────────────────────
            # ORGS
            # ────────────────────────────────────────────────
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS orgs (
                    org_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL
                        REFERENCES tenants(tenant_id),
                    name TEXT NOT NULL,
                    active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

            # ────────────────────────────────────────────────
            # USERS
            # ────────────────────────────────────────────────
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL
                        REFERENCES orgs(org_id),
                    tenant_id TEXT NOT NULL
                        REFERENCES tenants(tenant_id),
                    email TEXT NOT NULL,
                    display_name TEXT,
                    role TEXT NOT NULL DEFAULT 'viewer',
                    active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

            # ────────────────────────────────────────────────
            # AGENTS
            # ────────────────────────────────────────────────
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS agents (
                    agent_id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL
                        REFERENCES orgs(org_id),
                    tenant_id TEXT NOT NULL
                        REFERENCES tenants(tenant_id),
                    name TEXT NOT NULL,
                    description TEXT,
                    key_hash TEXT UNIQUE NOT NULL,
                    key_prefix TEXT,
                    max_budget_per_day DOUBLE PRECISION DEFAULT 100.0,
                    active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen_at TIMESTAMP
                )
                """
            )

            # ────────────────────────────────────────────────
            # IDENTITY EVENTS
            # ────────────────────────────────────────────────
            cur.execute(
                """
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
                """
            )

            cur.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_identity_events_tenant
                ON identity_events(tenant_id)
                """
            )

            cur.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_identity_events_created
                ON identity_events(created_at)
                """
            )

            conn.commit()

        finally:
            conn.close()

    else:
        # ────────────────────────────────────────────────────
        # SQLITE
        # ────────────────────────────────────────────────────
        db_path = _get_db_path()

        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA foreign_keys = ON")

        c = conn.cursor()

        try:
            # ────────────────────────────────────────────────
            # TENANTS
            # ────────────────────────────────────────────────
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS tenants (
                    tenant_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    active INTEGER DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

            # ────────────────────────────────────────────────
            # ORGS
            # ────────────────────────────────────────────────
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS orgs (
                    org_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL
                        REFERENCES tenants(tenant_id),
                    name TEXT NOT NULL,
                    active INTEGER DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

            # ────────────────────────────────────────────────
            # USERS
            # ────────────────────────────────────────────────
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL
                        REFERENCES orgs(org_id),
                    tenant_id TEXT NOT NULL
                        REFERENCES tenants(tenant_id),
                    email TEXT NOT NULL,
                    display_name TEXT,
                    role TEXT NOT NULL DEFAULT 'viewer',
                    active INTEGER DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

            # ────────────────────────────────────────────────
            # AGENTS
            # ────────────────────────────────────────────────
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS agents (
                    agent_id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL
                        REFERENCES orgs(org_id),
                    tenant_id TEXT NOT NULL
                        REFERENCES tenants(tenant_id),
                    name TEXT NOT NULL,
                    description TEXT,
                    key_hash TEXT UNIQUE NOT NULL,
                    key_prefix TEXT,
                    max_budget_per_day REAL DEFAULT 100.0,
                    active INTEGER DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen_at TIMESTAMP
                )
                """
            )

            # ────────────────────────────────────────────────
            # IDENTITY EVENTS
            # ────────────────────────────────────────────────
            c.execute(
                """
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
                """
            )

            try:
                c.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_identity_events_tenant
                    ON identity_events(tenant_id)
                    """
                )

                c.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_identity_events_created
                    ON identity_events(created_at)
                    """
                )
            except sqlite3.OperationalError:
                pass

            conn.commit()

            logger.info(
                "identity_tables_initialized",
                db="sqlite",
            )

        finally:
            conn.close()


# ═══════════════════════════════════════════════════════════════
# AGENT KEY RESOLUTION
# ═══════════════════════════════════════════════════════════════


def resolve_agent_identity(api_key: str) -> Optional[dict]:
    """Resolve an agent API key to its identity.

    Expected format:
        ag_<tenant_id>_<org_id>_<agent_id>_<secret>

    Returns:
        {
            "agent_id": ...,
            "org_id": ...,
            "tenant_id": ...,
            "agent_name": ...
        }

    Returns None when the key is invalid or inactive.
    """

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
                cur.execute(
                    """
                    SELECT
                        agent_id,
                        org_id,
                        tenant_id,
                        name
                    FROM agents
                    WHERE key_hash = %s
                      AND active = TRUE
                    """,
                    (key_hash,),
                )

                row = cur.fetchone()

            finally:
                conn.close()

        else:
            conn = sqlite3.connect(_get_db_path())
            cur = conn.cursor()

            try:
                cur.execute(
                    """
                    SELECT
                        agent_id,
                        org_id,
                        tenant_id,
                        name
                    FROM agents
                    WHERE key_hash = ?
                      AND active = 1
                    """,
                    (key_hash,),
                )

                row = cur.fetchone()

            finally:
                conn.close()

        if not row:
            return None

        # The embedded key components are intentionally not trusted.
        # The database record is authoritative.
        return {
            "agent_id": row[0],
            "org_id": row[1],
            "tenant_id": row[2],
            "agent_name": row[3],
        }

    except Exception as e:
        logger.debug(
            "agent_key_resolution_failed",
            error=str(e),
        )
        return None


def _hash_key(key: str) -> str:
    """Hash an API key with SHA-256."""
    return hashlib.sha256(
        key.encode("utf-8")
    ).hexdigest()


# ═══════════════════════════════════════════════════════════════
# DATABASE ROW UTILITIES
# ═══════════════════════════════════════════════════════════════


def dict_from_row(row, cursor=None) -> dict:
    """Convert a database row to a dict.

    Works for both SQLite and PostgreSQL rows.
    """

    if row is None:
        return None

    if hasattr(row, "_asdict"):
        return row._asdict()

    if hasattr(row, "_fields"):
        return dict(zip(row._fields, row))

    if hasattr(row, "keys"):
        return {
            key: row[key]
            for key in row.keys()
        }

    if cursor is not None and hasattr(cursor, "description"):
        return {
            col[0]: value
            for col, value in zip(
                cursor.description,
                row,
            )
        }

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
    "resolve_agent_identity",
    "_hash_key",
    "dict_from_row",
    "redact_pii",
    "psycopg2",
]
