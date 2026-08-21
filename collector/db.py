"""Database setup + PII redaction + Identity tables."""
import os
import re
import sqlite3
import structlog

logger = structlog.get_logger("agentguard.db")

# ── PII REDACTION ───────────────────────────────────────────────
_PII_PATTERNS = {
    "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "CARD": re.compile(r"\b(?:\d{4}[- ]?){3}\d{4}\b"),
    "API_KEY": re.compile(r"\b(sk-|pk-|Bearer\s)[A-Za-z0-9_-]{20,}\b"),
}


def redact_pii(obj):
    """Masque récursivement le PII dans les strings."""
    if isinstance(obj, str):
        text = obj
        for name, pattern in _PII_PATTERNS.items():
            text = pattern.sub(f"[REDACTED_{name}]", text)
        return text
    if isinstance(obj, dict):
        return {k: redact_pii(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_pii(v) for v in obj]
    return obj


# ── PSYCOPG COMPAT ──────────────────────────────────────────────
try:
    import psycopg
    import psycopg.rows

    class _PsycopgCompat:
        class extras:
            RealDictCursor = psycopg.rows.dict_row

        @staticmethod
        def connect(dsn=None, **kwargs):
            if dsn:
                kwargs["conninfo"] = dsn
            kwargs.setdefault("sslmode", "require")
            conn = psycopg.connect(**kwargs)
            conn.autocommit = True
            return conn

    psycopg2 = _PsycopgCompat()
except ImportError:
    psycopg2 = None


# ── DB CONNECTIONS ──────────────────────────────────────────────
DB_SQLITE_PATH = os.environ.get("AGENTGUARD_DB_PATH", "/tmp/agentguard.db")
_sqlite_dir = os.path.dirname(DB_SQLITE_PATH)
if _sqlite_dir and not os.path.isdir(_sqlite_dir):
    os.makedirs(_sqlite_dir, exist_ok=True)


def _get_db_config():
    """Retourne (db_type, database_url)."""
    return os.environ.get("AGENTGUARD_DB_TYPE", "sqlite"), os.environ.get("DATABASE_URL", "")


def get_pg_conn():
    """Connexion PostgreSQL (production) — psycopg3."""
    _, database_url = _get_db_config()
    if psycopg2 is None:
        raise RuntimeError("psycopg non installé. pip install 'psycopg[binary]'")
    try:
        conn = psycopg2.connect(database_url)
    except TypeError:
        import psycopg as _psycopg
        conn = _psycopg.connect(database_url)
    conn.autocommit = False
    return conn


def get_sqlite_conn():
    """Connexion SQLite (local dev) — WAL."""
    conn = sqlite3.connect(DB_SQLITE_PATH, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.row_factory = sqlite3.Row
    return conn


def get_db():
    """Retourne la bonne connexion selon l'environnement."""
    db_type, database_url = _get_db_config()
    if db_type == "postgres" and database_url:
        return get_pg_conn()
    return get_sqlite_conn()


def dict_from_row(row, is_pg=False):
    """Normalise une row en dict."""
    return dict(row)


def is_postgres() -> bool:
    """Teste si on est en mode postgres."""
    db_type, database_url = _get_db_config()
    return db_type == "postgres" and bool(database_url)


# ── INIT DB (spans + api_keys legacy) ───────────────────────────
def init_db():
    """Initialise les tables principales (spans + api_keys legacy)."""
    if is_postgres():
        _, database_url = _get_db_config()
        conn = get_pg_conn()
        cur = conn.cursor()
        cur.execute("SELECT pg_advisory_lock(727271)")
        try:
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
        conn = sqlite3.connect(DB_SQLITE_PATH)
        c = conn.cursor()
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
            c.execute(idx)
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
        c.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_hash TEXT UNIQUE NOT NULL,
                org_id TEXT NOT NULL, org_name TEXT, plan TEXT DEFAULT 'free',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                active INTEGER DEFAULT 1
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash)")
        conn.commit()
        conn.close()
        logger.info("sqlite_initialized", version="v6.1")

    # ✅ Initialise aussi les tables identity (Phase 1)
    try:
        init_identity_tables()
    except Exception as e:
        logger.warning("identity_tables_init_failed", error=str(e))


# ═══════════════════════════════════════════════════════════════
# IDENTITY TABLES (added in v6.1)
# ═══════════════════════════════════════════════════════════════

def init_identity_tables():
    """Crée les tables identity si elles n'existent pas."""
    if is_postgres():
        conn = get_pg_conn()
        cur = conn.cursor()
        try:
            # Tenants
            cur.execute("""
                CREATE TABLE IF NOT EXISTS tenants (
                    tenant_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    active BOOLEAN DEFAULT TRUE
                )
            """)
            
            # Orgs
            cur.execute("""
                CREATE TABLE IF NOT EXISTS orgs (
                    org_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
                    name TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    active BOOLEAN DEFAULT TRUE
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_orgs_tenant ON orgs(tenant_id)")
            
            # Users (humains)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL REFERENCES orgs(org_id),
                    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
                    email TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'viewer',
                    display_name TEXT,
                    password_hash TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    active BOOLEAN DEFAULT TRUE,
                    UNIQUE(org_id, email)
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_users_org ON users(org_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_users_tenant ON users(tenant_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
            
            # Agents (bots IA)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS agents (
                    agent_id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL REFERENCES orgs(org_id),
                    tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
                    name TEXT NOT NULL,
                    description TEXT,
                    key_hash TEXT UNIQUE NOT NULL,
                    key_prefix TEXT NOT NULL,
                    max_budget_per_day DOUBLE PRECISION DEFAULT 100.0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen_at TIMESTAMP,
                    active BOOLEAN DEFAULT TRUE
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_agents_org ON agents(org_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_agents_tenant ON agents(tenant_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_agents_key_hash ON agents(key_hash)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_agents_key_prefix ON agents(key_prefix)")
            
            # Sessions (pour humans seulement)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES users(user_id),
                    tenant_id TEXT NOT NULL,
                    org_id TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    active BOOLEAN DEFAULT TRUE
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)")
            
            # Identity events (audit enrichi)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS identity_events (
                    event_id TEXT PRIMARY KEY,
                    seq_no BIGSERIAL UNIQUE,
                    tenant_id TEXT NOT NULL,
                    org_id TEXT,
                    actor_user_id TEXT,
                    actor_agent_id TEXT,
                    event_type TEXT NOT NULL,
                    resource_type TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    details JSONB,
                    ip_address TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_id_events_tenant ON identity_events(tenant_id, created_at DESC)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_id_events_actor ON identity_events(actor_user_id, created_at DESC)")
            
            conn.commit()
            logger.info("identity_tables_initialized", db="postgres")
        except Exception as e:
            conn.rollback()
            logger.error("identity_tables_init_failed", error=str(e))
            raise
        finally:
            conn.close()
    else:
        # SQLite fallback (dev)
        conn = sqlite3.connect(DB_SQLITE_PATH)
        c = conn.cursor()
        try:
            c.execute("""
                CREATE TABLE IF NOT EXISTS tenants (
                    tenant_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    active INTEGER DEFAULT 1
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS orgs (
                    org_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    active INTEGER DEFAULT 1
                )
            """)
            c.execute("CREATE INDEX IF NOT EXISTS idx_orgs_tenant ON orgs(tenant_id)")
            c.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    email TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'viewer',
                    display_name TEXT,
                    password_hash TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    active INTEGER DEFAULT 1,
                    UNIQUE(org_id, email)
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS agents (
                    agent_id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    description TEXT,
                    key_hash TEXT UNIQUE NOT NULL,
                    key_prefix TEXT NOT NULL,
                    max_budget_per_day REAL DEFAULT 100.0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen_at TIMESTAMP,
                    active INTEGER DEFAULT 1
                )
            """)
            c.execute("CREATE INDEX IF NOT EXISTS idx_agents_key_hash ON agents(key_hash)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_agents_key_prefix ON agents(key_prefix)")
            c.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    org_id TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    active INTEGER DEFAULT 1
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
                    resource_type TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    details TEXT,
                    ip_address TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
            logger.info("identity_tables_initialized", db="sqlite")
        except Exception as e:
            logger.error("identity_tables_init_failed", error=str(e))
            raise
        finally:
            conn.close()


def resolve_agent_identity(api_key: str):
    """
    Résout une clé API agent en identité complète.
    Retourne un dict avec tenant/org/agent info, ou None.
    
    Optimisation : utilise le préfixe de la clé pour un premier
    filtre rapide avant de vérifier le hash complet.
    """
    try:
        from identity import parse_agent_api_key, hash_key as identity_hash
    except ImportError:
        return None
    
    parsed = parse_agent_api_key(api_key)
    if not parsed:
        return None  # Format non reconnu (ancienne clé "ag-xxx")
    
    key_hash = identity_hash(api_key)
    prefix = f"ag_{parsed['tenant_short']}_{parsed['org_short']}_{parsed['agent_short']}"
    
    if is_postgres():
        conn = get_pg_conn()
        cur = conn.cursor()
        try:
            cur.execute("""
                SELECT a.agent_id, a.org_id, a.tenant_id, a.name, a.active,
                       o.name as org_name, t.name as tenant_name
                FROM agents a
                JOIN orgs o ON a.org_id = o.org_id
                JOIN tenants t ON a.tenant_id = t.tenant_id
                WHERE a.key_hash = %s AND a.key_prefix = %s
            """, (key_hash, prefix))
            row = cur.fetchone()
            
            if row:
                # Update last_seen_at
                cur.execute(
                    "UPDATE agents SET last_seen_at = NOW() WHERE agent_id = %s",
                    (row[0],)
                )
                conn.commit()
        finally:
            conn.close()
    else:
        conn = sqlite3.connect(DB_SQLITE_PATH)
        cur = conn.cursor()
        try:
            cur.execute("""
                SELECT a.agent_id, a.org_id, a.tenant_id, a.name, a.active,
                       o.name, t.name
                FROM agents a
                JOIN orgs o ON a.org_id = o.org_id
                JOIN tenants t ON a.tenant_id = t.tenant_id
                WHERE a.key_hash = ? AND a.key_prefix = ?
            """, (key_hash, prefix))
            row = cur.fetchone()
        finally:
            conn.close()
    
    if not row:
        return None
    
    agent_id, org_id, tenant_id, agent_name, active, org_name, tenant_name = row
    
    if not active:
        return None  # Agent révoqué
    
    return {
        "identity_type": "agent",
        "tenant_id": tenant_id,
        "tenant_name": tenant_name,
        "org_id": org_id,
        "org_name": org_name,
        "agent_id": agent_id,
        "agent_name": agent_name,
    }
