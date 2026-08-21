"""Database setup + PII redaction."""
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


# ── INIT DB ─────────────────────────────────────────────────────
def init_db():
    """Initialise les tables avec support tokens + detection layer."""
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

            for col, dtype in [("org_id", "TEXT DEFAULT 'default'"), ("model", "TEXT"),
                               ("input_tokens", "BIGINT DEFAULT 0"), ("output_tokens", "BIGINT DEFAULT 0")]:
                try:
                    cur.execute(f"ALTER TABLE spans ADD COLUMN IF NOT EXISTS {col} {dtype}")
                except Exception:
                    conn.rollback()

            cur.execute("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    id SERIAL PRIMARY KEY, key_hash TEXT UNIQUE NOT NULL,
                    org_id TEXT NOT NULL, org_name TEXT, plan TEXT DEFAULT 'free',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, active BOOLEAN DEFAULT TRUE
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_hash_pg ON api_keys(key_hash)")
            conn.commit()
        finally:
            cur.execute("SELECT pg_advisory_unlock(727271)")
            conn.close()
        logger.info("postgres_initialized", version="v6.0")
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
        for col, dtype in [("org_id", "TEXT DEFAULT 'default'"), ("model", "TEXT"),
                           ("input_tokens", "INTEGER DEFAULT 0"), ("output_tokens", "INTEGER DEFAULT 0")]:
            try:
                c.execute(f"ALTER TABLE spans ADD COLUMN {col} {dtype}")
            except sqlite3.OperationalError:
                pass
        c.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT, key_hash TEXT UNIQUE NOT NULL,
                org_id TEXT NOT NULL, org_name TEXT, plan TEXT DEFAULT 'free',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, active INTEGER DEFAULT 1
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash)")
        conn.commit()
        conn.close()
        logger.info("sqlite_initialized", version="v6.0")
