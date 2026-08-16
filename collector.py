"""
AgentGuard Collector v5.0 — PostgreSQL production + SQLite local fallback
Support de la détection multi-couches (ML + LLM Judge)
Dashboard style Dynatrace AI Observability + Bedrock
"""

import os
import re
import json
import time
import secrets
import hashlib
try:
    import psycopg2
    import psycopg2.extras
except ImportError:
    # psycopg2 n'est nécessaire qu'en prod PostgreSQL ; en self-host SQLite
    # pur, son absence ne doit pas empêcher le collector de démarrer.
    psycopg2 = None
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template_string, make_response, redirect, url_for, g
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask_cors import CORS, cross_origin
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from markupsafe import escape as _esc

app = Flask(__name__)
app.secret_key = os.environ.get("AGENTGUARD_FLASK_SECRET") or secrets.token_urlsafe(32)
AUTH_SERIALIZER = URLSafeTimedSerializer(app.secret_key, salt="agentguard-auth-v1")
AUTH_SESSION_TTL = int(os.environ.get("AGENTGUARD_AUTH_SESSION_TTL", "900"))
AUTH_COOKIE_SECURE = os.environ.get("AGENTGUARD_COOKIE_SECURE", "true").lower() == "true"
app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("AGENTGUARD_MAX_BODY_BYTES", "262144"))
CORS_ORIGINS = [x.strip() for x in os.environ.get("AGENTGUARD_CORS_ORIGINS", "").split(",") if x.strip()]

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[os.environ.get("AGENTGUARD_RATE_LIMIT", "120 per minute")],
    storage_uri=os.environ.get("AGENTGUARD_LIMITER_STORAGE", "memory://"),
)
SPAN_RATE_LIMIT = os.environ.get("AGENTGUARD_SPAN_RATE_LIMIT", "30 per minute")

# ── CONFIG ───────────────────────────────────────────────────────────────────
DB_TYPE = os.environ.get("AGENTGUARD_DB_TYPE", "sqlite")
DATABASE_URL = os.environ.get("DATABASE_URL", "")
API_KEY = os.environ.get("AGENTGUARD_API_KEY", None)
ADMIN_SECRET = os.environ.get("AGENTGUARD_ADMIN_SECRET")
AUTH_COOKIE = "ag_auth"

_API_KEY_WAS_GENERATED = API_KEY is None
if not API_KEY:
    API_KEY = "ag-" + secrets.token_urlsafe(32)
    print("[AG] ⚠️ Aucune AGENTGUARD_API_KEY fournie — clé générée en mémoire")

# ── PII REDACTION ────────────────────────────────────────────────────────────
_PII_PATTERNS = {
    "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "CARD": re.compile(r"\b(?:\d{4}[- ]?){3}\d{4}\b"),
    "API_KEY": re.compile(r"\b(sk-|pk-|Bearer\s)[A-Za-z0-9_-]{20,}\b"),
}

def redact_pii(obj):
    """Masque récursivement le PII connu dans les strings avant stockage en DB."""
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

# ── DATABASE SETUP ───────────────────────────────────────────────────────────
import sqlite3

DB_SQLITE_PATH = os.environ.get("AGENTGUARD_DB_PATH", "/tmp/agentguard.db")
_sqlite_dir = os.path.dirname(DB_SQLITE_PATH)
if _sqlite_dir and not os.path.isdir(_sqlite_dir):
    os.makedirs(_sqlite_dir, exist_ok=True)

def get_pg_conn():
    """Connexion PostgreSQL (production)."""
    if psycopg2 is None:
        raise RuntimeError(
            "psycopg2 n'est pas installé — requis pour AGENTGUARD_DB_TYPE=postgres. "
            "pip install psycopg2-binary"
        )
    return psycopg2.connect(DATABASE_URL, sslmode="require")

def get_sqlite_conn():
    """Connexion SQLite (local dev) — WAL pour concurrence multi-workers."""
    conn = sqlite3.connect(DB_SQLITE_PATH, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.row_factory = sqlite3.Row
    return conn

def get_db():
    """Retourne la bonne connexion selon l'environnement."""
    if DB_TYPE == "postgres" and DATABASE_URL:
        return get_pg_conn()
    return get_sqlite_conn()

def init_db():
    """Initialise les tables avec support des nouvelles métriques (tokens inclus)."""
    if DB_TYPE == "postgres" and DATABASE_URL:
        conn = get_pg_conn()
        cur = conn.cursor()
        # Verrou advisory pour éviter les collisions multi-workers
        cur.execute("SELECT pg_advisory_lock(727271)")
        try:
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
            cur.execute("CREATE INDEX IF NOT EXISTS idx_trace_pg ON spans(trace_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_created_pg ON spans(created_at)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_blocked_pg ON spans(blocked)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_detection_layer_pg ON spans(detection_layer)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_llm_score_pg ON spans(llm_score)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_org_pg ON spans(org_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_pg ON spans(org_id, created_at DESC)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_cost_pg ON spans(cost_usd)")

            # Migrations douces
            for col, dtype in [("org_id", "TEXT DEFAULT 'default'"),
                               ("model", "TEXT"),
                               ("input_tokens", "BIGINT DEFAULT 0"),
                               ("output_tokens", "BIGINT DEFAULT 0")]:
                try:
                    cur.execute(f"ALTER TABLE spans ADD COLUMN IF NOT EXISTS {col} {dtype}")
                except Exception:
                    conn.rollback()

            cur.execute("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    id SERIAL PRIMARY KEY,
                    key_hash TEXT UNIQUE NOT NULL,
                    org_id TEXT NOT NULL,
                    org_name TEXT,
                    plan TEXT DEFAULT 'free',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    active BOOLEAN DEFAULT TRUE
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_hash_pg ON api_keys(key_hash)")
            conn.commit()
        finally:
            cur.execute("SELECT pg_advisory_unlock(727271)")
            conn.close()
        print("[AG] ✅ PostgreSQL initialisé v5.0")
    else:
        conn = sqlite3.connect(DB_SQLITE_PATH)
        c = conn.cursor()
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
        c.execute("CREATE INDEX IF NOT EXISTS idx_trace ON spans(trace_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_created ON spans(created_at)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_blocked ON spans(blocked)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_detection_layer ON spans(detection_layer)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_llm_score ON spans(llm_score)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_org ON spans(org_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_audit ON spans(org_id, created_at)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_cost ON spans(cost_usd)")
        for col, dtype in [("org_id", "TEXT DEFAULT 'default'"),
                           ("model", "TEXT"),
                           ("input_tokens", "INTEGER DEFAULT 0"),
                           ("output_tokens", "INTEGER DEFAULT 0")]:
            try:
                c.execute(f"ALTER TABLE spans ADD COLUMN {col} {dtype}")
            except sqlite3.OperationalError:
                pass
        c.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_hash TEXT UNIQUE NOT NULL,
                org_id TEXT NOT NULL,
                org_name TEXT,
                plan TEXT DEFAULT 'free',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                active INTEGER DEFAULT 1
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash)")
        conn.commit()
        conn.close()
        print("[AG] ✅ SQLite initialisé v5.0")

def dict_from_row(row, is_pg=False):
    """Normalise une row en dict."""
    return dict(row)

# ── AUTH ─────────────────────────────────────────────────────────────────────
PROTECTED_ENDPOINTS = {
    "receive_span", "list_traces", "get_trace", "get_metrics",
    "dashboard", "trace_detail", "get_detection_stats",
    "api_models", "api_heatmap", "api_checks_breakdown",
    "api_expensive_spans", "api_cost_trend", "api_latency_distribution",
    "api_recent_events", "api_trend_daily", "get_llm_stats",
    "api_audit_trail", "api_checks_daily", "api_models_daily",
}

def safe_compare(a: str, b: str) -> bool:
    if a is None or b is None:
        return False
    try:
        return secrets.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
    except Exception:
        return False

def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()

def _lookup_org_by_key(key: str):
    if not key:
        return None
    key_hash = hash_key(key)
    is_pg = DB_TYPE == "postgres" and DATABASE_URL
    conn = get_pg_conn() if is_pg else sqlite3.connect(DB_SQLITE_PATH)
    cur = conn.cursor()
    if is_pg:
        cur.execute("SELECT org_id FROM api_keys WHERE key_hash = %s AND active = TRUE", (key_hash,))
    else:
        cur.execute("SELECT org_id FROM api_keys WHERE key_hash = ? AND active = 1", (key_hash,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else None

def resolve_org_id(key: str):
    if not key:
        return None
    if API_KEY and safe_compare(key, API_KEY):
        return "default"
    return _lookup_org_by_key(key)

def _session_token(org_id: str, key_hash: str) -> str:
    return AUTH_SERIALIZER.dumps({"org_id": org_id, "key_hash": key_hash})

def _session_org_id(token: str):
    if not token:
        return None
    try:
        payload = AUTH_SERIALIZER.loads(token, max_age=AUTH_SESSION_TTL)
        org_id = payload.get("org_id")
        key_hash = payload.get("key_hash")
        if not org_id or not key_hash:
            return None
        if org_id == "default":
            if API_KEY and safe_compare(key_hash, hash_key(API_KEY)):
                return "default"
            return None
        is_pg = DB_TYPE == "postgres" and DATABASE_URL
        conn = get_pg_conn() if is_pg else sqlite3.connect(DB_SQLITE_PATH)
        cur = conn.cursor()
        if is_pg:
            cur.execute("SELECT 1 FROM api_keys WHERE org_id = %s AND key_hash = %s AND active = TRUE", (org_id, key_hash))
        else:
            cur.execute("SELECT 1 FROM api_keys WHERE org_id = ? AND key_hash = ? AND active = 1", (org_id, key_hash))
        valid = cur.fetchone() is not None
        conn.close()
        return org_id if valid else None
    except (BadSignature, SignatureExpired, TypeError, ValueError):
        return None

def require_auth():
    if not API_KEY:
        g.org_id = "default"
        return True
    key = request.headers.get("X-API-Key", "").strip()
    if key:
        org_id = resolve_org_id(key)
        if org_id:
            g.org_id = org_id
            return True
    org_id = _session_org_id(request.cookies.get(AUTH_COOKIE, ""))
    if org_id:
        g.org_id = org_id
        return True
    return False

LOGIN_HTML = '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AgentGuard — Sign in</title><style>:root{color-scheme:dark;--bg:#07111f;--card:#0d1b2d;--border:#21334a;--text:#eef5ff;--muted:#93a6bd;--accent:#38bdf8;--accent2:#2563eb}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:radial-gradient(circle at 50% 20%,#12304f 0%,var(--bg) 55%);font-family:Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif;color:var(--text)}.wrap{width:min(430px,92vw)}.brand{text-align:center;margin-bottom:24px}.logo{width:56px;height:56px;margin:0 auto 14px;border-radius:16px;display:grid;place-items:center;background:linear-gradient(135deg,var(--accent2),var(--accent));box-shadow:0 16px 40px rgba(37,99,235,.28);font-size:27px}h1{margin:0;font-size:24px;letter-spacing:-.02em}.subtitle{margin:8px 0 0;color:var(--muted);font-size:14px}.card{background:rgba(13,27,45,.94);border:1px solid var(--border);border-radius:20px;padding:28px;box-shadow:0 22px 70px rgba(0,0,0,.35);backdrop-filter:blur(16px)}label{display:block;margin:0 0 9px;font-size:13px;font-weight:600}input{width:100%;height:48px;border:1px solid #29425e;border-radius:12px;background:#091522;color:var(--text);padding:0 14px;outline:none;font:inherit}input:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(56,189,248,.12)}button{width:100%;height:48px;margin-top:16px;border:0;border-radius:12px;color:#fff;font:inherit;font-weight:700;cursor:pointer;background:linear-gradient(135deg,var(--accent2),var(--accent))}.hint{margin-top:15px;color:var(--muted);font-size:12px;line-height:1.5}.error{margin:0 0 14px;border:1px solid rgba(251,113,133,.35);background:rgba(127,29,29,.2);color:#fecdd3;border-radius:10px;padding:10px 12px;font-size:13px}.footer{text-align:center;margin-top:16px;color:#64748b;font-size:11px}</style></head><body><main class="wrap"><div class="brand"><div class="logo">🛡️</div><h1>AgentGuard</h1><div class="subtitle">Runtime Security Console</div></div><section class="card">{% if error %}<div class="error">{{ error }}</div>{% endif %}<form method="post" action="/login"><label for="api_key">API Key</label><input id="api_key" name="api_key" type="password" autocomplete="off" placeholder="ag-••••••••••••••••" required autofocus><button type="submit">Sign in to dashboard</button></form><div class="hint">Your API key is submitted over HTTPS and is never placed in the URL.</div></section><div class="footer">Protected runtime telemetry &amp; enforcement</div></main></body></html>'

@app.before_request
def check_auth():
    if request.method == "OPTIONS":
        return None
    if request.endpoint in ("login", "healthz", "auth_login", "logout"):
        return None
    if request.endpoint not in PROTECTED_ENDPOINTS:
        return None
    if not require_auth():
        if request.endpoint in ("dashboard", "trace_detail"):
            return redirect(url_for("login"))
        return jsonify({"error": "Unauthorized — use X-API-Key header"}), 401

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        key = str(request.form.get("api_key", "")).strip()
        org_id = resolve_org_id(key)
        if not org_id:
            return render_template_string(LOGIN_HTML, error="Invalid API key."), 401
        resp = redirect(url_for("dashboard"))
        resp.set_cookie(AUTH_COOKIE, _session_token(org_id, hash_key(key)), httponly=True, samesite="Lax", secure=AUTH_COOKIE_SECURE, max_age=AUTH_SESSION_TTL)
        return resp
    return render_template_string(LOGIN_HTML, error=None)

@app.post("/api/auth-login")
def auth_login():
    data = request.get_json(silent=True) or {}
    key = str(data.get("api_key", "")).strip()
    org_id = resolve_org_id(key)
    if not org_id:
        return jsonify({"error": "Unauthorized"}), 401
    resp = jsonify({"status": "ok", "org_id": org_id})
    resp.set_cookie(AUTH_COOKIE, _session_token(org_id, hash_key(key)), httponly=True, samesite="Lax", secure=AUTH_COOKIE_SECURE, max_age=AUTH_SESSION_TTL)
    return resp

@app.post("/logout")
def logout():
    resp = redirect(url_for("login"))
    resp.delete_cookie(AUTH_COOKIE)
    return resp

@app.get("/healthz")
def healthz():
    try:
        conn = get_db()
        conn.close()
        return jsonify({"status": "ok"}), 200
    except Exception as exc:
        return jsonify({"status": "degraded", "error": str(exc)[:120]}), 503

# ── API : INGESTION ──────────────────────────────────────────────────────────
@app.route("/span", methods=["POST"])
@limiter.limit(SPAN_RATE_LIMIT)
@cross_origin(origins=CORS_ORIGINS or [], allow_headers=["Content-Type", "X-API-Key"], supports_credentials=True)
def receive_span():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Body must be a JSON object"}), 400
    if len(request.get_data(cache=True)) > app.config["MAX_CONTENT_LENGTH"]:
        return jsonify({"error": "Payload too large"}), 413

    required_fields = ["trace_id", "span_id", "span_type", "timestamp", "latency_ms"]
    missing = [f for f in required_fields if f not in data]
    if missing:
        return jsonify({"error": f"Missing required field(s): {missing}"}), 400

    # Validation stricte des types numériques (anti-DoS / anti-corruption DB)
    try:
        data["latency_ms"] = max(0.0, min(float(data.get("latency_ms", 0) or 0), 3.6e6))
        data["cost_usd"] = max(0.0, min(float(data.get("cost_usd", 0) or 0), 1e6))
        data["timestamp"] = float(data.get("timestamp", 0) or 0)
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid numeric field"}), 400

    try:
        data["input_tokens"] = max(0, int(float(data.get("input_tokens", 0) or 0)))
        data["output_tokens"] = max(0, int(float(data.get("output_tokens", 0) or 0)))
    except (TypeError, ValueError):
        data["input_tokens"] = 0
        data["output_tokens"] = 0

    data["trace_id"] = str(data["trace_id"])[:64]
    data["span_id"] = str(data["span_id"])[:64]
    data["span_type"] = str(data["span_type"])[:64]

    data.setdefault("input_data", {})
    data.setdefault("output_data", {})
    data.setdefault("security_checks", [])
    data.setdefault("blocked", False)

    data["input_data"] = redact_pii(data.get("input_data", {}))
    data["output_data"] = redact_pii(data.get("output_data", {}))

    is_pg = DB_TYPE == "postgres" and DATABASE_URL

    # Extraction des métadonnées de détection
    detection_layer = None
    ml_score = None
    llm_score = None
    llm_reason = None

    if "metadata" in data:
        detection_layer = data.get("metadata", {}).get("detection_layer") or data.get("metadata", {}).get("layer")
        ml_score = data.get("metadata", {}).get("ml_score")
        llm_score = data.get("metadata", {}).get("llm_score")
        llm_reason = data.get("metadata", {}).get("llm_reason")

    if not detection_layer and data.get("security_checks"):
        for check in data["security_checks"]:
            if check.get("check_name") in ["prompt_injection", "llm_judge"]:
                detection_layer = check.get("metadata", {}).get("layer")
                ml_score = check.get("metadata", {}).get("ml_score")
                llm_score = check.get("metadata", {}).get("llm_score")
                llm_reason = check.get("details")
                break

    model = data.get("input_data", {}).get("model") if isinstance(data.get("input_data"), dict) else None

    if is_pg:
        conn = get_pg_conn()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO spans (
                trace_id, span_id, span_type, timestamp, latency_ms,
                input_data, output_data, security_checks, blocked,
                block_reason, cost_usd, input_tokens, output_tokens,
                detection_layer, ml_score, llm_score, llm_reason, org_id, model
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            data["trace_id"], data["span_id"], data["span_type"],
            data["timestamp"], data["latency_ms"],
            json.dumps(data["input_data"]),
            json.dumps(data["output_data"]),
            json.dumps(data["security_checks"]),
            data["blocked"], data.get("block_reason"), data["cost_usd"],
            data["input_tokens"], data["output_tokens"],
            detection_layer, ml_score, llm_score, llm_reason, g.org_id, model
        ))
    else:
        conn = sqlite3.connect(DB_SQLITE_PATH)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO spans (
                trace_id, span_id, span_type, timestamp, latency_ms,
                input_data, output_data, security_checks, blocked,
                block_reason, cost_usd, input_tokens, output_tokens,
                detection_layer, ml_score, llm_score, llm_reason, org_id, model
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data["trace_id"], data["span_id"], data["span_type"],
            data["timestamp"], data["latency_ms"],
            json.dumps(data["input_data"]),
            json.dumps(data["output_data"]),
            json.dumps(data["security_checks"]),
            1 if data["blocked"] else 0,
            data.get("block_reason"), data["cost_usd"],
            data["input_tokens"], data["output_tokens"],
            detection_layer, ml_score, llm_score, llm_reason, g.org_id, model
        ))

    conn.commit()
    conn.close()
    return jsonify({"status": "ok"}), 201

# ── API : QUERIES ────────────────────────────────────────────────────────────
@app.route("/api/traces")
def list_traces():
    is_pg = DB_TYPE == "postgres" and DATABASE_URL
    conn = get_db()

    if is_pg:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        org_filter = "%s"
        concat_fn = "STRING_AGG(DISTINCT detection_layer, ',')"
    else:
        cur = conn.cursor()
        org_filter = "?"
        concat_fn = "GROUP_CONCAT(DISTINCT detection_layer)"

    cur.execute(f"""
        SELECT trace_id, COUNT(*) as span_count,
               SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked_count,
               SUM(cost_usd) as total_cost,
               MAX(created_at) as last_seen,
               {concat_fn} as detection_layers
        FROM spans
        WHERE org_id = {org_filter}
        GROUP BY trace_id
        ORDER BY last_seen DESC
        LIMIT 100
    """, (g.org_id,))

    rows = [dict_from_row(r, is_pg) for r in cur.fetchall()]
    conn.close()
    return jsonify(rows)

@app.route("/api/traces/<trace_id>")
def get_trace(trace_id):
    is_pg = DB_TYPE == "postgres" and DATABASE_URL
    conn = get_db()

    if is_pg:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT * FROM spans WHERE trace_id = %s AND org_id = %s ORDER BY timestamp", (trace_id, g.org_id))
    else:
        cur = conn.cursor()
        cur.execute("SELECT * FROM spans WHERE trace_id = ? AND org_id = ? ORDER BY timestamp", (trace_id, g.org_id))

    rows = [dict_from_row(r, is_pg) for r in cur.fetchall()]
    for r in rows:
        r["input_data"] = json.loads(r["input_data"] or "{}")
        r["output_data"] = json.loads(r["output_data"] or "{}")
        r["security_checks"] = json.loads(r["security_checks"] or "[]")
        r["blocked"] = bool(r["blocked"])
    conn.close()
    return jsonify(rows)

@app.route("/api/metrics")
def get_metrics():
    is_pg = DB_TYPE == "postgres" and DATABASE_URL
    conn = get_db()

    if is_pg:
        cur = conn.cursor()
        p = "%s"
    else:
        cur = conn.cursor()
        p = "?"

    cur.execute(f"SELECT COUNT(*) FROM spans WHERE org_id = {p}", (g.org_id,))
    total_spans = cur.fetchone()[0]

    cur.execute(f"SELECT COUNT(DISTINCT trace_id) FROM spans WHERE org_id = {p}", (g.org_id,))
    total_traces = cur.fetchone()[0]

    cur.execute(f"SELECT SUM(CASE WHEN blocked THEN 1 ELSE 0 END) FROM spans WHERE org_id = {p}", (g.org_id,))
    blocked = cur.fetchone()[0] or 0

    cur.execute(f"SELECT SUM(cost_usd) FROM spans WHERE org_id = {p}", (g.org_id,))
    total_cost = cur.fetchone()[0] or 0

    # Total tokens
    cur.execute(f"SELECT COALESCE(SUM(input_tokens + output_tokens), 0) FROM spans WHERE org_id = {p}", (g.org_id,))
    total_tokens = cur.fetchone()[0] or 0

    cur.execute(f"SELECT AVG(latency_ms) FROM spans WHERE latency_ms > 0 AND org_id = {p}", (g.org_id,))
    avg_latency = cur.fetchone()[0] or 0

    if is_pg:
        cur.execute("""
            SELECT detection_layer, COUNT(*) as count
            FROM spans WHERE detection_layer IS NOT NULL AND org_id = %s
            GROUP BY detection_layer
        """, (g.org_id,))
    else:
        cur.execute("""
            SELECT detection_layer, COUNT(*) as count
            FROM spans WHERE detection_layer IS NOT NULL AND org_id = ?
            GROUP BY detection_layer
        """, (g.org_id,))
    detection_stats = {row[0]: row[1] for row in cur.fetchall()}

    cur.execute(f"SELECT AVG(ml_score) FROM spans WHERE ml_score IS NOT NULL AND org_id = {p}", (g.org_id,))
    avg_ml_score = cur.fetchone()[0] or 0

    cur.execute(f"SELECT AVG(llm_score) FROM spans WHERE llm_score IS NOT NULL AND org_id = {p}", (g.org_id,))
    avg_llm_score = cur.fetchone()[0] or 0

    cur.execute(f"SELECT COUNT(*) FROM spans WHERE detection_layer = 'llm_judge' AND org_id = {p}", (g.org_id,))
    llm_count = cur.fetchone()[0] or 0

    # Risques (24h)
    if is_pg:
        cur.execute("""
            SELECT jsonb_array_elements(security_checks) as check
            FROM spans WHERE created_at > NOW() - INTERVAL '1 day' AND org_id = %s
        """, (g.org_id,))
        risk_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for row in cur.fetchall():
            check = row[0] if isinstance(row[0], dict) else {}
            level = check.get("risk_level", "low")
            if level in risk_counts:
                risk_counts[level] += 1
    else:
        cur.execute("""
            SELECT security_checks FROM spans
            WHERE created_at > datetime('now', '-1 day') AND org_id = ?
        """, (g.org_id,))
        risk_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for row in cur.fetchall():
            try:
                checks = json.loads(row[0] or "[]")
                for check in checks:
                    level = check.get("risk_level", "low")
                    if level in risk_counts:
                        risk_counts[level] += 1
            except Exception:
                pass

    cur.execute(f"""
        SELECT block_reason, COUNT(*) as count
        FROM spans WHERE blocked = TRUE AND org_id = {p}
        GROUP BY block_reason ORDER BY count DESC LIMIT 5
    """, (g.org_id,))
    top_threats = [{"reason": r[0], "count": r[1]} for r in cur.fetchall()]

    conn.close()
    return jsonify({
        "total_spans": total_spans,
        "total_traces": total_traces,
        "blocked_operations": blocked,
        "total_cost_usd": round(float(total_cost or 0), 6),
        "total_tokens": int(total_tokens),
        "avg_latency_ms": round(float(avg_latency or 0), 2),
        "avg_ml_score": round(float(avg_ml_score or 0), 3),
        "avg_llm_score": round(float(avg_llm_score or 0), 3),
        "llm_judge_count": llm_count,
        "risk_distribution": risk_counts,
        "top_threats": top_threats,
        "detection_layers": detection_stats,
        "version": "v5.0.0"
    })

@app.route("/api/detection/stats")
def get_detection_stats():
    is_pg = DB_TYPE == "postgres" and DATABASE_URL
    conn = get_db()
    if is_pg:
        cur = conn.cursor()
        p = "%s"
    else:
        cur = conn.cursor()
        p = "?"

    cur.execute(f"""
        SELECT detection_layer, COUNT(*) as count
        FROM spans WHERE detection_layer IS NOT NULL AND org_id = {p}
        GROUP BY detection_layer ORDER BY count DESC
    """, (g.org_id,))
    layer_distribution = [{"layer": r[0], "count": r[1]} for r in cur.fetchall()]

    cur.execute(f"""
        SELECT detection_layer, COUNT(*) as total, SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked
        FROM spans WHERE detection_layer IS NOT NULL AND org_id = {p}
        GROUP BY detection_layer
    """, (g.org_id,))
    layer_accuracy = []
    for r in cur.fetchall():
        layer_accuracy.append({
            "layer": r[0], "total": r[1], "blocked": r[2],
            "block_rate": round((r[2] / r[1] * 100) if r[1] > 0 else 0, 2)
        })

    cur.execute(f"""
        SELECT
            CASE
                WHEN ml_score >= 0.9 THEN '0.9-1.0'
                WHEN ml_score >= 0.8 THEN '0.8-0.9'
                WHEN ml_score >= 0.7 THEN '0.7-0.8'
                WHEN ml_score >= 0.6 THEN '0.6-0.7'
                WHEN ml_score >= 0.5 THEN '0.5-0.6'
                ELSE '0.0-0.5'
            END as score_range,
            COUNT(*) as count
        FROM spans WHERE ml_score IS NOT NULL AND org_id = {p}
        GROUP BY score_range ORDER BY score_range DESC
    """, (g.org_id,))
    ml_score_distribution = [{"range": r[0], "count": r[1]} for r in cur.fetchall()]

    cur.execute(f"""
        SELECT
            CASE
                WHEN llm_score >= 0.9 THEN 'high_risk'
                WHEN llm_score >= 0.7 THEN 'medium_risk'
                ELSE 'low_risk'
            END as risk_category,
            COUNT(*) as count
        FROM spans WHERE llm_score IS NOT NULL AND org_id = {p}
        GROUP BY risk_category
    """, (g.org_id,))
    llm_score_distribution = [{"category": r[0], "count": r[1]} for r in cur.fetchall()]

    conn.close()
    return jsonify({
        "layer_distribution": layer_distribution,
        "layer_accuracy": layer_accuracy,
        "ml_score_distribution": ml_score_distribution,
        "llm_score_distribution": llm_score_distribution,
        "total_analyzed": sum(l["count"] for l in layer_distribution) if layer_distribution else 0
    })

@app.route("/api/llm/stats")
@limiter.limit("10 per minute")
def get_llm_stats():
    is_pg = DB_TYPE == "postgres" and DATABASE_URL
    conn = get_db()
    cur = conn.cursor()
    p = "%s" if is_pg else "?"

    cur.execute(f"SELECT COUNT(*) FROM spans WHERE detection_layer = 'llm_judge' AND org_id = {p}", (g.org_id,))
    total_llm = cur.fetchone()[0] or 0

    cur.execute(f"""
        SELECT COUNT(*), SUM(CASE WHEN blocked THEN 1 ELSE 0 END)
        FROM spans WHERE detection_layer = 'llm_judge' AND org_id = {p}
    """, (g.org_id,))
    total, blocked = cur.fetchone()
    total = total or 0
    blocked = blocked or 0
    block_rate = round((blocked / total * 100), 2) if total else 0

    cur.execute(f"""
        SELECT llm_reason, COUNT(*) as count
        FROM spans WHERE llm_reason IS NOT NULL AND detection_layer = 'llm_judge' AND org_id = {p}
        GROUP BY llm_reason ORDER BY count DESC LIMIT 5
    """, (g.org_id,))
    top_reasons = [{"reason": r[0], "count": r[1]} for r in cur.fetchall()]

    conn.close()
    return jsonify({
        "total_analyzed": total_llm,
        "block_rate": block_rate,
        "top_reasons": top_reasons,
        "status": "operational" if total_llm > 0 else "idle"
    })

@app.route("/api/models")
def api_models():
    """Répartition réelle par modèle + tokens agrégés."""
    is_pg = DB_TYPE == "postgres" and DATABASE_URL
    conn = get_db()
    if is_pg:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        p = "%s"
    else:
        cur = conn.cursor()
        p = "?"

    cur.execute(f"""
        SELECT model, COUNT(*) as requests, AVG(latency_ms) as avg_latency,
               SUM(cost_usd) as total_cost,
               SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked_count,
               COALESCE(SUM(input_tokens), 0) as input_tokens,
               COALESCE(SUM(output_tokens), 0) as output_tokens
        FROM spans
        WHERE org_id = {p} AND model IS NOT NULL AND model != ''
        GROUP BY model
        ORDER BY requests DESC
    """, (g.org_id,))
    models = []
    for r in cur.fetchall():
        row = dict(r) if is_pg else {
            "model": r[0], "requests": r[1], "avg_latency": r[2],
            "total_cost": r[3], "blocked_count": r[4],
            "input_tokens": r[5], "output_tokens": r[6],
        }
        models.append({
            "name": row["model"],
            "requests": row["requests"],
            "avg_latency_ms": round(float(row["avg_latency"] or 0), 1),
            "total_cost_usd": round(float(row["total_cost"] or 0), 6),
            "blocked_count": row["blocked_count"],
            "input_tokens": int(row.get("input_tokens") or 0),
            "output_tokens": int(row.get("output_tokens") or 0),
        })
    conn.close()
    return jsonify(models)

@app.route("/api/heatmap")
def api_heatmap():
    is_pg = DB_TYPE == "postgres" and DATABASE_URL
    conn = get_db()
    if is_pg:
        cur = conn.cursor()
        cur.execute("""
            SELECT EXTRACT(DAY FROM created_at)::int as day, EXTRACT(HOUR FROM created_at)::int as hour,
                   COUNT(*) as total, SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked
            FROM spans WHERE org_id = %s AND created_at > NOW() - INTERVAL '5 days'
            GROUP BY day, hour
        """, (g.org_id,))
    else:
        cur = conn.cursor()
        cur.execute("""
            SELECT CAST(strftime('%d', created_at) AS INTEGER) as day,
                   CAST(strftime('%H', created_at) AS INTEGER) as hour,
                   COUNT(*) as total,
                   SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked
            FROM spans WHERE org_id = ? AND created_at > datetime('now', '-5 days')
            GROUP BY day, hour
        """, (g.org_id,))
    cells = [{"day": r[0], "hour": r[1], "total": r[2], "blocked": r[3] or 0} for r in cur.fetchall()]
    conn.close()
    return jsonify(cells)

@app.route("/api/checks/breakdown")
def api_checks_breakdown():
    """Agrégation globale des check_name / flagged."""
    is_pg = DB_TYPE == "postgres" and DATABASE_URL
    conn = get_db()
    cur = conn.cursor()
    p = "%s" if is_pg else "?"
    cur.execute(f"SELECT security_checks FROM spans WHERE org_id = {p} AND security_checks IS NOT NULL", (g.org_id,))
    rows = cur.fetchall()
    conn.close()

    breakdown = {}
    for row in rows:
        raw = row[0]
        try:
            checks = raw if isinstance(raw, list) else json.loads(raw)
        except Exception:
            continue
        for c in (checks or []):
            name = c.get("check_name", "unknown")
            entry = breakdown.setdefault(name, {"total": 0, "flagged": 0})
            entry["total"] += 1
            if not c.get("passed", True):
                entry["flagged"] += 1

    result = [
        {"check_name": name, "total": v["total"], "flagged": v["flagged"],
         "flag_rate": round(v["flagged"] / v["total"] * 100, 1) if v["total"] else 0}
        for name, v in breakdown.items()
    ]
    return jsonify(sorted(result, key=lambda x: -x["total"]))

@app.route("/api/checks/daily")
@limiter.limit("30 per minute")
def api_checks_daily():
    """Breakdown jour-par-jour + par check_name (pour stacked time chart)."""
    is_pg = DB_TYPE == "postgres" and DATABASE_URL
    conn = get_db()
    cur = conn.cursor()
    try:
        if is_pg:
            cur.execute("""
                SELECT DATE(created_at) as day, c->>'check_name' as name,
                       COUNT(*) as total,
                       SUM(CASE WHEN (c->>'passed')::boolean THEN 0 ELSE 1 END) as flagged
                FROM spans, jsonb_array_elements(security_checks) c
                WHERE org_id = %s AND created_at > NOW() - INTERVAL '14 days'
                GROUP BY day, name ORDER BY day
            """, (g.org_id,))
        else:
            cur.execute("""
                SELECT DATE(created_at) as day, json_extract(c.value, '$.check_name') as name,
                       COUNT(*) as total,
                       SUM(CASE WHEN json_extract(c.value, '$.passed') = 1 THEN 0 ELSE 1 END) as flagged
                FROM spans, json_each(spans.security_checks) c
                WHERE org_id = ? AND created_at > datetime('now','-14 days')
                GROUP BY day, name ORDER BY day
            """, (g.org_id,))
        rows = [{"day": str(r[0]), "name": r[1], "total": r[2], "flagged": r[3] or 0} for r in cur.fetchall()]
    except Exception as e:
        rows = []
    conn.close()
    return jsonify(rows)

@app.route("/api/models/daily")
@limiter.limit("30 per minute")
def api_models_daily():
    """Requests par jour + par modèle (pour Compliance Audit Trend)."""
    is_pg = DB_TYPE == "postgres" and DATABASE_URL
    conn = get_db()
    cur = conn.cursor()
    p = "%s" if is_pg else "?"
    if is_pg:
        cur.execute(f"""
            SELECT DATE(created_at) as day, model, COUNT(*) as n
            FROM spans WHERE org_id = {p} AND model IS NOT NULL AND model != ''
              AND created_at > NOW() - INTERVAL '14 days'
            GROUP BY day, model ORDER BY day
        """, (g.org_id,))
    else:
        cur.execute(f"""
            SELECT DATE(created_at) as day, model, COUNT(*) as n
            FROM spans WHERE org_id = {p} AND model IS NOT NULL AND model != ''
              AND created_at > datetime('now', '-14 days')
            GROUP BY day, model ORDER BY day
        """, (g.org_id,))
    rows = [{"day": str(r[0]), "model": r[1], "n": r[2]} for r in cur.fetchall()]
    conn.close()
    return jsonify(rows)

@app.route("/api/spans/expensive")
def api_expensive_spans():
    """Top 10 spans coûteuses avec prompt/réponse/tokens."""
    is_pg = DB_TYPE == "postgres" and DATABASE_URL
    conn = get_db()
    cur = conn.cursor()
    try:
        if is_pg:
            cur.execute("""
                SELECT trace_id, span_id, span_type, model, cost_usd,
                       COALESCE(input_data->>'prompt', input_data->>'tool', '') AS prompt,
                       COALESCE(output_data->>'response', '') AS response,
                       input_tokens, output_tokens
                FROM spans WHERE org_id = %s AND cost_usd > 0
                ORDER BY cost_usd DESC LIMIT 10
            """, (g.org_id,))
        else:
            cur.execute("""
                SELECT trace_id, span_id, span_type, model, cost_usd,
                       COALESCE(json_extract(input_data, '$.prompt'), json_extract(input_data, '$.tool'), '') AS prompt,
                       COALESCE(json_extract(output_data, '$.response'), '') AS response,
                       input_tokens, output_tokens
                FROM spans WHERE org_id = ? AND cost_usd > 0
                ORDER BY cost_usd DESC LIMIT 10
            """, (g.org_id,))
        rows = [
            {"trace_id": r[0], "span_id": r[1], "span_type": r[2], "model": r[3],
             "cost_usd": r[4], "prompt": (r[5] or "")[:300], "response": (r[6] or "")[:300],
             "input_tokens": r[7] or 0, "output_tokens": r[8] or 0}
            for r in cur.fetchall()
        ]
    except Exception:
        rows = []
    conn.close()
    return jsonify(rows)

@app.route("/api/cost/trend")
def api_cost_trend():
    """Coût + tokens jour par jour (14 derniers jours)."""
    is_pg = DB_TYPE == "postgres" and DATABASE_URL
    conn = get_db()
    cur = conn.cursor()
    if is_pg:
        cur.execute("""
            SELECT DATE(created_at) as day,
                   SUM(cost_usd) as cost,
                   COALESCE(SUM(input_tokens + output_tokens), 0) as tokens
            FROM spans WHERE org_id = %s AND created_at > NOW() - INTERVAL '14 days'
            GROUP BY day ORDER BY day
        """, (g.org_id,))
    else:
        cur.execute("""
            SELECT DATE(created_at) as day,
                   SUM(cost_usd) as cost,
                   COALESCE(SUM(input_tokens + output_tokens), 0) as tokens
            FROM spans WHERE org_id = ? AND created_at > datetime('now', '-14 days')
            GROUP BY day ORDER BY day
        """, (g.org_id,))
    rows = [{"day": str(r[0]), "cost": round(float(r[1] or 0), 6), "tokens": int(r[2] or 0)} for r in cur.fetchall()]
    conn.close()
    return jsonify(rows)

@app.route("/api/latency/distribution")
def api_latency_distribution():
    is_pg = DB_TYPE == "postgres" and DATABASE_URL
    conn = get_db()
    cur = conn.cursor()
    p = "%s" if is_pg else "?"
    cur.execute(f"SELECT latency_ms FROM spans WHERE org_id = {p} AND latency_ms > 0 ORDER BY latency_ms", (g.org_id,))
    values = [r[0] for r in cur.fetchall()]
    conn.close()

    def pct(vals, q):
        if not vals:
            return 0
        idx = min(len(vals) - 1, int(len(vals) * q))
        return round(vals[idx], 1)

    return jsonify({
        "count": len(values),
        "p50": pct(values, 0.50),
        "p90": pct(values, 0.90),
        "p95": pct(values, 0.95),
        "p99": pct(values, 0.99),
        "min": round(min(values), 1) if values else 0,
        "max": round(max(values), 1) if values else 0,
    })

@app.route("/api/events/recent")
def api_recent_events():
    is_pg = DB_TYPE == "postgres" and DATABASE_URL
    conn = get_db()
    cur = conn.cursor()
    p = "%s" if is_pg else "?"
    cur.execute(f"""
        SELECT span_type, detection_layer, blocked, block_reason, created_at, security_checks
        FROM spans WHERE org_id = {p} ORDER BY created_at DESC LIMIT 8
    """, (g.org_id,))
    events = []
    for r in cur.fetchall():
        try:
            checks = r[5] if isinstance(r[5], list) else json.loads(r[5] or "[]")
        except Exception:
            checks = []
        risk = "low"
        for c in checks:
            if c.get("risk_level") in ("high", "critical"):
                risk = c.get("risk_level")
                break
        events.append({
            "span_type": r[0], "layer": r[1] or "regex", "blocked": bool(r[2]),
            "reason": r[3], "created_at": str(r[4]), "risk": risk,
        })
    conn.close()
    return jsonify(events)

@app.route("/api/trend/daily")
def api_trend_daily():
    is_pg = DB_TYPE == "postgres" and DATABASE_URL
    conn = get_db()
    cur = conn.cursor()
    if is_pg:
        cur.execute("""
            SELECT DATE(created_at) as day, COUNT(*) as total,
                   SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked
            FROM spans WHERE org_id = %s AND created_at > NOW() - INTERVAL '14 days'
            GROUP BY day ORDER BY day
        """, (g.org_id,))
    else:
        cur.execute("""
            SELECT DATE(created_at) as day, COUNT(*) as total,
                   SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked
            FROM spans WHERE org_id = ? AND created_at > datetime('now', '-14 days')
            GROUP BY day ORDER BY day
        """, (g.org_id,))
    rows = [{"day": str(r[0]), "total": r[1], "blocked": r[2] or 0} for r in cur.fetchall()]
    conn.close()
    return jsonify(rows)

# ── AUDIT TRAIL ──────────────────────────────────────────────────────────────
@app.route("/api/audit/trail")
@limiter.limit("30 per minute")
def api_audit_trail():
    """Audit trail façon Dynatrace : 50 derniers événements avec prompt."""
    is_pg = DB_TYPE == "postgres" and DATABASE_URL
    conn = get_db()
    cur = conn.cursor()
    if is_pg:
        cur.execute("""
            SELECT created_at, trace_id, span_id, span_type, detection_layer, model, blocked,
                   COALESCE(input_data->>'prompt', input_data->>'tool', '') AS prompt
            FROM spans WHERE org_id = %s ORDER BY created_at DESC LIMIT 50
        """, (g.org_id,))
    else:
        cur.execute("""
            SELECT created_at, trace_id, span_id, span_type, detection_layer, model, blocked,
                   COALESCE(json_extract(input_data, '$.prompt'), json_extract(input_data, '$.tool'), '') AS prompt
            FROM spans WHERE org_id = ? ORDER BY created_at DESC LIMIT 50
        """, (g.org_id,))
    rows = [
        {
            "timestamp": str(r[0]), "trace_id": r[1], "span_id": r[2],
            "span_type": r[3], "layer": r[4] or "regex", "model": r[5] or "—",
            "blocked": bool(r[6]), "prompt": (r[7] or "")[:120],
        }
        for r in cur.fetchall()
    ]
    conn.close()
    return jsonify(rows)

# ── DASHBOARD ────────────────────────────────────────────────────────────────
DASHBOARD_HTML = "<html><body>placeholder dashboard, remplacé plus bas</body></html>"

@app.route("/")
def dashboard():
    return make_response(render_template_string(DASHBOARD_HTML))

@app.route("/trace/<trace_id>")
def trace_detail(trace_id):
    """Détail d'une trace avec visualisation."""
    is_pg = DB_TYPE == "postgres" and DATABASE_URL
    conn = get_db()
    if is_pg:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT * FROM spans WHERE trace_id = %s AND org_id = %s ORDER BY timestamp", (trace_id, g.org_id))
    else:
        cur = conn.cursor()
        cur.execute("SELECT * FROM spans WHERE trace_id = ? AND org_id = ? ORDER BY timestamp", (trace_id, g.org_id))
    rows = [dict_from_row(r, is_pg) for r in cur.fetchall()]
    for r in rows:
        r["input_data"] = json.loads(r["input_data"] or "{}")
        r["output_data"] = json.loads(r["output_data"] or "{}")
        r["security_checks"] = json.loads(r["security_checks"] or "[]")
        r["blocked"] = bool(r["blocked"])
    conn.close()

    html = """<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Trace Detail</title>
    <style>body{font-family:-apple-system,sans-serif;background:#0b1121;color:#e2e8f0;padding:24px}
    .back{color:#38bdf8;text-decoration:none;font-size:.9rem;margin-bottom:20px;display:inline-block}
    h1{font-size:1.3rem;margin-bottom:20px}
    .span-card{background:#1e293b;border:1px solid #334155;border-radius:14px;padding:20px;margin-bottom:16px;border-left:4px solid #38bdf8}
    .span-card.blocked{border-left-color:#ef4444}
    .span-type{color:#38bdf8;font-weight:700;text-transform:uppercase;font-size:.75rem;letter-spacing:.05em}
    .meta{color:#64748b;font-size:.82rem;margin-top:4px}
    pre{background:#0f172a;padding:14px;border-radius:10px;overflow-x:auto;font-size:.82rem;line-height:1.5;border:1px solid #334155}
    h3{font-size:.85rem;color:#94a3b8;text-transform:uppercase;margin:16px 0 8px}
    .check{padding:10px 14px;margin:6px 0;border-radius:8px;font-size:.88rem}
    .check-pass{background:#22c55e15;border:1px solid #22c55e40}
    .check-fail{background:#ef444415;border:1px solid #ef444415}</style></head><body>
    <a class="back" href="/">← Retour au Dashboard</a>
    <h1>Trace <code style="color:#94a3b8">""" + _esc(trace_id[:20]) + """…</code></h1>"""

    for row in rows:
        checks = row["security_checks"]
        blocked = bool(row["blocked"])
        layer = _esc(row.get("detection_layer") or "unknown")

        html += f"""
        <div class="span-card {'blocked' if blocked else ''}">
            <div class="span-type">{_esc(row['span_type'])} — {float(row['latency_ms']):.0f}ms — ${float(row['cost_usd']):.6f} · {layer.upper()}</div>
            <div class="meta">{_esc(str(row['created_at']))}</div>
            <h3>📥 Input</h3><pre>{_esc(json.dumps(row['input_data'], indent=2, ensure_ascii=False))}</pre>
            <h3>📤 Output</h3><pre>{_esc(json.dumps(row['output_data'], indent=2, ensure_ascii=False))}</pre>
            <h3>🛡️ Security Checks ({len(checks)})</h3>
            {''.join(f'<div class="check check-{"pass" if c["passed"] else "fail"}">{"✅" if c["passed"] else "🚨"} <strong>{_esc(c["check_name"])}</strong> — {_esc(c["risk_level"])}<br><span style="color:#94a3b8;font-size:.8rem">{_esc(c["details"])}</span></div>' for c in checks)}
        </div>"""

    html += "</body></html>"
    return make_response(html)

# ── ERROR HANDLING ───────────────────────────────────────────────────────────
@app.errorhandler(Exception)
def handle_unexpected_error(e):
    from werkzeug.exceptions import HTTPException
    if isinstance(e, HTTPException):
        return e
    app.logger.exception("Unhandled error")
    return jsonify({"error": "Internal server error"}), 500

@app.route("/", methods=["POST"])
def root_post_handler():
    return "", 204

# ── ADMIN ENDPOINTS ──────────────────────────────────────────────────────────
@app.route("/api/key")
@limiter.limit("5 per minute")
def show_key():
    if not ADMIN_SECRET:
        return jsonify({"error": "AGENTGUARD_ADMIN_SECRET not configured — endpoint disabled"}), 404
    admin_secret = request.headers.get("X-Admin-Secret", "")
    if admin_secret and safe_compare(admin_secret, ADMIN_SECRET):
        return jsonify({"api_key": API_KEY})
    return jsonify({"error": "Admin secret required"}), 403

@app.route("/admin/customers", methods=["POST"])
@limiter.limit("10 per minute")
def create_customer():
    if not ADMIN_SECRET:
        return jsonify({"error": "AGENTGUARD_ADMIN_SECRET not configured — endpoint disabled"}), 404
    admin_secret = request.headers.get("X-Admin-Secret", "") or request.args.get("admin", "")
    if not safe_compare(admin_secret, ADMIN_SECRET):
        return jsonify({"error": "Admin secret required"}), 403

    payload = request.json or {}
    org_name = payload.get("org_name", "").strip()
    plan = payload.get("plan", "free")
    if not org_name:
        return jsonify({"error": "org_name is required"}), 400
    if plan not in ("free", "pro", "startup", "enterprise"):
        return jsonify({"error": "plan must be one of: free, pro, startup, enterprise"}), 400

    org_id = f"org_{secrets.token_urlsafe(8)}"
    new_key = "ag_" + secrets.token_urlsafe(32)
    key_hash = hash_key(new_key)

    is_pg = DB_TYPE == "postgres" and DATABASE_URL
    conn = get_pg_conn() if is_pg else sqlite3.connect(DB_SQLITE_PATH)
    cur = conn.cursor()
    if is_pg:
        cur.execute(
            "INSERT INTO api_keys (key_hash, org_id, org_name, plan) VALUES (%s, %s, %s, %s)",
            (key_hash, org_id, org_name, plan),
        )
    else:
        cur.execute(
            "INSERT INTO api_keys (key_hash, org_id, org_name, plan) VALUES (?, ?, ?, ?)",
            (key_hash, org_id, org_name, plan),
        )
    conn.commit()
    conn.close()

    return jsonify({
        "org_id": org_id,
        "org_name": org_name,
        "plan": plan,
        "api_key": new_key,
        "warning": "Cette clé ne sera plus jamais affichée — transmets-la au client maintenant.",
    }), 201

@app.route("/admin/customers/<org_id>/revoke", methods=["POST"])
@limiter.limit("10 per minute")
def revoke_customer(org_id):
    if not ADMIN_SECRET:
        return jsonify({"error": "AGENTGUARD_ADMIN_SECRET not configured — endpoint disabled"}), 404
    admin_secret = request.headers.get("X-Admin-Secret", "") or request.args.get("admin", "")
    if not safe_compare(admin_secret, ADMIN_SECRET):
        return jsonify({"error": "Admin secret required"}), 403

    is_pg = DB_TYPE == "postgres" and DATABASE_URL
    conn = get_pg_conn() if is_pg else sqlite3.connect(DB_SQLITE_PATH)
    cur = conn.cursor()
    if is_pg:
        cur.execute("UPDATE api_keys SET active = FALSE WHERE org_id = %s", (org_id,))
    else:
        cur.execute("UPDATE api_keys SET active = 0 WHERE org_id = ?", (org_id,))
    affected = cur.rowcount
    conn.commit()
    conn.close()
    return jsonify({"org_id": org_id, "keys_revoked": affected})

# ── BOOTSTRAP ────────────────────────────────────────────────────────────────
if _API_KEY_WAS_GENERATED and DB_TYPE == "postgres":
    print("[AG] 🚨 PostgreSQL actif (config prod) mais AGENTGUARD_API_KEY n'est "
          "pas fixée — chaque redémarrage invalidera les intégrations SDK "
          "existantes. Configure AGENTGUARD_API_KEY dans les variables d'env Render.")

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 8080))
    print(f"🛡️ AgentGuard Collector v5.0 running on http://0.0.0.0:{port}")
    print(f"   DB: {DB_TYPE}")
    print(f"   Detection: Regex + ML (if enabled) + LLM Judge (if enabled)")
    app.run(host="0.0.0.0", port=port, debug=False)
    
