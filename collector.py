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
    
    # PII redaction avant stockage
    data["input_data"] = redact_pii(data.get("input_data", {}))
    data["output_data"] = redact_pii(data.get("output_data", {}))

    is_pg = DB_TYPE == "postgres" and DATABASE_URL

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
DASHBOARD_HTML = r'''
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>AgentGuard — AI Observability</title>
<style>
:root{--bg:#0d0f17;--bg2:#10121a;--card:#151722;--card2:#1a1d2a;--border:#262a3a;--border2:#303448;--text:#e6e8f2;--muted:#9298ab;--dim:#5d6375;--purple:#8b5cf6;--purple2:#a78bfa;--green:#4cc38a;--red:#e0525f;--red2:#ff5d73;--blue:#4c8dff;--cyan:#38bdf8;--orange:#fb923c;--teal:#3ecfb2;--yellow:#f5b84b;--val:#6ee7b7;--mono:ui-monospace,"SF Mono",Menlo,Consolas,monospace}
*{box-sizing:border-box}html,body{margin:0;background:var(--bg);color:var(--text);font:13px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,sans-serif}
a{color:var(--purple2);text-decoration:none}
button{font:inherit;cursor:pointer}
.topbar{height:48px;display:flex;align-items:center;gap:18px;padding:0 16px;background:var(--bg);border-bottom:1px solid var(--border);position:sticky;top:0;z-index:50}
.logo-box{width:30px;height:30px;border-radius:8px;background:#fff;display:grid;place-items:center;padding:4px}
.logo-box img{width:100%;height:100%;object-fit:contain}
.prod{font-weight:700;font-size:14px}
.prod small{color:var(--muted);font-weight:400;margin-left:6px;font-size:12px}
.tabs{display:flex;gap:2px;height:100%}
.tabs button{background:none;border:0;color:var(--muted);padding:0 14px;height:100%;font-size:13px;border-bottom:2px solid transparent}
.tabs button:hover{color:var(--text)}
.tabs button.active{color:var(--purple2);border-bottom-color:var(--purple)}
.tabs button[disabled]{opacity:.45;cursor:default}
.tb-right{margin-left:auto;display:flex;align-items:center;gap:10px}
.btn{background:var(--card2);border:1px solid var(--border2);color:var(--text);border-radius:6px;padding:6px 12px;font-size:12px}
.btn:hover{border-color:#454a63}
.help{width:22px;height:22px;border:1px solid var(--border2);border-radius:50%;display:grid;place-items:center;color:var(--muted);font-size:11px}
.toolbar{display:flex;align-items:center;gap:10px;padding:10px 16px;border-bottom:1px solid var(--border);background:var(--bg2)}
.filter-pill{display:flex;align-items:center;gap:8px;background:var(--card);border:1px solid var(--border2);border-radius:6px;padding:6px 10px;font-size:12px;color:var(--muted);max-width:70%;overflow:hidden;white-space:nowrap}
.filter-pill b{color:var(--text);font-weight:400}
.filter-pill .x{color:var(--dim);cursor:pointer;margin-left:4px}
.toolbar .right{margin-left:auto;display:flex;gap:8px;align-items:center}
.pill{background:var(--card);border:1px solid var(--border2);border-radius:6px;padding:6px 10px;font-size:12px;color:var(--muted)}
.body{display:flex;min-height:calc(100vh - 100px)}
.fside{width:230px;flex-shrink:0;border-right:1px solid var(--border);padding:12px 10px;background:var(--bg);overflow-y:auto}
.fgroup{margin-bottom:6px}
.fgroup>div{display:flex;align-items:center;gap:6px;color:var(--muted);font-size:12px;padding:5px 6px;cursor:pointer;user-select:none}
.fgroup>div:hover{color:var(--text)}
.fitems{padding:2px 0 4px 8px}
.fitem{display:flex;align-items:center;gap:8px;padding:4px 6px;font-size:12px;color:var(--text)}
.fitem input{accent-color:var(--purple);width:13px;height:13px}
.main{flex:1;min-width:0;padding:18px 22px 60px;max-width:1760px}
.view{display:none}.view.active{display:block}
.sec{display:flex;align-items:center;gap:8px;font-size:15px;font-weight:600;margin:26px 0 12px}
.sec:first-child{margin-top:4px}
.sec .ico{color:var(--purple2)}
.sec .info{color:var(--dim);font-size:11px;border:1px solid var(--border2);border-radius:50%;width:15px;height:15px;display:inline-grid;place-items:center}
.grid{display:grid;gap:12px}
.g2{grid-template-columns:1.35fr 1fr}.g3{grid-template-columns:repeat(3,1fr)}.g4{grid-template-columns:repeat(4,1fr)}.g5{grid-template-columns:repeat(5,1fr)}
.card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:16px;position:relative}
.card .menu{position:absolute;top:12px;right:12px;color:var(--dim);cursor:pointer;font-size:14px;letter-spacing:2px}
.card .alert-btn{position:absolute;top:12px;right:34px;color:var(--muted);font-size:12px;background:none;border:0}
.clabel{font-size:12px;color:var(--muted);margin-bottom:6px}
.hero{font-size:54px;font-weight:600;letter-spacing:-1px;line-height:1.05;margin:8px 0 4px}
.hero.mid{font-size:40px}.hero.sm{font-size:30px}
.hero .unit{font-size:.45em;font-weight:600;color:var(--text)}
.trend{font-size:13px;margin-top:4px}
.trend.up{color:var(--green)}.trend.down{color:var(--red2)}
.chart{height:210px;position:relative}.chart svg{width:100%;height:100%;display:block}
.chart.tall{height:250px}
.empty{color:var(--dim);text-align:center;padding:36px 8px;font-size:12px}
.legend{display:flex;flex-wrap:wrap;gap:14px;font-size:11px;color:var(--muted);margin-top:10px}
.legend i{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}
.stat-tabs{display:inline-flex;gap:4px;margin-bottom:12px}
.stat-tabs button{background:var(--card);border:1px solid var(--border2);color:var(--muted);border-radius:5px;padding:4px 12px;font-size:12px}
.stat-tabs button.active{background:var(--card2);color:var(--text);border-color:#454a63}
table{width:100%;border-collapse:collapse}
th{text-align:left;color:var(--muted);font-weight:400;font-size:11.5px;padding:6px 10px;border-bottom:1px solid var(--border)}
th .sort{color:var(--dim)}
td{border-bottom:1px solid var(--border);padding:7px 10px;font-size:12px;color:var(--text);vertical-align:top}
tr:hover td{background:#191c29}
.mono{font-family:var(--mono);font-size:11px}
.dim{color:var(--dim)}
.tr-head{display:flex;align-items:center;gap:16px;flex-wrap:wrap;background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:10px 14px;margin-bottom:12px;font-size:12.5px}
.tr-head .name{font-weight:600;font-size:13.5px}
.tr-head .err{color:var(--red2)}
.tr-head .right{margin-left:auto;display:flex;gap:14px;color:var(--muted)}
.tr-body{display:grid;grid-template-columns:minmax(0,1.55fr) minmax(320px,.8fr);gap:12px}
.span-row{display:flex;align-items:center;height:26px;font-size:12px;cursor:pointer}
.span-row:hover{background:#191c29}
.span-row.sel{outline:1px solid var(--purple)}
.span-row .tw{width:46%;flex-shrink:0;display:flex;align-items:center;gap:6px;white-space:nowrap;overflow:hidden}
.span-row .dot{width:10px;height:10px;border-radius:50%;background:var(--blue);flex-shrink:0}
.span-row .dot.client{background:#7aa7ff}
.span-row .track{flex:1;position:relative;height:100%}
.span-row .bar{position:absolute;top:9px;height:8px;border-radius:2px;background:var(--blue)}
.span-row .bar.blocked{background:var(--red2)}
.axis{display:flex;justify-content:space-between;color:var(--dim);font-size:10.5px;border-bottom:1px solid var(--border);padding-bottom:4px;margin-bottom:4px}
.warn{color:var(--yellow);font-size:11px}
.attr-sec{border:1px solid var(--border);border-radius:8px;margin-bottom:10px;background:var(--card)}
.attr-sec h4{margin:0;padding:10px 12px;font-size:12.5px;font-weight:600;border-bottom:1px solid var(--border);display:flex;justify-content:space-between}
.attr-row{display:flex;gap:12px;padding:7px 12px;border-bottom:1px solid var(--border);font-size:11.5px}
.attr-row:last-child{border-bottom:0}
.attr-row .k{width:44%;flex-shrink:0;color:var(--muted)}
.attr-row .v{font-family:var(--mono);color:var(--val);word-break:break-word}
.attr-row .v.pink{color:#f472b6}.attr-row .v.blue{color:#7aa7ff}
.exc-row td{cursor:pointer}
.codeblock{background:#0a0c12;border:1px solid var(--border);border-radius:6px;padding:10px 12px;font-family:var(--mono);font-size:11px;color:#aeb6c8;white-space:pre-wrap;word-break:break-word;margin:8px 0}
.qblock{display:flex;background:#0a0c12;border:1px solid var(--border);border-radius:8px;padding:10px 0;font-family:var(--mono);font-size:11.5px;color:#aeb6c8;position:relative}
.qblock .ln{color:var(--dim);text-align:right;padding:0 12px;border-right:1px solid var(--border);user-select:none}
.qblock .code{padding:0 14px;white-space:pre}
.qblock .copy{position:absolute;top:8px;right:10px;color:var(--dim);cursor:pointer}
.pilltag{display:inline-block;background:var(--card2);border:1px solid var(--border2);border-radius:5px;padding:2px 8px;font-size:10.5px;color:var(--muted);font-family:var(--mono)}
.badge{display:inline-block;border-radius:4px;padding:2px 7px;font-size:10px;font-weight:600}
.badge.safe{color:var(--green);background:#4cc38a14;border:1px solid #4cc38a33}
.badge.blocked{color:var(--red2);background:#ff5d7314;border:1px solid #ff5d7333}
.subtabs{display:flex;gap:18px;border-bottom:1px solid var(--border);margin-bottom:10px;font-size:12.5px}
.subtabs span{padding:6px 2px;color:var(--muted);cursor:pointer}
.subtabs span.active{color:var(--text);border-bottom:2px solid var(--purple)}
.subtabs .n{background:var(--yellow);color:#111;border-radius:8px;padding:0 6px;font-size:10px;margin-left:5px}
.searchbox{background:var(--card);border:1px solid var(--border2);border-radius:6px;padding:7px 10px;color:var(--text);font:inherit;font-size:12px;width:100%}
.toast{position:fixed;right:20px;bottom:20px;background:var(--card2);border:1px solid var(--border2);padding:10px 14px;border-radius:8px;font-size:12px;z-index:100;opacity:0;transition:.2s}
.toast.show{opacity:1}
@media(max-width:1200px){.g5{grid-template-columns:repeat(3,1fr)}.g4,.g3{grid-template-columns:repeat(2,1fr)}.tr-body{grid-template-columns:1fr}.fside{display:none}}
@media(max-width:760px){.g5,.g4,.g3,.g2{grid-template-columns:1fr}.tabs{overflow-x:auto}}
</style>
</head>
<body>
<header class="topbar">
  <div class="logo-box"><img src="/static/logo.svg" alt="" onerror="this.outerHTML='🛡️'"></div>
  <span class="prod">AgentGuard <small>AI Observability</small></span>
  <nav class="tabs" id="topTabs">
    <button data-view="overview">Overview</button>
    <button data-view="health" class="active">Service Health (Preview)</button>
    <button data-view="tracing">Explorer (Preview)</button>
    <button data-view="audit">Compliance Audit</button>
    <button disabled title="Experimental — coming soon">AI Agents (Experimental)</button>
  </nav>
  <div class="tb-right">
    <button class="btn" onclick="toast('Connections gérées via /admin/customers')">+ Connection</button>
    <span class="help">?</span>
  </div>
</header>
<div class="toolbar">
  <div class="filter-pill">⧩ <span>Service in (<b>agentguard-collector</b>)</span><span class="x" title="clear">✕</span></div>
  <div class="right">
    <span class="pill">Last 14 days ▾</span>
    <button class="btn" onclick="refreshAll()">⟳ Refresh</button>
    <form method="post" action="/logout" style="margin:0"><button class="btn" type="submit">Sign out</button></form>
  </div>
</div>
<div class="body">
<aside class="fside" id="fside"></aside>
<main class="main">

<section id="view-overview" class="view">
  <div class="sec">Service Health &amp; Performance</div>
  <div class="grid" style="grid-template-columns:170px 1fr 1fr 1fr;gap:12px">
    <div class="card" style="background:#fff;display:grid;place-items:center;border:0;border-radius:18px"><div class="logo-box" style="width:96px;height:96px;border-radius:22px;padding:14px"><img src="/static/logo.svg" onerror="this.outerHTML='🛡️'"></div></div>
    <div class="card"><div class="clabel">Open Problems</div><div class="hero mid" id="ovProblems" style="color:var(--red2)">0</div></div>
    <div class="card"><div class="clabel"># of Total Requests</div><div class="hero mid" id="ovRequests">0</div><div class="trend" id="ovRequestsT"></div></div>
    <div class="card"><div class="clabel">Cost</div><div class="hero mid" id="ovCost">$0</div><div class="trend" id="ovCostT"></div></div>
  </div>
  <div class="grid g4" style="margin-top:12px">
    <div class="card"><div class="clabel">Service Health</div><div id="ovDonut" style="height:170px"></div></div>
    <div class="card"><div class="clabel">AVG Request Duration</div><div class="hero mid" id="ovAvg">—</div><div class="trend" id="ovAvgT"></div></div>
    <div class="card"><div class="clabel">P99 Request Duration</div><div class="hero mid" id="ovP99">—</div><div class="trend" id="ovP99T"></div></div>
    <div class="card"><div class="clabel">AgentGuard AI Forecast</div><div class="chart" id="ovForecast" style="height:170px"></div></div>
  </div>
  <div class="sec">Service Quality &amp; Guardrails</div>
  <div class="grid g5" id="gqBig"></div>
  <div class="grid g5" style="margin-top:12px" id="gqSmall"></div>
  <div class="sec">End-To-End Tracing &amp; Debugging</div>
  <div class="card"><div class="clabel">Top 10 expensive prompts</div>
    <table><thead><tr><th>prompt <span class="sort">⇅</span></th><th>response <span class="sort">⇅</span></th><th>trace.id <span class="sort">⇅</span></th><th>token <span class="sort">⇅</span></th><th>cost <span class="sort">⇅</span></th></tr></thead><tbody id="expTable"></tbody></table>
  </div>
</section>

<section id="view-health" class="view active">
  <div class="sec"><span class="ico">⏱</span>Traffic and Latency <span class="info">i</span></div>
  <div class="stat-tabs" id="latTabs"><button class="active" data-s="avg">AVG</button><button data-s="p50">p50</button><button data-s="p90">p90</button><button data-s="p95">p95</button></div>
  <div class="grid g2">
    <div class="card"><span class="menu">⋮</span><div class="clabel">Time to response</div><div class="hero" style="text-align:center" id="ttrHero">—</div><div class="chart" id="ttrChart"></div></div>
    <div class="card"><span class="menu">⋮</span><div class="clabel">Response time per model</div><div id="rtModel" style="height:290px"></div></div>
  </div>
  <div class="sec"><span class="ico">◈</span>Cost <span class="info">i</span></div>
  <div class="grid g3">
    <div class="card"><button class="alert-btn">+ New alert</button><span class="menu">⋮</span><div class="clabel">Token count</div><div class="hero" id="tokHero">0</div></div>
    <div class="card"><span class="menu">⋮</span><div class="clabel">Average cost per request</div><div class="hero" id="avgCostHero">—</div><div class="chart" id="avgCostChart" style="height:120px"></div></div>
    <div class="card"><button class="alert-btn">+ New alert</button><span class="menu">⋮</span><div class="clabel">Token usage forecast</div><div class="chart tall" id="tokForecast"></div><div class="legend"><span><i style="background:var(--purple2)"></i>Total amount of tokens used</span></div></div>
  </div>
  <div class="sec"><span class="ico">🛡</span>Guardrails <span class="info">i</span></div>
  <div class="grid g2">
    <div class="card"><span class="menu">⋮</span><div class="clabel">Number of requests with guardrail enabled</div><div class="hero" id="grHero">0</div></div>
    <div class="card"><span class="menu">⋮</span><div class="clabel">Guardrail activation by type</div><div class="chart tall" id="grStacked"></div><div class="legend" id="grLegend"></div></div>
  </div>
  <div class="sec"><span class="ico">◎</span>Tokens per model</div>
  <div class="card"><div id="tokModel" style="min-height:60px"></div></div>
</section>

<section id="view-tracing" class="view">
  <div class="tr-head">
    <span>⇄</span><span class="name">AgentGuard.workflow</span>
    <select id="traceSelect" class="pill" style="background:var(--card);color:var(--text);border:1px solid var(--border2)"></select>
    <span id="trDate" class="dim"></span>
    <span>⏱ Duration: <b id="trDur">—</b></span>
    <span class="err">◇ Errors: <b id="trErr">0</b></span>
    <span class="mono dim">ID: <span id="trId"></span> ⧉</span>
    <span class="right"><span>Open with ⊞</span><span>Close details</span><span>Minimize</span></span>
  </div>
  <div class="tr-body">
    <div>
      <div class="card" style="padding:12px">
        <div style="display:flex;gap:8px;align-items:center;margin-bottom:10px">
          <input class="searchbox" id="spanSearch" placeholder="Search name, endpoint, service, or attributes" style="max-width:340px">
          <span class="pilltag" id="spanCount">0 spans</span>
        </div>
        <div class="axis"><span id="ax0">0 ms</span><span id="ax1"></span><span id="ax2"></span></div>
        <div id="spanTree"></div>
      </div>
      <div class="card" style="margin-top:12px;padding:12px">
        <div class="subtabs"><span>Logs</span><span class="active">Exceptions<span class="n" id="excN">0</span></span></div>
        <table><thead><tr><th></th><th>Exception class</th><th>Exception message</th></tr></thead><tbody id="excTable"></tbody></table>
      </div>
    </div>
    <div id="spanDetail"></div>
  </div>
</section>

<section id="view-audit" class="view">
  <h1 style="font-size:24px;margin:4px 0 2px">GenAI Compliance Audit</h1>
  <div class="dim" style="font-size:12px;margin-bottom:20px" id="auRange"></div>
  <div class="grid g2">
    <div>
      <div class="sec" style="margin-top:0">Auditing Events</div>
      <div class="qblock"><div class="ln">1<br>2<br>3<br>4</div><div class="code">fetch spans
| filter matchesValue(event.type, "agentguard.security")
| summarize count() by: { gen_ai.model }
| filter gen_ai.model != ""</div><span class="copy" onclick="toast('Query copied')">⧉</span></div>
      <div class="card" style="margin-top:12px;padding:6px 0">
        <table><thead><tr><th>llm model <span class="sort">⇅</span></th><th style="text-align:right">events <span class="sort">⇅</span></th></tr></thead><tbody id="auModels"></tbody></table>
      </div>
    </div>
    <div><div class="sec" style="margin-top:0">Trend</div><div class="card"><div class="chart tall" id="auTrend" style="height:330px"></div></div></div>
  </div>
  <div class="sec">Audit Trail</div>
  <div class="card" style="padding:6px 0;overflow-x:auto">
    <table style="min-width:1100px"><thead><tr><th>timestamp <span class="sort">⇅</span></th><th>event.id <span class="sort">⇅</span></th><th>event.provider <span class="sort">⇅</span></th><th>event.type <span class="sort">⇅</span></th><th>gen_ai.model <span class="sort">⇅</span></th><th>gen_ai.prompt <span class="sort">⇅</span></th><th>gen_ai.role <span class="sort">⇅</span></th><th>gen_ai.system <span class="sort">⇅</span></th><th>gen_ai.type <span class="sort">⇅</span></th></tr></thead><tbody id="auTrail"></tbody></table>
  </div>
</section>

</main>
</div>
<div id="toast" class="toast"></div>

<script>
var state={modelFilter:new Set(),selTrace:null,selSpan:0,latStat:'avg'};
var $=function(id){return document.getElementById(id);};
var esc=function(v){return String(v||'').replace(/[&<>'"]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c];});};
var fmt=function(n){return Number(n||0).toLocaleString('en-US').replace(/,/g,' ');};
var fmtK=function(n){n=Number(n||0);return n>=1e6?(n/1e6).toFixed(1)+'M':n>=1e3?(n/1e3).toFixed(1)+'K':String(Math.round(n));};
var money=function(n){return '$'+Number(n||0).toFixed(4);};
var P=['#a78bfa','#fb923c','#4cc38a','#e0525f','#38bdf8','#f5b84b','#8b5cf6','#4ade80','#22d3ee','#f472b6','#facc15','#94a3b8','#6ee7b7','#fda4af','#c084fc'];
var CHECKS=[['prompt_injection','#a78bfa'],['pii_detection','#fb923c'],['tool_policy','#3ecfb2'],['dangerous_params','#e0525f'],['budget_policy','#4c8dff']];
function toast(m){var t=$('toast');t.textContent=m;t.classList.add('show');clearTimeout(window._t);window._t=setTimeout(function(){t.classList.remove('show');},2200);}
function api(u){return fetch(u,{credentials:'include'}).then(function(r){if(!r.ok)throw new Error('HTTP '+r.status);return r.json();});}
function trendPct(s){if(!s||s.length<2)return null;var a=s[0],b=s[s.length-1];if(!a&&!b)return null;var p=a===0?100:(b-a)/a*100;return p;}
function trendHTML(p,invert){if(p===null||isNaN(p))return'<span class="dim">—</span>';var up=p>=0;var good=invert?!up:up;return '<span class="trend '+(good?'up':'down')+'">'+(up?'↗':'↘')+' '+Math.abs(p).toFixed(2)+'%</span>';}
function areaChart(el,data,labels,color){color=color||'#a78bfa';if(!data.length){el.innerHTML='<div class="empty">No data</div>';return;}
 var W=el.clientWidth||600,H=el.clientHeight||200,pad={l:8,r:44,t:14,b:22},cw=W-pad.l-pad.r,ch=H-pad.t-pad.b;
 var max=Math.max.apply(null,[1].concat(data));var s='<svg viewBox="0 0 '+W+' '+H+'">';
 var pt=function(v,i){return[pad.l+(i/Math.max(1,data.length-1))*cw,pad.t+ch-(v/max)*ch];};
 var line='';data.forEach(function(v,i){var xy=pt(v,i);line+=(i?'L':'M')+xy[0]+','+xy[1];});
 s+='<path d="'+line+' L'+(pad.l+cw)+','+(pad.t+ch)+' L'+pad.l+','+(pad.t+ch)+' Z" fill="'+color+'" opacity=".14"/>';
 s+='<path d="'+line+'" fill="none" stroke="'+color+'" stroke-width="1.6"/>';
 (labels||[]).forEach(function(l,i){if(i%Math.ceil((labels.length||1)/6))return;var x=pad.l+(i/Math.max(1,labels.length-1))*cw;s+='<text x="'+x+'" y="'+(H-6)+'" fill="#5d6375" font-size="9.5" text-anchor="middle">'+esc(l)+'</text>';});
 s+='<text x="'+(W-4)+'" y="'+(pad.t+8)+'" fill="#9298ab" font-size="9.5" text-anchor="end">'+fmtK(max)+'</text></svg>';el.innerHTML=s;}
function hbarsLegend(el,items,valKey,fmtFn){if(!items.length){el.innerHTML='<div class="empty">No model data yet</div>';return;}
 var max=Math.max.apply(null,items.map(function(i){return Number(i[valKey])||0;}).concat([1e-9]));
 var s='<div style="display:flex;gap:14px;height:100%"><div style="flex:1;display:flex;flex-direction:column;justify-content:space-around">';
 items.forEach(function(m,i){s+='<div style="display:flex;align-items:center;gap:8px"><span style="width:170px;text-align:right;font-size:10.5px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">'+esc(m.name)+'</span><div style="flex:1;height:10px;background:#101320;border-radius:2px"><div style="width:'+(Number(m[valKey])/max*100).toFixed(1)+'%;height:100%;background:'+P[i%P.length]+';border-radius:2px"></div></div></div>';});
 s+='<div style="display:flex;justify-content:space-between;color:var(--dim);font-size:9.5px;margin-left:178px"><span>0</span><span>'+fmtFn(max/2)+'</span><span>'+fmtFn(max)+'</span></div></div>';
 s+='<div style="width:190px;overflow:auto;display:flex;flex-direction:column;gap:5px;font-size:10.5px;color:var(--muted)">';
 items.forEach(function(m,i){s+='<span style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis"><i style="display:inline-block;width:8px;height:8px;border-radius:50%;background:'+P[i%P.length]+';margin-right:6px"></i>'+esc(m.name)+'</span>';});
 s+='</div></div>';
 el.innerHTML=s;}
function stackedTime(el,days,map){if(!days.length){el.innerHTML='<div class="empty">No guardrail data yet</div>';return;}
 var W=el.clientWidth||600,H=el.clientHeight||250,pad={l:30,r:8,t:10,b:20},cw=W-pad.l-pad.r,ch=H-pad.t-pad.b;
 var totals=days.map(function(d){return CHECKS.reduce(function(a,arr){return a+(map[d+'|'+arr[0]]||0);},0);});
 var max=Math.max.apply(null,[1].concat(totals));var bw=Math.max(2,cw/days.length-2);var s='<svg viewBox="0 0 '+W+' '+H+'">';
 [0,.5,1].forEach(function(t){var y=pad.t+ch-t*ch;s+='<line x1="'+pad.l+'" y1="'+y+'" x2="'+(W-pad.r)+'" y2="'+y+'" stroke="#20243a" stroke-width=".5"/><text x="'+(pad.l-5)+'" y="'+(y+3)+'" fill="#5d6375" font-size="9" text-anchor="end">'+Math.round(max*t)+'</text>';});
 days.forEach(function(d,i){var y=pad.t+ch;CHECKS.forEach(function(arr){var n=arr[0],c=arr[1];var v=map[d+'|'+n]||0;if(!v)return;var h=(v/max)*ch;y-=h;s+='<rect x="'+(pad.l+i*(cw/days.length))+'" y="'+y+'" width="'+bw+'" height="'+h+'" fill="'+c+'"/>';});});
 days.forEach(function(d,i){if(i%Math.ceil(days.length/6))return;s+='<text x="'+(pad.l+i*(cw/days.length))+'" y="'+(H-5)+'" fill="#5d6375" font-size="9">'+esc(d.slice(5))+'</text>';});
 el.innerHTML=s+'</svg>';}
function multiLine(el,days,series){if(!series.length){el.innerHTML='<div class="empty">No data</div>';return;}
 var W=el.clientWidth||600,H=el.clientHeight||300,pad={l:36,r:8,t:10,b:20},cw=W-pad.l-pad.r,ch=H-pad.t-pad.b;
 var allVals=[];series.forEach(function(sr){allVals=allVals.concat(sr.values);});var max=Math.max.apply(null,[1].concat(allVals));var s='<svg viewBox="0 0 '+W+' '+H+'">';
 [0,.25,.5,.75,1].forEach(function(t){var y=pad.t+ch-t*ch;s+='<line x1="'+pad.l+'" y1="'+y+'" x2="'+(W-pad.r)+'" y2="'+y+'" stroke="#20243a" stroke-width=".5"/><text x="'+(pad.l-5)+'" y="'+(y+3)+'" fill="#5d6375" font-size="9" text-anchor="end">'+fmtK(max*t)+'</text>';});
 series.forEach(function(sr){var p='';sr.values.forEach(function(v,i){var x=pad.l+(i/Math.max(1,sr.values.length-1))*cw,y=pad.t+ch-(v/max)*ch;p+=(i?'L':'M')+x+','+y;});s+='<path d="'+p+'" fill="none" stroke="'+sr.color+'" stroke-width="1.2"/>';});
 days.forEach(function(d,i){if(i%Math.ceil(days.length/5))return;var x=pad.l+(i/Math.max(1,days.length-1))*cw;s+='<text x="'+x+'" y="'+(H-5)+'" fill="#5d6375" font-size="9" text-anchor="middle">'+esc(d.slice(5))+'</text>';});
 el.innerHTML=s+'</svg><div class="legend">';
 series.forEach(function(sr){s+='<span><i style="background:'+sr.color+'"></i>'+esc(sr.name)+'</span>';});
 el.innerHTML=s+'</div>';}
function donut(el,okPct,okN,failN){var r1=75+56*Math.sin(Math.max(.02,(1-okPct/100)*6.283));var r2=75-56*Math.cos(Math.max(.02,(1-okPct/100)*6.283));el.innerHTML='<div style="display:flex;align-items:center;gap:18px;height:100%;justify-content:center"><svg width="150" height="150" viewBox="0 0 150 150"><circle cx="75" cy="75" r="56" fill="#2b8a5e" opacity=".9"/><path d="M75 19 A56 56 0 0 1 '+r1+' '+r2+'" stroke="var(--red2)" stroke-width="3" fill="none"/><circle cx="75" cy="75" r="34" fill="var(--card)"/><text x="75" y="72" text-anchor="middle" fill="var(--dim)" font-size="9">'+(100-okPct).toFixed(0)+'%</text><text x="75" y="86" text-anchor="middle" fill="var(--dim)" font-size="9">'+okPct.toFixed(0)+'%</text></svg><div style="font-size:11px;color:var(--muted);display:flex;flex-direction:column;gap:6px"><span><i style="display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--red2);margin-right:6px"></i>Failed Requests</span><span><i style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#2b8a5e;margin-right:6px"></i>Successful Requests</span></div></div>';}
function forecastBand(el,hist){if(!hist||hist.length<2){el.innerHTML='<div class="empty">Not enough history</div>';return;}
 var W=el.clientWidth||500,H=el.clientHeight||170,pad={l:26,r:6,t:10,b:16},cw=W-pad.l-pad.r,ch=H-pad.t-pad.b;
 var delta=(hist[hist.length-1]-hist[0])/(hist.length-1);
 var fc=[];for(var i=0;i<6;i++){fc.push(Math.max(0,hist[hist.length-1]+delta*(i+1)));}
 var histMax=Math.max.apply(null,[1].concat(hist));
 var band=fc.map(function(v){return Math.max(v*.25,histMax*.06);});
 var fcWithBand=fc.map(function(v,i){return v+band[i];});
 var max=Math.max.apply(null,hist.concat(fcWithBand))*1.1;
 var X=function(i){return pad.l+(i/(hist.length-1))*cw*.62;};
 var XF=function(i){return pad.l+cw*.62+(i/6)*cw*.38;};
 var s='<svg viewBox="0 0 '+W+' '+H+'">';
 var p='';hist.forEach(function(v,i){var y=pad.t+ch-(v/max)*ch;p+=(i?'L':'M')+X(i)+','+y;});s+='<path d="'+p+'" fill="none" stroke="#e6e8f2" stroke-width="1"/>';
 var ly=pad.t+ch-(hist[hist.length-1]/max)*ch,lx=X(hist.length-1);
 var up='',lo='';fc.forEach(function(v,i){up+='L'+XF(i+1)+','+(pad.t+ch-((v+band[i])/max)*ch)+' ';});
 for(var j=fc.length-1;j>=0;j--){lo+='L'+XF(j+1)+','+(pad.t+ch-(Math.max(0,fc[j]-band[j])/max)*ch)+' ';}
 s+='<path d="M'+lx+','+ly+' '+up+lo+' Z" fill="#4c8dff" opacity=".25"/>';
 var fl='M'+lx+','+ly;fc.forEach(function(v,i){fl+=' L'+XF(i+1)+','+(pad.t+ch-(v/max)*ch);});s+='<path d="'+fl+'" fill="none" stroke="#7aa7ff" stroke-width="1"/></svg>';
 el.innerHTML=s;}
function spark(el,data,color){color=color||'#4c8dff';if(!data||data.length<2){el.innerHTML='';return;}var W=el.clientWidth||180,H=40,max=Math.max.apply(null,[1].concat(data));var p='';data.forEach(function(v,i){p+=(i?'L':'M')+(i/(data.length-1))*W+','+(H-4-(v/max)*(H-8));});el.innerHTML='<svg viewBox="0 0 '+W+' '+H+'" style="width:100%;height:40px"><path d="'+p+'" fill="none" stroke="'+color+'" stroke-width="1"/></svg>';}
function showView(n){document.querySelectorAll('.view').forEach(function(v){v.classList.remove('active');});$('view-'+n).classList.add('active');document.querySelectorAll('#topTabs button').forEach(function(b){b.classList.toggle('active',b.dataset.view===n);});$('fside').style.display=(n==='health')?'':'none';
 if(n==='health')renderHealth();if(n==='overview')renderOverview();if(n==='tracing')renderTracing();if(n==='audit')renderAudit();}
document.querySelectorAll('#topTabs button').forEach(function(b){b.addEventListener('click',function(){if(b.dataset.view)showView(b.dataset.view);});});
document.querySelectorAll('#latTabs button').forEach(function(b){b.addEventListener('click',function(){document.querySelectorAll('#latTabs button').forEach(function(x){x.classList.remove('active');});b.classList.add('active');state.latStat=b.dataset.s;renderLatency();});});
function buildSidebar(){
  var models=(state.models||[]).map(function(m){return m.name;});
  if(!state.modelFilter.size)models.forEach(function(m){state.modelFilter.add(m);});
  function makeItem(checked,onchange,name){
    return '<label class="fitem"><input type="checkbox" '+(checked?'checked':'')+' onchange="'+onchange+'(this,\''+esc(name)+'\')">'+esc(name)+'</label>';
  }
  function makeGroup(title,items,checked,cb){
    var content=items.length?items.map(function(i){return makeItem(checked.has(i),cb,i);}).join(''):'<div class="dim" style="padding:4px 6px;font-size:11px">—</div>';
    return '<div class="fgroup"><div onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display===\'none\'?\'\':\'none\'">▾ '+esc(title)+'</div><div class="fitems">'+content+'</div></div>';
  }
  var noop='noop';
  window.noop=function(){};
  window.toggleModel=function(el,name){
    if(el.checked){state.modelFilter.add(name);}else{state.modelFilter.delete(name);}
    renderHealth();
  };
  var modelItems=models.length?models.map(function(m){return makeItem(state.modelFilter.has(m),'toggleModel',m);}).join(''):'<div class="dim" style="padding:4px 6px;font-size:11px">no models yet</div>';
  $('fside').innerHTML=makeGroup('Provider',['agentguard'],new Set(['agentguard']),noop)+'<div class="fgroup"><div>▾ Model</div><div class="fitems">'+modelItems+'</div></div>'+makeGroup('Service',['agentguard-collector'],new Set(['agentguard-collector']),noop)+makeGroup('Agent',['sdk-agent'],new Set(),noop);
}
function filteredModels(){return(state.models||[]).filter(function(m){return state.modelFilter.has(m.name);});}
function renderHealth(){buildSidebar();renderLatency();
 var m=state.metrics||{};
 $('tokHero').textContent=fmtK(m.total_tokens||0);
 var avg=(m.total_cost_usd||0)/Math.max(1,m.total_spans||0);
 $('avgCostHero').innerHTML=(avg*1e6).toFixed(1)+'<span class="unit">µ$</span>';
 areaChart($('avgCostChart'),(state.costTrend||[]).map(function(d){return d.cost;}),null);
 forecastBand($('tokForecast'),(state.costTrend||[]).map(function(d){return d.tokens||0;}));
 $('grHero').textContent=fmtK(m.total_spans||0);
 var daySet={};(state.checksDaily||[]).forEach(function(c){daySet[c.day]=1;});var days=Object.keys(daySet).sort();
 var map={};(state.checksDaily||[]).forEach(function(c){map[c.day+'|'+c.name]=c.flagged;});
 stackedTime($('grStacked'),days,map);
 var legendHTML='';CHECKS.forEach(function(arr){legendHTML+='<span><i style="background:'+arr[1]+'"></i>'+arr[0]+'</span>';});
 $('grLegend').innerHTML=legendHTML;
 hbarsLegend($('tokModel'),filteredModels().slice().sort(function(a,b){return(b.input_tokens+b.output_tokens)-(a.input_tokens+a.output_tokens);}),'output_tokens',function(v){return fmtK(v);});
}
function renderLatency(){var m=state.metrics||{},lat=state.latencyDist||{};
 var val=state.latStat==='avg'?m.avg_latency_ms:lat[state.latStat];
 $('ttrHero').innerHTML=val?(Number(val)/1000).toFixed(2)+'<span class="unit">s</span>':'—';
 areaChart($('ttrChart'),(state.dailyTrend||[]).map(function(d){return d.total;}),(state.dailyTrend||[]).map(function(d){return(d.day||'').slice(5);}));
 hbarsLegend($('rtModel'),filteredModels().slice().sort(function(a,b){return b.avg_latency_ms-a.avg_latency_ms;}),'avg_latency_ms',function(v){return Number(v).toFixed(0)+'ms';});}
function renderOverview(){var m=state.metrics||{},r=m.risk_distribution||{};
 $('ovProblems').textContent=Number(r.high||0)+Number(r.critical||0);
 $('ovRequests').textContent=fmtK(m.total_spans||0);
 $('ovRequestsT').innerHTML=trendHTML(trendPct((state.dailyTrend||[]).map(function(d){return d.total;})));
 $('ovCost').textContent='$'+(m.total_cost_usd||0).toFixed(2);
 $('ovCostT').innerHTML=trendHTML(trendPct((state.costTrend||[]).map(function(d){return d.cost;})),true);
 var total=Math.max(1,m.total_spans||0),blk=m.blocked_operations||0;
 donut($('ovDonut'),(total-blk)/total*100,total-blk,blk);
 $('ovAvg').innerHTML=(Number(m.avg_latency_ms||0)/1000).toFixed(2)+'<span class="unit">s</span>';
 $('ovAvgT').innerHTML=trendHTML(trendPct((state.dailyTrend||[]).map(function(d){return d.total;})),true);
 var p99=(state.latencyDist||{}).p99;
 $('ovP99').innerHTML=p99?((p99)/1000).toFixed(2)+'<span class="unit">s</span>':'—';
 var p95=(state.latencyDist||{}).p95||1;
 $('ovP99T').innerHTML='<span class="trend down">↗ '+(((p99||0)/Math.max(1,p95)*8).toFixed(2))+'%</span>';
 forecastBand($('ovForecast'),(state.costTrend||[]).map(function(d){return d.cost;}));
 var cb=state.checksBreakdown||[];var get=function(n){return cb.find(function(c){return c.check_name===n;});};
 var inj=get('prompt_injection'),pii=get('pii_detection'),tool=get('tool_policy')||get('dangerous_params'),bud=get('budget_policy');
 function bigCard(t,v){return '<div class="card"><div class="hero mid" style="font-size:34px">'+esc(v)+'</div><div class="clabel" style="text-align:center;margin-top:4px">'+esc(t)+'</div></div>';}
 $('gqBig').innerHTML=bigCard('Guardrail Executions','100%')+bigCard('Prompt Injection',inj?inj.flag_rate+'%':'0%')+bigCard('PII Leaks',pii?pii.flag_rate+'%':'0%')+bigCard('Tool Policy',tool?tool.flag_rate+'%':'0%')+'<div class="card"><div class="clabel" style="text-align:center">ML Confidence</div><div class="hero sm" style="text-align:center">'+(((m.avg_ml_score||0)*100).toFixed(2))+'</div><div id="spkML"></div></div>';
 function smCard(t,v,id){return '<div class="card"><div class="clabel" style="font-size:10.5px">'+esc(t)+'</div><div class="hero sm">'+esc(v)+'</div><div id="'+id+'"></div></div>';}
 $('gqSmall').innerHTML=smCard('Overall Guardrail Activation',fmt(cb.reduce(function(a,c){return a+c.flagged;},0)),'s1')+smCard('Blocked Prompts',fmt(m.blocked_operations||0),'s2')+smCard('Prevented PII Leaks',fmt(pii?pii.flagged:0),'s3')+smCard('Budget Blocks',fmt(bud?bud.flagged:0),'s4')+'<div class="card"><div class="clabel" style="font-size:10.5px">Judge Confidence</div><div class="hero sm">'+(((m.avg_llm_score||0)*100).toFixed(2))+'</div><div id="s5"></div></div>';
 spark($('s1'),(state.checksDaily||[]).filter(function(c){return c.name==='prompt_injection';}).map(function(c){return c.flagged;}));
 spark($('s2'),(state.dailyTrend||[]).map(function(d){return d.blocked;}));
 spark($('s3'),(state.checksDaily||[]).filter(function(c){return c.name==='pii_detection';}).map(function(c){return c.flagged;}));
 spark($('s4'),(state.checksDaily||[]).filter(function(c){return c.name==='budget_policy';}).map(function(c){return c.flagged;}));
 spark($('s5'),(state.dailyTrend||[]).map(function(d){return d.total;}));
 var expRows='';(state.expensive||[]).forEach(function(e){expRows+='<tr><td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+esc(e.prompt||'')+'">'+esc(e.prompt||'—')+'</td><td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+esc(e.response||'—')+'</td><td class="mono">'+esc(e.trace_id)+'</td><td class="mono">'+fmt((e.input_tokens||0)+(e.output_tokens||0))+'</td><td class="mono">'+money(e.cost_usd)+'</td></tr>';});
 $('expTable').innerHTML=expRows||'<tr><td colspan="5" class="empty">No spans yet</td></tr>';}
function renderTracing(){var traces=state.traces||[];
 if(!state.selTrace&&traces.length)state.selTrace=traces[0].trace_id;
 var opts='';traces.forEach(function(t){opts+='<option value="'+esc(t.trace_id)+'" '+(t.trace_id===state.selTrace?'selected':'')+'>'+esc(t.trace_id)+'</option>';});
 $('traceSelect').innerHTML=opts||'<option>—</option>';
 $('traceSelect').onchange=function(e){state.selTrace=e.target.value;loadTrace();};
 loadTrace();}
function loadTrace(){var id=state.selTrace;if(!id){$('spanTree').innerHTML='<div class="empty">No traces</div>';return Promise.resolve();}
 return api('/api/traces/'+encodeURIComponent(id)).then(function(rows){
 state.spans=rows;
 var dur=rows.reduce(function(a,r){return a+Number(r.latency_ms||0);},0);
 $('trDur').textContent=(dur/1000).toFixed(2)+' s';
 $('trErr').textContent=rows.filter(function(r){return r.blocked;}).length;
 $('trId').textContent=id||'—';
 $('trDate').textContent=rows[0]?('at '+String(rows[0].created_at).slice(0,19)):'';
 $('spanCount').textContent=rows.length+' spans';
 var maxT=Math.max.apply(null,[1].concat(rows.map(function(r){return Number(r.latency_ms||0);})));
 $('ax0').textContent='0 ms';$('ax1').textContent=(maxT/2).toFixed(0)+' ms';$('ax2').textContent=maxT.toFixed(0)+' ms';
 var q=($('spanSearch').value||'').toLowerCase();
 var treeHTML='';rows.forEach(function(r,i){var w=Math.max(2,(Number(r.latency_ms||0)/maxT)*96);var hide=q&&!(r.span_type+' '+(r.model||'')).toLowerCase().indexOf(q)===-1;
  var dotClass=r.span_type==='tool_call'?'client':'';var clientLabel=r.span_type==='llm_call'?'client':'internal';
  var modelPart=r.model?'.'+esc(r.model.split('-')[0]):'';var warnPart=r.blocked?'<span class="warn">⚠</span>':'';
  treeHTML+='<div class="span-row '+(i===state.selSpan?'sel':'')+'" style="'+(hide?'display:none':'')+'" onclick="selectSpan('+i+')"><span class="tw"><span style="color:var(--dim)">—</span><span class="dot '+dotClass+'"></span><span style="color:var(--dim);font-size:10.5px">'+clientLabel+'</span>'+esc(r.span_type)+modelPart+' '+warnPart+'</span><span class="track"><span class="bar '+(r.blocked?'blocked':'')+'" style="left:2%;width:'+w+'%"></span></span></div>';});
 $('spanTree').innerHTML=treeHTML||'<div class="empty">No spans</div>';
 $('excN').textContent=rows.filter(function(r){return r.blocked;}).length;
 var excHTML='';rows.filter(function(r){return r.blocked;}).forEach(function(r,i){
  var checksFailed=(r.security_checks||[]).filter(function(c){return !c.passed;}).map(function(c){return '  🚨 '+c.check_name+' — '+c.details;}).join('\n');
  excHTML+='<tr class="exc-row" onclick="this.nextElementSibling.hidden=!this.nextElementSibling.hidden"><td>▾</td><td class="mono">agentguard.SecurityException</td><td>'+esc(r.block_reason||'blocked')+'</td></tr><tr hidden><td></td><td colspan="2"><div class="pilltag">Span events: exception id: '+esc(r.span_id)+'</div><div class="codeblock"><b>Exception root cause:</b> '+esc(r.block_reason||'')+'\n\nTraceback (most recent call last):\n  File "agentguard_sdk.py", in guard_'+esc(r.span_type)+'\n    raise SecurityException(...)\n'+checksFailed+'</div></td></tr>';});
 $('excTable').innerHTML=excHTML||'<tr><td colspan="3" class="empty">No exceptions 🎉</td></tr>';
 selectSpan(state.selSpan||0);}).catch(function(){$('spanTree').innerHTML='<div class="empty">Error loading trace</div>';});}
window.selectSpan=function(i){state.selSpan=i;var r=(state.spans||[])[i];if(!r)return;
 document.querySelectorAll('.span-row').forEach(function(el,j){el.classList.toggle('sel',j===i);});
 function kv(k,v,cls){cls=cls||'';return '<div class="attr-row"><span class="k">'+esc(k)+'</span><span class="v '+cls+'">'+esc(v)+'</span></div>';}
 var prompt=((r.input_data||{}).prompt||(r.input_data||{}).tool)||'';
 var response=((r.output_data||{}).response||'').slice(0,400);
 var mlScore=r.ml_score!=null?(r.ml_score*100).toFixed(1)+'%':'—';
 var llmScore=r.llm_score!=null?(r.llm_score*100).toFixed(1)+'%':'—';
 var decision=r.blocked?'BLOCK':'ALLOW';
 var decisionClass=r.blocked?'pink':'';
 $('spanDetail').innerHTML='<div class="card" style="margin-bottom:10px"><div style="display:flex;gap:10px;align-items:center"><span style="width:30px;height:30px;border-radius:6px;background:#3776ab;color:#fff;display:grid;place-items:center;font-weight:700">🐍</span><div><b>'+esc(r.span_type)+'</b><div class="dim" style="font-size:11px">Service: <a href="#">agentguard-collector</a></div></div></div><div style="margin:10px 0;color:var(--muted);font-size:12px">⏱ Duration: '+Number(r.latency_ms||0).toFixed(2)+' ms</div></div><div class="attr-sec"><h4>gen ai <span>▾</span></h4>'+kv('Gen ai agent name','agentguard-sdk')+kv('Gen ai request model',r.model||'unknown')+kv('Gen ai prompt 0 role','user')+kv('Gen ai prompt 0 content',prompt)+kv('Gen ai completion 0 role','assistant')+kv('Gen ai completion 0 content',response)+kv('Gen ai usage input tokens',r.input_tokens||0,'pink')+kv('Gen ai usage output tokens',r.output_tokens||0,'pink')+'</div><div class="attr-sec"><h4>agentguard <span>▾</span></h4>'+kv('Agentguard detection layer',r.detection_layer||'regex')+kv('Agentguard ml score',mlScore,'blue')+kv('Agentguard llm score',llmScore,'blue')+kv('Agentguard decision',decision,decisionClass)+kv('Agentguard cost usd',Number(r.cost_usd||0).toFixed(6),'pink')+'</div>';};
function renderAudit(){var d=new Date();var from=new Date(d-14*864e5);
 $('auRange').textContent=from.toDateString().slice(4)+' - '+d.toDateString().slice(4);
 var modelsHTML='';(state.models||[]).slice().sort(function(a,b){return b.requests-a.requests;}).forEach(function(m){modelsHTML+='<tr><td>'+esc(m.name)+'</td><td style="text-align:right" class="mono">'+fmt(m.requests)+'</td></tr>';});
 $('auModels').innerHTML=modelsHTML||'<tr><td colspan="2" class="empty">No models</td></tr>';
 var daySet={};(state.modelsDaily||[]).forEach(function(x){daySet[x.day]=1;});var days=Object.keys(daySet).sort();
 var nameSet={};(state.modelsDaily||[]).forEach(function(x){nameSet[x.model]=1;});var names=Object.keys(nameSet).slice(0,10);
 var series=names.map(function(n,i){return{name:n,color:P[i%P.length],values:days.map(function(dy){var f=(state.modelsDaily||[]).find(function(x){return x.day===dy&&x.model===n;});return f?f.n:0;});};})
 multiLine($('auTrend'),days,series);
 var trailHTML='';(state.audit||[]).forEach(function(r){trailHTML+='<tr><td class="dim">'+esc(String(r.timestamp).replace(' ',' , ').slice(0,20))+'</td><td class="mono">'+esc(r.trace_id)+esc((r.span_id||'').slice(0,4))+'</td><td>agentguard</td><td class="mono">agentguard.security</td><td>'+esc(r.model)+'</td><td style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+esc(r.prompt)+'">'+esc(r.prompt||'—')+'</td><td>'+esc(r.span_type)+'</td><td>'+esc(r.layer)+'</td><td class="mono">'+(r.blocked?'PromptType.BLOCKED':'PromptType.INPUT')+'</td></tr>';});
 $('auTrail').innerHTML=trailHTML||'<tr><td colspan="9" class="empty">No audit events</td></tr>';}
function refreshAll(){Promise.all([
 api('/api/metrics'),api('/api/traces'),api('/api/detection/stats'),api('/api/models'),api('/api/checks/breakdown'),api('/api/heatmap'),api('/api/spans/expensive'),api('/api/cost/trend'),api('/api/latency/distribution'),api('/api/events/recent'),api('/api/trend/daily'),api('/api/audit/trail'),api('/api/checks/daily'),api('/api/models/daily')]).then(function(results){
 var m=results[0],t=results[1],d=results[2],models=results[3],checks=results[4],heatmap=results[5],expensive=results[6],costTrend=results[7],latencyDist=results[8],recentEvents=results[9],dailyTrend=results[10],audit=results[11],checksDaily=results[12],modelsDaily=results[13];
 state.metrics=m;state.traces=t;state.detection=d;state.models=models;state.checksBreakdown=checks;state.heatmap=heatmap;state.expensive=expensive;state.costTrend=costTrend;state.latencyDist=latencyDist;state.recentEvents=recentEvents;state.dailyTrend=dailyTrend;state.audit=audit;state.checksDaily=checksDaily;state.modelsDaily=modelsDaily;
 var active=document.querySelector('.view.active').id.replace('view-','');
 showView(active);toast('Dashboard refreshed');}).catch(function(e){toast('Collector unavailable: '+e.message);});}
refreshAll();setInterval(refreshAll,20000);
</script>
</body>
</html>
'''

@app.route("/")
def dashboard():
    return make_response(render_template_string(DASHBOARD_HTML))

@app.route("/trace/<trace_id>")
def trace_detail(trace_id):
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
