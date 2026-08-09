"""
AgentGuard Collector v4 — PostgreSQL production + SQLite local fallback
Support de la détection multi-couches (ML + LLM Judge)
Stats avancées et badges de détection dans le dashboard
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
from flask import Flask, request, jsonify, render_template_string, make_response, g
from flask_cors import CORS, cross_origin
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.secret_key = os.environ.get("AGENTGUARD_FLASK_SECRET", secrets.token_urlsafe(32))

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["120 per minute"],
    storage_uri=os.environ.get("AGENTGUARD_LIMITER_STORAGE", "memory://"),
)

# ── CONFIG ──
DB_TYPE = os.environ.get("AGENTGUARD_DB_TYPE", "sqlite")
DATABASE_URL = os.environ.get("DATABASE_URL", "")
API_KEY = os.environ.get("AGENTGUARD_API_KEY", None)
ADMIN_SECRET = os.environ.get("AGENTGUARD_ADMIN_SECRET")
AUTH_COOKIE = "ag_auth"

# Génère une clé si aucune n'est définie
_API_KEY_WAS_GENERATED = API_KEY is None
if not API_KEY:
    API_KEY = "ag-" + secrets.token_urlsafe(32)
    print("[AG] ⚠️ Aucune AGENTGUARD_API_KEY fournie — clé générée en mémoire")

# ── PII REDACTION ──
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

# ── DATABASE SETUP ──
import sqlite3

DB_SQLITE_PATH = os.environ.get("AGENTGUARD_DB_PATH", "/tmp/agentguard.db")
_sqlite_dir = os.path.dirname(DB_SQLITE_PATH)
if _sqlite_dir and not os.path.isdir(_sqlite_dir):
    os.makedirs(_sqlite_dir, exist_ok=True)

def get_pg_conn():
    """Connexion PostgreSQL (production Render)."""
    if psycopg2 is None:
        raise RuntimeError(
            "psycopg2 n'est pas installé — requis pour AGENTGUARD_DB_TYPE=postgres. "
            "pip install psycopg2-binary"
        )
    conn = psycopg2.connect(DATABASE_URL, sslmode="require")
    return conn

def get_sqlite_conn():
    """Connexion SQLite (local dev)."""
    conn = sqlite3.connect(DB_SQLITE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def get_db():
    """Retourne la bonne connexion selon l'environnement."""
    if DB_TYPE == "postgres" and DATABASE_URL:
        return get_pg_conn()
    return get_sqlite_conn()

def init_db():
    """Initialise les tables avec support des nouvelles métriques."""
    if DB_TYPE == "postgres" and DATABASE_URL:
        conn = get_pg_conn()
        cur = conn.cursor()
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
        # Migration douce pour une DB existante créée avant le multi-tenant
        try:
            cur.execute("ALTER TABLE spans ADD COLUMN IF NOT EXISTS org_id TEXT DEFAULT 'default'")
            cur.execute("ALTER TABLE spans ADD COLUMN IF NOT EXISTS model TEXT")
        except Exception:
            pass
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
        conn.close()
        print("[AG] ✅ PostgreSQL initialisé v4.1")
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
        # Migration douce pour une DB SQLite existante (ADD COLUMN plante si
        # la colonne existe déjà — on l'ignore proprement dans ce cas).
        try:
            c.execute("ALTER TABLE spans ADD COLUMN org_id TEXT DEFAULT 'default'")
        except sqlite3.OperationalError:
            pass
        try:
            c.execute("ALTER TABLE spans ADD COLUMN model TEXT")
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
        print("[AG] ✅ SQLite initialisé v4.1")

def dict_from_row(row, is_pg=False):
    """Normalise une row en dict."""
    if is_pg:
        return dict(row)
    return dict(row)

# ── AUTH ──
PROTECTED_ENDPOINTS = {
    "receive_span", "list_traces", "get_trace", "get_metrics",
    "dashboard", "trace_detail", "get_detection_stats",
    "api_models", "api_heatmap", "api_checks_breakdown",
    "api_expensive_spans", "api_cost_trend", "api_latency_distribution",
    "api_recent_events", "api_trend_daily",
}

def safe_compare(a: str, b: str) -> bool:
    """secrets.compare_digest plante (TypeError) si l'une des deux strings
    contient du non-ASCII — n'importe quelle clé farfelue envoyée par un
    client ferait planter l'auth en 500 au lieu d'un 401 propre. On encode
    en UTF-8 d'abord : compare_digest sur bytes ne pose aucun problème."""
    if a is None or b is None:
        return False
    try:
        return secrets.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
    except Exception:
        return False

def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()

def _lookup_org_by_key(key: str):
    """Cherche la clé dans la table api_keys (clients hébergés payants).
    Retourne l'org_id si trouvée et active, sinon None."""
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
    """Retourne l'org_id associé à une clé valide, ou None si invalide.
    La clé maître (AGENTGUARD_API_KEY, self-host) reste toujours valide et
    mappée à l'org 'default' — rétrocompatible avec le mode single-tenant.
    Les clés clients (hébergement payant) sont vérifiées par hash en base."""
    if not key:
        return None
    if API_KEY and safe_compare(key, API_KEY):
        return "default"
    return _lookup_org_by_key(key)

def require_auth():
    if not API_KEY:
        g.org_id = "default"
        return True
    key = request.headers.get("X-API-Key", "")
    org_id = resolve_org_id(key) if key else None
    if not org_id:
        key = request.args.get("api_key") or request.args.get("key") or ""
        org_id = resolve_org_id(key) if key else None
    if not org_id:
        org_id = resolve_org_id(request.cookies.get(AUTH_COOKIE, ""))
    if org_id:
        g.org_id = org_id
        return True
    return False

def set_auth_cookie_if_valid(resp):
    key = request.args.get("api_key") or request.args.get("key")
    if key and resolve_org_id(key):
        resp.set_cookie(AUTH_COOKIE, key, httponly=True, samesite="Lax",
                         secure=True, max_age=60 * 60 * 24 * 30)
    return resp

@app.before_request
def check_auth():
    if request.method == "OPTIONS":
        return None
    if request.endpoint not in PROTECTED_ENDPOINTS:
        return None
    if not require_auth():
        if request.endpoint in ("dashboard", "trace_detail"):
            return (
                "<h3>🛡️ AgentGuard — accès protégé</h3>"
                "<p>Ajoute ta clé à l'URL : <code>?key=TA_CLE</code></p>",
                401,
            )
        return jsonify({"error": "Unauthorized — X-API-Key header or ?key= required"}), 401

# ── API ──
@app.route("/span", methods=["POST"])
@limiter.limit("30 per minute")
@cross_origin(origins="*", allow_headers=["Content-Type", "X-API-Key"])
def receive_span():
    data = request.json
    if not isinstance(data, dict):
        return jsonify({"error": "Body must be a JSON object"}), 400

    required_fields = ["trace_id", "span_id", "span_type", "timestamp", "latency_ms"]
    missing = [f for f in required_fields if f not in data]
    if missing:
        return jsonify({"error": f"Missing required field(s): {missing}"}), 400

    data.setdefault("input_data", {})
    data.setdefault("output_data", {})
    data.setdefault("security_checks", [])
    data.setdefault("blocked", False)
    data.setdefault("cost_usd", 0.0)

    data["input_data"] = redact_pii(data.get("input_data", {}))
    data["output_data"] = redact_pii(data.get("output_data", {}))
    
    is_pg = DB_TYPE == "postgres" and DATABASE_URL

    # Extraire les métadonnées de détection
    detection_layer = None
    ml_score = None
    llm_score = None
    llm_reason = None
    
    if "metadata" in data:
        detection_layer = data.get("metadata", {}).get("detection_layer") or data.get("metadata", {}).get("layer")
        ml_score = data.get("metadata", {}).get("ml_score")
        llm_score = data.get("metadata", {}).get("llm_score")
        llm_reason = data.get("metadata", {}).get("llm_reason")
    
    # Si la détection est dans les security_checks, on l'extrait aussi
    if not detection_layer and data.get("security_checks"):
        for check in data["security_checks"]:
            if check.get("check_name") in ["prompt_injection", "llm_judge"]:
                detection_layer = check.get("metadata", {}).get("layer")
                ml_score = check.get("metadata", {}).get("ml_score")
                llm_score = check.get("metadata", {}).get("llm_score")
                llm_reason = check.get("details")
                break

    # Le modèle appelé (capturé par le SDK depuis kwargs["model"]) — sert au
    # vrai breakdown par modèle du dashboard, pas de valeur inventée.
    model = data.get("input_data", {}).get("model") if isinstance(data.get("input_data"), dict) else None

    if is_pg:
        conn = get_pg_conn()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO spans (
                trace_id, span_id, span_type, timestamp, latency_ms,
                input_data, output_data, security_checks, blocked,
                block_reason, cost_usd, detection_layer, ml_score, llm_score, llm_reason, org_id, model
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            data["trace_id"], data["span_id"], data["span_type"],
            data["timestamp"], data["latency_ms"],
            json.dumps(data["input_data"]),
            json.dumps(data["output_data"]),
            json.dumps(data["security_checks"]),
            data["blocked"], data.get("block_reason"), data["cost_usd"],
            detection_layer, ml_score, llm_score, llm_reason, g.org_id, model
        ))
    else:
        conn = sqlite3.connect(DB_SQLITE_PATH)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO spans (
                trace_id, span_id, span_type, timestamp, latency_ms,
                input_data, output_data, security_checks, blocked,
                block_reason, cost_usd, detection_layer, ml_score, llm_score, llm_reason, org_id, model
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data["trace_id"], data["span_id"], data["span_type"],
            data["timestamp"], data["latency_ms"],
            json.dumps(data["input_data"]),
            json.dumps(data["output_data"]),
            json.dumps(data["security_checks"]),
            1 if data["blocked"] else 0,
            data.get("block_reason"), data["cost_usd"],
            detection_layer, ml_score, llm_score, llm_reason, g.org_id, model
        ))

    conn.commit()
    conn.close()
    return jsonify({"status": "ok"}), 201

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
        r["input_data"] = json.loads(r["input_data"])
        r["output_data"] = json.loads(r["output_data"])
        r["security_checks"] = json.loads(r["security_checks"])
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

    # Calcul de la latence moyenne
    cur.execute(f"SELECT AVG(latency_ms) FROM spans WHERE latency_ms > 0 AND org_id = {p}", (g.org_id,))
    avg_latency = cur.fetchone()[0] or 0

    # Statistiques de détection par couche
    if is_pg:
        cur.execute("""
            SELECT detection_layer, COUNT(*) as count
            FROM spans
            WHERE detection_layer IS NOT NULL AND org_id = %s
            GROUP BY detection_layer
        """, (g.org_id,))
    else:
        cur.execute("""
            SELECT detection_layer, COUNT(*) as count
            FROM spans
            WHERE detection_layer IS NOT NULL AND org_id = ?
            GROUP BY detection_layer
        """, (g.org_id,))
    detection_stats = {row[0]: row[1] for row in cur.fetchall()}

    # Score ML moyen
    cur.execute(f"SELECT AVG(ml_score) FROM spans WHERE ml_score IS NOT NULL AND org_id = {p}", (g.org_id,))
    avg_ml_score = cur.fetchone()[0] or 0

    # Score LLM moyen
    cur.execute(f"SELECT AVG(llm_score) FROM spans WHERE llm_score IS NOT NULL AND org_id = {p}", (g.org_id,))
    avg_llm_score = cur.fetchone()[0] or 0

    # Nombre de spans LLM Judge
    cur.execute(f"SELECT COUNT(*) FROM spans WHERE detection_layer = 'llm_judge' AND org_id = {p}", (g.org_id,))
    llm_count = cur.fetchone()[0] or 0

    # Risques
    if is_pg:
        cur.execute("""
            SELECT jsonb_array_elements(security_checks) as check
            FROM spans
            WHERE created_at > NOW() - INTERVAL '1 day' AND org_id = %s
        """, (g.org_id,))
    else:
        cur.execute("""
            SELECT json_extract(security_checks, '$') as checks
            FROM spans
            WHERE created_at > datetime('now', '-1 day') AND org_id = ?
        """, (g.org_id,))

    risk_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for row in cur.fetchall():
        if is_pg:
            check = row[0]
        else:
            checks = json.loads(row[0])
            for check in checks:
                level = check.get("risk_level", "low")
                risk_counts[level] = risk_counts.get(level, 0) + 1

    # Top threats
    cur.execute(f"""
        SELECT block_reason, COUNT(*) as count
        FROM spans
        WHERE blocked = TRUE AND org_id = {p}
        GROUP BY block_reason
        ORDER BY count DESC
        LIMIT 5
    """, (g.org_id,))
    top_threats = [{"reason": r[0], "count": r[1]} for r in cur.fetchall()]

    conn.close()
    return jsonify({
        "total_spans": total_spans,
        "total_traces": total_traces,
        "blocked_operations": blocked,
        "total_cost_usd": round(float(total_cost or 0), 6),
        "avg_latency_ms": round(float(avg_latency or 0), 2),
        "avg_ml_score": round(float(avg_ml_score or 0), 3),
        "avg_llm_score": round(float(avg_llm_score or 0), 3),
        "llm_judge_count": llm_count,
        "risk_distribution": risk_counts,
        "top_threats": top_threats,
        "detection_layers": detection_stats,
        "version": "v4.1.0"
    })

@app.route("/api/detection/stats")
def get_detection_stats():
    """Endpoint dédié aux statistiques de détection multi-couches."""
    is_pg = DB_TYPE == "postgres" and DATABASE_URL
    conn = get_db()

    if is_pg:
        cur = conn.cursor()
        p = "%s"
    else:
        cur = conn.cursor()
        p = "?"

    # Distribution par couche de détection
    cur.execute(f"""
        SELECT detection_layer, COUNT(*) as count
        FROM spans
        WHERE detection_layer IS NOT NULL AND org_id = {p}
        GROUP BY detection_layer
        ORDER BY count DESC
    """, (g.org_id,))
    layer_distribution = [{"layer": r[0], "count": r[1]} for r in cur.fetchall()]

    # Précision par couche (ratio blocages / total)
    cur.execute(f"""
        SELECT detection_layer,
               COUNT(*) as total,
               SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked
        FROM spans
        WHERE detection_layer IS NOT NULL AND org_id = {p}
        GROUP BY detection_layer
    """, (g.org_id,))
    layer_accuracy = []
    for r in cur.fetchall():
        layer_accuracy.append({
            "layer": r[0],
            "total": r[1],
            "blocked": r[2],
            "block_rate": round((r[2] / r[1] * 100) if r[1] > 0 else 0, 2)
        })

    # Distribution des scores ML
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
        FROM spans
        WHERE ml_score IS NOT NULL AND org_id = {p}
        GROUP BY score_range
        ORDER BY score_range DESC
    """, (g.org_id,))
    ml_score_distribution = [{"range": r[0], "count": r[1]} for r in cur.fetchall()]

    # Distribution des scores LLM
    cur.execute(f"""
        SELECT
            CASE
                WHEN llm_score >= 0.9 THEN 'high_risk'
                WHEN llm_score >= 0.7 THEN 'medium_risk'
                ELSE 'low_risk'
            END as risk_category,
            COUNT(*) as count
        FROM spans
        WHERE llm_score IS NOT NULL AND org_id = {p}
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
    """Statistiques spécifiques au LLM Judge."""
    is_pg = DB_TYPE == "postgres" and DATABASE_URL
    conn = get_db()

    if is_pg:
        cur = conn.cursor()
    else:
        cur = conn.cursor()

    # Nombre de spans analysées par LLM
    cur.execute("""
        SELECT COUNT(*) as total_llm_analysis
        FROM spans
        WHERE detection_layer = 'llm_judge'
    """)
    total_llm = cur.fetchone()[0]

    # Taux de blocage du LLM
    cur.execute("""
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked
        FROM spans
        WHERE detection_layer = 'llm_judge'
    """)
    row = cur.fetchone()
    block_rate = round((row[1] / row[0] * 100), 2) if row[0] > 0 else 0

    # Top raisons LLM
    cur.execute("""
        SELECT llm_reason, COUNT(*) as count
        FROM spans
        WHERE llm_reason IS NOT NULL AND detection_layer = 'llm_judge'
        GROUP BY llm_reason
        ORDER BY count DESC
        LIMIT 5
    """)
    top_reasons = [{"reason": r[0], "count": r[1]} for r in cur.fetchall()] if is_pg else \
                  [{"reason": r[0], "count": r[1]} for r in cur.fetchall()]

    conn.close()
    
    return jsonify({
        "total_analyzed": total_llm,
        "block_rate": block_rate,
        "top_reasons": top_reasons,
        "status": "operational" if total_llm > 0 else "idle"
    })

# ── ENDPOINTS "DASHBOARD RÉEL" ──
# Chacun de ces endpoints remplace une section du dashboard qui affichait
# auparavant des données inventées (modèles fictifs, heatmap Math.random(),
# "guardrails" jamais implémentés). Tout ici vient d'une vraie requête sur
# les spans stockées — s'il n'y a pas de données, la réponse est vide,
# jamais remplie de chiffres plausibles.

@app.route("/api/models")
def api_models():
    """Répartition réelle par modèle — nécessite que le SDK envoie
    kwargs['model'] (fait automatiquement par guard_llm_call)."""
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
               SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked_count
        FROM spans
        WHERE org_id = {p} AND model IS NOT NULL AND model != ''
        GROUP BY model
        ORDER BY requests DESC
    """, (g.org_id,))
    models = []
    for r in cur.fetchall():
        row = dict(r) if is_pg else {"model": r[0], "requests": r[1], "avg_latency": r[2], "total_cost": r[3], "blocked_count": r[4]}
        models.append({
            "name": row["model"],
            "requests": row["requests"],
            "avg_latency_ms": round(float(row["avg_latency"] or 0), 1),
            "total_cost_usd": round(float(row["total_cost"] or 0), 6),
            "blocked_count": row["blocked_count"],
        })
    conn.close()
    return jsonify(models)

@app.route("/api/heatmap")
def api_heatmap():
    """Activité bloquée par heure réelle, sur les 5 derniers jours."""
    is_pg = DB_TYPE == "postgres" and DATABASE_URL
    conn = get_db()
    if is_pg:
        cur = conn.cursor()
        cur.execute("""
            SELECT EXTRACT(DAY FROM created_at)::int as day, EXTRACT(HOUR FROM created_at)::int as hour,
                   COUNT(*) as total, SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked
            FROM spans
            WHERE org_id = %s AND created_at > NOW() - INTERVAL '5 days'
            GROUP BY day, hour
        """, (g.org_id,))
    else:
        cur = conn.cursor()
        cur.execute("""
            SELECT strftime('%j', created_at) as day, CAST(strftime('%H', created_at) AS INTEGER) as hour,
                   COUNT(*) as total, SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked
            FROM spans
            WHERE org_id = ? AND created_at > datetime('now', '-5 days')
            GROUP BY day, hour
        """, (g.org_id,))
    cells = [{"day": r[0], "hour": r[1], "total": r[2], "blocked": r[3] or 0} for r in cur.fetchall()]
    conn.close()
    return jsonify(cells)

@app.route("/api/checks/breakdown")
def api_checks_breakdown():
    """Le vrai remplaçant de l'ancienne section 'Guardrails' fictive : les
    catégories qui existent réellement dans PolicyEngine (prompt_injection,
    pii_detection, tool_policy/dangerous_params, budget_policy) — pas de
    toxicité ni de 'denied topics', qui ne sont pas des fonctionnalités
    implémentées."""
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

@app.route("/api/spans/expensive")
def api_expensive_spans():
    """Les vraies spans les plus coûteuses — pas des trace_id inventés."""
    is_pg = DB_TYPE == "postgres" and DATABASE_URL
    conn = get_db()
    cur = conn.cursor()
    p = "%s" if is_pg else "?"
    cur.execute(f"""
        SELECT trace_id, span_id, span_type, model, cost_usd
        FROM spans WHERE org_id = {p} AND cost_usd > 0
        ORDER BY cost_usd DESC LIMIT 5
    """, (g.org_id,))
    rows = [{"trace_id": r[0], "span_id": r[1], "span_type": r[2], "model": r[3], "cost_usd": r[4]} for r in cur.fetchall()]
    conn.close()
    return jsonify(rows)

@app.route("/api/cost/trend")
def api_cost_trend():
    """Coût réel jour par jour, sur les 14 derniers jours — base pour une
    projection linéaire honnête plutôt qu'une courbe de forecast inventée."""
    is_pg = DB_TYPE == "postgres" and DATABASE_URL
    conn = get_db()
    cur = conn.cursor()
    if is_pg:
        cur.execute("""
            SELECT DATE(created_at) as day, SUM(cost_usd) as cost
            FROM spans WHERE org_id = %s AND created_at > NOW() - INTERVAL '14 days'
            GROUP BY day ORDER BY day
        """, (g.org_id,))
    else:
        cur.execute("""
            SELECT DATE(created_at) as day, SUM(cost_usd) as cost
            FROM spans WHERE org_id = ? AND created_at > datetime('now', '-14 days')
            GROUP BY day ORDER BY day
        """, (g.org_id,))
    rows = [{"day": str(r[0]), "cost": round(float(r[1] or 0), 6)} for r in cur.fetchall()]
    conn.close()
    return jsonify(rows)

@app.route("/api/latency/distribution")
def api_latency_distribution():
    """Vrais percentiles de latence — remplace l'ancien graphique 'token
    usage' qui affichait des nombres inventés (les tokens ne sont pas
    mesurés par le SDK actuellement, donc on ne les affiche pas du tout
    plutôt que de les simuler)."""
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
        "p95": pct(values, 0.95),
        "p99": pct(values, 0.99),
        "min": round(min(values), 1) if values else 0,
        "max": round(max(values), 1) if values else 0,
    })

@app.route("/api/events/recent")
def api_recent_events():
    """Les vrais derniers événements — remplace le flux 'live events' qui
    affichait 6 lignes hardcodées ('Flagged prompt injection', '2s ago'...)."""
    is_pg = DB_TYPE == "postgres" and DATABASE_URL
    conn = get_db()
    cur = conn.cursor()
    p = "%s" if is_pg else "?"
    cur.execute(f"""
        SELECT span_type, detection_layer, blocked, block_reason, created_at, security_checks
        FROM spans WHERE org_id = {p}
        ORDER BY created_at DESC LIMIT 8
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
        events.append({
            "span_type": r[0], "layer": r[1] or "regex", "blocked": bool(r[2]),
            "reason": r[3], "created_at": str(r[4]), "risk": risk,
        })
    conn.close()
    return jsonify(events)

@app.route("/api/trend/daily")
def api_trend_daily():
    """Totaux réels jour par jour (14 derniers jours) — utilisé pour les
    sparklines des KPI, qui affichaient auparavant des tableaux de nombres
    écrits en dur (ex: '+186.36%')."""
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

# ── DASHBOARD (Professional UI) ──
DASHBOARD_HTML = r'''
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="theme-color" content="#080b12">
<title>AgentGuard — AI Runtime Security</title>
<style>
:root{--bg:#070a10;--panel:#0d121b;--panel2:#111824;--border:#1e2937;--border2:#263244;--text:#eef4fb;--muted:#8996a8;--dim:#5f6b7b;--accent:#38bdf8;--accent2:#22d3ee;--green:#35d07f;--yellow:#f5b84b;--orange:#fb923c;--red:#ff5d73;--purple:#a78bfa;--shadow:0 14px 45px rgba(0,0,0,.28);--radius:14px;}
*{box-sizing:border-box}html,body{margin:0;min-height:100%;background:var(--bg);color:var(--text);font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
body{display:flex;font-size:14px}.app{display:flex;width:100%;min-height:100vh}
.sidebar{width:238px;border-right:1px solid var(--border);background:#090d14;padding:20px 14px;position:fixed;inset:0 auto 0 0;z-index:20;display:flex;flex-direction:column}
.brand{display:flex;align-items:center;gap:11px;padding:4px 9px 24px}.brand-mark{width:31px;height:31px;border:1px solid #31546a;border-radius:9px;display:grid;place-items:center;background:linear-gradient(145deg,#122333,#0b111a);color:var(--accent);box-shadow:0 0 20px #38bdf812}.brand-mark svg{width:19px}.brand strong{font-size:15px;letter-spacing:.02em}.brand span{display:block;color:var(--dim);font-size:10px;margin-top:2px;letter-spacing:.08em;text-transform:uppercase}
.nav-label{font-size:10px;color:#526074;text-transform:uppercase;letter-spacing:.13em;padding:14px 10px 7px}
.nav button{width:100%;border:0;background:transparent;color:#8f9caf;text-align:left;padding:10px 11px;border-radius:9px;cursor:pointer;display:flex;align-items:center;gap:10px;font:inherit}.nav button:hover{background:#111824;color:#dbe7f4}.nav button.active{background:#102131;color:#e9f8ff;box-shadow:inset 2px 0 0 var(--accent)}.nav svg{width:16px;height:16px;stroke:currentColor}.sidebar-bottom{margin-top:auto;border-top:1px solid var(--border);padding:14px 8px 2px}.status{display:flex;align-items:center;gap:8px;color:#8e9bac;font-size:11px}.dot{width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 12px #35d07f88}.version{color:#4e5b6d;font-size:10px;margin-top:8px}
.main{margin-left:238px;width:calc(100% - 238px);min-width:0}.topbar{height:68px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;padding:0 28px;background:#090d14e8;backdrop-filter:blur(14px);position:sticky;top:0;z-index:15}.crumb{display:flex;align-items:center;gap:9px}.crumb small{color:var(--dim)}.top-actions{display:flex;align-items:center;gap:10px}.pill{border:1px solid var(--border2);background:#0d131d;border-radius:999px;padding:7px 10px;color:#9ba8b8;font-size:11px;display:flex;align-items:center;gap:7px}.btn{border:1px solid var(--border2);background:#101722;color:#d8e2ee;padding:8px 12px;border-radius:9px;cursor:pointer;font:inherit;font-size:12px}.btn:hover{border-color:#385067;background:#131d29}.btn.primary{background:#0f2634;border-color:#23516b;color:#bcecff}.content{padding:26px 28px 40px;max-width:1700px;margin:auto}.page-head{display:flex;justify-content:space-between;align-items:flex-end;margin-bottom:22px}.eyebrow{font-size:10px;text-transform:uppercase;letter-spacing:.14em;color:var(--accent);font-weight:700}.page-title{font-size:25px;letter-spacing:-.03em;margin:5px 0 5px}.page-sub{color:var(--muted);margin:0;font-size:13px}.head-actions{display:flex;gap:8px}
.grid-kpi{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:12px;margin-bottom:14px}.card{background:linear-gradient(180deg,#0e141d,#0b1018);border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow)}.kpi{padding:16px 17px;min-height:112px;position:relative;overflow:hidden}.kpi:after{content:"";position:absolute;width:100px;height:100px;border-radius:50%;right:-50px;top:-60px;background:var(--accent);opacity:.035}.kpi-top{display:flex;justify-content:space-between;align-items:center;color:#788698;font-size:11px}.kpi-icon{width:25px;height:25px;border:1px solid var(--border2);border-radius:7px;display:grid;place-items:center;color:#8190a2}.kpi-value{font-size:26px;font-weight:700;letter-spacing:-.04em;margin:13px 0 3px}.kpi-meta{font-size:10px;color:#667486}.positive{color:var(--green)}.danger{color:var(--red)}
.layout{display:grid;grid-template-columns:minmax(0,1.6fr) minmax(310px,.8fr);gap:14px}.panel{padding:18px}.panel-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:15px}.panel-title{font-size:13px;font-weight:700;letter-spacing:.01em}.panel-desc{font-size:10px;color:var(--dim);margin-top:3px}
.chart-wrap{height:250px;position:relative}.chart-wrap svg{width:100%;height:100%;display:block}.legend{display:flex;gap:14px;align-items:center;font-size:10px;color:#7c8a9d}.legend i{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:5px}.legend .a{background:var(--accent)}.legend .r{background:var(--red)}
.risk-grid{display:grid;grid-template-columns:1fr 1fr;gap:9px}.risk{border:1px solid var(--border);background:#0b1119;padding:12px;border-radius:10px}.risk-label{display:flex;justify-content:space-between;color:#9ba7b7;font-size:11px}.risk-count{font-size:21px;font-weight:700;margin-top:8px}.risk-bar{height:4px;background:#18212d;border-radius:9px;margin-top:9px;overflow:hidden}.risk-bar span{display:block;height:100%;border-radius:9px}.low span{background:var(--green)}.medium span{background:var(--yellow)}.high span{background:var(--orange)}.critical span{background:var(--red)}
.two{display:grid;grid-template-columns:1.15fr .85fr;gap:14px;margin-top:14px}.three{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-top:14px}.four{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:14px}
.threat-list,.trace-list{display:flex;flex-direction:column;gap:8px}.threat{display:flex;justify-content:space-between;align-items:center;border:1px solid var(--border);padding:10px 11px;border-radius:9px;background:#0b1119}.threat-name{color:#cbd6e3;font-size:12px;max-width:78%;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.threat-count{color:#91a0b1;font-size:11px}.empty{color:#5f6b7b;text-align:center;padding:28px 10px;font-size:12px}.trace-row{display:grid;grid-template-columns:1fr auto auto;gap:12px;align-items:center;border:1px solid var(--border);padding:10px 11px;border-radius:9px;background:#0b1119;cursor:pointer}.trace-row:hover{border-color:#2a4255;background:#0d141e}.trace-main{min-width:0}.trace-id{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:10px;color:#aebaca;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.trace-sub{font-size:10px;color:#647184;margin-top:4px}.badge{display:inline-flex;align-items:center;border-radius:999px;padding:4px 7px;font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.05em}.badge.safe{color:#82e5ac;background:#35d07f12;border:1px solid #35d07f28}.badge.blocked{color:#ff8797;background:#ff5d7312;border:1px solid #ff5d7330}.badge.neutral{color:#9caabe;background:#8996a812;border:1px solid #8996a81f}
.table{width:100%;border-collapse:collapse}.table th{text-align:left;color:#5f6c7d;font-size:9px;text-transform:uppercase;letter-spacing:.1em;font-weight:600;padding:0 10px 10px}.table td{border-top:1px solid var(--border);padding:11px 10px;color:#b9c5d3;font-size:11px}.table tr:hover td{background:#0e151f}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}.score{display:flex;align-items:center;gap:7px}.scorebar{width:55px;height:4px;border-radius:5px;background:#18212d;overflow:hidden}.scorebar span{height:100%;display:block;background:var(--accent)}
.detection{display:grid;grid-template-columns:1fr 1fr 1fr;gap:9px}.det{border:1px solid var(--border);border-radius:10px;padding:12px;background:#0b1119}.det-label{color:#8390a1;font-size:10px}.det-value{font-size:19px;font-weight:700;margin-top:7px}.det-rate{color:#637083;font-size:10px;margin-top:3px}.bar{height:5px;border-radius:6px;background:#18212d;overflow:hidden;margin-top:10px}.bar span{display:block;height:100%;background:var(--accent)}
.view{display:none}.view.active{display:block}.mobile-menu{display:none}
.search-wrap{display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap}.search-wrap input,.search-wrap select{background:#0b1119;border:1px solid var(--border);color:#c5d1e3;padding:8px 10px;border-radius:8px;font:inherit;font-size:12px;outline:none}.search-wrap input:focus,.search-wrap select:focus{border-color:#385067}.search-wrap input{flex:1;min-width:200px}.search-wrap select{width:140px}
.export-btn{background:#0f2634;border:1px solid #23516b;color:#bcecff;padding:8px 12px;border-radius:8px;cursor:pointer;font:inherit;font-size:12px}.export-btn:hover{background:#132e3f}
.layer-badge{display:inline-flex;align-items:center;border-radius:999px;padding:3px 8px;font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;margin-left:6px}.layer-regex{color:#60a5fa;background:#3b82f612;border:1px solid #3b82f630}.layer-ml{color:#a78bfa;background:#8b5cf612;border:1px solid #8b5cf630}.layer-llm_judge{color:#fbbf24;background:#f59e0b12;border:1px solid #f59e0b30}.layer-mixed{color:#c084fc;background:#a855f712;border:1px solid #a855f730}.layer-unknown{color:#94a3b8;background:#64748b12;border:1px solid #64748b30}
.score-pill{font-size:10px;padding:2px 6px;border-radius:4px;font-weight:600}.score-pill.high{color:#ef4444;background:#ef444415;border:1px solid #ef444430}.score-pill.medium{color:#f59e0b;background:#f59e0b15;border:1px solid #f59e0b30}.score-pill.low{color:#22c55e;background:#22c55e15;border:1px solid #22c55e30}
.spark{position:absolute;top:12px;right:12px;width:70px;height:24px;opacity:0.6}
.heat{display:grid;grid-template-columns:repeat(12,1fr);gap:3px}.heat-cell{height:22px;border-radius:3px;cursor:pointer;transition:transform .1s}.heat-cell:hover{transform:scale(1.15);z-index:2}
.gantt{position:relative;overflow-x:auto}.gantt-row{display:flex;align-items:center;height:30px;border-bottom:1px solid var(--border);position:relative}.gantt-label{width:200px;flex-shrink:0;font-size:10px;color:#8e9bac;padding-right:10px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.gantt-track{flex:1;position:relative;height:100%}.gantt-bar{position:absolute;height:16px;top:7px;border-radius:3px;opacity:0.85;transition:opacity .15s}.gantt-bar:hover{opacity:1}.gantt-bar.safe{background:#38bdf8}.gantt-bar.blocked{background:#ff5d73}.gantt-bar.warn{background:#f59e0b}
.toast{position:fixed;right:22px;bottom:22px;background:#101923;border:1px solid #294055;padding:11px 14px;border-radius:10px;box-shadow:var(--shadow);font-size:12px;z-index:100;opacity:0;transform:translateY(8px);transition:.2s}.toast.show{opacity:1;transform:none}
.modal{position:fixed;inset:0;background:#02050ab8;backdrop-filter:blur(8px);z-index:60;display:none;align-items:center;justify-content:center;padding:24px}.modal.open{display:flex}.modal-box{width:min(980px,100%);max-height:90vh;overflow:auto;background:#0b1119;border:1px solid var(--border2);border-radius:16px;box-shadow:0 30px 90px #000b}.modal-head{padding:18px 20px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;background:#0b1119ee;backdrop-filter:blur(10px);z-index:2}.modal-body{padding:20px}.close{border:0;background:#131c27;color:#a7b4c3;border-radius:8px;width:30px;height:30px;cursor:pointer}
.timeline{display:flex;flex-direction:column;gap:0}.event{display:grid;grid-template-columns:90px 18px 1fr;gap:10px;min-height:76px}.event-time{font-size:10px;color:#657285;padding-top:3px;text-align:right}.event-line{position:relative}.event-line:before{content:"";width:8px;height:8px;border-radius:50%;background:var(--accent);position:absolute;top:4px;left:0;box-shadow:0 0 0 4px #38bdf810}.event-line:after{content:"";position:absolute;width:1px;background:#263342;top:15px;bottom:0;left:4px}.event:last-child .event-line:after{display:none}.event-card{border:1px solid var(--border);border-radius:10px;background:#0d141e;padding:12px;margin-bottom:10px}.event-card.block{border-color:#5a2833}.event-title{font-size:12px;font-weight:700}.event-meta{font-size:10px;color:#6c7889;margin-top:5px}.json{white-space:pre-wrap;word-break:break-word;background:#070b11;border:1px solid var(--border);border-radius:8px;padding:10px;color:#9fb0c2;font:10px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;margin-top:10px;max-height:220px;overflow:auto}
@media(max-width:1100px){.grid-kpi{grid-template-columns:repeat(3,1fr)}.layout,.two,.three,.four{grid-template-columns:1fr}.sidebar{width:210px}.main{margin-left:210px;width:calc(100% - 210px)}}
@media(max-width:760px){.sidebar{display:none}.main{margin-left:0;width:100%}.mobile-menu{display:block}.topbar{padding:0 15px}.content{padding:18px 14px}.grid-kpi{grid-template-columns:1fr 1fr}.detection{grid-template-columns:1fr}.page-head{align-items:flex-start;gap:14px;flex-direction:column}.table-wrap{overflow:auto}.table{min-width:700px}}
</style>
<base target="_blank">
</head>
<body>
<div class="app">
<aside class="sidebar">
  <div class="brand"><div class="brand-mark"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 3l7 3v5c0 4.8-2.8 8.2-7 10-4.2-1.8-7-5.2-7-10V6l7-3z"/><path d="M9 12l2 2 4-5"/></svg></div><div><strong>AgentGuard</strong><span>AI Runtime Security</span></div></div>
  <nav class="nav">
    <div class="nav-label">Monitor</div>
    <button class="active" data-view="overview"><svg fill="none" viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>Overview</button>
    <button data-view="traces"><svg fill="none" viewBox="0 0 24 24"><path d="M4 5h16M4 12h10M4 19h16"/></svg>Traces</button>
    <button data-view="models"><svg fill="none" viewBox="0 0 24 24"><circle cx="12" cy="8" r="3"/><path d="M5 20c.8-4 3.1-6 7-6s6.2 2 7 6"/></svg>Models</button>
    <div class="nav-label">Security</div>
    <button data-view="guardrails"><svg fill="none" viewBox="0 0 24 24"><path d="M12 3l8 4v5c0 4.8-3.1 8.4-8 10-4.9-1.6-8-5.2-8-10V7l8-4z"/><path d="M12 8v5M12 16h.01"/></svg>Guardrails</button>
    <button data-view="threats"><svg fill="none" viewBox="0 0 24 24"><path d="M12 3l8 4v5c0 4.8-3.1 8.4-8 10-4.9-1.6-8-5.2-8-10V7l8-4z"/><path d="M12 8v5M12 16h.01"/></svg>Threats</button>
    <button data-view="detection"><svg fill="none" viewBox="0 0 24 24"><path d="M4 17l5-5 4 3 7-8"/><path d="M20 7v5h-5"/></svg>Detection</button>
    <button data-view="policies"><svg fill="none" viewBox="0 0 24 24"><path d="M5 4h14v16H5z"/><path d="M8 8h8M8 12h8M8 16h5"/></svg>Policies</button>
    <div class="nav-label">Operations</div>
    <button data-view="usage"><svg fill="none" viewBox="0 0 24 24"><path d="M12 3v18M16 7.5c0-1.7-1.8-3-4-3S8 5.3 8 7s1.4 2.5 4 3 4 1.3 4 3-1.8 3-4 3-4-1.3-4-3"/></svg>Usage & Cost</button>
    <button data-view="audit"><svg fill="none" viewBox="0 0 24 24"><path d="M6 3h12v18H6z"/><path d="M9 7h6M9 11h6M9 15h4"/></svg>Audit Log</button>
  </nav>
  <div class="sidebar-bottom"><div class="status"><span class="dot"></span><span>Collector operational</span></div><div class="version">AgentGuard v5.0 · local runtime</div></div>
</aside>
<main class="main">
<header class="topbar"><div class="crumb"><button class="btn mobile-menu" onclick="document.querySelector('.sidebar').style.display='flex'">☰</button><small>Workspace</small><span style="color:#435163">/</span><strong id="crumbTitle">Overview</strong></div><div class="top-actions"><div class="pill"><span class="dot"></span><span id="lastSync">Live</span></div><button class="btn" onclick="refreshAll()">↻ Refresh</button></div></header>
<div class="content">

<section id="view-overview" class="view active">
  <div class="page-head"><div><div class="eyebrow">Runtime security</div><h1 class="page-title">Security overview</h1><p class="page-sub">Monitor AI agents, runtime decisions, threats and detection performance.</p></div><div class="head-actions"><button class="btn primary" onclick="refreshAll()">Live refresh</button></div></div>
  <div class="grid-kpi" id="kpiRow"></div>
  <div class="four" id="guardrailKpis"></div>
  <div class="layout">
    <div class="card panel"><div class="panel-head"><div><div class="panel-title">Runtime activity</div><div class="panel-desc">Observed spans and blocked decisions — last 14 days</div></div><div class="legend"><span><i class="a"></i>Spans</span><span><i class="r"></i>Blocked</span></div></div><div class="chart-wrap" id="activityChartWrap"></div></div>
    <div class="card panel"><div class="panel-head"><div><div class="panel-title">Risk distribution</div><div class="panel-desc">Security checks observed in the last 24h</div></div></div><div class="risk-grid" id="riskGrid"></div></div>
  </div>
  <div class="two">
    <div class="card panel"><div class="panel-head"><div><div class="panel-title">Model breakdown</div><div class="panel-desc">Latency & requests per model</div></div><button class="btn" onclick="showView('models')">View all</button></div><div id="modelBreakdown"></div></div>
    <div class="card panel"><div class="panel-head"><div><div class="panel-title">Success vs Blocked</div><div class="panel-desc">Request outcome distribution</div></div></div><div id="pieChart" style="height:200px;display:flex;align-items:center;justify-content:center"></div></div>
  </div>
  <div class="two" style="margin-top:14px">
    <div class="card panel"><div class="panel-head"><div><div class="panel-title">Attack heatmap</div><div class="panel-desc">Blocked events by hour — last 5 days</div></div></div><div id="heatmap" style="margin-top:8px"></div><div style="display:flex;justify-content:space-between;margin-top:8px;font-size:10px;color:#4e5b6d"><span>00h</span><span>06h</span><span>12h</span><span>18h</span><span>23h</span></div></div>
    <div class="card panel"><div class="panel-head"><div><div class="panel-title">Top expensive spans</div><div class="panel-desc">Highest cost operations</div></div></div><div id="expensiveSpans"></div></div>
  </div>
  <div class="two" style="margin-top:14px">
    <div class="card panel"><div class="panel-head"><div><div class="panel-title">Live events</div><div class="panel-desc">Real-time security decisions</div></div></div><div class="trace-list" id="liveEvents"></div></div>
    <div class="card panel"><div class="panel-head"><div><div class="panel-title">Recent traces</div><div class="panel-desc">Latest runtime activity</div></div><button class="btn" onclick="showView('traces')">All traces</button></div><div class="trace-list" id="recentTraces"></div></div>
  </div>
</section>

<section id="view-traces" class="view">
  <div class="page-head"><div><div class="eyebrow">Observability</div><h1 class="page-title">Distributed Traces</h1><p class="page-sub">Follow an agent execution from request to tool call and security decision.</p></div></div>
  <div class="search-wrap">
    <input type="text" id="traceSearch" placeholder="Search trace_id, model, detection layer, block reason…" oninput="filterTraces()">
    <select id="traceFilterBlocked" onchange="filterTraces()"><option value="">All statuses</option><option value="blocked">Blocked only</option><option value="safe">Safe only</option></select>
    <select id="traceFilterLayer" onchange="filterTraces()"><option value="">All layers</option><option value="regex">Regex</option><option value="ml">ML</option><option value="llm_judge">LLM Judge</option><option value="mixed">Mixed</option></select>
    <button class="export-btn" onclick="exportTracesCSV()">⬇ Export CSV</button>
  </div>
  <div class="card panel"><div class="table-wrap"><table class="table"><thead><tr><th>Trace</th><th>Spans</th><th>Blocked</th><th>Layer</th><th>Model</th><th>Cost</th><th>P50 Lat</th><th>P99 Lat</th><th>Last seen</th></tr></thead><tbody id="traceTable"></tbody></table></div></div>
</section>

<section id="view-models" class="view">
  <div class="page-head"><div><div class="eyebrow">Observability</div><h1 class="page-title">Model Performance</h1><p class="page-sub">Per-model latency, cost, token usage and block rate.</p></div></div>
  <div class="three" id="modelCards"></div>
  <div class="card panel" style="margin-top:14px"><div class="panel-head"><div><div class="panel-title">Model comparison</div><div class="panel-desc">Cost (bars) vs avg latency (line) per model</div></div></div><div class="chart-wrap" id="modelComparison"></div></div>
</section>

<section id="view-guardrails" class="view">
  <div class="page-head"><div><div class="eyebrow">Security</div><h1 class="page-title">Guardrails</h1><p class="page-sub">Runtime policy enforcement and content filtering metrics.</p></div></div>
  <div class="four" id="guardrailDetail"></div>
  <div class="two" style="margin-top:14px">
    <div class="card panel"><div class="panel-head"><div><div class="panel-title">Guardrail activation by type</div><div class="panel-desc">Total analyzed vs flagged, per detection category</div></div></div><div class="chart-wrap" id="guardrailStacked"></div></div>
    <div class="card panel"><div class="panel-head"><div><div class="panel-title">Activation trend</div><div class="panel-desc">Blocked requests per day — last 14 days</div></div></div><div class="chart-wrap" id="guardrailTrend"></div></div>
  </div>
</section>

<section id="view-threats" class="view">
  <div class="page-head"><div><div class="eyebrow">Security</div><h1 class="page-title">Threats</h1><p class="page-sub">Runtime violations and enforcement signals collected by AgentGuard.</p></div></div>
  <div class="four" id="threatKpis"></div>
  <div class="card panel" style="margin-top:14px"><div class="panel-head"><div><div class="panel-title">Threat catalogue</div><div class="panel-desc">Current top blocked reasons</div></div></div><div class="threat-list" id="threatFull"></div></div>
</section>

<section id="view-detection" class="view">
  <div class="page-head"><div><div class="eyebrow">Intelligence</div><h1 class="page-title">Detection center</h1><p class="page-sub">Compare the signals produced by the detection layers already enabled in the collector.</p></div></div>
  <div class="card panel"><div class="panel-head"><div><div class="panel-title">Detection layers</div><div class="panel-desc">Observed volume and block rate</div></div></div><div class="detection" id="detectionCards"></div></div>
  <div class="two" style="margin-top:14px"><div class="card panel"><div class="panel-head"><div><div class="panel-title">ML score distribution</div></div></div><div id="mlDistribution"></div></div><div class="card panel"><div class="panel-head"><div><div class="panel-title">LLM Judge distribution</div></div></div><div id="llmDistribution"></div></div></div>
</section>

<section id="view-policies" class="view"><div class="page-head"><div><div class="eyebrow">Governance</div><h1 class="page-title">Policies</h1><p class="page-sub">Policy management UI is prepared here; the current collector does not yet expose policy CRUD endpoints.</p></div></div><div class="card panel"><div class="empty"><div style="font-size:25px;margin-bottom:8px">◇</div><strong style="color:#cbd6e3">Policy engine workspace</strong><p style="max-width:560px;margin:8px auto;color:#667486">The dashboard is ready for runtime policies, approvals and enforcement rules. Those capabilities require backend policy endpoints that are not currently present in collector.py.</p><span class="badge neutral">Backend extension required</span></div></div></section>

<section id="view-usage" class="view">
  <div class="page-head"><div><div class="eyebrow">Operations</div><h1 class="page-title">Usage & cost</h1><p class="page-sub">Cost and latency telemetry derived from the observed spans.</p></div></div>
  <div class="four" id="usageKpis"></div>
  <div class="two" style="margin-top:14px">
    <div class="card panel"><div class="panel-head"><div><div class="panel-title">Cost forecast</div><div class="panel-desc">Projected spend based on current trajectory</div></div></div><div class="chart-wrap" id="costForecast"></div></div>
    <div class="card panel"><div class="panel-head"><div><div class="panel-title">Latency distribution</div><div class="panel-desc">Real p50 / p95 / p99 / max observed latency</div></div></div><div class="chart-wrap" id="tokenUsage"></div></div>
  </div>
</section>

<section id="view-audit" class="view">
  <div class="page-head"><div><div class="eyebrow">Governance</div><h1 class="page-title">Audit log</h1><p class="page-sub">A lightweight audit view derived from runtime traces. Administrative audit events require a dedicated backend log.</p></div></div>
  <div class="card panel"><div class="table-wrap"><table class="table"><thead><tr><th>Time</th><th>Trace</th><th>Event</th><th>Model</th><th>Decision</th><th>Layer</th></tr></thead><tbody id="auditTable"></tbody></table></div></div>
</section>

</div></main></div>
<div id="toast" class="toast"></div>
<div id="traceModal" class="modal" onclick="if(event.target===this)closeModal()">
  <div class="modal-box">
    <div class="modal-head"><div><div class="eyebrow">Trace investigation</div><div id="modalTitle" style="font-weight:700;margin-top:4px">Trace</div></div><button class="close" onclick="closeModal()">×</button></div>
    <div class="modal-body" id="modalBody"></div>
  </div>
</div>
<script>
const state={metrics:null,traces:[],detection:null,llm:null,allTraces:[]};
const $=id=>document.getElementById(id);
const esc=v=>String(v||'').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
const fmt=n=>new Intl.NumberFormat('en-US').format(Number(n||0));
const money=n=>'$'+Number(n||0).toFixed(4);
function toast(msg){const t=$('toast');t.textContent=msg;t.classList.add('show');clearTimeout(window._toast);window._toast=setTimeout(()=>t.classList.remove('show'),2200)}
async function api(url){const r=await fetch(url,{credentials:'include',headers:{'Accept':'application/json'}});if(!r.ok)throw new Error('HTTP '+r.status);return r.json()}

function showView(name){
  document.querySelectorAll('.view').forEach(x=>x.classList.remove('active'));
  const v=$('view-'+name); if(v)v.classList.add('active');
  document.querySelectorAll('.nav button').forEach(b=>b.classList.toggle('active',b.dataset.view===name));
  $('crumbTitle').textContent=name==='overview'?'Overview':name.charAt(0).toUpperCase()+name.slice(1).replace('-',' ');
  if(name==='traces')renderTraceTable(state.allTraces);
  if(name==='models')renderModels();
  if(name==='guardrails')renderGuardrails();
  if(name==='threats')renderThreats();
  if(name==='detection')renderDetection(state.detection);
  if(name==='usage')renderUsage();
  if(name==='audit')renderAudit();
}
document.querySelectorAll('.nav button').forEach(b=>b.addEventListener('click',()=>showView(b.dataset.view)));

function securityScore(m){
  const blocked=Number(m.blocked_operations||0), spans=Number(m.total_spans||0), blockRate=spans?blocked/spans:0;
  const ml=Number(m.avg_ml_score||0), llm=Number(m.avg_llm_score||0);
  let score=100-(blockRate*35)-(Math.max(ml,llm)*12);
  return Math.max(0,Math.min(100,Math.round(score)));
}

// ── SVG HELPERS ──
function sparkSVG(data,color,w,h){
  const max=Math.max(1,...data);
  const step=w/(data.length-1);
  let path='';
  data.forEach((v,i)=>{const x=i*step,y=h-(v/max)*h;path+=i?` L${x},${y}`:`M${x},${y}`;});
  return `<svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" class="spark"><path d="${path}" fill="none" stroke="${color}" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/><path d="${path} L${w},${h} L0,${h} Z" fill="${color}" opacity="0.08"/></svg>`;
}
function describeArc(x,y,r,startAngle,endAngle){
  const start=polarToCartesian(x,y,r,endAngle);
  const end=polarToCartesian(x,y,r,startAngle);
  const largeArcFlag=endAngle-startAngle<=180?"0":"1";
  return["M",start.x,start.y,"A",r,r,0,largeArcFlag,0,end.x,end.y].join(" ");
}
function polarToCartesian(cx,cy,r,angleDeg){const angleRad=(angleDeg-90)*Math.PI/180;return{x:cx+r*Math.cos(angleRad),y:cy+r*Math.sin(angleRad)};}

function renderOverview(){
  const m=state.metrics; if(!m)return;
  const daily=state.dailyTrend||[];
  const dailyTotals=daily.map(d=>d.total);
  const dailyBlocked=daily.map(d=>d.blocked);
  const costSeries=(state.costTrend||[]).map(d=>d.cost);
  const lat=state.latencyDist||{};

  function trendOf(series){
    if(series.length<2)return {has:false};
    const first=series[0]||0, last=series[series.length-1]||0;
    const pct=first===0?(last>0?100:0):((last-first)/first*100);
    return {has:true, up:pct>=0, text:(pct>=0?'+':'')+pct.toFixed(1)+'%'};
  }
  const reqTrend=trendOf(dailyTotals), costTrend=trendOf(costSeries);
  function trendHtml(t){
    return t.has?`<span style="color:${t.up?'#35d07f':'#ff5d73'}">${t.up?'↑':'↓'} ${esc(t.text)}</span> sur 14j`
                :`<span style="color:#5c6674">historique &lt; 2 jours</span>`;
  }

  const kpis=[
    {label:"Security Score",value:securityScore(m)+'/100',spark:dailyTotals,color:'#35d07f',trend:{has:false}},
    {label:"Total Requests",value:fmt(m.total_spans),spark:dailyTotals,color:'#38bdf8',trend:reqTrend},
    {label:"Avg Latency",value:Number(m.avg_latency_ms||0).toFixed(1)+'ms',spark:dailyTotals,color:'#35d07f',trend:{has:false}},
    {label:"P99 Latency",value:(lat.p99?lat.p99.toFixed(0):'—')+'ms',spark:dailyTotals,color:'#ff5d73',trend:{has:false}},
    {label:"LLM Judge Analyzed",value:fmt(m.llm_judge_count||0),spark:dailyTotals,color:'#a78bfa',trend:{has:false}},
    {label:"AI Spend",value:money(m.total_cost_usd),spark:costSeries,color:'#f59e0b',trend:costTrend},
  ];
  $('kpiRow').innerHTML=kpis.map(k=>`<div class="card kpi"><div class="spark">${sparkSVG(k.spark.length?k.spark:[0,0],k.color,70,24)}</div><div class="kpi-top">${esc(k.label)}</div><div class="kpi-value">${esc(k.value)}</div><div class="kpi-meta">${trendHtml(k.trend)}</div></div>`).join('');

  const checkLabels={prompt_injection:'Prompt Injection', pii_detection:'PII Detection', dangerous_params:'Tool Policy', tool_policy:'Tool Policy', budget_policy:'Budget'};
  const checks=state.checksBreakdown||[];
  $('guardrailKpis').innerHTML = checks.length
    ? checks.slice(0,4).map(c=>`<div class="card kpi"><div class="kpi-top">${esc(checkLabels[c.check_name]||c.check_name)}</div><div class="kpi-value ${c.flagged>0?'danger':''}">${c.flag_rate}%</div><div class="kpi-meta">${fmt(c.flagged)} signalé(s) sur ${fmt(c.total)} analysés</div></div>`).join('')
    : '<div class="empty" style="grid-column:1/-1">Pas encore de vérifications de sécurité enregistrées.</div>';

  const wrap=$('activityChartWrap');
  const W=wrap.clientWidth||600,H=250;
  if(daily.length<2){
    wrap.innerHTML='<div class="empty" style="padding-top:90px">Pas assez d\\\'historique pour un graphique (minimum 2 jours d\\\'activité).</div>';
  }else{
    const maxS=Math.max(1,...dailyTotals);
    const pad={l:40,r:15,t:15,b:28};
    const cw=W-pad.l-pad.r,ch=H-pad.t-pad.b;
    let svg=`<svg viewBox="0 0 ${W} ${H}" style="width:100%;height:100%">`;
    for(let i=0;i<4;i++){const y=pad.t+ch*i/3;svg+=`<line x1="${pad.l}" y1="${y}" x2="${W-pad.r}" y2="${y}" stroke="#1b2634" stroke-width="0.5"/>`;}
    let area=`M${pad.l},${pad.t+ch}`;
    dailyTotals.forEach((v,i)=>{const x=pad.l+(i/(dailyTotals.length-1))*cw,y=pad.t+ch-(v/maxS)*ch;area+=` L${x},${y}`;});
    area+=` L${W-pad.r},${pad.t+ch} Z`;
    svg+=`<path d="${area}" fill="#38bdf8" opacity="0.1"/>`;
    let l1='';dailyTotals.forEach((v,i)=>{const x=pad.l+(i/(dailyTotals.length-1))*cw,y=pad.t+ch-(v/maxS)*ch;l1+=i?` L${x},${y}`:`M${x},${y}`;});
    svg+=`<path d="${l1}" fill="none" stroke="#38bdf8" stroke-width="2" stroke-linecap="round"/>`;
    let l2='';dailyBlocked.forEach((v,i)=>{const x=pad.l+(i/(dailyBlocked.length-1))*cw,y=pad.t+ch-(v/maxS)*ch;l2+=i?` L${x},${y}`:`M${x},${y}`;});
    svg+=`<path d="${l2}" fill="none" stroke="#ff5d73" stroke-width="2" stroke-linecap="round" stroke-dasharray="4,3"/>`;
    daily.forEach((d,i)=>{const x=pad.l+(i/(daily.length-1))*cw;svg+=`<text x="${x}" y="${H-8}" fill="#536174" font-size="9" text-anchor="middle">${esc((d.day||'').slice(5))}</text>`;});
    [0,Math.round(maxS/2),maxS].forEach((v,i)=>{const y=pad.t+ch-(i/2)*ch;svg+=`<text x="${pad.l-6}" y="${y+3}" fill="#536174" font-size="9" text-anchor="end">${v}</text>`;});
    svg+='</svg>'; wrap.innerHTML=svg;
  }

  const r=m.risk_distribution||{};
  const maxR=Math.max(1,...['low','medium','high','critical'].map(k=>Number(r[k]||0)));
  $('riskGrid').innerHTML=['low','medium','high','critical'].map(k=>`<div class="risk ${k}"><div class="risk-label"><span>${k}</span><b>${fmt(r[k]||0)}</b></div><div class="risk-count">${maxR?Math.round((Number(r[k]||0)/maxR)*100):0}%</div><div class="risk-bar"><span style="width:${maxR?Number(r[k]||0)/maxR*100:0}%"></span></div></div>`).join('');

  const models=state.models||[];
  if(models.length){
    const maxReq=Math.max(...models.map(x=>x.requests));
    const palette=['#38bdf8','#a78bfa','#22d3ee','#f59e0b','#fb923c','#4ade80'];
    $('modelBreakdown').innerHTML=models.map((mo,i)=>`<div style="display:flex;align-items:center;gap:10px;margin-bottom:8px"><span style="width:120px;font-size:11px;color:#8e9bac;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(mo.name)}</span><div style="flex:1"><div class="risk-bar"><span style="width:${(mo.requests/maxReq*100).toFixed(1)}%;background:${palette[i%palette.length]};display:block;height:100%;border-radius:9px"></span></div></div><span style="width:50px;text-align:right;font-size:10px;font-weight:700;color:#cbd6e3">${fmt(mo.requests)}</span><span style="width:55px;text-align:right;font-size:10px;color:#647184">${mo.avg_latency_ms}ms</span></div>`).join('');
  }else{
    $('modelBreakdown').innerHTML='<div class="empty">Aucun modèle identifié pour l\\\'instant — passe model="..." à ton appel LLM pour l\\\'afficher ici.</div>';
  }

  const total=Math.max(1,m.total_spans||0),blk=m.blocked_operations||0,safe=total-blk;
  const safePct=(safe/total*100).toFixed(1);
  const R=55,C=65;
  $('pieChart').innerHTML=`<svg width="160" height="140" viewBox="0 0 130 130"><circle cx="${C}" cy="${C}" r="${R}" fill="none" stroke="#18212d" stroke-width="18"/><path d="${describeArc(C,C,R,0,safePct/100*360)}" fill="none" stroke="#38bdf8" stroke-width="18" stroke-linecap="round"/><path d="${describeArc(C,C,R,safePct/100*360,360)}" fill="none" stroke="#ff5d73" stroke-width="18" stroke-linecap="round"/><text x="${C}" y="${C-4}" text-anchor="middle" fill="#eef4fb" font-size="18" font-weight="800">${safePct}%</text><text x="${C}" y="${C+14}" text-anchor="middle" fill="#647184" font-size="9">Safe</text></svg><div style="margin-left:16px;display:flex;flex-direction:column;gap:8px"><div style="display:flex;align-items:center;gap:6px"><span style="width:8px;height:8px;border-radius:50%;background:#38bdf8"></span><span style="font-size:11px;color:#8e9bac">Safe — ${fmt(safe)}</span></div><div style="display:flex;align-items:center;gap:6px"><span style="width:8px;height:8px;border-radius:50%;background:#ff5d73"></span><span style="font-size:11px;color:#8e9bac">Blocked — ${fmt(blk)}</span></div></div>`;

  const hm=state.heatmap||[];
  const heat=$('heatmap');
  if(hm.length){
    const byHour={};
    hm.forEach(c=>{byHour[c.hour]=(byHour[c.hour]||0)+c.blocked;});
    const maxB=Math.max(1,...Object.values(byHour));
    let cells='';
    for(let h=0;h<24;h++){
      const v=byHour[h]||0, intensity=v/maxB;
      const bg=intensity>0.66?'#ff5d73':intensity>0.33?'#f59e0b':intensity>0?'#38bdf8':'#111824';
      cells+=`<div class="heat-cell" style="background:${bg};opacity:${v?0.4+intensity*0.6:0.5}" title="${h}h — ${v} blocage(s) réel(s)"></div>`;
    }
    heat.innerHTML=`<div class="heat" style="grid-template-columns:repeat(24,1fr)">${cells}</div>`;
  }else{
    heat.innerHTML='<div class="empty">Pas encore assez de données horaires.</div>';
  }

  const expensive=state.expensiveSpans||[];
  $('expensiveSpans').innerHTML=expensive.length?expensive.map(e=>`<div class="threat"><div style="min-width:0"><div style="font-size:12px;color:#cbd6e3;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(e.trace_id)} · ${esc(e.model||'modèle inconnu')}</div><div style="font-size:10px;color:#647184;margin-top:2px">${esc(e.span_type)}</div></div><span style="font-size:12px;font-weight:700;color:#ff5d73">${money(e.cost_usd)}</span></div>`).join(''):'<div class="empty">Aucune span coûteuse enregistrée.</div>';

  const events=state.recentEvents||[];
  const layerColors={regex:'#3b82f6',ml:'#8b5cf6',llm_judge:'#f59e0b',mixed:'#a855f7'};
  $('liveEvents').innerHTML=events.length?events.map(ev=>{
    const riskDot=ev.risk==='critical'?'🔴':ev.risk==='high'?'🟠':ev.risk==='medium'?'🟡':'🟢';
    const action=ev.blocked?('Bloqué — '+(ev.reason||'raison non précisée')):(ev.span_type+' autorisé');
    const color=layerColors[ev.layer]||'#8996a8';
    return `<div class="trace-row" style="grid-template-columns:auto 1fr auto;gap:10px"><span style="display:inline-block;padding:2px 7px;border-radius:999px;font-size:9px;font-weight:700;text-transform:uppercase;background:${color}18;color:${color};border:1px solid ${color}35">${esc(ev.layer)}</span><span style="font-size:11px;color:#8e9bac;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(action)}</span><span style="font-size:10px;color:#4e5b6d">${riskDot} ${esc(ev.created_at||'')}</span></div>`;
  }).join(''):'<div class="empty">Aucun événement pour l\\\'instant.</div>';

  renderRecentTraces();
}

function renderRecentTraces(){
}

function renderTraceTable(data){
  const tbody=$('traceTable');
  tbody.innerHTML=data.length?data.map(t=>`<tr onclick="openTrace('${esc(t.trace_id)}')" style="cursor:pointer"><td class="mono">${esc(t.trace_id)}</td><td>${fmt(t.span_count)}</td><td><span class="badge ${Number(t.blocked_count)>0?'blocked':'safe'}">${fmt(t.blocked_count)}</span></td><td>${layerBadge(t.detection_layers)}</td><td style="color:#8e9bac;font-size:10px">${esc(t.model||'—')}</td><td>${money(t.total_cost)}</td><td>${t.p50||'—'}ms</td><td>${t.p99||'—'}ms</td><td style="color:#647184">${esc(t.last_seen||'—')}</td></tr>`).join(''):'<tr><td colspan="9" class="empty">No traces available.</td></tr>';
}

function layerBadge(layer){
  if(!layer)return '<span class="badge neutral">—</span>';
  const l=(layer||'').toLowerCase();
  const cls=l.includes('llm_judge')?'layer-llm_judge':l.includes('mixed')?'layer-mixed':l.includes('ml')?'layer-ml':l.includes('regex')?'layer-regex':'layer-unknown';
  const txt=l.includes('llm_judge')?'LLM JUDGE':l.includes('mixed')?'MIXED':l.includes('ml')?'ML':l.includes('regex')?'REGEX':'UNKNOWN';
  return `<span class="layer-badge ${cls}">${txt}</span>`;
}

function filterTraces(){
  const q=$('traceSearch').value.toLowerCase();
  const blockedFilter=$('traceFilterBlocked').value;
  const layerFilter=$('traceFilterLayer').value;
  let filtered=state.allTraces;
  if(q)filtered=filtered.filter(t=>t.trace_id.toLowerCase().includes(q)||(t.detection_layers||'').toLowerCase().includes(q)||(t.model||'').toLowerCase().includes(q));
  if(blockedFilter==='blocked')filtered=filtered.filter(t=>Number(t.blocked_count)>0);
  if(blockedFilter==='safe')filtered=filtered.filter(t=>Number(t.blocked_count)===0);
  if(layerFilter)filtered=filtered.filter(t=>(t.detection_layers||'').toLowerCase().includes(layerFilter));
  renderTraceTable(filtered);
}

function exportTracesCSV(){
  const rows=state.allTraces.map(t=>`${t.trace_id},${t.span_count},${t.blocked_count},"${t.detection_layers||''}","${t.model||''}",${t.total_cost},${t.p50||''},${t.p99||''},${t.last_seen||''}`).join('\n');
  const csv='trace_id,span_count,blocked_count,detection_layers,model,total_cost,p50_ms,p99_ms,last_seen\n'+rows;
  const blob=new Blob([csv],{type:'text/csv'});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='agentguard_traces.csv';a.click();
  toast('CSV exported');
}

function renderModels(){
  const models=state.models||[];
  if(!models.length){
    $('modelCards').innerHTML='<div class="empty" style="grid-column:1/-1">Aucun modèle observé pour l\\\'instant. Passe model="..." dans les kwargs de ton appel LLM (guard_llm_call le capture automatiquement) pour peupler cette page.</div>';
    $('modelComparison').innerHTML='';
    return;
  }
  $('modelCards').innerHTML=models.map(m=>`<div class="card kpi"><div class="kpi-top">${esc(m.name)}</div><div class="kpi-value">${fmt(m.requests)}</div><div class="kpi-meta">${money(m.total_cost_usd)} · ${fmt(m.blocked_count)} bloqué(s)</div><div style="margin-top:10px;font-size:10px;color:#647184">Latence moy.: <strong style="color:#8e9bac">${m.avg_latency_ms}ms</strong></div></div>`).join('');

  const comp=$('modelComparison');
  const W=comp.clientWidth||600,H=250;
  const pad={l:45,r:15,t:15,b:30};
  const cw=W-pad.l-pad.r,ch=H-pad.t-pad.b;
  const maxCost=Math.max(...models.map(m=>m.total_cost_usd),0.000001);
  const maxLat=Math.max(...models.map(m=>m.avg_latency_ms),1);
  let svg=`<svg viewBox="0 0 ${W} ${H}" style="width:100%;height:100%">`;
  for(let i=0;i<3;i++){const y=pad.t+ch*i/2;svg+=`<line x1="${pad.l}" y1="${y}" x2="${W-pad.r}" y2="${y}" stroke="#1b2634" stroke-width="0.5"/>`;}
  const bw=cw/models.length*0.35;
  models.forEach((m,i)=>{const x=pad.l+(i+0.3)*(cw/models.length);const h=(m.total_cost_usd/maxCost)*ch;svg+=`<rect x="${x}" y="${pad.t+ch-h}" width="${bw}" height="${h}" fill="#38bdf8" rx="3" opacity="0.8"/>`;});
  let lpath='';
  models.forEach((m,i)=>{const x=pad.l+(i+0.5)*(cw/models.length);const y=pad.t+ch-(m.avg_latency_ms/maxLat)*ch;lpath+=i?` L${x},${y}`:`M${x},${y}`;svg+=`<circle cx="${x}" cy="${y}" r="3" fill="#ff5d73"/>`;});
  svg+=`<path d="${lpath}" fill="none" stroke="#ff5d73" stroke-width="2" stroke-linecap="round"/>`;
  models.forEach((m,i)=>{const x=pad.l+(i+0.5)*(cw/models.length);svg+=`<text x="${x}" y="${H-8}" fill="#536174" font-size="9" text-anchor="middle">${esc(m.name.split('-')[0])}</text>`;});
  svg+='<text x="10" y="20" fill="#647184" font-size="9">Cost ($)</text>';
  svg+='<text x="10" y="35" fill="#647184" font-size="9">Latence moy. (ms)</text>';
  svg+='</svg>';
  comp.innerHTML=svg;
}

function renderGuardrails(){
  const checkLabels={prompt_injection:'Prompt Injection', pii_detection:'PII Detection', dangerous_params:'Tool Policy', tool_policy:'Tool Policy', budget_policy:'Budget'};
  const checks=state.checksBreakdown||[];

  $('guardrailDetail').innerHTML = checks.length
    ? checks.map(c=>`<div class="card kpi"><div class="kpi-top">${esc(checkLabels[c.check_name]||c.check_name)}</div><div class="kpi-value ${c.flagged>0?'danger':''}">${c.flag_rate}%</div><div class="kpi-meta">${fmt(c.flagged)} signalé(s) · ${fmt(c.total)} analysés au total</div></div>`).join('')
    : '<div class="empty" style="grid-column:1/-1">Aucune vérification enregistrée pour l\\\'instant.</div>';

  const wrap=$('guardrailStacked');
  if(!checks.length){
    wrap.innerHTML='<div class="empty">Pas encore de données.</div>';
  }else{
    const W=wrap.clientWidth||500,H=250;
    const pad={l:110,r:15,t:15,b:15};
    const cw=W-pad.l-pad.r,ch=H-pad.t-pad.b;
    const rowH=ch/checks.length;
    const maxTotal=Math.max(1,...checks.map(c=>c.total));
    let svg=`<svg viewBox="0 0 ${W} ${H}" style="width:100%;height:100%">`;
    checks.forEach((c,i)=>{
      const y=pad.t+i*rowH+rowH*0.2, barH=rowH*0.6;
      const wTotal=(c.total/maxTotal)*cw, wFlag=(c.flagged/maxTotal)*cw;
      svg+=`<text x="${pad.l-8}" y="${y+barH/2+3}" fill="#8e9bac" font-size="10" text-anchor="end">${esc(checkLabels[c.check_name]||c.check_name)}</text>`;
      svg+=`<rect x="${pad.l}" y="${y}" width="${wTotal}" height="${barH}" fill="#38bdf8" opacity="0.25" rx="3"/>`;
      svg+=`<rect x="${pad.l}" y="${y}" width="${wFlag}" height="${barH}" fill="#ff5d73" rx="3"/>`;
    });
    svg+='</svg>';
    wrap.innerHTML=svg;
  }

  const trend=$('guardrailTrend');
  const daily=state.dailyTrend||[];
  if(daily.length<2){
    trend.innerHTML='<div class="empty">Pas assez d\\\'historique pour une tendance.</div>';
  }else{
    const W2=trend.clientWidth||500;
    const trendData=daily.map(d=>d.blocked);
    const maxT=Math.max(1,...trendData);
    let svg2=`<svg viewBox="0 0 ${W2} 250" style="width:100%;height:100%">`;
    let area=`M0,250 `;trendData.forEach((v,i)=>{const x=(i/(trendData.length-1))*W2,y=250-(v/maxT)*220;area+=`L${x},${y} `;});
    area+='L'+W2+',250 Z';
    svg2+=`<path d="${area}" fill="#ff5d73" opacity="0.08"/>`;
    let line='';trendData.forEach((v,i)=>{const x=(i/(trendData.length-1))*W2,y=250-(v/maxT)*220;line+=i?` L${x},${y}`:`M${x},${y}`;});
    svg2+=`<path d="${line}" fill="none" stroke="#ff5d73" stroke-width="2" stroke-linecap="round"/>`;
    svg2+='</svg>';
    trend.innerHTML=svg2;
  }
}

function renderThreats(){
  const m=state.metrics||{};
  const r=m.risk_distribution||{};
  $('threatKpis').innerHTML=`<div class="card kpi"><div class="kpi-top">Blocked</div><div class="kpi-value danger">${fmt(m.blocked_operations||0)}</div><div class="kpi-meta">All observed blocked operations</div></div>
    <div class="card kpi"><div class="kpi-top">High + Critical</div><div class="kpi-value">${fmt(Number(r.high||0)+Number(r.critical||0))}</div><div class="kpi-meta">Risk signals</div></div>
    <div class="card kpi"><div class="kpi-top">ML Score</div><div class="kpi-value">${(Number(m.avg_ml_score||0)*100).toFixed(1)}%</div><div class="kpi-meta">Average observed score</div></div>
    <div class="card kpi"><div class="kpi-top">LLM Score</div><div class="kpi-value">${(Number(m.avg_llm_score||0)*100).toFixed(1)}%</div><div class="kpi-meta">Average Judge score</div></div>`;
  const arr=m.top_threats||[];
  $('threatFull').innerHTML=arr.length?arr.map(t=>`<div class="threat"><span class="threat-name" title="${esc(t.reason||'Unknown')}">${esc(t.reason||'Unknown')}</span><span class="threat-count">${fmt(t.count)}</span></div>`).join(''):'<div class="empty">No blocked threats observed.</div>';
}

function renderDetection(d){
  state.detection=d;
  const a=d.layer_accuracy||[];
  $('detectionCards').innerHTML=a.length?a.map(x=>{const l=(x.layer||'').toLowerCase();const barColor=l==='regex'?'#3b82f6':l==='ml'?'#8b5cf6':l==='llm_judge'?'#f59e0b':l==='mixed'?'#a855f7':'#38bdf8';return `<div class="det"><div class="det-label">${esc(x.layer||'unknown')}</div><div class="det-value">${fmt(x.total)}</div><div class="det-rate">${Number(x.block_rate||0).toFixed(2)}% blocked · ${fmt(x.blocked)} decisions</div><div class="bar"><span style="width:${Math.min(100,Number(x.block_rate||0))}%;background:${barColor}"></span></div></div>`;}).join(''):'<div class="empty">No detection-layer data yet.</div>';
  const ml=d.ml_score_distribution||[];
  $('mlDistribution').innerHTML=ml.length?ml.map(x=>`<div class="threat"><span>${esc(x.range)}</span><b>${fmt(x.count)}</b></div>`).join(''):'<div class="empty">No ML scores recorded.</div>';
  const llm=d.llm_score_distribution||[];
  $('llmDistribution').innerHTML=llm.length?llm.map(x=>`<div class="threat"><span>${esc(x.category)}</span><b>${fmt(x.count)}</b></div>`).join(''):'<div class="empty">No LLM Judge scores recorded.</div>';
}

function renderUsage(){
  const m=state.metrics||{};
  $('usageKpis').innerHTML=`<div class="card kpi"><div class="kpi-top">Total Cost</div><div class="kpi-value">${money(m.total_cost_usd||0)}</div></div>
    <div class="card kpi"><div class="kpi-top">Spans</div><div class="kpi-value">${fmt(m.total_spans||0)}</div></div>
    <div class="card kpi"><div class="kpi-top">Avg Latency</div><div class="kpi-value">${Number(m.avg_latency_ms||0).toFixed(1)}ms</div></div>
    <div class="card kpi"><div class="kpi-top">LLM Analyzed</div><div class="kpi-value">${fmt(m.llm_judge_count||0)}</div></div>`;

  const cf=$('costForecast');
  const hist=(state.costTrend||[]).map(d=>d.cost);
  if(hist.length<2){
    cf.innerHTML='<div class="empty" style="padding-top:90px">Pas assez d\\\'historique de coût pour une projection (minimum 2 jours).</div>';
  }else{
    const W=cf.clientWidth||500;
    const dailyAvgDelta=(hist[hist.length-1]-hist[0])/(hist.length-1);
    const forecastDays=7;
    const forecast=Array.from({length:forecastDays},(_,i)=>Math.max(0,hist[hist.length-1]+dailyAvgDelta*(i+1)));
    const maxC=Math.max(...hist,...forecast,0.000001);
    const histShare=0.65;
    let svg=`<svg viewBox="0 0 ${W} 250" style="width:100%;height:100%">`;
    let area=`M0,250 `;hist.forEach((v,i)=>{const x=(i/(hist.length-1))*(W*histShare),y=250-(v/maxC)*220;area+=`L${x},${y} `;});
    const lastX=W*histShare;
    forecast.forEach((v,i)=>{const x=lastX+(i/(forecast.length-1))*(W*(1-histShare)),y=250-(v/maxC)*220;area+=`L${x},${y} `;});
    area+='L'+W+',250 Z';
    svg+=`<path d="${area}" fill="#38bdf8" opacity="0.08"/>`;
    let line='';hist.forEach((v,i)=>{const x=(i/(hist.length-1))*(W*histShare),y=250-(v/maxC)*220;line+=i?` L${x},${y}`:`M${x},${y}`;});
    svg+=`<path d="${line}" fill="none" stroke="#38bdf8" stroke-width="2" stroke-linecap="round"/>`;
    let fline='';forecast.forEach((v,i)=>{const x=lastX+(i/(forecast.length-1))*(W*(1-histShare)),y=250-(v/maxC)*220;fline+=i?` L${x},${y}`:`M${lastX},${250-(hist[hist.length-1]/maxC)*220}`;});
    svg+=`<path d="${fline}" fill="none" stroke="#a78bfa" stroke-width="2" stroke-linecap="round" stroke-dasharray="5,3"/>`;
    svg+=`<line x1="${lastX}" y1="0" x2="${lastX}" y2="250" stroke="#64748b" stroke-width="0.5" stroke-dasharray="4,4"/>`;
    svg+='<text x="10" y="20" fill="#647184" font-size="9">Historique réel</text>';
    svg+=`<text x="${lastX+5}" y="20" fill="#a78bfa" font-size="9">Projection linéaire →</text>`;
    svg+='</svg>';
    cf.innerHTML=svg;
  }

  const tu=$('tokenUsage');
  const lat=state.latencyDist||{};
  if(!lat.count){
    tu.innerHTML='<div class="empty" style="padding-top:90px">Pas encore de données de latence.</div>';
  }else{
    const W2=tu.clientWidth||500;
    const bars=[{label:'p50',v:lat.p50,color:'#35d07f'},{label:'p95',v:lat.p95,color:'#f59e0b'},{label:'p99',v:lat.p99,color:'#ff5d73'},{label:'max',v:lat.max,color:'#a78bfa'}];
    const maxV=Math.max(1,...bars.map(b=>b.v));
    const bw=W2/bars.length*0.5;
    let svg2=`<svg viewBox="0 0 ${W2} 250" style="width:100%;height:100%">`;
    bars.forEach((b,i)=>{
      const x=(i+0.25)*(W2/bars.length), h=(b.v/maxV)*200;
      svg2+=`<rect x="${x}" y="${220-h}" width="${bw}" height="${h}" fill="${b.color}" rx="4"/>`;
      svg2+=`<text x="${x+bw/2}" y="${220-h-8}" fill="#cbd6e3" font-size="11" text-anchor="middle" font-weight="700">${b.v.toFixed(0)}ms</text>`;
      svg2+=`<text x="${x+bw/2}" y="240" fill="#536174" font-size="10" text-anchor="middle">${b.label}</text>`;
    });
    svg2+='</svg>';
    tu.innerHTML=svg2;
  }
}

function renderAudit(){
  const arr=state.allTraces.slice(0,25);
  $('auditTable').innerHTML=arr.length?arr.map(t=>`<tr><td style="color:#647184">${esc(t.last_seen||'—')}</td><td class="mono">${esc(t.trace_id)}</td><td>${fmt(t.span_count)} span(s)</td><td style="color:#8e9bac;font-size:10px">${esc(t.model||'—')}</td><td><span class="badge ${Number(t.blocked_count)>0?'blocked':'safe'}">${Number(t.blocked_count)>0?'BLOCK':'ALLOW'}</span></td><td style="color:#647184">${esc(t.detection_layers||'—')}</td></tr>`).join(''):'<tr><td colspan="6" class="empty">No audit data.</td></tr>';
}

async function openTrace(id){
  try{
    $('traceModal').classList.add('open');
    $('modalTitle').textContent=id;
    $('modalBody').innerHTML='<div class="empty">Loading trace…</div>';
    const rows=await api('/api/traces/'+encodeURIComponent(id));
    if(!rows.length){$('modalBody').innerHTML='<div class="empty">No span detail available for this trace.</div>';return;}

    const totalDur=Math.max(...rows.map(r=>Number(r.timestamp||0)+Number(r.latency_ms||0)))-Math.min(...rows.map(r=>Number(r.timestamp||0)));
    const minT=Math.min(...rows.map(r=>Number(r.timestamp||0)));
    const trackW=600;
    let ganttHtml='<div style="margin-bottom:20px"><div style="font-size:12px;font-weight:700;margin-bottom:10px">Execution Timeline</div><div class="gantt">';
    rows.forEach((r,i)=>{
      const start=((Number(r.timestamp||0)-minT)/totalDur)*trackW;
      const width=Math.max(20,(Number(r.latency_ms||0)/totalDur)*trackW);
      const blocked=!!r.blocked;
      const layer=(r.detection_layer||'unknown').toLowerCase();
      const barCls=blocked?'blocked':layer==='llm_judge'?'warn':'safe';
      ganttHtml+=`<div class="gantt-row"><div class="gantt-label">${esc(r.span_type||'span')} — ${esc(r.model||'—')}</div><div class="gantt-track"><div class="gantt-bar ${barCls}" style="left:${start}px;width:${width}px" title="${esc(r.span_type||'')} — ${Number(r.latency_ms||0).toFixed(1)}ms"></div></div></div>`;
    });
    ganttHtml+='</div></div>';

    ganttHtml+='<div class="timeline">'+rows.map(r=>{
      const blocked=!!r.blocked;
      const checks=Array.isArray(r.security_checks)?r.security_checks:[];
      const layer=(r.detection_layer||'unknown').toLowerCase();
      const layerCls=layer==='regex'?'layer-regex':layer==='ml'?'layer-ml':layer==='llm_judge'?'layer-llm_judge':layer==='mixed'?'layer-mixed':'layer-unknown';
      const layerTxt=layer==='regex'?'REGEX':layer==='ml'?'ML':layer==='llm_judge'?'LLM JUDGE':layer==='mixed'?'MIXED':'UNKNOWN';
      let scores='';
      if(r.ml_score!=null)scores+=`<span class="score-pill low" style="margin-right:6px">ML ${(r.ml_score*100).toFixed(1)}%</span>`;
      if(r.llm_score!=null){const cls=r.llm_score>0.85?'high':r.llm_score>0.7?'medium':'low';scores+=`<span class="score-pill ${cls}">LLM ${(r.llm_score*100).toFixed(1)}%</span>`;}
      return `<div class="event"><div class="event-time">${esc(r.created_at||'')}</div><div class="event-line"></div><div class="event-card ${blocked?'block':''}"><div class="event-title">${esc(r.span_type||'span')} <span class="layer-badge ${layerCls}">${layerTxt}</span> ${blocked?'<span class="badge blocked">blocked</span>':'<span class="badge safe">allowed</span>'} ${scores}</div><div class="event-meta">${Number(r.latency_ms||0).toFixed(1)} ms · ${money(r.cost_usd)} · ${esc(r.model||'—')}</div>${r.block_reason?`<div class="event-meta" style="color:#ff7e8d;margin-top:8px">Reason: ${esc(r.block_reason)}</div>`:''}${r.llm_reason?`<div class="event-meta" style="color:#fbbf24;margin-top:4px">LLM: ${esc(r.llm_reason)}</div>`:''}<div class="json">${esc(JSON.stringify({input:r.input_data,output:r.output_data,security_checks:checks},null,2))}</div></div></div>`;
    }).join('')+'</div>';
    $('modalBody').innerHTML=ganttHtml;
  }catch(e){$('modalBody').innerHTML='<div class="empty">Unable to load trace: '+esc(e.message)+'</div>';}
}
function closeModal(){$('traceModal').classList.remove('open')}

async function refreshAll(){
  try{
    $('lastSync').textContent='Syncing…';
    const [m,t,d,models,checks,heatmap,expensive,costTrend,latencyDist,recentEvents,dailyTrend]=await Promise.all([
      api('/api/metrics'), api('/api/traces'), api('/api/detection/stats'),
      api('/api/models'), api('/api/checks/breakdown'), api('/api/heatmap'),
      api('/api/spans/expensive'), api('/api/cost/trend'), api('/api/latency/distribution'),
      api('/api/events/recent'), api('/api/trend/daily'),
    ]);
    state.allTraces=t.map(x=>({...x, model:x.model||null, p50:x.p50||null, p99:x.p99||null}));
    state.traces=t;
    state.models=models;
    state.checksBreakdown=checks;
    state.heatmap=heatmap;
    state.expensiveSpans=expensive;
    state.costTrend=costTrend;
    state.latencyDist=latencyDist;
    state.recentEvents=recentEvents;
    state.dailyTrend=dailyTrend;
    renderMetrics(m);
    renderDetection(d);
    $('lastSync').textContent='Updated '+new Date().toLocaleTimeString();
    toast('Dashboard refreshed');
  }catch(e){
    $('lastSync').textContent='Offline';
    toast('Collector unavailable: '+e.message);
  }
}

function renderMetrics(m){
  state.metrics=m;
  renderOverview();
  renderThreats();
  renderUsage();
  renderAudit();
}

window.addEventListener('resize',()=>{if(state.metrics){renderOverview();renderUsage();}});
refreshAll();
setInterval(refreshAll,15000);
</script>
</body></html>
'''

@app.route("/")
def dashboard():
    resp = make_response(render_template_string(DASHBOARD_HTML))
    return set_auth_cookie_if_valid(resp)

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
        r["input_data"] = json.loads(r["input_data"])
        r["output_data"] = json.loads(r["output_data"])
        r["security_checks"] = json.loads(r["security_checks"])
        r["blocked"] = bool(r["blocked"])
    conn.close()

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Trace Detail</title>
        <style>
            body { font-family: -apple-system, sans-serif; background: #0b1121; color: #e2e8f0; padding: 24px; }
            .back { color: #38bdf8; text-decoration: none; font-size: 0.9rem; margin-bottom: 20px; display: inline-block; }
            h1 { font-size: 1.3rem; margin-bottom: 20px; }
            .span-card { background: #1e293b; border: 1px solid #334155; border-radius: 14px; padding: 20px; margin-bottom: 16px; border-left: 4px solid #38bdf8; }
            .span-card.blocked { border-left-color: #ef4444; background: #1e293b; }
            .span-type { color: #38bdf8; font-weight: 700; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em; display: flex; align-items: center; flex-wrap: wrap; gap: 8px; }
            .meta { color: #64748b; font-size: 0.82rem; margin-top: 4px; }
            .detection-badge { display: inline-block; padding: 2px 10px; border-radius: 10px; font-size: 0.7rem; font-weight: 600; }
            .badge-regex { background: #3b82f620; color: #3b82f6; border: 1px solid #3b82f640; }
            .badge-ml { background: #8b5cf620; color: #8b5cf6; border: 1px solid #8b5cf640; }
            .badge-llm { background: #f59e0b20; color: #f59e0b; border: 1px solid #f59e0b40; }
            .badge-mixed { background: #a855f720; color: #a855f7; border: 1px solid #a855f740; }
            .llm-score { font-size: 0.7rem; }
            .llm-score.high { color: #ef4444; }
            .llm-score.medium { color: #f59e0b; }
            .llm-score.low { color: #22c55e; }
            .check { padding: 10px 14px; margin: 6px 0; border-radius: 8px; font-size: 0.88rem; }
            .check-pass { background: #22c55e15; border: 1px solid #22c55e40; }
            .check-fail { background: #ef444415; border: 1px solid #ef444440; }
            pre { background: #0f172a; padding: 14px; border-radius: 10px; overflow-x: auto; font-size: 0.82rem; line-height: 1.5; border: 1px solid #334155; }
            h3 { font-size: 0.85rem; color: #94a3b8; text-transform: uppercase; margin: 16px 0 8px; letter-spacing: 0.03em; }
        </style>
    </head>
    <body>
        <a class="back" href="/">← Retour au Dashboard</a>
        <h1>Trace <code style="color:#94a3b8">""" + trace_id[:20] + """...</code></h1>
    """
    for row in rows:
        checks = json.loads(row["security_checks"])
        blocked = bool(row["blocked"])
        
        layer = row.get("detection_layer", "unknown")
        badge_classes = {
            "regex": "badge-regex",
            "ml": "badge-ml",
            "llm_judge": "badge-llm",
            "mixed": "badge-mixed"
        }
        badge_class = badge_classes.get(layer, "badge-regex")
        
        ml_score = row.get("ml_score")
        llm_score = row.get("llm_score")
        llm_reason = row.get("llm_reason")
        
        scores_html = ""
        if ml_score is not None:
            scores_html += f'<span style="color:#8b5cf6;font-size:0.7rem;">ML: {(ml_score*100):.1f}%</span> '
        if llm_score is not None:
            score_class = "high" if llm_score > 0.85 else "medium" if llm_score > 0.7 else "low"
            scores_html += f'<span class="llm-score {score_class}">🎯 LLM: {(llm_score*100):.1f}%</span>'
            if llm_reason:
                scores_html += f' <span style="color:#94a3b8;font-size:0.65rem;">— {llm_reason[:60]}…</span>'
        
        html += f"""
        <div class="span-card {'blocked' if blocked else ''}">
            <div class="span-type">
                {row["span_type"]} — {row["latency_ms"]:.0f}ms — ${row["cost_usd"]:.6f}
                <span class="detection-badge {badge_class}">{layer.upper()}</span>
                {scores_html}
            </div>
            <div class="meta">{row["created_at"]}</div>
            <h3>📥 Input</h3>
            <pre>{json.dumps(json.loads(row["input_data"]), indent=2, ensure_ascii=False)}</pre>
            <h3>📤 Output</h3>
            <pre>{json.dumps(json.loads(row["output_data"]), indent=2, ensure_ascii=False)}</pre>
            <h3>🛡️ Security Checks ({len(checks)})</h3>
            {''.join(f'<div class="check check-{"pass" if c["passed"] else "fail"}">{"✅" if c["passed"] else "🚨"} <strong>{c["check_name"]}</strong> — <span style="color:{"#22c55e" if c["risk_level"]=="low" else "#f59e0b" if c["risk_level"]=="medium" else "#ef4444"}">{c["risk_level"]}</span><br><span style="color:#94a3b8;font-size:0.8rem">{c["details"]}</span></div>' for c in checks)}
        </div>
        """
    html += "</body></html>"
    resp = make_response(html)
    return set_auth_cookie_if_valid(resp)

@app.errorhandler(Exception)
def handle_unexpected_error(e):
    from werkzeug.exceptions import HTTPException
    if isinstance(e, HTTPException):
        return e
    app.logger.exception("Unhandled error")
    return jsonify({"error": "Internal server error"}), 500

@app.route("/api/key")
@limiter.limit("5 per minute")
def show_key():
    if not ADMIN_SECRET:
        return jsonify({"error": "AGENTGUARD_ADMIN_SECRET not configured — endpoint disabled"}), 404
    admin_secret = request.args.get("admin", "")
    if safe_compare(admin_secret, ADMIN_SECRET):
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

if _API_KEY_WAS_GENERATED and DB_TYPE == "postgres":
    print("[AG] 🚨 PostgreSQL actif (config prod) mais AGENTGUARD_API_KEY n'est "
          "pas fixée — chaque redémarrage invalidera les intégrations SDK "
          "existantes. Configure AGENTGUARD_API_KEY dans les variables d'env Render.")

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 8080))
    print(f"🛡️ AgentGuard Collector v4.1 running on http://0.0.0.0:{port}")
    print(f"   DB: {DB_TYPE}")
    print(f"   Detection: Regex + ML (if enabled) + LLM Judge (if enabled)")
    app.run(host="0.0.0.0", port=port, debug=False)
