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
    import psycopg2
    import psycopg2.extras
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
    else:
        cur = conn.cursor()
        org_filter = "?"

    cur.execute(f"""
        SELECT trace_id, COUNT(*) as span_count,
               SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked_count,
               SUM(cost_usd) as total_cost,
               MAX(created_at) as last_seen,
               GROUP_CONCAT(DISTINCT detection_layer) as detection_layers
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
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
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
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
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
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
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
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AgentGuard — AI Runtime Security</title>
<style>
/* ============================================
   THEME CLAIR & VIF — AgentGuard Dashboard
   ============================================ */

:root {
  /* Fonds clairs */
  --bg-deep: #f8fafc;
  --bg-base: #ffffff;
  --bg-surface: #f1f5f9;
  --bg-elevated: #e2e8f0;

  /* Bordures */
  --border-subtle: #e2e8f0;
  --border-default: #cbd5e1;
  --border-active: #94a3b8;

  /* Texte */
  --text-primary: #0f172a;
  --text-secondary: #334155;
  --text-tertiary: #64748b;
  --text-muted: #94a3b8;

  /* Couleurs VIVES */
  --accent: #0284c7;
  --accent-soft: #0ea5e9;
  --success: #16a34a;
  --warning: #f59e0b;
  --danger: #dc2626;
  --info: #7c3aed;
  --pink: #db2777;
  --teal: #0d9488;

  --space-xs: 4px;
  --space-sm: 8px;
  --space-md: 16px;
  --space-lg: 24px;
  --space-xl: 32px;
  --radius-sm: 8px;
  --radius-md: 12px;
  --radius-lg: 16px;
  --shadow-sm: 0 1px 3px rgba(0,0,0,0.08);
  --shadow-md: 0 4px 16px rgba(0,0,0,0.08);
  --shadow-lg: 0 8px 32px rgba(0,0,0,0.1);
}

* { box-sizing: border-box; margin: 0; padding: 0; }

html, body {
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  background: var(--bg-deep);
  color: var(--text-primary);
  font-size: 14px;
  line-height: 1.5;
  min-height: 100vh;
  -webkit-font-smoothing: antialiased;
}

.app { display: flex; min-height: 100vh; }

/* Sidebar claire */
.sidebar {
  width: 260px;
  background: var(--bg-base);
  border-right: 1px solid var(--border-subtle);
  position: fixed;
  inset: 0 auto 0 0;
  z-index: 50;
  display: flex;
  flex-direction: column;
  padding: var(--space-lg) 0;
}

.brand {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 0 var(--space-lg) var(--space-xl);
  border-bottom: 1px solid var(--border-subtle);
  margin: 0 var(--space-md) var(--space-md);
  padding-bottom: var(--space-lg);
}

.brand-mark {
  width: 40px;
  height: 40px;
  border-radius: var(--radius-md);
  background: linear-gradient(135deg, var(--accent), var(--info));
  display: grid;
  place-items: center;
  color: white;
  font-weight: 800;
  font-size: 18px;
  box-shadow: 0 4px 12px rgba(2, 132, 199, 0.3);
}

.brand-text strong {
  font-size: 17px;
  font-weight: 800;
  letter-spacing: -0.02em;
  display: block;
  color: var(--text-primary);
}

.brand-text span {
  font-size: 11px;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.1em;
  margin-top: 2px;
  display: block;
  font-weight: 600;
}

.nav {
  flex: 1;
  overflow-y: auto;
  padding: 0 var(--space-sm);
}

.nav-label {
  font-size: 10px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.14em;
  color: var(--text-muted);
  padding: var(--space-lg) var(--space-md) var(--space-sm);
}

.nav button {
  width: 100%;
  border: none;
  background: transparent;
  color: var(--text-tertiary);
  text-align: left;
  padding: 11px var(--space-md);
  border-radius: var(--radius-md);
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 12px;
  font: inherit;
  font-size: 13px;
  font-weight: 600;
  transition: all 0.15s ease;
  margin-bottom: 3px;
}

.nav button:hover {
  background: var(--bg-surface);
  color: var(--text-secondary);
}

.nav button.active {
  background: rgba(2, 132, 199, 0.1);
  color: var(--accent);
  font-weight: 700;
  box-shadow: inset 3px 0 0 var(--accent);
}

.nav button svg {
  width: 18px;
  height: 18px;
  stroke: currentColor;
  stroke-width: 2;
  fill: none;
  flex-shrink: 0;
}

.sidebar-footer {
  margin-top: auto;
  padding: var(--space-md) var(--space-lg) 0;
  border-top: 1px solid var(--border-subtle);
}

.status-indicator {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 12px;
  font-weight: 600;
  color: var(--text-tertiary);
}

.status-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--success);
  box-shadow: 0 0 0 3px rgba(22, 163, 74, 0.2);
  animation: pulse 2s infinite;
}

@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.5; }
}

.version {
  font-size: 11px;
  color: var(--text-muted);
  margin-top: var(--space-sm);
  font-weight: 500;
}

/* Main */
.main {
  margin-left: 260px;
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
}

.topbar {
  height: 68px;
  background: rgba(255, 255, 255, 0.95);
  backdrop-filter: blur(12px);
  border-bottom: 1px solid var(--border-subtle);
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 var(--space-xl);
  position: sticky;
  top: 0;
  z-index: 40;
}

.breadcrumb {
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 14px;
}

.breadcrumb small { color: var(--text-muted); font-size: 13px; font-weight: 500; }
.breadcrumb strong { font-weight: 700; color: var(--text-primary); }

.top-actions {
  display: flex;
  align-items: center;
  gap: var(--space-sm);
}

/* Content */
.content {
  padding: var(--space-xl);
  max-width: 1600px;
  margin: 0 auto;
  width: 100%;
}

/* Page Header */
.page-header {
  margin-bottom: var(--space-xl);
  display: flex;
  justify-content: space-between;
  align-items: flex-end;
  gap: var(--space-md);
}

.page-header-left { flex: 1; }

.eyebrow {
  font-size: 11px;
  font-weight: 800;
  text-transform: uppercase;
  letter-spacing: 0.14em;
  color: var(--accent);
  margin-bottom: var(--space-xs);
}

.page-title {
  font-size: 30px;
  font-weight: 900;
  letter-spacing: -0.03em;
  color: var(--text-primary);
  margin-bottom: var(--space-xs);
}

.page-subtitle {
  font-size: 14px;
  color: var(--text-tertiary);
  max-width: 600px;
  line-height: 1.6;
  font-weight: 500;
}

/* Buttons */
.btn {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 9px 16px;
  border-radius: var(--radius-md);
  border: 1px solid var(--border-default);
  background: var(--bg-base);
  color: var(--text-secondary);
  font: inherit;
  font-size: 13px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.15s ease;
  box-shadow: var(--shadow-sm);
}

.btn:hover {
  background: var(--bg-surface);
  border-color: var(--border-active);
  color: var(--text-primary);
  transform: translateY(-1px);
  box-shadow: var(--shadow-md);
}

.btn-primary {
  background: var(--accent);
  border-color: var(--accent);
  color: white;
  font-weight: 700;
}

.btn-primary:hover {
  background: var(--accent-soft);
  border-color: var(--accent-soft);
  box-shadow: 0 4px 16px rgba(2, 132, 199, 0.3);
  transform: translateY(-1px);
}

.btn-ghost {
  background: transparent;
  border-color: transparent;
  box-shadow: none;
}

/* Badges */
.badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 5px 12px;
  border-radius: 999px;
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.badge-success {
  background: rgba(22, 163, 74, 0.12);
  color: var(--success);
  border: 1px solid rgba(22, 163, 74, 0.25);
}

.badge-danger {
  background: rgba(220, 38, 38, 0.1);
  color: var(--danger);
  border: 1px solid rgba(220, 38, 38, 0.2);
}

.badge-neutral {
  background: rgba(148, 163, 184, 0.15);
  color: var(--text-tertiary);
  border: 1px solid rgba(148, 163, 184, 0.25);
}

.badge-warning {
  background: rgba(245, 158, 11, 0.12);
  color: #d97706;
  border: 1px solid rgba(245, 158, 11, 0.25);
}

/* Cards */
.card {
  background: var(--bg-base);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-sm);
  transition: all 0.2s ease;
}

.card:hover {
  box-shadow: var(--shadow-md);
  border-color: var(--border-default);
  transform: translateY(-1px);
}

.card-header {
  padding: var(--space-md) var(--space-lg);
  border-bottom: 1px solid var(--border-subtle);
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.card-title {
  font-size: 15px;
  font-weight: 800;
  color: var(--text-primary);
}

.card-subtitle {
  font-size: 12px;
  color: var(--text-muted);
  margin-top: 3px;
  font-weight: 500;
}

.card-body {
  padding: var(--space-lg);
}

/* Grids */
.grid-kpi {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: var(--space-md);
  margin-bottom: var(--space-xl);
}

.grid-2 { display: grid; grid-template-columns: repeat(2, 1fr); gap: var(--space-md); }
.grid-3 { display: grid; grid-template-columns: repeat(3, 1fr); gap: var(--space-md); }
.grid-4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: var(--space-md); }

.layout-split {
  display: grid;
  grid-template-columns: 1.6fr 0.8fr;
  gap: var(--space-md);
}

/* KPI Cards */
.kpi-card {
  padding: var(--space-lg);
  position: relative;
  overflow: hidden;
  background: linear-gradient(135deg, var(--bg-base), var(--bg-surface));
}

.kpi-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: var(--space-sm);
}

.kpi-label {
  font-size: 11px;
  font-weight: 700;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.08em;
}

.kpi-value {
  font-size: 34px;
  font-weight: 900;
  letter-spacing: -0.04em;
  color: var(--text-primary);
  margin: var(--space-sm) 0;
  line-height: 1;
}

.kpi-trend {
  font-size: 12px;
  font-weight: 700;
  display: flex;
  align-items: center;
  gap: 4px;
}

.trend-up { color: var(--success); }
.trend-down { color: var(--danger); }
.trend-neutral { color: var(--text-muted); }

.kpi-sparkline {
  position: absolute;
  top: var(--space-md);
  right: var(--space-md);
  opacity: 0.5;
}

/* Tables */
.table-container {
  overflow-x: auto;
  border-radius: var(--radius-md);
}

.data-table {
  width: 100%;
  border-collapse: separate;
  border-spacing: 0;
  font-size: 13px;
}

.data-table th {
  text-align: left;
  padding: 14px var(--space-md);
  font-size: 10px;
  font-weight: 800;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  color: var(--text-muted);
  background: var(--bg-surface);
  border-bottom: 1px solid var(--border-subtle);
  white-space: nowrap;
}

.data-table th:first-child { border-radius: var(--radius-md) 0 0 0; }
.data-table th:last-child { border-radius: 0 var(--radius-md) 0 0; }

.data-table td {
  padding: 14px var(--space-md);
  border-bottom: 1px solid var(--border-subtle);
  color: var(--text-secondary);
  vertical-align: middle;
  font-weight: 500;
}

.data-table tr:hover td {
  background: rgba(241, 245, 249, 0.8);
}

.data-table tr:last-child td:first-child { border-radius: 0 0 0 var(--radius-md); }
.data-table tr:last-child td:last-child { border-radius: 0 0 var(--radius-md) 0; }

.mono {
  font-family: 'SF Mono', 'Fira Code', ui-monospace, monospace;
  font-size: 12px;
  font-weight: 600;
}

/* List Items */
.list-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 14px var(--space-md);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md);
  background: var(--bg-base);
  margin-bottom: var(--space-sm);
  transition: all 0.15s ease;
  cursor: pointer;
  box-shadow: var(--shadow-sm);
}

.list-item:hover {
  border-color: var(--border-active);
  background: var(--bg-surface);
  transform: translateX(3px);
  box-shadow: var(--shadow-md);
}

.list-item-main { min-width: 0; flex: 1; }

.list-item-title {
  font-size: 13px;
  font-weight: 700;
  color: var(--text-secondary);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.list-item-meta {
  font-size: 11px;
  color: var(--text-muted);
  margin-top: 3px;
  font-weight: 500;
}

.list-item-value {
  font-size: 14px;
  font-weight: 800;
  color: var(--text-primary);
  white-space: nowrap;
}

/* Progress Bars */
.progress-bar {
  height: 8px;
  background: var(--bg-elevated);
  border-radius: 999px;
  overflow: hidden;
  margin-top: var(--space-sm);
}

.progress-fill {
  height: 100%;
  border-radius: 999px;
  transition: width 0.6s cubic-bezier(0.4, 0, 0.2, 1);
}

.progress-fill.success { background: linear-gradient(90deg, #22c55e, #4ade80); }
.progress-fill.warning { background: linear-gradient(90deg, #f59e0b, #fbbf24); }
.progress-fill.danger { background: linear-gradient(90deg, #dc2626, #f87171); }
.progress-fill.info { background: linear-gradient(90deg, #0284c7, #38bdf8); }

/* Charts */
.chart-container {
  position: relative;
  height: 260px;
  width: 100%;
}

.chart-container svg {
  width: 100%;
  height: 100%;
  display: block;
}

.chart-legend {
  display: flex;
  gap: var(--space-lg);
  align-items: center;
  font-size: 12px;
  font-weight: 600;
  color: var(--text-tertiary);
}

.legend-dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  display: inline-block;
  margin-right: 6px;
}

/* Heatmap */
.heatmap-grid {
  display: grid;
  grid-template-columns: repeat(24, 1fr);
  gap: 3px;
}

.heatmap-cell {
  aspect-ratio: 1;
  border-radius: 4px;
  cursor: pointer;
  transition: transform 0.15s ease, opacity 0.2s ease;
  box-shadow: inset 0 0 0 1px rgba(0,0,0,0.05);
}

.heatmap-cell:hover {
  transform: scale(1.25);
  z-index: 2;
  opacity: 1 !important;
  box-shadow: 0 2px 8px rgba(0,0,0,0.15);
}

/* Layer Badges */
.layer-badge {
  display: inline-flex;
  align-items: center;
  padding: 4px 10px;
  border-radius: 999px;
  font-size: 10px;
  font-weight: 800;
  text-transform: uppercase;
  letter-spacing: 0.06em;
}

.layer-regex {
  background: rgba(59, 130, 246, 0.12);
  color: #2563eb;
  border: 1px solid rgba(59, 130, 246, 0.25);
}

.layer-ml {
  background: rgba(139, 92, 246, 0.12);
  color: #7c3aed;
  border: 1px solid rgba(139, 92, 246, 0.25);
}

.layer-llm {
  background: rgba(245, 158, 11, 0.12);
  color: #d97706;
  border: 1px solid rgba(245, 158, 11, 0.25);
}

.layer-mixed {
  background: rgba(236, 72, 153, 0.12);
  color: #db2777;
  border: 1px solid rgba(236, 72, 153, 0.25);
}

/* Modal */
.modal-overlay {
  position: fixed;
  inset: 0;
  background: rgba(15, 23, 42, 0.6);
  backdrop-filter: blur(8px);
  z-index: 100;
  display: none;
  align-items: center;
  justify-content: center;
  padding: var(--space-xl);
}

.modal-overlay.open { display: flex; }

.modal-box {
  width: min(900px, 100%);
  max-height: 85vh;
  overflow: auto;
  background: var(--bg-base);
  border: 1px solid var(--border-default);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-lg);
}

.modal-header {
  padding: var(--space-lg) var(--space-xl);
  border-bottom: 1px solid var(--border-subtle);
  display: flex;
  justify-content: space-between;
  align-items: center;
  position: sticky;
  top: 0;
  background: rgba(255, 255, 255, 0.98);
  backdrop-filter: blur(10px);
  z-index: 2;
}

.modal-body { padding: var(--space-xl); }

.modal-close {
  width: 36px;
  height: 36px;
  border-radius: var(--radius-md);
  border: 1px solid var(--border-default);
  background: var(--bg-surface);
  color: var(--text-tertiary);
  cursor: pointer;
  display: grid;
  place-items: center;
  font-size: 20px;
  font-weight: 700;
  transition: all 0.15s ease;
}

.modal-close:hover {
  background: var(--danger);
  border-color: var(--danger);
  color: white;
  transform: rotate(90deg);
}

/* Timeline */
.timeline {
  display: flex;
  flex-direction: column;
  gap: 0;
}

.timeline-event {
  display: grid;
  grid-template-columns: 100px 20px 1fr;
  gap: var(--space-md);
  min-height: 80px;
  position: relative;
}

.timeline-time {
  font-size: 11px;
  color: var(--text-muted);
  text-align: right;
  padding-top: 4px;
  font-variant-numeric: tabular-nums;
  font-weight: 600;
}

.timeline-line {
  position: relative;
  display: flex;
  justify-content: center;
}

.timeline-line::before {
  content: "";
  width: 12px;
  height: 12px;
  border-radius: 50%;
  background: var(--accent);
  position: absolute;
  top: 3px;
  box-shadow: 0 0 0 4px rgba(2, 132, 199, 0.15);
  z-index: 2;
}

.timeline-line::after {
  content: "";
  position: absolute;
  width: 2px;
  background: var(--border-default);
  top: 20px;
  bottom: -10px;
}

.timeline-event:last-child .timeline-line::after { display: none; }

.timeline-card {
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md);
  background: var(--bg-surface);
  padding: var(--space-md);
  margin-bottom: var(--space-md);
  box-shadow: var(--shadow-sm);
}

.timeline-card.blocked {
  border-color: rgba(220, 38, 38, 0.3);
  background: rgba(220, 38, 38, 0.04);
}

.timeline-title {
  font-size: 14px;
  font-weight: 800;
  color: var(--text-primary);
  display: flex;
  align-items: center;
  gap: var(--space-sm);
  flex-wrap: wrap;
}

.timeline-meta {
  font-size: 12px;
  color: var(--text-muted);
  margin-top: 6px;
  line-height: 1.6;
  font-weight: 500;
}

.json-block {
  background: var(--bg-deep);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md);
  padding: var(--space-md);
  margin-top: var(--space-sm);
  font-family: 'SF Mono', ui-monospace, monospace;
  font-size: 11px;
  line-height: 1.6;
  color: var(--text-tertiary);
  max-height: 200px;
  overflow: auto;
  white-space: pre-wrap;
  word-break: break-word;
  font-weight: 500;
}

/* Search */
.search-bar {
  display: flex;
  gap: var(--space-sm);
  margin-bottom: var(--space-lg);
  flex-wrap: wrap;
}

.search-input,
.search-select {
  background: var(--bg-base);
  border: 1px solid var(--border-default);
  color: var(--text-secondary);
  padding: 11px 16px;
  border-radius: var(--radius-md);
  font: inherit;
  font-size: 13px;
  font-weight: 500;
  outline: none;
  transition: all 0.15s ease;
  box-shadow: var(--shadow-sm);
}

.search-input:focus,
.search-select:focus {
  border-color: var(--accent);
  box-shadow: 0 0 0 3px rgba(2, 132, 199, 0.1), var(--shadow-sm);
}

.search-input { flex: 1; min-width: 240px; }
.search-select { min-width: 140px; }

/* Empty States */
.empty-state {
  text-align: center;
  padding: var(--space-xl);
  color: var(--text-muted);
}

.empty-state-icon {
  font-size: 40px;
  margin-bottom: var(--space-md);
  opacity: 0.4;
}

.empty-state-title {
  font-size: 16px;
  font-weight: 800;
  color: var(--text-secondary);
  margin-bottom: var(--space-xs);
}

.empty-state-desc {
  font-size: 13px;
  max-width: 500px;
  margin: 0 auto;
  line-height: 1.7;
  font-weight: 500;
}

/* Toast */
.toast {
  position: fixed;
  right: var(--space-xl);
  bottom: var(--space-xl);
  background: var(--bg-base);
  border: 1px solid var(--border-default);
  padding: 16px 20px;
  border-radius: var(--radius-md);
  box-shadow: var(--shadow-lg);
  font-size: 13px;
  font-weight: 700;
  color: var(--text-secondary);
  z-index: 200;
  opacity: 0;
  transform: translateY(10px);
  transition: all 0.3s ease;
  display: flex;
  align-items: center;
  gap: 10px;
}

.toast.show {
  opacity: 1;
  transform: none;
}

/* Views */
.view {
  display: none;
  animation: fadeIn 0.3s ease;
}

.view.active { display: block; }

@keyframes fadeIn {
  from { opacity: 0; transform: translateY(8px); }
  to { opacity: 1; transform: none; }
}

/* Mobile */
.mobile-toggle {
  display: none;
  background: none;
  border: none;
  color: var(--text-secondary);
  font-size: 22px;
  cursor: pointer;
  padding: 4px;
  font-weight: 700;
}

.mobile-overlay {
  display: none;
  position: fixed;
  inset: 0;
  background: rgba(15, 23, 42, 0.3);
  z-index: 45;
}

@media (max-width: 1100px) {
  .grid-4 { grid-template-columns: repeat(2, 1fr); }
  .layout-split { grid-template-columns: 1fr; }
}

@media (max-width: 768px) {
  .sidebar {
    transform: translateX(-100%);
    transition: transform 0.3s ease;
    width: 280px;
    box-shadow: var(--shadow-lg);
  }
  .sidebar.open { transform: translateX(0); }
  .main { margin-left: 0; }
  .mobile-toggle { display: block; }
  .grid-2, .grid-3, .grid-4, .layout-split { grid-template-columns: 1fr; }
  .page-header { flex-direction: column; align-items: flex-start; }
  .content { padding: var(--space-md); }
  .topbar { padding: 0 var(--space-md); }
  .mobile-overlay.show { display: block; }
}
</style>
<base target="_blank">
</head>
<body>

<div class="app">
  <aside class="sidebar" id="sidebar">
    <div class="brand">
      <div class="brand-mark">AG</div>
      <div class="brand-text">
        <strong>AgentGuard</strong>
        <span>AI Runtime Security</span>
      </div>
    </div>

    <nav class="nav">
      <div class="nav-label">Surveillance</div>
      <button class="active" data-view="overview" onclick="showView('overview')">
        <svg viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7" rx="2"/><rect x="14" y="3" width="7" height="7" rx="2"/><rect x="3" y="14" width="7" height="7" rx="2"/><rect x="14" y="14" width="7" height="7" rx="2"/></svg>
        Vue d'ensemble
      </button>
      <button data-view="traces" onclick="showView('traces')">
        <svg viewBox="0 0 24 24"><path d="M4 5h16M4 12h10M4 19h16"/></svg>
        Traces
      </button>
      <button data-view="models" onclick="showView('models')">
        <svg viewBox="0 0 24 24"><circle cx="12" cy="8" r="3"/><path d="M5 20c.8-4 3.1-6 7-6s6.2 2 7 6"/></svg>
        Modèles
      </button>

      <div class="nav-label">Sécurité</div>
      <button data-view="guardrails" onclick="showView('guardrails')">
        <svg viewBox="0 0 24 24"><path d="M12 3l8 4v5c0 4.8-3.1 8.4-8 10-4.9-1.6-8-5.2-8-10V7l8-4z"/><path d="M12 8v5M12 16h.01"/></svg>
        Guardrails
      </button>
      <button data-view="threats" onclick="showView('threats')">
        <svg viewBox="0 0 24 24"><path d="M12 3l8 4v5c0 4.8-3.1 8.4-8 10-4.9-1.6-8-5.2-8-10V7l8-4z"/><path d="M12 8v5M12 16h.01"/></svg>
        Menaces
      </button>
      <button data-view="detection" onclick="showView('detection')">
        <svg viewBox="0 0 24 24"><path d="M4 17l5-5 4 3 7-8"/><path d="M20 7v5h-5"/></svg>
        Détection
      </button>
      <button data-view="policies" onclick="showView('policies')">
        <svg viewBox="0 0 24 24"><path d="M5 4h14v16H5z"/><path d="M8 8h8M8 12h8M8 16h5"/></svg>
        Politiques
      </button>

      <div class="nav-label">Opérations</div>
      <button data-view="usage" onclick="showView('usage')">
        <svg viewBox="0 0 24 24"><path d="M12 3v18M16 7.5c0-1.7-1.8-3-4-3S8 5.3 8 7s1.4 2.5 4 3 4 1.3 4 3-1.8 3-4 3-4-1.3-4-3"/></svg>
        Usage & Coût
      </button>
      <button data-view="audit" onclick="showView('audit')">
        <svg viewBox="0 0 24 24"><path d="M6 3h12v18H6z"/><path d="M9 7h6M9 11h6M9 15h4"/></svg>
        Journal d'audit
      </button>
    </nav>

    <div class="sidebar-footer">
      <div class="status-indicator">
        <span class="status-dot"></span>
        <span>Collecteur opérationnel</span>
      </div>
      <div class="version">AgentGuard v5.0 · Runtime local</div>
    </div>
  </aside>

  <div class="mobile-overlay" id="mobileOverlay" onclick="toggleSidebar()"></div>

  <main class="main">
    <header class="topbar">
      <div class="breadcrumb">
        <button class="mobile-toggle" onclick="toggleSidebar()">☰</button>
        <small>Workspace</small>
        <span style="color: var(--text-muted)">/</span>
        <strong id="crumbTitle">Vue d'ensemble</strong>
      </div>
      <div class="top-actions">
        <span class="badge badge-success" id="lastSync">
          <span class="status-dot" style="width:6px;height:6px;box-shadow:none;animation:none"></span>
          En direct
        </span>
        <button class="btn" onclick="refreshAll()">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M23 4v6h-6M1 20v-6h6M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15"/></svg>
          Actualiser
        </button>
      </div>
    </header>

    <div class="content">

      <!-- VUE D'ENSEMBLE -->
      <section id="view-overview" class="view active">
        <div class="page-header">
          <div class="page-header-left">
            <div class="eyebrow">Sécurité runtime</div>
            <h1 class="page-title">Vue d'ensemble</h1>
            <p class="page-subtitle">Surveillez les agents IA, les décisions runtime, les menaces et les performances de détection en temps réel.</p>
          </div>
          <div class="top-actions">
            <button class="btn btn-primary" onclick="refreshAll()">Actualisation live</button>
          </div>
        </div>

        <div class="grid-kpi" id="kpiRow"></div>
        <div class="grid-4" id="guardrailKpis" style="margin-bottom: var(--space-xl)"></div>

        <div class="layout-split">
          <div class="card">
            <div class="card-header">
              <div>
                <div class="card-title">Activité runtime</div>
                <div class="card-subtitle">Spans observés et décisions bloquées — 14 derniers jours</div>
              </div>
              <div class="chart-legend">
                <span><span class="legend-dot" style="background: var(--accent)"></span>Spans</span>
                <span><span class="legend-dot" style="background: var(--danger)"></span>Bloqués</span>
              </div>
            </div>
            <div class="card-body">
              <div class="chart-container" id="activityChartWrap"></div>
            </div>
          </div>

          <div class="card">
            <div class="card-header">
              <div>
                <div class="card-title">Distribution des risques</div>
                <div class="card-subtitle">Vérifications de sécurité — 24 dernières heures</div>
              </div>
            </div>
            <div class="card-body">
              <div id="riskGrid"></div>
            </div>
          </div>
        </div>

        <div class="grid-2" style="margin-top: var(--space-md)">
          <div class="card">
            <div class="card-header">
              <div>
                <div class="card-title">Répartition par modèle</div>
                <div class="card-subtitle">Latence et requêtes par modèle</div>
              </div>
              <button class="btn btn-ghost" onclick="showView('models')">Voir tout →</button>
            </div>
            <div class="card-body" id="modelBreakdown"></div>
          </div>

          <div class="card">
            <div class="card-header">
              <div>
                <div class="card-title">Succès vs Bloqués</div>
                <div class="card-subtitle">Distribution des résultats de requêtes</div>
              </div>
            </div>
            <div class="card-body" style="display:flex;align-items:center;justify-content:center;height:240px">
              <div id="pieChart"></div>
            </div>
          </div>
        </div>

        <div class="grid-2" style="margin-top: var(--space-md)">
          <div class="card">
            <div class="card-header">
              <div>
                <div class="card-title">Carte thermique des attaques</div>
                <div class="card-subtitle">Événements bloqués par heure — 5 derniers jours</div>
              </div>
            </div>
            <div class="card-body">
              <div id="heatmap"></div>
              <div style="display:flex;justify-content:space-between;margin-top:12px;font-size:11px;color:var(--text-muted);font-weight:600">
                <span>00h</span><span>06h</span><span>12h</span><span>18h</span><span>23h</span>
              </div>
            </div>
          </div>

          <div class="card">
            <div class="card-header">
              <div>
                <div class="card-title">Spans les plus coûteuses</div>
                <div class="card-subtitle">Opérations au coût le plus élevé</div>
              </div>
            </div>
            <div class="card-body" id="expensiveSpans"></div>
          </div>
        </div>

        <div class="grid-2" style="margin-top: var(--space-md)">
          <div class="card">
            <div class="card-header">
              <div>
                <div class="card-title">Événements en direct</div>
                <div class="card-subtitle">Décisions de sécurité temps réel</div>
              </div>
            </div>
            <div class="card-body" id="liveEvents"></div>
          </div>

          <div class="card">
            <div class="card-header">
              <div>
                <div class="card-title">Traces récentes</div>
                <div class="card-subtitle">Dernière activité runtime</div>
              </div>
              <button class="btn btn-ghost" onclick="showView('traces')">Toutes →</button>
            </div>
            <div class="card-body" id="recentTraces"></div>
          </div>
        </div>
      </section>

      <!-- TRACES -->
      <section id="view-traces" class="view">
        <div class="page-header">
          <div class="page-header-left">
            <div class="eyebrow">Observabilité</div>
            <h1 class="page-title">Traces distribuées</h1>
            <p class="page-subtitle">Suivez l'exécution d'un agent de la requête à l'appel d'outil et à la décision de sécurité.</p>
          </div>
        </div>

        <div class="search-bar">
          <input type="text" class="search-input" id="traceSearch" placeholder="Rechercher trace_id, modèle, couche de détection, raison de blocage…" oninput="filterTraces()">
          <select class="search-select" id="traceFilterBlocked" onchange="filterTraces()">
            <option value="">Tous les statuts</option>
            <option value="blocked">Bloqués uniquement</option>
            <option value="safe">Sûrs uniquement</option>
          </select>
          <select class="search-select" id="traceFilterLayer" onchange="filterTraces()">
            <option value="">Toutes les couches</option>
            <option value="regex">Regex</option>
            <option value="ml">ML</option>
            <option value="llm_judge">LLM Judge</option>
            <option value="mixed">Mixed</option>
          </select>
          <button class="btn btn-primary" onclick="exportTracesCSV()">⬇ Exporter CSV</button>
        </div>

        <div class="card">
          <div class="table-container">
            <table class="data-table">
              <thead>
                <tr><th>Trace</th><th>Spans</th><th>Bloqués</th><th>Couche</th><th>Modèle</th><th>Coût</th><th>P50 Lat</th><th>P99 Lat</th><th>Dernier vu</th></tr>
              </thead>
              <tbody id="traceTable"></tbody>
            </table>
          </div>
        </div>
      </section>

      <!-- MODÈLES -->
      <section id="view-models" class="view">
        <div class="page-header">
          <div class="page-header-left">
            <div class="eyebrow">Observabilité</div>
            <h1 class="page-title">Performance des modèles</h1>
            <p class="page-subtitle">Latence, coût, usage de tokens et taux de blocage par modèle.</p>
          </div>
        </div>

        <div class="grid-3" id="modelCards"></div>

        <div class="card" style="margin-top: var(--space-md)">
          <div class="card-header">
            <div>
              <div class="card-title">Comparaison des modèles</div>
              <div class="card-subtitle">Coût (barres) vs latence moyenne (ligne) par modèle</div>
            </div>
          </div>
          <div class="card-body">
            <div class="chart-container" id="modelComparison"></div>
          </div>
        </div>
      </section>

      <!-- GUARDRAILS -->
      <section id="view-guardrails" class="view">
        <div class="page-header">
          <div class="page-header-left">
            <div class="eyebrow">Sécurité</div>
            <h1 class="page-title">Guardrails</h1>
            <p class="page-subtitle">Métriques d'application des politiques runtime et de filtrage de contenu.</p>
          </div>
        </div>

        <div class="grid-4" id="guardrailDetail"></div>

        <div class="grid-2" style="margin-top: var(--space-md)">
          <div class="card">
            <div class="card-header">
              <div>
                <div class="card-title">Activation par type</div>
                <div class="card-subtitle">Total analysé vs signalé, par catégorie de détection</div>
              </div>
            </div>
            <div class="card-body">
              <div class="chart-container" id="guardrailStacked"></div>
            </div>
          </div>

          <div class="card">
            <div class="card-header">
              <div>
                <div class="card-title">Tendance d'activation</div>
                <div class="card-subtitle">Requêtes bloquées par jour — 14 derniers jours</div>
              </div>
            </div>
            <div class="card-body">
              <div class="chart-container" id="guardrailTrend"></div>
            </div>
          </div>
        </div>
      </section>

      <!-- MENACES -->
      <section id="view-threats" class="view">
        <div class="page-header">
          <div class="page-header-left">
            <div class="eyebrow">Sécurité</div>
            <h1 class="page-title">Menaces</h1>
            <p class="page-subtitle">Violations runtime et signaux d'application collectés par AgentGuard.</p>
          </div>
        </div>

        <div class="grid-4" id="threatKpis"></div>

        <div class="card" style="margin-top: var(--space-md)">
          <div class="card-header">
            <div>
              <div class="card-title">Catalogue des menaces</div>
              <div class="card-subtitle">Principales raisons de blocage actuelles</div>
            </div>
          </div>
          <div class="card-body" id="threatFull"></div>
        </div>
      </section>

      <!-- DÉTECTION -->
      <section id="view-detection" class="view">
        <div class="page-header">
          <div class="page-header-left">
            <div class="eyebrow">Intelligence</div>
            <h1 class="page-title">Centre de détection</h1>
            <p class="page-subtitle">Comparez les signaux produits par les couches de détection activées dans le collecteur.</p>
          </div>
        </div>

        <div class="card">
          <div class="card-header">
            <div>
              <div class="card-title">Couches de détection</div>
              <div class="card-subtitle">Volume observé et taux de blocage</div>
            </div>
          </div>
          <div class="card-body">
            <div class="grid-3" id="detectionCards"></div>
          </div>
        </div>

        <div class="grid-2" style="margin-top: var(--space-md)">
          <div class="card">
            <div class="card-header"><div class="card-title">Distribution des scores ML</div></div>
            <div class="card-body" id="mlDistribution"></div>
          </div>
          <div class="card">
            <div class="card-header"><div class="card-title">Distribution LLM Judge</div></div>
            <div class="card-body" id="llmDistribution"></div>
          </div>
        </div>
      </section>

      <!-- POLITIQUES -->
      <section id="view-policies" class="view">
        <div class="page-header">
          <div class="page-header-left">
            <div class="eyebrow">Gouvernance</div>
            <h1 class="page-title">Politiques</h1>
            <p class="page-subtitle">Interface de gestion des politiques prête ; le collecteur actuel n'expose pas encore les endpoints CRUD.</p>
          </div>
        </div>

        <div class="card">
          <div class="empty-state">
            <div class="empty-state-icon">◇</div>
            <div class="empty-state-title">Espace de travail du moteur de politiques</div>
            <p class="empty-state-desc">Le tableau de bord est prêt pour les politiques runtime, les approbations et les règles d'application. Ces capacités nécessitent des endpoints backend qui ne sont pas présents dans collector.py.</p>
            <span class="badge badge-neutral" style="margin-top: var(--space-md)">Extension backend requise</span>
          </div>
        </div>
      </section>

      <!-- USAGE & COÛT -->
      <section id="view-usage" class="view">
        <div class="page-header">
          <div class="page-header-left">
            <div class="eyebrow">Opérations</div>
            <h1 class="page-title">Usage & Coût</h1>
            <p class="page-subtitle">Télémétrie de coût et de latence dérivée des spans observées.</p>
          </div>
        </div>

        <div class="grid-4" id="usageKpis"></div>

        <div class="grid-2" style="margin-top: var(--space-md)">
          <div class="card">
            <div class="card-header">
              <div>
                <div class="card-title">Prévision de coût</div>
                <div class="card-subtitle">Dépense projetée basée sur la trajectoire actuelle</div>
              </div>
            </div>
            <div class="card-body">
              <div class="chart-container" id="costForecast"></div>
            </div>
          </div>

          <div class="card">
            <div class="card-header">
              <div>
                <div class="card-title">Distribution de latence</div>
                <div class="card-subtitle">Latence réelle p50 / p95 / p99 / max observée</div>
              </div>
            </div>
            <div class="card-body">
              <div class="chart-container" id="tokenUsage"></div>
            </div>
          </div>
        </div>
      </section>

      <!-- AUDIT -->
      <section id="view-audit" class="view">
        <div class="page-header">
          <div class="page-header-left">
            <div class="eyebrow">Gouvernance</div>
            <h1 class="page-title">Journal d'audit</h1>
            <p class="page-subtitle">Vue d'audit légère dérivée des traces runtime. Les événements d'audit administratifs nécessitent un backend dédié.</p>
          </div>
        </div>

        <div class="card">
          <div class="table-container">
            <table class="data-table">
              <thead>
                <tr><th>Heure</th><th>Trace</th><th>Événement</th><th>Modèle</th><th>Décision</th><th>Couche</th></tr>
              </thead>
              <tbody id="auditTable"></tbody>
            </table>
          </div>
        </div>
      </section>

    </div>
  </main>
</div>

<div id="toast" class="toast"></div>

<div id="traceModal" class="modal-overlay" onclick="if(event.target===this)closeModal()">
  <div class="modal-box">
    <div class="modal-header">
      <div>
        <div class="eyebrow">Investigation de trace</div>
        <div id="modalTitle" style="font-weight:900;margin-top:4px;font-size:18px">Trace</div>
      </div>
      <button class="modal-close" onclick="closeModal()">×</button>
    </div>
    <div class="modal-body" id="modalBody"></div>
  </div>
</div>

<script>
// ============================================
// STATE & UTILITAIRES
// ============================================
const state = {
  metrics: null, traces: [], detection: null, llm: null, allTraces: [],
  models: [], checksBreakdown: [], heatmap: [], expensiveSpans: [],
  costTrend: [], latencyDist: {}, recentEvents: [], dailyTrend: []
};

const $ = id => document.getElementById(id);
const esc = v => String(v || '').replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
const fmt = n => new Intl.NumberFormat('fr-FR').format(Number(n || 0));
const money = n => Number(n || 0).toFixed(4) + ' €';

function toast(msg) {
  const t = $('toast');
  t.innerHTML = `<span style="color:var(--success)">●</span> ${esc(msg)}`;
  t.classList.add('show');
  clearTimeout(window._toast);
  window._toast = setTimeout(() => t.classList.remove('show'), 2500);
}

async function api(url) {
  const r = await fetch(url, { credentials: 'include', headers: { 'Accept': 'application/json' } });
  if (!r.ok) throw new Error('HTTP ' + r.status);
  return r.json();
}

// ============================================
// NAVIGATION
// ============================================
function showView(name) {
  document.querySelectorAll('.view').forEach(x => x.classList.remove('active'));
  const v = $('view-' + name);
  if (v) v.classList.add('active');
  document.querySelectorAll('.nav button').forEach(b => b.classList.toggle('active', b.dataset.view === name));

  const titles = {
    overview: "Vue d'ensemble", traces: "Traces", models: "Modèles",
    guardrails: "Guardrails", threats: "Menaces", detection: "Détection",
    policies: "Politiques", usage: "Usage & Coût", audit: "Journal d'audit"
  };
  $('crumbTitle').textContent = titles[name] || name;

  if (name === 'traces') renderTraceTable(state.allTraces);
  if (name === 'models') renderModels();
  if (name === 'guardrails') renderGuardrails();
  if (name === 'threats') renderThreats();
  if (name === 'detection') renderDetection(state.detection);
  if (name === 'usage') renderUsage();
  if (name === 'audit') renderAudit();
}

function toggleSidebar() {
  document.getElementById('sidebar').classList.toggle('open');
  document.getElementById('mobileOverlay').classList.toggle('show');
}

// ============================================
// SCORE DE SÉCURITÉ
// ============================================
function securityScore(m) {
  const blocked = Number(m.blocked_operations || 0);
  const spans = Number(m.total_spans || 0);
  const blockRate = spans ? blocked / spans : 0;
  const ml = Number(m.avg_ml_score || 0);
  const llm = Number(m.avg_llm_score || 0);
  let score = 100 - (blockRate * 35) - (Math.max(ml, llm) * 12);
  return Math.max(0, Math.min(100, Math.round(score)));
}

// ============================================
// SVG HELPERS
// ============================================
function sparkSVG(data, color, w, h) {
  const max = Math.max(1, ...data);
  const step = w / (data.length - 1);
  let path = '';
  data.forEach((v, i) => {
    const x = i * step, y = h - (v / max) * h;
    path += i ? ` L${x},${y}` : `M${x},${y}`;
  });
  return `<svg width="${w}" height="${h}" class="kpi-sparkline" viewBox="0 0 ${w} ${h}"><path d="${path}" fill="none" stroke="${color}" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/><path d="${path} L${w},${h} L0,${h} Z" fill="${color}" opacity="0.08"/></svg>`;
}

function describeArc(x, y, r, startAngle, endAngle) {
  const start = polarToCartesian(x, y, r, endAngle);
  const end = polarToCartesian(x, y, r, startAngle);
  const largeArcFlag = endAngle - startAngle <= 180 ? "0" : "1";
  return ["M", start.x, start.y, "A", r, r, 0, largeArcFlag, 0, end.x, end.y].join(" ");
}

function polarToCartesian(cx, cy, r, angleDeg) {
  const angleRad = (angleDeg - 90) * Math.PI / 180;
  return { x: cx + r * Math.cos(angleRad), y: cy + r * Math.sin(angleRad) };
}

// ============================================
// RENDER — VUE D'ENSEMBLE
// ============================================
function renderOverview() {
  const m = state.metrics;
  if (!m) return;

  const daily = state.dailyTrend || [];
  const dailyTotals = daily.map(d => d.total);
  const dailyBlocked = daily.map(d => d.blocked);
  const costSeries = (state.costTrend || []).map(d => d.cost);
  const lat = state.latencyDist || {};

  function trendOf(series) {
    if (series.length < 2) return { has: false };
    const first = series[0] || 0, last = series[series.length - 1] || 0;
    const pct = first === 0 ? (last > 0 ? 100 : 0) : ((last - first) / first * 100);
    return { has: true, up: pct >= 0, text: (pct >= 0 ? '+' : '') + pct.toFixed(1) + '%' };
  }

  const reqTrend = trendOf(dailyTotals), costTrend = trendOf(costSeries);

  function trendHtml(t) {
    return t.has 
      ? `<span class="kpi-trend ${t.up ? 'trend-up' : 'trend-down'}">${t.up ? '↑' : '↓'} ${esc(t.text)} <span style="color:var(--text-muted);font-weight:500">sur 14j</span></span>`
      : `<span class="kpi-trend trend-neutral">Historique &lt; 2 jours</span>`;
  }

  const kpis = [
    { label: "Score de sécurité", value: securityScore(m) + '/100', spark: dailyTotals, color: '#16a34a', trend: { has: false } },
    { label: "Requêtes totales", value: fmt(m.total_spans), spark: dailyTotals, color: '#0284c7', trend: reqTrend },
    { label: "Latence moyenne", value: Number(m.avg_latency_ms || 0).toFixed(1) + 'ms', spark: dailyTotals, color: '#16a34a', trend: { has: false } },
    { label: "Latence P99", value: (lat.p99 ? lat.p99.toFixed(0) : '—') + 'ms', spark: dailyTotals, color: '#dc2626', trend: { has: false } },
    { label: "Analyses LLM Judge", value: fmt(m.llm_judge_count || 0), spark: dailyTotals, color: '#7c3aed', trend: { has: false } },
    { label: "Dépenses IA", value: money(m.total_cost_usd), spark: costSeries, color: '#d97706', trend: costTrend },
  ];

  $('kpiRow').innerHTML = kpis.map(k => `
    <div class="card kpi-card">
      ${sparkSVG(k.spark.length ? k.spark : [0, 0], k.color, 80, 28)}
      <div class="kpi-header">
        <span class="kpi-label">${esc(k.label)}</span>
      </div>
      <div class="kpi-value">${esc(k.value)}</div>
      ${trendHtml(k.trend)}
    </div>
  `).join('');

  const checkLabels = {
    prompt_injection: 'Injection de prompt',
    pii_detection: 'Détection PII',
    dangerous_params: "Politique d'outil",
    tool_policy: "Politique d'outil",
    budget_policy: 'Budget'
  };
  const checks = state.checksBreakdown || [];

  $('guardrailKpis').innerHTML = checks.length
    ? checks.slice(0, 4).map(c => `
      <div class="card kpi-card">
        <div class="kpi-header">
          <span class="kpi-label">${esc(checkLabels[c.check_name] || c.check_name)}</span>
        </div>
        <div class="kpi-value ${c.flagged > 0 ? 'trend-down' : 'trend-up'}" style="font-size:28px">${c.flag_rate}%</div>
        <div class="kpi-trend trend-neutral">${fmt(c.flagged)} signalé(s) sur ${fmt(c.total)} analysés</div>
      </div>
    `).join('')
    : '<div class="empty-state" style="grid-column:1/-1"><p class="empty-state-desc">Pas encore de vérifications de sécurité enregistrées.</p></div>';

  // Graphique d'activité
  const wrap = $('activityChartWrap');
  const W = wrap.clientWidth || 600, H = 260;

  if (daily.length < 2) {
    wrap.innerHTML = '<div class="empty-state"><p class="empty-state-desc">Pas assez d'historique pour un graphique (minimum 2 jours d'activité).</p></div>';
  } else {
    const maxS = Math.max(1, ...dailyTotals);
    const pad = { l: 45, r: 20, t: 20, b: 35 };
    const cw = W - pad.l - pad.r, ch = H - pad.t - pad.b;

    let svg = `<svg viewBox="0 0 ${W} ${H}" style="width:100%;height:100%">`;

    for (let i = 0; i < 4; i++) {
      const y = pad.t + ch * i / 3;
      svg += `<line x1="${pad.l}" y1="${y}" x2="${W - pad.r}" y2="${y}" stroke="#e2e8f0" stroke-width="0.5"/>`;
    }

    let area = `M${pad.l},${pad.t + ch}`;
    dailyTotals.forEach((v, i) => {
      const x = pad.l + (i / (dailyTotals.length - 1)) * cw;
      const y = pad.t + ch - (v / maxS) * ch;
      area += ` L${x},${y}`;
    });
    area += ` L${W - pad.r},${pad.t + ch} Z`;
    svg += `<path d="${area}" fill="#0284c7" opacity="0.08"/>`;

    let l1 = '';
    dailyTotals.forEach((v, i) => {
      const x = pad.l + (i / (dailyTotals.length - 1)) * cw;
      const y = pad.t + ch - (v / maxS) * ch;
      l1 += i ? ` L${x},${y}` : `M${x},${y}`;
    });
    svg += `<path d="${l1}" fill="none" stroke="#0284c7" stroke-width="2.5" stroke-linecap="round"/>`;

    let l2 = '';
    dailyBlocked.forEach((v, i) => {
      const x = pad.l + (i / (dailyBlocked.length - 1)) * cw;
      const y = pad.t + ch - (v / maxS) * ch;
      l2 += i ? ` L${x},${y}` : `M${x},${y}`;
    });
    svg += `<path d="${l2}" fill="none" stroke="#dc2626" stroke-width="2" stroke-linecap="round" stroke-dasharray="5,4"/>`;

    daily.forEach((d, i) => {
      const x = pad.l + (i / (daily.length - 1)) * cw;
      svg += `<text x="${x}" y="${H - 10}" fill="#94a3b8" font-size="10" text-anchor="middle" font-weight="600">${esc((d.day || '').slice(5))}</text>`;
    });

    [0, Math.round(maxS / 2), maxS].forEach((v, i) => {
      const y = pad.t + ch - (i / 2) * ch;
      svg += `<text x="${pad.l - 8}" y="${y + 4}" fill="#94a3b8" font-size="10" text-anchor="end" font-weight="600">${fmt(v)}</text>`;
    });

    svg += '</svg>';
    wrap.innerHTML = svg;
  }

  // Distribution des risques
  const r = m.risk_distribution || {};
  const maxR = Math.max(1, ...['low', 'medium', 'high', 'critical'].map(k => Number(r[k] || 0)));
  const riskLabels = { low: 'Faible', medium: 'Moyen', high: 'Élevé', critical: 'Critique' };
  const riskColors = { low: 'var(--success)', medium: 'var(--warning)', high: '#f97316', critical: 'var(--danger)' };

  $('riskGrid').innerHTML = ['low', 'medium', 'high', 'critical'].map(k => {
    const val = Number(r[k] || 0);
    const pct = maxR ? Math.round((val / maxR) * 100) : 0;
    return `
      <div style="margin-bottom:16px">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
          <span style="font-size:12px;font-weight:700;color:var(--text-tertiary)">${riskLabels[k]}</span>
          <span style="font-size:12px;font-weight:800;color:var(--text-primary)">${fmt(val)}</span>
        </div>
        <div class="progress-bar">
          <div class="progress-fill" style="width:${pct}%;background:${riskColors[k]}"></div>
        </div>
        <div style="font-size:11px;color:var(--text-muted);margin-top:4px;font-weight:500">${pct}% du maximum</div>
      </div>
    `;
  }).join('');

  // Répartition par modèle
  const models = state.models || [];
  if (models.length) {
    const maxReq = Math.max(...models.map(x => x.requests));
    const palette = ['#0284c7', '#7c3aed', '#0d9488', '#d97706', '#f97316', '#16a34a'];
    $('modelBreakdown').innerHTML = models.map((mo, i) => `
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px">
        <span style="width:130px;font-size:12px;color:var(--text-tertiary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-weight:600">${esc(mo.name)}</span>
        <div style="flex:1">
          <div class="progress-bar" style="height:8px">
            <div class="progress-fill" style="width:${(mo.requests / maxReq * 100).toFixed(1)}%;background:${palette[i % palette.length]}"></div>
          </div>
        </div>
        <span style="width:55px;text-align:right;font-size:11px;font-weight:800;color:var(--text-secondary)">${fmt(mo.requests)}</span>
        <span style="width:60px;text-align:right;font-size:11px;color:var(--text-muted);font-weight:600">${mo.avg_latency_ms}ms</span>
      </div>
    `).join('');
  } else {
    $('modelBreakdown').innerHTML = '<div class="empty-state"><p class="empty-state-desc">Aucun modèle identifié pour l'instant — passe model="..." à ton appel LLM pour l'afficher ici.</p></div>';
  }

  // Pie chart
  const total = Math.max(1, m.total_spans || 0), blk = m.blocked_operations || 0, safe = total - blk;
  const safePct = (safe / total * 100).toFixed(1);
  const R = 55, C = 65;

  $('pieChart').innerHTML = `
    <svg width="160" height="140" viewBox="0 0 130 130">
      <circle cx="${C}" cy="${C}" r="${R}" fill="none" stroke="#e2e8f0" stroke-width="18"/>
      <path d="${describeArc(C, C, R, 0, safePct / 100 * 360)}" fill="none" stroke="#0284c7" stroke-width="18" stroke-linecap="round"/>
      <path d="${describeArc(C, C, R, safePct / 100 * 360, 360)}" fill="none" stroke="#dc2626" stroke-width="18" stroke-linecap="round"/>
      <text x="${C}" y="${C - 4}" text-anchor="middle" fill="var(--text-primary)" font-size="22" font-weight="900">${safePct}%</text>
      <text x="${C}" y="${C + 18}" text-anchor="middle" fill="var(--text-muted)" font-size="10" font-weight="700">Sûr</text>
    </svg>
    <div style="margin-left:20px;display:flex;flex-direction:column;gap:10px">
      <div style="display:flex;align-items:center;gap:8px">
        <span style="width:10px;height:10px;border-radius:50%;background:#0284c7"></span>
        <span style="font-size:12px;color:var(--text-tertiary);font-weight:600">Sûr — ${fmt(safe)}</span>
      </div>
      <div style="display:flex;align-items:center;gap:8px">
        <span style="width:10px;height:10px;border-radius:50%;background:#dc2626"></span>
        <span style="font-size:12px;color:var(--text-tertiary);font-weight:600">Bloqué — ${fmt(blk)}</span>
      </div>
    </div>
  `;

  // Heatmap
  const hm = state.heatmap || [];
  const heat = $('heatmap');
  if (hm.length) {
    const byHour = {};
    hm.forEach(c => { byHour[c.hour] = (byHour[c.hour] || 0) + c.blocked; });
    const maxB = Math.max(1, ...Object.values(byHour));
    let cells = '';
    for (let h = 0; h < 24; h++) {
      const v = byHour[h] || 0, intensity = v / maxB;
      const bg = intensity > 0.66 ? '#dc2626' : intensity > 0.33 ? '#f59e0b' : intensity > 0 ? '#0284c7' : '#e2e8f0';
      cells += `<div class="heatmap-cell" style="background:${bg};opacity:${v ? 0.6 + intensity * 0.4 : 0.5}" title="${h}h — ${v} blocage(s)"></div>`;
    }
    heat.innerHTML = `<div class="heatmap-grid">${cells}</div>`;
  } else {
    heat.innerHTML = '<div class="empty-state"><p class="empty-state-desc">Pas encore assez de données horaires.</p></div>';
  }

  // Expensive spans
  const expensive = state.expensiveSpans || [];
  $('expensiveSpans').innerHTML = expensive.length ? expensive.map(e => `
    <div class="list-item">
      <div class="list-item-main">
        <div class="list-item-title">${esc(e.trace_id)} · ${esc(e.model || 'modèle inconnu')}</div>
        <div class="list-item-meta">${esc(e.span_type)}</div>
      </div>
      <span style="font-size:14px;font-weight:800;color:var(--danger)">${money(e.cost_usd)}</span>
    </div>
  `).join('') : '<div class="empty-state"><p class="empty-state-desc">Aucune span coûteuse enregistrée.</p></div>';

  // Live events
  const events = state.recentEvents || [];
  const layerColors = { regex: '#2563eb', ml: '#7c3aed', llm_judge: '#d97706', mixed: '#db2777' };
  $('liveEvents').innerHTML = events.length ? events.map(ev => {
    const riskDot = ev.risk === 'critical' ? '🔴' : ev.risk === 'high' ? '🟠' : ev.risk === 'medium' ? '🟡' : '🟢';
    const action = ev.blocked ? ('Bloqué — ' + (ev.reason || 'raison non précisée')) : (ev.span_type + ' autorisé');
    const color = layerColors[ev.layer] || '#64748b';
    return `
      <div class="list-item" style="display:grid;grid-template-columns:auto 1fr auto;gap:12px">
        <span style="display:inline-flex;align-items:center;padding:4px 10px;border-radius:999px;font-size:10px;font-weight:800;text-transform:uppercase;background:${color}15;color:${color};border:1px solid ${color}30">${esc(ev.layer)}</span>
        <span style="font-size:12px;color:var(--text-tertiary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-weight:600">${esc(action)}</span>
        <span style="font-size:11px;color:var(--text-muted);white-space:nowrap;font-weight:600">${riskDot} ${esc(ev.created_at || '')}</span>
      </div>
    `;
  }).join('') : '<div class="empty-state"><p class="empty-state-desc">Aucun événement pour l'instant.</p></div>';

  renderRecentTraces();
}

function renderRecentTraces() {
  const traces = state.allTraces.slice(0, 8);
  $('recentTraces').innerHTML = traces.length ? traces.map(t => `
    <div class="list-item" onclick="openTrace('${esc(t.trace_id)}')">
      <div class="list-item-main">
        <div class="list-item-title mono">${esc(t.trace_id)}</div>
        <div class="list-item-meta">${fmt(t.span_count)} spans · ${esc(t.model || '—')}</div>
      </div>
      <span class="badge ${Number(t.blocked_count) > 0 ? 'badge-danger' : 'badge-success'}">${Number(t.blocked_count) > 0 ? 'BLOQUÉ' : 'SÛR'}</span>
    </div>
  `).join('') : '<div class="empty-state"><p class="empty-state-desc">Aucune trace récente.</p></div>';
}

// ============================================
// RENDER — TRACES
// ============================================
function renderTraceTable(data) {
  const tbody = $('traceTable');
  tbody.innerHTML = data.length ? data.map(t => `
    <tr onclick="openTrace('${esc(t.trace_id)}')" style="cursor:pointer">
      <td class="mono">${esc(t.trace_id)}</td>
      <td>${fmt(t.span_count)}</td>
      <td><span class="badge ${Number(t.blocked_count) > 0 ? 'badge-danger' : 'badge-success'}">${fmt(t.blocked_count)}</span></td>
      <td>${layerBadge(t.detection_layers)}</td>
      <td style="color:var(--text-tertiary);font-size:11px;font-weight:600">${esc(t.model || '—')}</td>
      <td>${money(t.total_cost)}</td>
      <td>${t.p50 || '—'}ms</td>
      <td>${t.p99 || '—'}ms</td>
      <td style="color:var(--text-muted);font-weight:600">${esc(t.last_seen || '—')}</td>
    </tr>
  `).join('') : '<tr><td colspan="9" class="empty-state" style="padding:40px"><p class="empty-state-desc">Aucune trace disponible.</p></td></tr>';
}

function layerBadge(layer) {
  if (!layer) return '<span class="badge badge-neutral">—</span>';
  const l = (layer || '').toLowerCase();
  const cls = l.includes('llm_judge') ? 'layer-llm' : l.includes('mixed') ? 'layer-mixed' : l.includes('ml') ? 'layer-ml' : l.includes('regex') ? 'layer-regex' : 'layer-mixed';
  const txt = l.includes('llm_judge') ? 'LLM JUDGE' : l.includes('mixed') ? 'MIXED' : l.includes('ml') ? 'ML' : l.includes('regex') ? 'REGEX' : 'UNKNOWN';
  return `<span class="layer-badge ${cls}">${txt}</span>`;
}

function filterTraces() {
  const q = $('traceSearch').value.toLowerCase();
  const blockedFilter = $('traceFilterBlocked').value;
  const layerFilter = $('traceFilterLayer').value;
  let filtered = state.allTraces;
  if (q) filtered = filtered.filter(t => 
    t.trace_id.toLowerCase().includes(q) || 
    (t.detection_layers || '').toLowerCase().includes(q) || 
    (t.model || '').toLowerCase().includes(q)
  );
  if (blockedFilter === 'blocked') filtered = filtered.filter(t => Number(t.blocked_count) > 0);
  if (blockedFilter === 'safe') filtered = filtered.filter(t => Number(t.blocked_count) === 0);
  if (layerFilter) filtered = filtered.filter(t => (t.detection_layers || '').toLowerCase().includes(layerFilter));
  renderTraceTable(filtered);
}

function exportTracesCSV() {
  const rows = state.allTraces.map(t => 
    `${t.trace_id},${t.span_count},${t.blocked_count},"${t.detection_layers || ''}","${t.model || ''}",${t.total_cost},${t.p50 || ''},${t.p99 || ''},${t.last_seen || ''}`
  ).join('\n');
  const csv = 'trace_id,span_count,blocked_count,detection_layers,model,total_cost,p50_ms,p99_ms,last_seen\n' + rows;
  const blob = new Blob([csv], { type: 'text/csv' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'agentguard_traces.csv';
  a.click();
  toast('CSV exporté');
}

// ============================================
// RENDER — MODÈLES
// ============================================
function renderModels() {
  const models = state.models || [];
  if (!models.length) {
    $('modelCards').innerHTML = '<div class="empty-state" style="grid-column:1/-1"><p class="empty-state-desc">Aucun modèle observé pour l'instant. Passe model="..." dans les kwargs de ton appel LLM pour peupler cette page.</p></div>';
    $('modelComparison').innerHTML = '';
    return;
  }

  $('modelCards').innerHTML = models.map(m => `
    <div class="card kpi-card">
      <div class="kpi-header">
        <span class="kpi-label">${esc(m.name)}</span>
      </div>
      <div class="kpi-value">${fmt(m.requests)}</div>
      <div class="kpi-trend trend-neutral">${money(m.total_cost_usd)} · ${fmt(m.blocked_count)} bloqué(s)</div>
      <div style="margin-top:12px;font-size:11px;color:var(--text-muted);font-weight:600">Latence moy.: <strong style="color:var(--text-tertiary)">${m.avg_latency_ms}ms</strong></div>
    </div>
  `).join('');

  const comp = $('modelComparison');
  const W = comp.clientWidth || 600, H = 260;
  const pad = { l: 50, r: 20, t: 20, b: 35 };
  const cw = W - pad.l - pad.r, ch = H - pad.t - pad.b;
  const maxCost = Math.max(...models.map(m => m.total_cost_usd), 0.000001);
  const maxLat = Math.max(...models.map(m => m.avg_latency_ms), 1);

  let svg = `<svg viewBox="0 0 ${W} ${H}" style="width:100%;height:100%">`;

  for (let i = 0; i < 3; i++) {
    const y = pad.t + ch * i / 2;
    svg += `<line x1="${pad.l}" y1="${y}" x2="${W - pad.r}" y2="${y}" stroke="#e2e8f0" stroke-width="0.5"/>`;
  }

  const bw = cw / models.length * 0.3;
  models.forEach((m, i) => {
    const x = pad.l + (i + 0.25) * (cw / models.length);
    const h = (m.total_cost_usd / maxCost) * ch;
    svg += `<rect x="${x}" y="${pad.t + ch - h}" width="${bw}" height="${h}" fill="#0284c7" rx="5" opacity="0.85"/>`;
  });

  let lpath = '';
  models.forEach((m, i) => {
    const x = pad.l + (i + 0.5) * (cw / models.length);
    const y = pad.t + ch - (m.avg_latency_ms / maxLat) * ch;
    lpath += i ? ` L${x},${y}` : `M${x},${y}`;
    svg += `<circle cx="${x}" cy="${y}" r="4" fill="#dc2626"/>`;
  });
  svg += `<path d="${lpath}" fill="none" stroke="#dc2626" stroke-width="2.5" stroke-linecap="round"/>`;

  models.forEach((m, i) => {
    const x = pad.l + (i + 0.5) * (cw / models.length);
    svg += `<text x="${x}" y="${H - 10}" fill="#94a3b8" font-size="10" text-anchor="middle" font-weight="700">${esc(m.name.split('-')[0])}</text>`;
  });

  svg += `<text x="12" y="20" fill="var(--text-muted)" font-size="10" font-weight="800">Coût (€)</text>`;
  svg += `<text x="12" y="35" fill="var(--text-muted)" font-size="10" font-weight="800">Latence (ms)</text>`;
  svg += '</svg>';
  comp.innerHTML = svg;
}

// ============================================
// RENDER — GUARDRAILS
// ============================================
function renderGuardrails() {
  const checkLabels = {
    prompt_injection: 'Injection de prompt',
    pii_detection: 'Détection PII',
    dangerous_params: "Politique d'outil",
    tool_policy: "Politique d'outil",
    budget_policy: 'Budget'
  };
  const checks = state.checksBreakdown || [];

  $('guardrailDetail').innerHTML = checks.length
    ? checks.map(c => `
      <div class="card kpi-card">
        <div class="kpi-header">
          <span class="kpi-label">${esc(checkLabels[c.check_name] || c.check_name)}</span>
        </div>
        <div class="kpi-value ${c.flagged > 0 ? 'trend-down' : 'trend-up'}" style="font-size:28px">${c.flag_rate}%</div>
        <div class="kpi-trend trend-neutral">${fmt(c.flagged)} signalé(s) · ${fmt(c.total)} analysés</div>
      </div>
    `).join('')
    : '<div class="empty-state" style="grid-column:1/-1"><p class="empty-state-desc">Aucune vérification enregistrée pour l'instant.</p></div>';

  const wrap = $('guardrailStacked');
  if (!checks.length) {
    wrap.innerHTML = '<div class="empty-state"><p class="empty-state-desc">Pas encore de données.</p></div>';
  } else {
    const W = wrap.clientWidth || 500, H = 260;
    const pad = { l: 140, r: 20, t: 20, b: 15 };
    const cw = W - pad.l - pad.r, ch = H - pad.t - pad.b;
    const rowH = ch / checks.length;
    const maxTotal = Math.max(1, ...checks.map(c => c.total));

    let svg = `<svg viewBox="0 0 ${W} ${H}" style="width:100%;height:100%">`;
    checks.forEach((c, i) => {
      const y = pad.t + i * rowH + rowH * 0.2;
      const barH = rowH * 0.55;
      const wTotal = (c.total / maxTotal) * cw;
      const wFlag = (c.flagged / maxTotal) * cw;
      svg += `<text x="${pad.l - 10}" y="${y + barH / 2 + 4}" fill="var(--text-tertiary)" font-size="11" text-anchor="end" font-weight="700">${esc(checkLabels[c.check_name] || c.check_name)}</text>`;
      svg += `<rect x="${pad.l}" y="${y}" width="${wTotal}" height="${barH}" fill="#0284c7" opacity="0.15" rx="5"/>`;
      svg += `<rect x="${pad.l}" y="${y}" width="${wFlag}" height="${barH}" fill="#dc2626" rx="5"/>`;
    });
    svg += '</svg>';
    wrap.innerHTML = svg;
  }

  const trend = $('guardrailTrend');
  const daily = state.dailyTrend || [];
  if (daily.length < 2) {
    trend.innerHTML = '<div class="empty-state"><p class="empty-state-desc">Pas assez d'historique pour une tendance.</p></div>';
  } else {
    const W2 = trend.clientWidth || 500;
    const trendData = daily.map(d => d.blocked);
    const maxT = Math.max(1, ...trendData);

    let svg2 = `<svg viewBox="0 0 ${W2} 260" style="width:100%;height:100%">`;
    let area = `M0,260 `;
    trendData.forEach((v, i) => {
      const x = (i / (trendData.length - 1)) * W2;
      const y = 260 - (v / maxT) * 230;
      area += `L${x},${y} `;
    });
    area += 'L' + W2 + ',260 Z';
    svg2 += `<path d="${area}" fill="#dc2626" opacity="0.06"/>`;

    let line = '';
    trendData.forEach((v, i) => {
      const x = (i / (trendData.length - 1)) * W2;
      const y = 260 - (v / maxT) * 230;
      line += i ? ` L${x},${y}` : `M${x},${y}`;
    });
    svg2 += `<path d="${line}" fill="none" stroke="#dc2626" stroke-width="2.5" stroke-linecap="round"/>`;
    svg2 += '</svg>';
    trend.innerHTML = svg2;
  }
}

// ============================================
// RENDER — MENACES
// ============================================
function renderThreats() {
  const m = state.metrics || {};
  const r = m.risk_distribution || {};

  $('threatKpis').innerHTML = `
    <div class="card kpi-card">
      <div class="kpi-header"><span class="kpi-label">Bloqués</span></div>
      <div class="kpi-value trend-down">${fmt(m.blocked_operations || 0)}</div>
      <div class="kpi-trend trend-neutral">Toutes les opérations bloquées</div>
    </div>
    <div class="card kpi-card">
      <div class="kpi-header"><span class="kpi-label">Haut + Critique</span></div>
      <div class="kpi-value">${fmt(Number(r.high || 0) + Number(r.critical || 0))}</div>
      <div class="kpi-trend trend-neutral">Signaux de risque</div>
    </div>
    <div class="card kpi-card">
      <div class="kpi-header"><span class="kpi-label">Score ML</span></div>
      <div class="kpi-value">${(Number(m.avg_ml_score || 0) * 100).toFixed(1)}%</div>
      <div class="kpi-trend trend-neutral">Score moyen observé</div>
    </div>
    <div class="card kpi-card">
      <div class="kpi-header"><span class="kpi-label">Score LLM</span></div>
      <div class="kpi-value">${(Number(m.avg_llm_score || 0) * 100).toFixed(1)}%</div>
      <div class="kpi-trend trend-neutral">Score Judge moyen</div>
    </div>
  `;

  const arr = m.top_threats || [];
  $('threatFull').innerHTML = arr.length ? arr.map(t => `
    <div class="list-item">
      <span class="list-item-title" title="${esc(t.reason || 'Inconnu')}">${esc(t.reason || 'Inconnu')}</span>
      <span class="list-item-value">${fmt(t.count)}</span>
    </div>
  `).join('') : '<div class="empty-state"><p class="empty-state-desc">Aucune menace bloquée observée.</p></div>';
}

// ============================================
// RENDER — DÉTECTION
// ============================================
function renderDetection(d) {
  state.detection = d;
  const a = d.layer_accuracy || [];

  $('detectionCards').innerHTML = a.length ? a.map(x => {
    const l = (x.layer || '').toLowerCase();
    const barColor = l === 'regex' ? '#2563eb' : l === 'ml' ? '#7c3aed' : l === 'llm_judge' ? '#d97706' : l === 'mixed' ? '#db2777' : '#0284c7';
    return `
      <div class="card" style="padding:var(--space-lg)">
        <div style="font-size:11px;font-weight:800;color:var(--text-tertiary);text-transform:uppercase;letter-spacing:0.06em;margin-bottom:8px">${esc(x.layer || 'unknown')}</div>
        <div style="font-size:28px;font-weight:900;color:var(--text-primary);margin-bottom:4px">${fmt(x.total)}</div>
        <div style="font-size:12px;color:var(--text-muted);margin-bottom:14px;font-weight:600">${Number(x.block_rate || 0).toFixed(2)}% bloqués · ${fmt(x.blocked)} décisions</div>
        <div class="progress-bar"><div class="progress-fill" style="width:${Math.min(100, Number(x.block_rate || 0))}%;background:${barColor}"></div></div>
      </div>
    `;
  }).join('') : '<div class="empty-state" style="grid-column:1/-1"><p class="empty-state-desc">Aucune donnée de couche de détection pour l'instant.</p></div>';

  const ml = d.ml_score_distribution || [];
  $('mlDistribution').innerHTML = ml.length ? ml.map(x => `
    <div class="list-item"><span class="list-item-title">${esc(x.range)}</span><span class="list-item-value">${fmt(x.count)}</span></div>
  `).join('') : '<div class="empty-state"><p class="empty-state-desc">Aucun score ML enregistré.</p></div>';

  const llm = d.llm_score_distribution || [];
  $('llmDistribution').innerHTML = llm.length ? llm.map(x => `
    <div class="list-item"><span class="list-item-title">${esc(x.category)}</span><span class="list-item-value">${fmt(x.count)}</span></div>
  `).join('') : '<div class="empty-state"><p class="empty-state-desc">Aucun score LLM Judge enregistré.</p></div>';
}

// ============================================
// RENDER — USAGE
// ============================================
function renderUsage() {
  const m = state.metrics || {};
  $('usageKpis').innerHTML = `
    <div class="card kpi-card">
      <div class="kpi-header"><span class="kpi-label">Coût total</span></div>
      <div class="kpi-value">${money(m.total_cost_usd || 0)}</div>
    </div>
    <div class="card kpi-card">
      <div class="kpi-header"><span class="kpi-label">Spans</span></div>
      <div class="kpi-value">${fmt(m.total_spans || 0)}</div>
    </div>
    <div class="card kpi-card">
      <div class="kpi-header"><span class="kpi-label">Latence moyenne</span></div>
      <div class="kpi-value">${Number(m.avg_latency_ms || 0).toFixed(1)}ms</div>
    </div>
    <div class="card kpi-card">
      <div class="kpi-header"><span class="kpi-label">Analyses LLM</span></div>
      <div class="kpi-value">${fmt(m.llm_judge_count || 0)}</div>
    </div>
  `;

  const cf = $('costForecast');
  const hist = (state.costTrend || []).map(d => d.cost);

  if (hist.length < 2) {
    cf.innerHTML = '<div class="empty-state" style="padding-top:80px"><p class="empty-state-desc">Pas assez d'historique de coût pour une projection (minimum 2 jours).</p></div>';
  } else {
    const W = cf.clientWidth || 500;
    const dailyAvgDelta = (hist[hist.length - 1] - hist[0]) / (hist.length - 1);
    const forecastDays = 7;
    const forecast = Array.from({ length: forecastDays }, (_, i) => Math.max(0, hist[hist.length - 1] + dailyAvgDelta * (i + 1)));
    const maxC = Math.max(...hist, ...forecast, 0.000001);
    const histShare = 0.65;

    let svg = `<svg viewBox="0 0 ${W} 260" style="width:100%;height:100%">`;
    let area = `M0,260 `;
    hist.forEach((v, i) => {
      const x = (i / (hist.length - 1)) * (W * histShare);
      const y = 260 - (v / maxC) * 230;
      area += `L${x},${y} `;
    });
    const lastX = W * histShare;
    forecast.forEach((v, i) => {
      const x = lastX + (i / (forecast.length - 1)) * (W * (1 - histShare));
      const y = 260 - (v / maxC) * 230;
      area += `L${x},${y} `;
    });
    area += 'L' + W + ',260 Z';
    svg += `<path d="${area}" fill="#0284c7" opacity="0.06"/>`;

    let line = '';
    hist.forEach((v, i) => {
      const x = (i / (hist.length - 1)) * (W * histShare);
      const y = 260 - (v / maxC) * 230;
      line += i ? ` L${x},${y}` : `M${x},${y}`;
    });
    svg += `<path d="${line}" fill="none" stroke="#0284c7" stroke-width="2.5" stroke-linecap="round"/>`;

    let fline = '';
    forecast.forEach((v, i) => {
      const x = lastX + (i / (forecast.length - 1)) * (W * (1 - histShare));
      const y = 260 - (v / maxC) * 230;
      fline += i ? ` L${x},${y}` : `M${lastX},${260 - (hist[hist.length - 1] / maxC) * 230}`;
    });
    svg += `<path d="${fline}" fill="none" stroke="#7c3aed" stroke-width="2.5" stroke-linecap="round" stroke-dasharray="6,4"/>`;
    svg += `<line x1="${lastX}" y1="0" x2="${lastX}" y2="260" stroke="#94a3b8" stroke-width="0.5" stroke-dasharray="4,4"/>`;
    svg += `<text x="12" y="20" fill="var(--text-muted)" font-size="10" font-weight="800">Historique réel</text>`;
    svg += `<text x="${lastX + 8}" y="20" fill="#7c3aed" font-size="10" font-weight="800">Projection linéaire →</text>`;
    svg += '</svg>';
    cf.innerHTML = svg;
  }

  const tu = $('tokenUsage');
  const lat = state.latencyDist || {};

  if (!lat.count) {
    tu.innerHTML = '<div class="empty-state" style="padding-top:80px"><p class="empty-state-desc">Pas encore de données de latence.</p></div>';
  } else {
    const W2 = tu.clientWidth || 500;
    const bars = [
      { label: 'p50', v: lat.p50, color: '#16a34a' },
      { label: 'p95', v: lat.p95, color: '#d97706' },
      { label: 'p99', v: lat.p99, color: '#dc2626' },
      { label: 'max', v: lat.max, color: '#7c3aed' }
    ];
    const maxV = Math.max(1, ...bars.map(b => b.v));
    const bw = W2 / bars.length * 0.45;

    let svg2 = `<svg viewBox="0 0 ${W2} 260" style="width:100%;height:100%">`;
    bars.forEach((b, i) => {
      const x = (i + 0.275) * (W2 / bars.length);
      const h = (b.v / maxV) * 200;
      svg2 += `<rect x="${x}" y="${220 - h}" width="${bw}" height="${h}" fill="${b.color}" rx="6"/>`;
      svg2 += `<text x="${x + bw / 2}" y="${220 - h - 10}" fill="var(--text-secondary)" font-size="12" text-anchor="middle" font-weight="800">${b.v.toFixed(0)}ms</text>`;
      svg2 += `<text x="${x + bw / 2}" y="245" fill="var(--text-muted)" font-size="11" text-anchor="middle" font-weight="700">${b.label}</text>`;
    });
    svg2 += '</svg>';
    tu.innerHTML = svg2;
  }
}

// ============================================
// RENDER — AUDIT
// ============================================
function renderAudit() {
  const arr = state.allTraces.slice(0, 25);
  $('auditTable').innerHTML = arr.length ? arr.map(t => `
    <tr>
      <td style="color:var(--text-muted);font-weight:600">${esc(t.last_seen || '—')}</td>
      <td class="mono">${esc(t.trace_id)}</td>
      <td>${fmt(t.span_count)} span(s)</td>
      <td style="color:var(--text-tertiary);font-size:11px;font-weight:600">${esc(t.model || '—')}</td>
      <td><span class="badge ${Number(t.blocked_count) > 0 ? 'badge-danger' : 'badge-success'}">${Number(t.blocked_count) > 0 ? 'BLOQUER' : 'AUTORISER'}</span></td>
      <td style="color:var(--text-muted);font-weight:600">${esc(t.detection_layers || '—')}</td>
    </tr>
  `).join('') : '<tr><td colspan="6" class="empty-state" style="padding:40px"><p class="empty-state-desc">Aucune donnée d'audit.</p></td></tr>';
}

// ============================================
// MODAL TRACE
// ============================================
async function openTrace(id) {
  try {
    $('traceModal').classList.add('open');
    $('modalTitle').textContent = id;
    $('modalBody').innerHTML = '<div class="empty-state"><p class="empty-state-desc">Chargement de la trace…</p></div>';

    const rows = await api('/api/traces/' + encodeURIComponent(id));
    if (!rows.length) {
      $('modalBody').innerHTML = '<div class="empty-state"><p class="empty-state-desc">Aucun détail de span disponible pour cette trace.</p></div>';
      return;
    }

    const totalDur = Math.max(...rows.map(r => Number(r.timestamp || 0) + Number(r.latency_ms || 0))) - Math.min(...rows.map(r => Number(r.timestamp || 0)));
    const minT = Math.min(...rows.map(r => Number(r.timestamp || 0)));
    const trackW = 600;

    let ganttHtml = '<div style="margin-bottom:24px"><div style="font-size:14px;font-weight:900;margin-bottom:12px;color:var(--text-primary)">Timeline d'exécution</div><div style="overflow-x:auto">';
    ganttHtml += '<div style="min-width:600px">';
    rows.forEach((r, i) => {
      const start = ((Number(r.timestamp || 0) - minT) / totalDur) * trackW;
      const width = Math.max(20, (Number(r.latency_ms || 0) / totalDur) * trackW);
      const blocked = !!r.blocked;
      const layer = (r.detection_layer || 'unknown').toLowerCase();
      const barColor = blocked ? '#dc2626' : layer === 'llm_judge' ? '#d97706' : '#0284c7';
      ganttHtml += `
        <div style="display:flex;align-items:center;height:34px;border-bottom:1px solid var(--border-subtle)">
          <div style="width:180px;flex-shrink:0;font-size:11px;color:var(--text-tertiary);padding-right:10px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-weight:700">${esc(r.span_type || 'span')} — ${esc(r.model || '—')}</div>
          <div style="flex:1;position:relative;height:100%">
            <div style="position:absolute;height:16px;top:9px;border-radius:4px;opacity:0.9;transition:opacity 0.15s;left:${start}px;width:${width}px;background:${barColor};box-shadow:0 2px 6px rgba(0,0,0,0.1)" title="${esc(r.span_type || '')} — ${Number(r.latency_ms || 0).toFixed(1)}ms"></div>
          </div>
        </div>
      `;
    });
    ganttHtml += '</div></div></div>';

    ganttHtml += '<div class="timeline">' + rows.map(r => {
      const blocked = !!r.blocked;
      const checks = Array.isArray(r.security_checks) ? r.security_checks : [];
      const layer = (r.detection_layer || 'unknown').toLowerCase();
      const layerCls = layer === 'regex' ? 'layer-regex' : layer === 'ml' ? 'layer-ml' : layer === 'llm_judge' ? 'layer-llm' : layer === 'mixed' ? 'layer-mixed' : 'layer-mixed';
      const layerTxt = layer === 'regex' ? 'REGEX' : layer === 'ml' ? 'ML' : layer === 'llm_judge' ? 'LLM JUDGE' : layer === 'mixed' ? 'MIXED' : 'UNKNOWN';

      let scores = '';
      if (r.ml_score != null) scores += `<span class="badge badge-success" style="margin-right:6px">ML ${(r.ml_score * 100).toFixed(1)}%</span>`;
      if (r.llm_score != null) {
        const cls = r.llm_score > 0.85 ? 'badge-danger' : r.llm_score > 0.7 ? 'badge-warning' : 'badge-success';
        scores += `<span class="badge ${cls}">LLM ${(r.llm_score * 100).toFixed(1)}%</span>`;
      }

      return `
        <div class="timeline-event">
          <div class="timeline-time">${esc(r.created_at || '')}</div>
          <div class="timeline-line"></div>
          <div class="timeline-card ${blocked ? 'blocked' : ''}">
            <div class="timeline-title">
              ${esc(r.span_type || 'span')} 
              <span class="layer-badge ${layerCls}">${layerTxt}</span> 
              ${blocked ? '<span class="badge badge-danger">bloqué</span>' : '<span class="badge badge-success">autorisé</span>'} 
              ${scores}
            </div>
            <div class="timeline-meta">${Number(r.latency_ms || 0).toFixed(1)} ms · ${money(r.cost_usd)} · ${esc(r.model || '—')}</div>
            ${r.block_reason ? `<div class="timeline-meta" style="color:var(--danger);margin-top:8px;font-weight:700">Raison: ${esc(r.block_reason)}</div>` : ''}
            ${r.llm_reason ? `<div class="timeline-meta" style="color:#d97706;margin-top:4px;font-weight:700">LLM: ${esc(r.llm_reason)}</div>` : ''}
            <div class="json-block">${esc(JSON.stringify({ input: r.input_data, output: r.output_data, security_checks: checks }, null, 2))}</div>
          </div>
        </div>
      `;
    }).join('') + '</div>';

    $('modalBody').innerHTML = ganttHtml;
  } catch (e) {
    $('modalBody').innerHTML = '<div class="empty-state"><p class="empty-state-desc">Impossible de charger la trace: ' + esc(e.message) + '</p></div>';
  }
}

function closeModal() {
  $('traceModal').classList.remove('open');
}

// ============================================
// REFRESH & INIT
// ============================================
async function refreshAll() {
  try {
    $('lastSync').innerHTML = '<span style="color:#d97706">●</span> Synchronisation…';

    const [m, t, d, models, checks, heatmap, expensive, costTrend, latencyDist, recentEvents, dailyTrend] = await Promise.all([
      api('/api/metrics'), api('/api/traces'), api('/api/detection/stats'),
      api('/api/models'), api('/api/checks/breakdown'), api('/api/heatmap'),
      api('/api/spans/expensive'), api('/api/cost/trend'), api('/api/latency/distribution'),
      api('/api/events/recent'), api('/api/trend/daily'),
    ]);

    state.allTraces = t.map(x => ({ ...x, model: x.model || null, p50: x.p50 || null, p99: x.p99 || null }));
    state.traces = t;
    state.models = models;
    state.checksBreakdown = checks;
    state.heatmap = heatmap;
    state.expensiveSpans = expensive;
    state.costTrend = costTrend;
    state.latencyDist = latencyDist;
    state.recentEvents = recentEvents;
    state.dailyTrend = dailyTrend;

    renderMetrics(m);
    renderDetection(d);
    $('lastSync').innerHTML = '<span class="status-dot" style="width:6px;height:6px;box-shadow:none;animation:none"></span> Actualisé ' + new Date().toLocaleTimeString('fr-FR');
    toast('Dashboard actualisé');
  } catch (e) {
    $('lastSync').innerHTML = '<span style="color:#dc2626">●</span> Hors ligne';
    toast('Collecteur indisponible: ' + e.message);
  }
}

function renderMetrics(m) {
  state.metrics = m;
  renderOverview();
  renderThreats();
  renderUsage();
  renderAudit();
}

// ============================================
// EVENTS & INIT
// ============================================
window.addEventListener('resize', () => {
  if (state.metrics) {
    renderOverview();
    renderUsage();
  }
});

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeModal();
});

refreshAll();
setInterval(refreshAll, 15000);
</script>
</body>
</html>
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

