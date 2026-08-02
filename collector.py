"""
AgentGuard Collector v3 — PostgreSQL production + SQLite local fallback
"""

import os
import re
import json
import time
import secrets
from datetime import datetime
from flask import Flask, request, jsonify, render_template_string, make_response
from flask_cors import CORS, cross_origin
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.secret_key = os.environ.get("AGENTGUARD_FLASK_SECRET", secrets.token_urlsafe(32))

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["120 per minute"],  # garde-fou global raisonnable
    storage_uri=os.environ.get("AGENTGUARD_LIMITER_STORAGE", "memory://"),
)
# CORS n'est nécessaire QUE si un SDK tourne côté navigateur et appelle le
# collector en cross-origin. Le dashboard lui-même est same-origin.
# On ne l'ouvre donc que sur /span, jamais sur les routes API/dashboard.

# ── CONFIG ──
DB_TYPE = os.environ.get("AGENTGUARD_DB_TYPE", "sqlite")  # "sqlite" ou "postgres"
DATABASE_URL = os.environ.get("DATABASE_URL", "")  # Render injecte ça auto
API_KEY = os.environ.get("AGENTGUARD_API_KEY", None)
ADMIN_SECRET = os.environ.get("AGENTGUARD_ADMIN_SECRET")  # pas de valeur par défaut !
AUTH_COOKIE = "ag_auth"

# Génère une clé si aucune n'est définie
_API_KEY_WAS_GENERATED = API_KEY is None
if not API_KEY:
    API_KEY = "ag-" + secrets.token_urlsafe(32)
    print("[AG] ⚠️  Aucune AGENTGUARD_API_KEY fournie — clé générée en mémoire "
          "pour cette instance (elle changera au prochain redémarrage, et n'est "
          "PAS affichée dans les logs). Configure AGENTGUARD_API_KEY pour la fixer.")

# ── PII REDACTION (avant stockage, pas juste détection) ──
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
    """Initialise les tables (PostgreSQL ou SQLite)."""
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
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_trace_pg ON spans(trace_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_created_pg ON spans(created_at)")
        conn.commit()
        conn.close()
        print("[AG] ✅ PostgreSQL initialisé")
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
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_trace ON spans(trace_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_created ON spans(created_at)")
        conn.commit()
        conn.close()
        print("[AG] ✅ SQLite initialisé")

def dict_from_row(row, is_pg=False):
    """Normalise une row en dict (PostgreSQL ou SQLite)."""
    if is_pg:
        return dict(row)
    return dict(row)

# ── AUTH ──
# Toutes les routes qui donnent accès à des données (spans, traces, metrics,
# dashboard) exigent la clé — via header, ?key=, ou un cookie posé une fois
# que la clé a été fournie une première fois (pour que le dashboard reste
# utilisable au navigateur sans exposer les données sans authentification).
PROTECTED_ENDPOINTS = {
    "receive_span", "list_traces", "get_trace", "get_metrics",
    "dashboard", "trace_detail",
}

def require_auth():
    if not API_KEY:
        return True
    key = request.headers.get("X-API-Key", "")
    if key == API_KEY:
        return True
    key = request.args.get("api_key") or request.args.get("key") or ""
    if key == API_KEY:
        return True
    return secrets.compare_digest(request.cookies.get(AUTH_COOKIE, ""), API_KEY)

def set_auth_cookie_if_valid(resp):
    """Si la clé a été fournie en query param, pose un cookie httponly pour
    que les prochaines requêtes (dont les fetch() same-origin du dashboard)
    soient authentifiées sans avoir à toucher au JS existant."""
    key = request.args.get("api_key") or request.args.get("key")
    if key == API_KEY:
        resp.set_cookie(AUTH_COOKIE, API_KEY, httponly=True, samesite="Lax",
                         secure=True, max_age=60 * 60 * 24 * 30)
    return resp

@app.before_request
def check_auth():
    # Le preflight CORS (OPTIONS) ne porte jamais les headers custom du navigateur
    # (X-API-Key) — c'est normal et ce n'est pas la vraie requête. Le bloquer ici
    # casse la négociation CORS avant même que la vraie requête parte.
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
@cross_origin(origins="*", headers=["Content-Type", "X-API-Key"])  # seul endpoint appelable par un SDK cross-origin
def receive_span():
    data = request.json
    # On redacte le PII connu AVANT stockage — pas seulement à la détection —
    # pour que la donnée sensible ne finisse jamais en DB ni sur le dashboard.
    data["input_data"] = redact_pii(data.get("input_data", {}))
    data["output_data"] = redact_pii(data.get("output_data", {}))
    is_pg = DB_TYPE == "postgres" and DATABASE_URL

    if is_pg:
        conn = get_pg_conn()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO spans (trace_id, span_id, span_type, timestamp, latency_ms,
                              input_data, output_data, security_checks, blocked,
                              block_reason, cost_usd)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            data["trace_id"], data["span_id"], data["span_type"],
            data["timestamp"], data["latency_ms"],
            json.dumps(data["input_data"]),
            json.dumps(data["output_data"]),
            json.dumps(data["security_checks"]),
            data["blocked"], data.get("block_reason"), data["cost_usd"]
        ))
    else:
        conn = sqlite3.connect(DB_SQLITE_PATH)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO spans (trace_id, span_id, span_type, timestamp, latency_ms,
                              input_data, output_data, security_checks, blocked,
                              block_reason, cost_usd)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data["trace_id"], data["span_id"], data["span_type"],
            data["timestamp"], data["latency_ms"],
            json.dumps(data["input_data"]),
            json.dumps(data["output_data"]),
            json.dumps(data["security_checks"]),
            1 if data["blocked"] else 0,
            data.get("block_reason"), data["cost_usd"]
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
    else:
        cur = conn.cursor()

    cur.execute("""
        SELECT trace_id, COUNT(*) as span_count,
               SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked_count,
               SUM(cost_usd) as total_cost,
               MAX(created_at) as last_seen
        FROM spans
        GROUP BY trace_id
        ORDER BY last_seen DESC
        LIMIT 100
    """)

    rows = [dict_from_row(r, is_pg) for r in cur.fetchall()]
    conn.close()
    return jsonify(rows)

@app.route("/api/traces/<trace_id>")
def get_trace(trace_id):
    is_pg = DB_TYPE == "postgres" and DATABASE_URL
    conn = get_db()

    if is_pg:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT * FROM spans WHERE trace_id = %s ORDER BY timestamp", (trace_id,))
    else:
        cur = conn.cursor()
        cur.execute("SELECT * FROM spans WHERE trace_id = ? ORDER BY timestamp", (trace_id,))

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
    else:
        cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM spans")
    total_spans = cur.fetchone()[0]

    cur.execute("SELECT COUNT(DISTINCT trace_id) FROM spans")
    total_traces = cur.fetchone()[0]

    cur.execute("SELECT SUM(CASE WHEN blocked THEN 1 ELSE 0 END) FROM spans")
    blocked = cur.fetchone()[0] or 0

    cur.execute("SELECT SUM(cost_usd) FROM spans")
    total_cost = cur.fetchone()[0] or 0

    # Risques
    if is_pg:
        cur.execute("""
            SELECT jsonb_array_elements(security_checks) as check
            FROM spans
            WHERE created_at > NOW() - INTERVAL '1 day'
        """)
    else:
        cur.execute("""
            SELECT json_extract(security_checks, '$') as checks
            FROM spans
            WHERE created_at > datetime('now', '-1 day')
        """)

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
    cur.execute("""
        SELECT block_reason, COUNT(*) as count
        FROM spans
        WHERE blocked = TRUE
        GROUP BY block_reason
        ORDER BY count DESC
        LIMIT 5
    """)
    top_threats = [{"reason": r[0], "count": r[1]} for r in cur.fetchall()]

    conn.close()
    return jsonify({
        "total_spans": total_spans,
        "total_traces": total_traces,
        "blocked_operations": blocked,
        "total_cost_usd": round(float(total_cost or 0), 6),
        "risk_distribution": risk_counts,
        "top_threats": top_threats
    })

# ── DASHBOARD (le même sci-fi) ──
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AGENTGUARD // SECURE TERMINAL v2.6.1</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700;800&family=Rajdhani:wght@300;500;600;700&display=swap');

:root {
  --bg-primary: #050810;
  --bg-panel: #0a0f1e;
  --bg-panel-hover: #0f1629;
  --border-dim: #1a2342;
  --border-glow: #2a3a6a;
  --cyan: #00f0ff;
  --cyan-dim: #00a8b3;
  --green: #00ff88;
  --green-dim: #00b35f;
  --red: #ff2a6d;
  --red-dim: #b31d4c;
  --orange: #ff9f1c;
  --yellow: #ffd60a;
  --purple: #bc13fe;
  --text-primary: #e0e6f1;
  --text-dim: #6b7a9c;
  --text-dark: #3a4566;
  --font-mono: 'JetBrains Mono', monospace;
  --font-display: 'Rajdhani', sans-serif;
}

* { margin:0; padding:0; box-sizing:border-box; }

body {
  background: var(--bg-primary);
  color: var(--text-primary);
  font-family: var(--font-mono);
  font-size: 12px;
  overflow-x: hidden;
  min-height: 100vh;
}

/* Scanline effect */
body::before {
  content: '';
  position: fixed;
  top:0; left:0; right:0; bottom:0;
  background: repeating-linear-gradient(
    0deg,
    transparent,
    transparent 2px,
    rgba(0,240,255,0.015) 2px,
    rgba(0,240,255,0.015) 4px
  );
  pointer-events: none;
  z-index: 9999;
}

/* Grid background */
.bg-grid {
  position: fixed;
  top:0; left:0; right:0; bottom:0;
  background-image: 
    linear-gradient(rgba(0,240,255,0.03) 1px, transparent 1px),
    linear-gradient(90deg, rgba(0,240,255,0.03) 1px, transparent 1px);
  background-size: 50px 50px;
  pointer-events: none;
  z-index: 0;
}

/* HEADER */
.header {
  position: relative;
  z-index: 10;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 24px;
  background: linear-gradient(180deg, rgba(10,15,30,0.95) 0%, rgba(10,15,30,0.8) 100%);
  border-bottom: 1px solid var(--border-dim);
  backdrop-filter: blur(10px);
}

.header-left {
  display: flex;
  align-items: center;
  gap: 16px;
}

.logo {
  font-family: var(--font-display);
  font-size: 22px;
  font-weight: 700;
  letter-spacing: 4px;
  color: var(--cyan);
  text-shadow: 0 0 20px rgba(0,240,255,0.4);
}

.logo span { color: var(--text-dim); font-weight: 300; }

.badge-class {
  font-size: 9px;
  letter-spacing: 2px;
  padding: 3px 10px;
  border: 1px solid var(--red);
  color: var(--red);
  background: rgba(255,42,109,0.08);
  font-family: var(--font-display);
  font-weight: 600;
}

.header-right {
  display: flex;
  align-items: center;
  gap: 20px;
}

.status-indicator {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 10px;
  letter-spacing: 2px;
  color: var(--green);
}

.status-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--green);
  box-shadow: 0 0 10px var(--green), 0 0 20px var(--green-dim);
  animation: pulse-dot 2s ease-in-out infinite;
}

@keyframes pulse-dot {
  0%, 100% { opacity: 1; transform: scale(1); }
  50% { opacity: 0.5; transform: scale(0.8); }
}

.clock {
  font-family: var(--font-display);
  font-size: 18px;
  font-weight: 600;
  color: var(--cyan);
  letter-spacing: 2px;
}

/* MAIN GRID */
.main-grid {
  position: relative;
  z-index: 5;
  display: grid;
  grid-template-columns: 280px 1fr 320px;
  grid-template-rows: auto 1fr auto;
  gap: 12px;
  padding: 16px;
  height: calc(100vh - 60px);
}

/* PANELS */
.panel {
  background: var(--bg-panel);
  border: 1px solid var(--border-dim);
  border-radius: 4px;
  position: relative;
  overflow: hidden;
}

.panel::before {
  content: '';
  position: absolute;
  top: 0; left: 0; right: 0;
  height: 2px;
  background: linear-gradient(90deg, transparent, var(--cyan-dim), transparent);
  opacity: 0.5;
}

.panel-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px 14px;
  border-bottom: 1px solid var(--border-dim);
  font-family: var(--font-display);
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 2px;
  text-transform: uppercase;
  color: var(--cyan);
}

.panel-header .panel-id {
  color: var(--text-dark);
  font-size: 9px;
  font-family: var(--font-mono);
}

/* CORNER DECORATIONS */
.corner {
  position: absolute;
  width: 8px;
  height: 8px;
  border: 1px solid var(--cyan-dim);
  opacity: 0.6;
}
.corner-tl { top: 4px; left: 4px; border-right: none; border-bottom: none; }
.corner-tr { top: 4px; right: 4px; border-left: none; border-bottom: none; }
.corner-bl { bottom: 4px; left: 4px; border-right: none; border-top: none; }
.corner-br { bottom: 4px; right: 4px; border-left: none; border-top: none; }

/* LEFT COLUMN */
.left-col {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

/* THREAT LEVEL */
.threat-level {
  padding: 16px;
  text-align: center;
}

.threat-label {
  font-family: var(--font-display);
  font-size: 10px;
  letter-spacing: 3px;
  color: var(--text-dim);
  margin-bottom: 8px;
}

.threat-value {
  font-family: var(--font-display);
  font-size: 42px;
  font-weight: 800;
  color: var(--green);
  text-shadow: 0 0 30px var(--green-dim);
  line-height: 1;
}

.threat-value.warning { color: var(--orange); text-shadow: 0 0 30px rgba(255,159,28,0.4); }
.threat-value.critical { color: var(--red); text-shadow: 0 0 30px var(--red-dim); animation: flicker 1.5s infinite; }

@keyframes flicker {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.7; }
  75% { opacity: 0.9; }
}

.threat-sub {
  font-size: 10px;
  color: var(--text-dim);
  margin-top: 6px;
  letter-spacing: 1px;
}

/* KPI LIST */
.kpi-list {
  padding: 8px 0;
}

.kpi-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px 14px;
  border-bottom: 1px solid rgba(26,35,66,0.5);
  transition: background 0.2s;
}
.kpi-item:hover { background: var(--bg-panel-hover); }
.kpi-item:last-child { border-bottom: none; }

.kpi-label {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 10px;
  color: var(--text-dim);
  letter-spacing: 1px;
}

.kpi-icon { font-size: 14px; }

.kpi-value {
  font-family: var(--font-display);
  font-size: 16px;
  font-weight: 700;
  color: var(--text-primary);
}

.kpi-value.alert { color: var(--red); text-shadow: 0 0 10px var(--red-dim); }
.kpi-value.warn { color: var(--orange); }
.kpi-value.ok { color: var(--green); }

.kpi-delta {
  font-size: 9px;
  color: var(--text-dark);
  margin-left: 4px;
}

/* CENTER COLUMN */
.center-col {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

/* CHART CONTAINER */
.chart-container {
  position: relative;
  padding: 14px;
  flex: 1;
  min-height: 0;
}

.chart-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  grid-template-rows: 1fr 1fr;
  gap: 12px;
  height: 100%;
}

.chart-box {
  background: rgba(10,15,30,0.5);
  border: 1px solid var(--border-dim);
  border-radius: 4px;
  padding: 10px;
  position: relative;
  display: flex;
  flex-direction: column;
}

.chart-box .chart-title {
  font-family: var(--font-display);
  font-size: 10px;
  letter-spacing: 2px;
  color: var(--text-dim);
  text-transform: uppercase;
  margin-bottom: 8px;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.chart-box .chart-title .live-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--green);
  animation: pulse-dot 2s infinite;
}

.chart-box .chart-title .live-dot.alert { background: var(--red); }

.chart-wrapper {
  flex: 1;
  min-height: 0;
  position: relative;
}

/* RIGHT COLUMN */
.right-col {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

/* LOG TERMINAL */
.terminal {
  flex: 1;
  display: flex;
  flex-direction: column;
  font-family: var(--font-mono);
  font-size: 10px;
}

.terminal-body {
  flex: 1;
  overflow-y: auto;
  padding: 10px 14px;
  line-height: 1.8;
}

.terminal-line {
  display: flex;
  gap: 10px;
  opacity: 0;
  animation: fade-in 0.3s forwards;
}

@keyframes fade-in {
  to { opacity: 1; }
}

.terminal-time { color: var(--text-dark); min-width: 70px; }
.terminal-tag { 
  min-width: 50px; 
  font-weight: 600; 
  font-size: 9px;
  letter-spacing: 1px;
}
.terminal-tag.info { color: var(--cyan); }
.terminal-tag.warn { color: var(--orange); }
.terminal-tag.alert { color: var(--red); }
.terminal-tag.ok { color: var(--green); }
.terminal-msg { color: var(--text-dim); }
.terminal-msg.alert { color: var(--red); }

/* GAUGE STYLES */
.gauge-container {
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 10px;
}

.gauge-value {
  position: absolute;
  text-align: center;
}
.gauge-value .num {
  font-family: var(--font-display);
  font-size: 28px;
  font-weight: 800;
  color: var(--cyan);
}
.gauge-value .label {
  font-size: 9px;
  color: var(--text-dim);
  letter-spacing: 2px;
}

/* RADAR OVERLAY */
.radar-overlay {
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  width: 60%;
  height: 60%;
  border: 1px solid rgba(0,240,255,0.1);
  border-radius: 50%;
  pointer-events: none;
}
.radar-overlay::before {
  content: '';
  position: absolute;
  top: 25%; left: 25%; right: 25%; bottom: 25%;
  border: 1px solid rgba(0,240,255,0.08);
  border-radius: 50%;
}

/* SCROLLBAR */
::-webkit-scrollbar { width: 4px; }
::-webkit-scrollbar-track { background: var(--bg-primary); }
::-webkit-scrollbar-thumb { background: var(--border-dim); border-radius: 2px; }
::-webkit-scrollbar-thumb:hover { background: var(--border-glow); }

/* RESPONSIVE */
@media (max-width: 1200px) {
  .main-grid { grid-template-columns: 240px 1fr 280px; }
}
@media (max-width: 900px) {
  .main-grid { grid-template-columns: 1fr; grid-template-rows: auto; height: auto; }
  .chart-grid { grid-template-columns: 1fr; }
}
</style>
<base target="_blank">
</head>
<body>
<div class="bg-grid"></div>

<!-- HEADER -->
<div class="header">
  <div class="header-left">
    <div class="logo">AGENT<span>GUARD</span></div>
    <div class="badge-class">CLASSIFIED // LEVEL 4</div>
  </div>
  <div class="header-right">
    <div class="status-indicator">
      <div class="status-dot"></div>
      <span>SYSTEM OPERATIONAL</span>
    </div>
    <div class="clock" id="clock">00:00:00</div>
  </div>
</div>

<!-- MAIN GRID -->
<div class="main-grid">

  <!-- LEFT COLUMN -->
  <div class="left-col">

    <!-- THREAT LEVEL -->
    <div class="panel">
      <div class="corner corner-tl"></div><div class="corner corner-tr"></div>
      <div class="corner corner-bl"></div><div class="corner corner-br"></div>
      <div class="panel-header">
        <span>Niveau de Menace</span>
        <span class="panel-id">SYS-THR-01</span>
      </div>
      <div class="threat-level">
        <div class="threat-label">GLOBAL THREAT INDEX</div>
        <div class="threat-value" id="threatValue">LOW</div>
        <div class="threat-sub" id="threatSub">Aucune menace active détectée</div>
      </div>
    </div>

    <!-- KPIs -->
    <div class="panel" style="flex:1;">
      <div class="corner corner-tl"></div><div class="corner corner-tr"></div>
      <div class="corner corner-bl"></div><div class="corner corner-br"></div>
      <div class="panel-header">
        <span>Métriques Clés</span>
        <span class="panel-id">KPI-MON-02</span>
      </div>
      <div class="kpi-list" id="kpiList">
        <div class="kpi-item">
          <div class="kpi-label"><span class="kpi-icon">📡</span> SPANS TOTALES</div>
          <div class="kpi-value" id="kpiSpans">0</div>
        </div>
        <div class="kpi-item">
          <div class="kpi-label"><span class="kpi-icon">🛡️</span> BLOQUÉES</div>
          <div class="kpi-value alert" id="kpiBlocked">0</div>
        </div>
        <div class="kpi-item">
          <div class="kpi-label"><span class="kpi-icon">💰</span> COÛT (USD)</div>
          <div class="kpi-value" id="kpiCost">$0.0000</div>
        </div>
        <div class="kpi-item">
          <div class="kpi-label"><span class="kpi-icon">⚡</span> LATENCE MOY</div>
          <div class="kpi-value ok" id="kpiLatency">0ms</div>
        </div>
        <div class="kpi-item">
          <div class="kpi-label"><span class="kpi-icon">🔴</span> RISQUE CRITIQUE</div>
          <div class="kpi-value" id="kpiCritical">0</div>
        </div>
        <div class="kpi-item">
          <div class="kpi-label"><span class="kpi-icon">🟠</span> RISQUE ÉLEVÉ</div>
          <div class="kpi-value warn" id="kpiHigh">0</div>
        </div>
        <div class="kpi-item">
          <div class="kpi-label"><span class="kpi-icon">📊</span> TRACES ACTIVES</div>
          <div class="kpi-value" id="kpiTraces">0</div>
        </div>
        <div class="kpi-item">
          <div class="kpi-label"><span class="kpi-icon">🧠</span> AGENTS PROTÉGÉS</div>
          <div class="kpi-value ok" id="kpiAgents">1</div>
        </div>
      </div>
    </div>

    <!-- BUDGET GAUGE -->
    <div class="panel">
      <div class="corner corner-tl"></div><div class="corner corner-tr"></div>
      <div class="corner corner-bl"></div><div class="corner corner-br"></div>
      <div class="panel-header">
        <span>Budget Restant</span>
        <span class="panel-id">BUD-GAU-03</span>
      </div>
      <div class="gauge-container" style="height:140px; position:relative;">
        <canvas id="gaugeBudget"></canvas>
        <div class="gauge-value">
          <div class="num" id="gaugeValue">100%</div>
          <div class="label">BUDGET</div>
        </div>
      </div>
    </div>
  </div>

  <!-- CENTER COLUMN -->
  <div class="center-col">

    <!-- MAIN CHARTS -->
    <div class="panel" style="flex:1;">
      <div class="corner corner-tl"></div><div class="corner corner-tr"></div>
      <div class="corner corner-bl"></div><div class="corner corner-br"></div>
      <div class="panel-header">
        <span>Analyse Temps Réel</span>
        <span class="panel-id">ANA-RTL-04</span>
      </div>
      <div class="chart-container">
        <div class="chart-grid">

          <!-- LINE CHART -->
          <div class="chart-box">
            <div class="chart-title">
              <span>Flux d'Activité (24h)</span>
              <div class="live-dot"></div>
            </div>
            <div class="chart-wrapper">
              <canvas id="chartActivity"></canvas>
            </div>
          </div>

          <!-- RADAR CHART -->
          <div class="chart-box">
            <div class="chart-title">
              <span>Profil de Risque</span>
              <div class="live-dot alert"></div>
            </div>
            <div class="chart-wrapper" style="position:relative;">
              <canvas id="chartRadar"></canvas>
              <div class="radar-overlay"></div>
            </div>
          </div>

          <!-- BAR CHART -->
          <div class="chart-box">
            <div class="chart-title">
              <span>Distribution des Menaces</span>
              <div class="live-dot"></div>
            </div>
            <div class="chart-wrapper">
              <canvas id="chartBar"></canvas>
            </div>
          </div>

          <!-- DOUGHNUT CHART -->
          <div class="chart-box">
            <div class="chart-title">
              <span>Taux de Blocage</span>
              <div class="live-dot"></div>
            </div>
            <div class="chart-wrapper">
              <canvas id="chartDoughnut"></canvas>
            </div>
          </div>

        </div>
      </div>
    </div>

    <!-- BOTTOM STRIP -->
    <div style="display:grid; grid-template-columns: repeat(4, 1fr); gap:12px;">
      <div class="panel" style="padding:12px; text-align:center;">
        <div style="font-size:9px; color:var(--text-dark); letter-spacing:2px; margin-bottom:4px;">INJECTIONS</div>
        <div style="font-family:var(--font-display); font-size:24px; font-weight:700; color:var(--red);" id="statInjection">0</div>
      </div>
      <div class="panel" style="padding:12px; text-align:center;">
        <div style="font-size:9px; color:var(--text-dark); letter-spacing:2px; margin-bottom:4px;">PII LEAKS</div>
        <div style="font-family:var(--font-display); font-size:24px; font-weight:700; color:var(--orange);" id="statPII">0</div>
      </div>
      <div class="panel" style="padding:12px; text-align:center;">
        <div style="font-size:9px; color:var(--text-dark); letter-spacing:2px; margin-bottom:4px;">TOOL MISUSE</div>
        <div style="font-family:var(--font-display); font-size:24px; font-weight:700; color:var(--yellow);" id="statTool">0</div>
      </div>
      <div class="panel" style="padding:12px; text-align:center;">
        <div style="font-size:9px; color:var(--text-dark); letter-spacing:2px; margin-bottom:4px;">BUDGET ALERTS</div>
        <div style="font-family:var(--font-display); font-size:24px; font-weight:700; color:var(--green);" id="statBudget">0</div>
      </div>
    </div>
  </div>

  <!-- RIGHT COLUMN -->
  <div class="right-col">

    <!-- TERMINAL -->
    <div class="panel terminal" style="flex:1;">
      <div class="corner corner-tl"></div><div class="corner corner-tr"></div>
      <div class="corner corner-bl"></div><div class="corner corner-br"></div>
      <div class="panel-header">
        <span>Journal d'Événements</span>
        <span class="panel-id">LOG-EVN-05</span>
      </div>
      <div class="terminal-body" id="terminalBody">
        <div class="terminal-line"><span class="terminal-time">00:00:00</span><span class="terminal-tag ok">[INIT]</span><span class="terminal-msg">AgentGuard Secure Terminal v2.6.1</span></div>
        <div class="terminal-line"><span class="terminal-time">00:00:00</span><span class="terminal-tag info">[SYS]</span><span class="terminal-msg">Connexion au collector établie</span></div>
        <div class="terminal-line"><span class="terminal-time">00:00:00</span><span class="terminal-tag info">[SYS]</span><span class="terminal-msg">Surveillance active — 6 vecteurs d'attaque</span></div>
      </div>
    </div>

    <!-- TOP THREATS -->
    <div class="panel" style="height:200px;">
      <div class="corner corner-tl"></div><div class="corner corner-tr"></div>
      <div class="corner corner-bl"></div><div class="corner corner-br"></div>
      <div class="panel-header">
        <span>Menaces Prioritaires</span>
        <span class="panel-id">THR-LST-06</span>
      </div>
      <div id="threatList" style="padding:10px 14px; font-size:10px;">
        <div style="color:var(--text-dark); text-align:center; padding:20px;">Aucune menace détectée</div>
      </div>
    </div>

    <!-- SYSTEM STATUS -->
    <div class="panel">
      <div class="corner corner-tl"></div><div class="corner corner-tr"></div>
      <div class="corner corner-bl"></div><div class="corner corner-br"></div>
      <div class="panel-header">
        <span>État des Sous-systèmes</span>
        <span class="panel-id">SUB-SYS-07</span>
      </div>
      <div style="padding:10px 14px;">
        <div style="display:flex; justify-content:space-between; align-items:center; padding:6px 0; border-bottom:1px solid var(--border-dim);">
          <span style="font-size:10px; color:var(--text-dim);">🔍 Scanner d'Injection</span>
          <span style="font-size:10px; color:var(--green); font-weight:600;">ONLINE</span>
        </div>
        <div style="display:flex; justify-content:space-between; align-items:center; padding:6px 0; border-bottom:1px solid var(--border-dim);">
          <span style="font-size:10px; color:var(--text-dim);">🔒 PII Detector</span>
          <span style="font-size:10px; color:var(--green); font-weight:600;">ONLINE</span>
        </div>
        <div style="display:flex; justify-content:space-between; align-items:center; padding:6px 0; border-bottom:1px solid var(--border-dim);">
          <span style="font-size:10px; color:var(--text-dim);">🛡️ Policy Engine</span>
          <span style="font-size:10px; color:var(--green); font-weight:600;">ONLINE</span>
        </div>
        <div style="display:flex; justify-content:space-between; align-items:center; padding:6px 0; border-bottom:1px solid var(--border-dim);">
          <span style="font-size:10px; color:var(--text-dim);">💰 Budget Monitor</span>
          <span style="font-size:10px; color:var(--green); font-weight:600;">ONLINE</span>
        </div>
        <div style="display:flex; justify-content:space-between; align-items:center; padding:6px 0;">
          <span style="font-size:10px; color:var(--text-dim);">📡 Collector Uplink</span>
          <span style="font-size:10px; color:var(--green); font-weight:600;">ONLINE</span>
        </div>
      </div>
    </div>
  </div>
</div>

<script>
// ── CONFIG ──
const COLLECTOR = 'https://agentguard-aqal.onrender.com';
const REFRESH_MS = 3000;

// ── CHART.JS THEME ──
Chart.defaults.color = '#6b7a9c';
Chart.defaults.borderColor = '#1a2342';
Chart.defaults.font.family = "'JetBrains Mono', monospace";
Chart.defaults.font.size = 10;

// ── CLOCK ──
function updateClock() {
  const now = new Date();
  document.getElementById('clock').textContent = 
    now.toLocaleTimeString('fr-FR', { hour12: false }) + ' UTC';
}
setInterval(updateClock, 1000);
updateClock();

// ── GAUGE (Budget) ──
const gaugeCtx = document.getElementById('gaugeBudget').getContext('2d');
const gaugeChart = new Chart(gaugeCtx, {
  type: 'doughnut',
  data: {
    labels: ['Utilisé', 'Restant'],
    datasets: [{
      data: [0, 100],
      backgroundColor: ['#ff2a6d', '#00ff88'],
      borderWidth: 0,
      cutout: '75%'
    }]
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display: false }, tooltip: { enabled: false } },
    animation: { duration: 1000, easing: 'easeOutQuart' }
  }
});

// ── LINE CHART (Activity) ──
const activityCtx = document.getElementById('chartActivity').getContext('2d');
const activityGradient = activityCtx.createLinearGradient(0, 0, 0, 200);
activityGradient.addColorStop(0, 'rgba(0,240,255,0.3)');
activityGradient.addColorStop(1, 'rgba(0,240,255,0)');

const activityChart = new Chart(activityCtx, {
  type: 'line',
  data: {
    labels: Array(12).fill('').map((_,i) => `-${12-i}h`),
    datasets: [{
      label: 'Spans',
      data: Array(12).fill(0),
      borderColor: '#00f0ff',
      backgroundColor: activityGradient,
      fill: true,
      tension: 0.4,
      pointRadius: 3,
      pointBackgroundColor: '#00f0ff',
      pointBorderColor: '#050810',
      pointBorderWidth: 2,
      borderWidth: 2
    }, {
      label: 'Bloquées',
      data: Array(12).fill(0),
      borderColor: '#ff2a6d',
      backgroundColor: 'transparent',
      fill: false,
      tension: 0.4,
      pointRadius: 3,
      pointBackgroundColor: '#ff2a6d',
      borderWidth: 2
    }]
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { labels: { color: '#6b7a9c', font: { size: 10 } } } },
    scales: {
      x: { grid: { color: '#1a2342' }, ticks: { color: '#3a4566', font: { size: 9 } } },
      y: { grid: { color: '#1a2342' }, ticks: { color: '#3a4566', font: { size: 9 } } }
    },
    animation: { duration: 800 }
  }
});

// ── RADAR CHART ──
const radarCtx = document.getElementById('chartRadar').getContext('2d');
const radarChart = new Chart(radarCtx, {
  type: 'radar',
  data: {
    labels: ['Injection', 'PII', 'Tool Misuse', 'Budget', 'Exfiltration', 'Jailbreak'],
    datasets: [{
      label: 'Menaces détectées',
      data: [0, 0, 0, 0, 0, 0],
      borderColor: '#ff2a6d',
      backgroundColor: 'rgba(255,42,109,0.15)',
      pointBackgroundColor: '#ff2a6d',
      pointBorderColor: '#050810',
      pointBorderWidth: 2,
      pointRadius: 4,
      borderWidth: 2
    }, {
      label: 'Seuil critique',
      data: [10, 10, 10, 10, 10, 10],
      borderColor: 'rgba(0,240,255,0.3)',
      backgroundColor: 'transparent',
      borderDash: [5, 5],
      pointRadius: 0,
      borderWidth: 1
    }]
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { labels: { color: '#6b7a9c', font: { size: 9 } } } },
    scales: {
      r: {
        grid: { color: '#1a2342' },
        angleLines: { color: '#1a2342' },
        pointLabels: { color: '#6b7a9c', font: { size: 9, family: "'Rajdhani', sans-serif" } },
        ticks: { display: false, backdropColor: 'transparent' },
        suggestedMin: 0,
        suggestedMax: 15
      }
    }
  }
});

// ── BAR CHART ──
const barCtx = document.getElementById('chartBar').getContext('2d');
const barChart = new Chart(barCtx, {
  type: 'bar',
  data: {
    labels: ['Low', 'Medium', 'High', 'Critical'],
    datasets: [{
      label: 'Incidents',
      data: [0, 0, 0, 0],
      backgroundColor: ['#00ff88', '#ff9f1c', '#ff2a6d', '#bc13fe'],
      borderRadius: 4,
      borderSkipped: false
    }]
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display: false } },
    scales: {
      x: { grid: { display: false }, ticks: { color: '#6b7a9c', font: { size: 10 } } },
      y: { grid: { color: '#1a2342' }, ticks: { color: '#3a4566', font: { size: 9 } } }
    }
  }
});

// ── DOUGHNUT CHART ──
const doughnutCtx = document.getElementById('chartDoughnut').getContext('2d');
const doughnutChart = new Chart(doughnutCtx, {
  type: 'doughnut',
  data: {
    labels: ['Safe', 'Blocked'],
    datasets: [{
      data: [100, 0],
      backgroundColor: ['#00ff88', '#ff2a6d'],
      borderWidth: 0,
      cutout: '65%'
    }]
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { position: 'bottom', labels: { color: '#6b7a9c', font: { size: 10 }, padding: 15 } }
    }
  }
});

// ── TERMINAL ──
function addLog(tag, msg, type = 'info') {
  const body = document.getElementById('terminalBody');
  const time = new Date().toLocaleTimeString('fr-FR', { hour12: false });
  const tagClass = type === 'alert' ? 'alert' : type === 'warn' ? 'warn' : type === 'ok' ? 'ok' : 'info';
  const msgClass = type === 'alert' ? 'alert' : '';
  const line = document.createElement('div');
  line.className = 'terminal-line';
  line.innerHTML = `<span class="terminal-time">${time}</span><span class="terminal-tag ${tagClass}">[${tag}]</span><span class="terminal-msg ${msgClass}">${msg}</span>`;
  body.appendChild(line);
  body.scrollTop = body.scrollHeight;
  if (body.children.length > 50) body.removeChild(body.children[0]);
}

// ── DATA FETCH ──
let lastData = null;
let historyData = Array(12).fill(0);
let blockedHistory = Array(12).fill(0);

async function fetchData() {
  try {
    const r = await fetch(`${COLLECTOR}/api/metrics`);
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const d = await r.json();

    // Update KPIs
    document.getElementById('kpiSpans').textContent = d.total_spans;
    document.getElementById('kpiBlocked').textContent = d.blocked_operations;
    document.getElementById('kpiCost').textContent = '$' + d.total_cost_usd.toFixed(4);
    document.getElementById('kpiTraces').textContent = d.total_traces;
    document.getElementById('kpiCritical').textContent = d.risk_distribution.critical;
    document.getElementById('kpiHigh').textContent = d.risk_distribution.high;

    // Threat level
    const threatEl = document.getElementById('threatValue');
    const threatSub = document.getElementById('threatSub');
    if (d.risk_distribution.critical > 0) {
      threatEl.textContent = 'CRITICAL';
      threatEl.className = 'threat-value critical';
      threatSub.textContent = `${d.risk_distribution.critical} menace(s) critique(s) active(s)`;
    } else if (d.risk_distribution.high > 0) {
      threatEl.textContent = 'ELEVATED';
      threatEl.className = 'threat-value warning';
      threatSub.textContent = `${d.risk_distribution.high} menace(s) élevée(s) détectée(s)`;
    } else {
      threatEl.textContent = 'LOW';
      threatEl.className = 'threat-value';
      threatSub.textContent = 'Aucune menace active détectée';
    }

    // Gauge
    const total = d.total_spans || 1;
    const blocked = d.blocked_operations;
    const pct = Math.min((blocked / total) * 100, 100);
    gaugeChart.data.datasets[0].data = [pct, 100 - pct];
    gaugeChart.data.datasets[0].backgroundColor = [pct > 30 ? '#ff2a6d' : '#00ff88', '#1a2342'];
    document.getElementById('gaugeValue').textContent = (100 - pct).toFixed(0) + '%';
    document.getElementById('gaugeValue').style.color = pct > 30 ? '#ff2a6d' : '#00ff88';
    gaugeChart.update('none');

    // Activity chart
    historyData.shift();
    historyData.push(d.total_spans);
    blockedHistory.shift();
    blockedHistory.push(d.blocked_operations);
    activityChart.data.datasets[0].data = historyData;
    activityChart.data.datasets[1].data = blockedHistory;
    activityChart.update('none');

    // Radar
    radarChart.data.datasets[0].data = [
      d.risk_distribution.high + d.risk_distribution.critical,
      d.risk_distribution.medium,
      d.risk_distribution.high,
      d.blocked_operations,
      Math.floor(d.risk_distribution.medium / 2),
      d.risk_distribution.high
    ];
    radarChart.update('none');

    // Bar
    barChart.data.datasets[0].data = [
      d.risk_distribution.low,
      d.risk_distribution.medium,
      d.risk_distribution.high,
      d.risk_distribution.critical
    ];
    barChart.update('none');

    // Doughnut
    const safe = Math.max(d.total_spans - d.blocked_operations, 0);
    doughnutChart.data.datasets[0].data = [safe, d.blocked_operations];
    doughnutChart.update('none');

    // Bottom stats
    document.getElementById('statInjection').textContent = d.risk_distribution.high;
    document.getElementById('statPII').textContent = d.risk_distribution.medium;
    document.getElementById('statTool').textContent = d.blocked_operations;
    document.getElementById('statBudget').textContent = d.total_cost_usd > 1 ? '1' : '0';

    // Threat list
    const threatList = document.getElementById('threatList');
    if (d.top_threats && d.top_threats.length > 0) {
      threatList.innerHTML = d.top_threats.map(t => `
        <div style="display:flex; justify-content:space-between; align-items:center; padding:6px 0; border-bottom:1px solid var(--border-dim);">
          <span style="color:var(--red); font-weight:600;">⚠ ${t.reason}</span>
          <span style="color:var(--orange); font-family:var(--font-display); font-weight:700;">${t.count}</span>
        </div>
      `).join('');
    } else {
      threatList.innerHTML = '<div style="color:var(--text-dark); text-align:center; padding:20px;">Aucune menace détectée</div>';
    }

    // Logs on change
    if (lastData && d.total_spans > lastData.total_spans) {
      const newSpans = d.total_spans - lastData.total_spans;
      const newBlocked = d.blocked_operations - lastData.blocked_operations;
      if (newBlocked > 0) {
        addLog('ALERT', `${newBlocked} span(s) bloquée(s) — menace détectée`, 'alert');
      } else {
        addLog('INFO', `${newSpans} nouvelle(s) span(s) reçue(s)`, 'ok');
      }
    }

    lastData = d;

  } catch (e) {
    addLog('ERR', 'Collector inaccessible: ' + e.message, 'warn');
  }
}

// ── INIT ──
fetchData();
setInterval(fetchData, REFRESH_MS);

// Demo data if empty
setTimeout(() => {
  if (!lastData || lastData.total_spans === 0) {
    addLog('INFO', 'Aucune donnée — utilisez le simulateur pour injecter des spans', 'warn');
  }
}, 2000);

</script>
</body>
</html>
"""

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
        cur.execute("SELECT * FROM spans WHERE trace_id = %s ORDER BY timestamp", (trace_id,))
    else:
        cur = conn.cursor()
        cur.execute("SELECT * FROM spans WHERE trace_id = ? ORDER BY timestamp", (trace_id,))
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
            .span-type { color: #38bdf8; font-weight: 700; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em; }
            .meta { color: #64748b; font-size: 0.82rem; margin-top: 4px; }
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
        html += f"""
        <div class="span-card {'blocked' if blocked else ''}">
            <div class="span-type">{row["span_type"]} — {row["latency_ms"]:.0f}ms — ${row["cost_usd"]:.6f}</div>
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

@app.route("/api/key")
@limiter.limit("5 per minute")
def show_key():
    # Pas de valeur par défaut : si AGENTGUARD_ADMIN_SECRET n'est pas configuré,
    # l'endpoint est désactivé plutôt que de tomber sur un secret devinable.
    if not ADMIN_SECRET:
        return jsonify({"error": "AGENTGUARD_ADMIN_SECRET not configured — endpoint disabled"}), 404
    admin_secret = request.args.get("admin", "")
    if secrets.compare_digest(admin_secret, ADMIN_SECRET):
        return jsonify({"api_key": API_KEY})
    return jsonify({"error": "Admin secret required"}), 403

if _API_KEY_WAS_GENERATED and DB_TYPE == "postgres":
    print("[AG] 🚨 PostgreSQL actif (config prod) mais AGENTGUARD_API_KEY n'est "
          "pas fixée — chaque redémarrage invalidera les intégrations SDK "
          "existantes. Configure AGENTGUARD_API_KEY dans les variables d'env Render.")

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 8080))
    print(f"🛡️ AgentGuard Collector v3 running on http://0.0.0.0:{port}")
    print(f"   DB: {DB_TYPE}")
    app.run(host="0.0.0.0", port=port, debug=False)
