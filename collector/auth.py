"""Authentication + session management."""
import hashlib
import secrets
import structlog
from flask import Blueprint, request, jsonify, render_template_string, redirect, url_for, g, current_app
from collector.db import get_pg_conn, is_postgres
import sqlite3
import os

logger = structlog.get_logger("agentguard.auth")

auth_bp = Blueprint("auth", __name__)

DB_SQLITE_PATH = os.environ.get("AGENTGUARD_DB_PATH", "/tmp/agentguard.db")


# ── PROTECTED ENDPOINTS ─────────────────────────────────────────
PROTECTED_ENDPOINTS = {
    "api.receive_span", "api.list_traces", "api.get_trace", "api.get_metrics",
    "auth.dashboard", "trace.trace_detail", "api.get_detection_stats",
    "api.api_models", "api.api_heatmap", "api.api_checks_breakdown",
    "api.api_expensive_spans", "api.api_cost_trend", "api.api_latency_distribution",
    "api.api_recent_events", "api.api_trend_daily", "api.get_llm_stats",
    "api.api_audit_trail", "api.api_checks_daily", "api.api_models_daily",
    "audit.audit_stats", "audit.audit_verify", "audit.audit_query",
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
    if is_postgres():
        conn = get_pg_conn()
        cur = conn.cursor()
        cur.execute("SELECT org_id FROM api_keys WHERE key_hash = %s AND active = TRUE", (key_hash,))
    else:
        conn = sqlite3.connect(DB_SQLITE_PATH)
        cur = conn.cursor()
        cur.execute("SELECT org_id FROM api_keys WHERE key_hash = ? AND active = 1", (key_hash,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else None


def resolve_org_id(key: str):
    if not key:
        return None
    api_key = current_app.config["API_KEY"]
    if api_key and safe_compare(key, api_key):
        return "default"
    return _lookup_org_by_key(key)


def _session_token(org_id: str, key_hash: str) -> str:
    return current_app.auth_serializer.dumps({"org_id": org_id, "key_hash": key_hash})


def _session_org_id(token: str):
    if not token:
        return None
    try:
        payload = current_app.auth_serializer.loads(token, max_age=current_app.auth_session_ttl)
        org_id = payload.get("org_id")
        key_hash = payload.get("key_hash")
        if not org_id or not key_hash:
            return None
        if org_id == "default":
            api_key = current_app.config["API_KEY"]
            if api_key and safe_compare(key_hash, hash_key(api_key)):
                return "default"
            return None
        if is_postgres():
            conn = get_pg_conn()
            cur = conn.cursor()
            cur.execute("SELECT 1 FROM api_keys WHERE org_id = %s AND key_hash = %s AND active = TRUE", (org_id, key_hash))
        else:
            conn = sqlite3.connect(DB_SQLITE_PATH)
            cur = conn.cursor()
            cur.execute("SELECT 1 FROM api_keys WHERE org_id = ? AND key_hash = ? AND active = 1", (org_id, key_hash))
        valid = cur.fetchone() is not None
        conn.close()
        return org_id if valid else None
    except Exception:
        return None


def require_auth():
    api_key = current_app.config["API_KEY"]
    if not api_key:
        g.org_id = "default"
        return True
    key = request.headers.get("X-API-Key", "").strip()
    if key:
        org_id = resolve_org_id(key)
        if org_id:
            g.org_id = org_id
            return True
    auth_cookie = current_app.config["AUTH_COOKIE"]
    org_id = _session_org_id(request.cookies.get(auth_cookie, ""))
    if org_id:
        g.org_id = org_id
        return True
    return False


LOGIN_HTML = '''<!doctype html><html lang="en"><head><meta charset="utf-8"><title>AgentGuard — Sign in</title>
<style>:root{color-scheme:dark;--bg:#07111f;--card:#0d1b2d;--border:#21334a;--text:#eef5ff;--muted:#93a6bd;--accent:#38bdf8;--accent2:#2563eb}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:radial-gradient(circle at 50% 20%,#12304f 0%,var(--bg) 55%);font-family:Inter,system-ui,sans-serif;color:var(--text)}.wrap{width:min(430px,92vw)}.brand{text-align:center;margin-bottom:24px}.logo{width:56px;height:56px;margin:0 auto 14px;border-radius:16px;display:grid;place-items:center;background:linear-gradient(135deg,var(--accent2),var(--accent));font-size:27px}h1{margin:0;font-size:24px}.subtitle{margin:8px 0 0;color:var(--muted);font-size:14px}.card{background:rgba(13,27,45,.94);border:1px solid var(--border);border-radius:20px;padding:28px;backdrop-filter:blur(16px)}label{display:block;margin:0 0 9px;font-size:13px;font-weight:600}input{width:100%;height:48px;border:1px solid #29425e;border-radius:12px;background:#091522;color:var(--text);padding:0 14px;font:inherit}input:focus{border-color:var(--accent);outline:none}button{width:100%;height:48px;margin-top:16px;border:0;border-radius:12px;color:#fff;font:inherit;font-weight:700;cursor:pointer;background:linear-gradient(135deg,var(--accent2),var(--accent))}.hint{margin-top:15px;color:var(--muted);font-size:12px}.error{margin:0 0 14px;border:1px solid rgba(251,113,133,.35);background:rgba(127,29,29,.2);color:#fecdd3;border-radius:10px;padding:10px 12px;font-size:13px}</style></head>
<body><main class="wrap"><div class="brand"><div class="logo">🛡️</div><h1>AgentGuard</h1><div class="subtitle">Runtime Security Console</div></div><section class="card">{% if error %}<div class="error">{{ error }}</div>{% endif %}<form method="post" action="/login"><label for="api_key">API Key</label><input id="api_key" name="api_key" type="password" autocomplete="off" placeholder="ag-••••••••••••" required autofocus><button type="submit">Sign in to dashboard</button></form><div class="hint">API key submitted over HTTPS, never in URL.</div></section></main></body></html>'''


@auth_bp.before_app_request
def check_auth():
    if request.method == "OPTIONS":
        return None
    if request.endpoint in ("auth.login", "auth.healthz", "auth.auth_login", "auth.logout"):
        return None
    if request.endpoint not in PROTECTED_ENDPOINTS:
        return None
    if not require_auth():
        if request.endpoint in ("auth.dashboard", "trace.trace_detail"):
            return redirect(url_for("auth.login"))
        return jsonify({"error": "Unauthorized — use X-API-Key header"}), 401


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    from collector.audit_routes import get_audit_log, AuditEventType
    
    if request.method == "POST":
        key = str(request.form.get("api_key", "")).strip()
        org_id = resolve_org_id(key)
        if not org_id:
            # Audit : login failed
            try:
                audit = get_audit_log()
                if audit:
                    audit.log_event(
                        event_type=AuditEventType.LOGIN_FAILED,
                        org_id="unknown", actor="unknown",
                        resource="dashboard", action="login_failed",
                        details={"reason": "invalid_api_key"},
                        risk_level="warning",
                    )
            except Exception:
                pass
            return render_template_string(LOGIN_HTML, error="Invalid API key."), 401
        
        # ✅ Login success : créer la réponse AVANT l'audit
        resp = redirect(url_for("auth.dashboard"))
        auth_cookie = current_app.config["AUTH_COOKIE"]
        resp.set_cookie(
            auth_cookie,
            _session_token(org_id, hash_key(key)),
            httponly=True, samesite="Lax",
            secure=current_app.auth_cookie_secure,
            max_age=current_app.auth_session_ttl,
        )
        
        # ✅ Audit : login success (APRÈS la création de la réponse)
        try:
            audit = get_audit_log()
            if audit:
                audit.log_event(
                    event_type=AuditEventType.LOGIN_SUCCESS,
                    org_id=org_id,
                    actor=f"user:{org_id}",
                    resource="dashboard",
                    action="login",
                    details={"method": "api_key"},
                    risk_level="info",
                )
        except Exception:
            pass
        
        return resp
    
    return render_template_string(LOGIN_HTML, error=None)


@auth_bp.post("/api/auth-login")
def auth_login():
    data = request.get_json(silent=True) or {}
    key = str(data.get("api_key", "")).strip()
    org_id = resolve_org_id(key)
    if not org_id:
        return jsonify({"error": "Unauthorized"}), 401
    resp = jsonify({"status": "ok", "org_id": org_id})
    auth_cookie = current_app.config["AUTH_COOKIE"]
    resp.set_cookie(
        auth_cookie,
        _session_token(org_id, hash_key(key)),
        httponly=True, samesite="Lax",
        secure=current_app.auth_cookie_secure,
        max_age=current_app.auth_session_ttl,
    )
    return resp


@auth_bp.post("/logout")
def logout():
    resp = redirect(url_for("auth.login"))
    resp.delete_cookie(current_app.config["AUTH_COOKIE"])
    return resp


@auth_bp.get("/healthz")
def healthz():
    try:
        from collector.db import get_db
        conn = get_db()
        conn.close()
        return jsonify({"status": "ok"}), 200
    except Exception as exc:
        return jsonify({"status": "degraded", "error": str(exc)[:120]}), 503


@auth_bp.route("/")
def dashboard():
    from collector.dashboard import DASHBOARD_HTML
    from flask import make_response
    return make_response(render_template_string(DASHBOARD_HTML))
