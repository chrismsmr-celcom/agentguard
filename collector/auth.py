"""Authentication + session management + RBAC (Identity Engine Phase 1)."""
import hashlib
import secrets
import structlog
from functools import wraps
from typing import Optional, List
from flask import (
    Blueprint, request, jsonify, render_template_string,
    redirect, url_for, g, current_app,
)
from collector.db import (
    get_pg_conn, get_sqlite_conn, is_postgres, 
    resolve_agent_identity, _get_db_path
)
import sqlite3
import os

logger = structlog.get_logger("agentguard.auth")

auth_bp = Blueprint("auth", __name__)


# ── PROTECTED ENDPOINTS ─────────────────────────────────────────
PROTECTED_ENDPOINTS = {
    "api.receive_span", "api.list_traces", "api.get_trace", "api.get_metrics",
    "auth.dashboard", "trace.trace_detail", "api.get_detection_stats",
    "api.api_models", "api.api_heatmap", "api.api_checks_breakdown",
    "api.api_expensive_spans", "api.api_cost_trend", "api.api_latency_distribution",
    "api.api_recent_events", "api.api_trend_daily", "api.get_llm_stats",
    "api.api_audit_trail", "api.api_checks_daily", "api.api_models_daily",
    "audit.audit_stats", "audit.audit_verify", "audit.audit_query",
    "identity.create_tenant", "identity.create_org",
    "identity.create_user", "identity.create_agent",
    "identity.revoke_agent", "identity.list_agents",
    "identity.get_me",
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
    """Legacy : lookup dans la table api_keys (ancien système)."""
    if not key:
        return None
    key_hash = hash_key(key)
    if is_postgres():
        conn = get_pg_conn()
        cur = conn.cursor()
        try:
            cur.execute(
                "SELECT org_id FROM api_keys WHERE key_hash = %s AND active = TRUE",
                (key_hash,),
            )
            row = cur.fetchone()
        finally:
            conn.close()
    else:
        # ✅ DYNAMIC PATH LOOKUP
        conn = sqlite3.connect(_get_db_path())
        cur = conn.cursor()
        try:
            cur.execute(
                "SELECT org_id FROM api_keys WHERE key_hash = ? AND active = 1",
                (key_hash,),
            )
            row = cur.fetchone()
        finally:
            conn.close()
    return row[0] if row else None


# ── PLATFORM IDENTITY RESOLUTION (Phase 1) ────────────────
def resolve_org_id(key: str):
    """
    Résout une clé API en org_id.
    
    Order of resolution:
    1. Platform key (agp_...) → sets g.platform_identity
    2. Legacy global API key → "default"
    3. Agent key (ag_...) → resolves via DB
    4. Legacy key in api_keys table
    """
    if not key:
        return None
    
    # ── 1. PLATFORM KEY (NEW) ──────────────────────────
    try:
        from collector.platform_identity import (
            resolve_platform_identity, PLATFORM_KEY_PREFIX
        )
        if key.startswith(PLATFORM_KEY_PREFIX):
            platform_identity = resolve_platform_identity(key)
            if platform_identity:
                g.platform_identity = platform_identity
                # Platform identities act as "default" org for authorization
                # but with explicit permissions checked per-route
                logger.info(
                    "platform_identity_resolved",
                    service=platform_identity["service_name"],
                    permissions=[p.value for p in platform_identity["permissions"]],
                )
                return "platform"  # Special org_id for platform identities
    except Exception as e:
        logger.warning("platform_identity_resolution_failed", error=str(e))
    
    # ── 2. Legacy global API key ───────────────────────
    api_key = current_app.config["API_KEY"]
    if api_key and safe_compare(key, api_key):
        # ⚠️ PHASE 2: Log SYSTEM usage for deprecation tracking
        logger.warning(
            "legacy_system_key_used",
            ip=request.remote_addr,
            endpoint=request.endpoint,
            note="DEPRECATED: migrate to platform service identities (agp_...)",
        )
        return "default"
    
    # ── 3. Agent key (ag_...) ──────────────────────────
    identity = resolve_agent_identity(key)
    if identity:
        g.agent_identity = identity
        return identity["org_id"]
    
    # ── 4. Fallback: legacy api_keys table ─────────────
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
            try:
                cur.execute(
                    "SELECT 1 FROM api_keys WHERE org_id = %s AND key_hash = %s AND active = TRUE",
                    (org_id, key_hash),
                )
                valid = cur.fetchone() is not None
            finally:
                conn.close()
        else:
            # ✅ DYNAMIC PATH LOOKUP
            conn = sqlite3.connect(_get_db_path())
            cur = conn.cursor()
            try:
                cur.execute(
                    "SELECT 1 FROM api_keys WHERE org_id = ? AND key_hash = ? AND active = 1",
                    (org_id, key_hash),
                )
                valid = cur.fetchone() is not None
            finally:
                conn.close()
        return org_id if valid else None
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════
# IDENTITY RESOLUTION (Phase 1)
# ═══════════════════════════════════════════════════════════════

def resolve_full_identity():
    """
    Résout l'identité complète depuis la requête courante.
    Retourne un ResolvedIdentity ou None.
    """
    try:
        from identity import ResolvedIdentity, IdentityType, Role
    except ImportError:
        return None
    
    # Déjà résolu ?
    if hasattr(g, "identity") and g.identity is not None:
        return g.identity
    
    # Agent identity déjà résolu par resolve_org_id ?
    if hasattr(g, "agent_identity") and g.agent_identity:
        info = g.agent_identity
        identity = ResolvedIdentity(
            identity_type=IdentityType.AGENT,
            tenant_id=info["tenant_id"],
            org_id=info["org_id"],
            subject_id=info["agent_id"],
            role=Role.DEVELOPER,
            agent_name=info.get("agent_name"),
        )
        g.identity = identity
        return identity
    
    # Clé API globale legacy → rôle admin (contrôlé)
    api_key = current_app.config["API_KEY"]
    if api_key:
        key = request.headers.get("X-API-Key", "").strip()
        if key and safe_compare(key, api_key):
            # ✅ Security hardening : vérifier si legacy key est autorisée
            allow_legacy = current_app.config.get("ALLOW_LEGACY_SYSTEM_KEY", False)
            environment = current_app.config.get("ENVIRONMENT", "development")
            
            if not allow_legacy and environment == "production":
                logger.error(
                    "legacy_system_key_rejected_in_production",
                    ip=request.remote_addr,
                )
                return None
            
            # Log chaque utilisation de SYSTEM (surveillance)
            logger.warning(
                "legacy_system_key_used",
                ip=request.remote_addr,
                endpoint=request.endpoint,
                note="Consider migrating to tenant-scoped admin keys",
            )
            
            identity = ResolvedIdentity(
                identity_type=IdentityType.SYSTEM,
                tenant_id="default",
                org_id="default",
                subject_id="system_legacy_key",
                role=Role.ADMIN,
            )
            g.identity = identity
            return identity
    
    # Session user
    if hasattr(g, "user_identity") and g.user_identity:
        g.identity = g.user_identity
        return g.user_identity
    
    return None


# ═══════════════════════════════════════════════════════════════
# BOLA AUTHORIZATION (CWE-639 prevention)
# ═══════════════════════════════════════════════════════════════

def authorize_resource_access(
    target_tenant_id: str,
    target_org_id: Optional[str] = None,
    allow_cross_org: bool = False,
) -> bool:
    """
    Vérifie que l'identité courante a accès à la ressource ciblée.
    
    Règles :
      - SYSTEM → accès total (legacy, à déprécier)
      - ADMIN → accès à toutes les orgs de SON tenant
      - DEVELOPER/AUDITOR/VIEWER → uniquement leur org
    """
    try:
        from identity import IdentityType, Role
    except ImportError:
        return False
    
    identity = resolve_full_identity()
    if not identity:
        logger.warning("authz_denied_no_identity", target_tenant=target_tenant_id)
        return False
    
    # SYSTEM identity (legacy global admin)
    if identity.identity_type == IdentityType.SYSTEM:
        return True
    
    # Vérification tenant : TOUJOURS requise
    if identity.tenant_id != target_tenant_id:
        logger.warning(
            "authz_denied_cross_tenant",
            actor_tenant=identity.tenant_id,
            target_tenant=target_tenant_id,
            actor_role=identity.role.value if hasattr(identity.role, "value") else str(identity.role),
        )
        return False
    
    # Pas d'org_id cible → OK pour tenant admin
    if target_org_id is None:
        return True
    
    # Tenant admin peut accéder à toutes les orgs du tenant
    if identity.role == Role.ADMIN:
        return True
    
    # Developer/Auditor/Viewer : uniquement son org
    if not allow_cross_org and identity.org_id != target_org_id:
        logger.warning(
            "authz_denied_cross_org",
            actor_org=identity.org_id,
            target_org=target_org_id,
            actor_role=identity.role.value if hasattr(identity.role, "value") else str(identity.role),
        )
        return False
    
    return True


# ═══════════════════════════════════════════════════════════════
# RBAC DECORATORS
# ═══════════════════════════════════════════════════════════════

def require_role(*required_roles: str):
    """Décorateur Flask pour restreindre un endpoint à certains rôles."""
    try:
        from identity import Role
        required = [Role(r) for r in required_roles]
    except (ImportError, ValueError):
        required = []
    
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not require_auth():
                return jsonify({"error": "Unauthorized"}), 401
            
            if not required:
                return f(*args, **kwargs)
            
            identity = resolve_full_identity()
            if not identity:
                return jsonify({"error": "Identity not resolved"}), 401
            
            for req_role in required:
                if identity.has_role(req_role):
                    return f(*args, **kwargs)
            
            logger.warning(
                "rbac_denied",
                identity=identity.to_dict() if hasattr(identity, "to_dict") else str(identity),
                required=[r.value for r in required],
                endpoint=request.endpoint,
            )
            return jsonify({
                "error": "Forbidden",
                "required_roles": [r.value for r in required],
                "your_role": identity.role.value if hasattr(identity.role, "value") else str(identity.role),
            }), 403
        
        return wrapper
    return decorator


def require_permission(permission: str):
    """Décorateur pour vérifier une permission spécifique."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not require_auth():
                return jsonify({"error": "Unauthorized"}), 401
            
            identity = resolve_full_identity()
            if not identity:
                return jsonify({"error": "Identity not resolved"}), 401
            
            try:
                from identity import role_has_permission
                if not role_has_permission(identity.role, permission):
                    logger.warning(
                        "permission_denied",
                        identity=identity.to_dict() if hasattr(identity, "to_dict") else str(identity),
                        permission=permission,
                    )
                    return jsonify({
                        "error": "Forbidden",
                        "required_permission": permission,
                        "your_role": identity.role.value if hasattr(identity.role, "value") else str(identity.role),
                    }), 403
            except ImportError:
                pass
            
            return f(*args, **kwargs)
        
        return wrapper
    return decorator


# ═══════════════════════════════════════════════════════════════
# AUTH MIDDLEWARE
# ═══════════════════════════════════════════════════════════════

def require_auth():
    """Vérifie l'authentification et enrichit g.org_id + g.identity."""
    api_key = current_app.config["API_KEY"]
    if not api_key:
        g.org_id = "default"
        return True
    
    key = request.headers.get("X-API-Key", "").strip()
    if key:
        # ✅ Security hardening : rejet explicite de la clé legacy en production
        if safe_compare(key, api_key):
            environment = current_app.config.get("ENVIRONMENT", "development")
            allow_legacy = current_app.config.get("ALLOW_LEGACY_SYSTEM_KEY", False)
            if environment == "production" and not allow_legacy:
                logger.error(
                    "legacy_system_key_rejected_in_production",
                    ip=request.remote_addr,
                )
                return False  # ← Refuser l'auth
        
        org_id = resolve_org_id(key)
        if org_id:
            g.org_id = org_id
            try:
                resolve_full_identity()
            except Exception as e:
                logger.debug("identity_resolution_failed", error=str(e))
            return True
    
    auth_cookie = current_app.config["AUTH_COOKIE"]
    org_id = _session_org_id(request.cookies.get(auth_cookie, ""))
    if org_id:
        g.org_id = org_id
        return True
    
    return False


# ── LOGIN HTML ───────────────────────────────────────────────────
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
    
    try:
        if not require_auth():
            if request.endpoint in ("auth.dashboard", "trace.trace_detail"):
                return redirect(url_for("auth.login"))
            return jsonify({"error": "Unauthorized — use X-API-Key header"}), 401
    except Exception as e:
        # ✅ Catch all auth errors and return 401
        logger.error("auth_middleware_error", error=str(e))
        return jsonify({"error": "Unauthorized"}), 401


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    from collector.audit_routes import get_audit_log, AuditEventType
    
    if request.method == "POST":
        key = str(request.form.get("api_key", "")).strip()
        org_id = resolve_org_id(key)
        if not org_id:
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
        
        resp = redirect(url_for("auth.dashboard"))
        auth_cookie = current_app.config["AUTH_COOKIE"]
        resp.set_cookie(
            auth_cookie,
            _session_token(org_id, hash_key(key)),
            httponly=True, samesite="Lax",
            secure=current_app.auth_cookie_secure,
            max_age=current_app.auth_session_ttl,
        )
        
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
