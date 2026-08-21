"""
Admin endpoints : customer management.

Security hardening (P0 fix):
- Admin secret ONLY via X-Admin-Secret header (never query params)
- Prevents CWE-598: Information Exposure Through Query String
- Query params leak into: reverse proxy logs, browser history, referrer headers
"""
import secrets
import structlog
from flask import Blueprint, request, jsonify, current_app
from collector.db import get_pg_conn, is_postgres
from collector.auth import safe_compare, hash_key
import sqlite3
import os

logger = structlog.get_logger("agentguard.admin")
admin_bp = Blueprint("admin", __name__)

DB_SQLITE_PATH = os.environ.get("AGENTGUARD_DB_PATH", "/tmp/agentguard.db")


def _verify_admin_secret() -> bool:
    """
    Vérifie le secret admin via header uniquement.
    
    ⚠️ SECURITY: Ne JAMAIS accepter le secret via query parameter.
    Les query params fuient dans :
      - Access logs du reverse proxy (nginx, Cloudflare, etc.)
      - Historique du navigateur
      - Header Referer vers des sites tiers
      - Outils de monitoring/analytics
    
    Si un client essaie d'utiliser ?admin=SECRET, on log une alerte.
    """
    admin_secret = current_app.config.get("ADMIN_SECRET")
    if not admin_secret:
        return False
    
    # ✅ UNIQUEMENT le header
    provided = request.headers.get("X-Admin-Secret", "")
    
    # 🔍 Détection d'attaque : si quelqu'un essaie via query param
    query_secret = request.args.get("admin")
    if query_secret:
        logger.warning(
            "admin_secret_in_query_param_detected",
            ip=request.remote_addr,
            endpoint=request.endpoint,
            user_agent=request.headers.get("User-Agent", "")[:100],
        )
        # Ne pas l'accepter, même s'il est valide
        return False
    
    return bool(provided) and safe_compare(provided, admin_secret)


@admin_bp.route("/api/key")
def show_key():
    """Retourne la clé API globale (admin only)."""
    if not current_app.config.get("ADMIN_SECRET"):
        return jsonify({"error": "AGENTGUARD_ADMIN_SECRET not configured"}), 404
    
    if not _verify_admin_secret():
        return jsonify({"error": "Admin secret required (X-Admin-Secret header)"}), 403
    
    return jsonify({"api_key": current_app.config["API_KEY"]})


@admin_bp.route("/admin/customers", methods=["POST"])
def create_customer():
    """Crée un nouveau client (org + API key)."""
    if not current_app.config.get("ADMIN_SECRET"):
        return jsonify({"error": "AGENTGUARD_ADMIN_SECRET not configured"}), 404
    
    if not _verify_admin_secret():
        return jsonify({
            "error": "Admin secret required",
            "hint": "Use X-Admin-Secret header (never query params)",
        }), 403
    
    payload = request.json or {}
    org_name = payload.get("org_name", "").strip()
    plan = payload.get("plan", "free")
    
    if not org_name:
        return jsonify({"error": "org_name is required"}), 400
    if plan not in ("free", "pro", "startup", "enterprise"):
        return jsonify({"error": "plan must be one of: free, pro, startup, enterprise"}), 400
    
    # Créer les valeurs AVANT l'audit log
    org_id = f"org_{secrets.token_urlsafe(8)}"
    new_key = "ag_" + secrets.token_urlsafe(32)
    key_hash = hash_key(new_key)
    
    # Insert DB
    try:
        if is_postgres():
            conn = get_pg_conn()
            cur = conn.cursor()
            try:
                cur.execute(
                    "INSERT INTO api_keys (key_hash, org_id, org_name, plan) VALUES (%s, %s, %s, %s)",
                    (key_hash, org_id, org_name, plan),
                )
                conn.commit()
            finally:
                conn.close()
        else:
            conn = sqlite3.connect(DB_SQLITE_PATH)
            cur = conn.cursor()
            try:
                cur.execute(
                    "INSERT INTO api_keys (key_hash, org_id, org_name, plan) VALUES (?, ?, ?, ?)",
                    (key_hash, org_id, org_name, plan),
                )
                conn.commit()
            finally:
                conn.close()
    except Exception as e:
        logger.error("customer_creation_db_failed", error=str(e))
        return jsonify({"error": "database error"}), 500
    
    # Audit log APRÈS (org_id existe maintenant)
    try:
        from collector.audit_routes import get_audit_log, AuditEventType
        audit = get_audit_log()
        if audit:
            audit.log_event(
                event_type=AuditEventType.API_KEY_CREATED,
                org_id=org_id,
                actor="admin",
                resource=f"api_key:{org_id}",
                action="created",
                details={
                    "org_name": org_name,
                    "plan": plan,
                    "ip": request.remote_addr,
                },
                risk_level="info",
            )
    except Exception as e:
        logger.warning("audit_log_failed", error=str(e))
    
    logger.info("customer_created", org_id=org_id, org_name=org_name, plan=plan)
    
    return jsonify({
        "org_id": org_id,
        "org_name": org_name,
        "plan": plan,
        "api_key": new_key,
        "warning": "⚠️ This API key will NEVER be shown again. Store it securely now.",
    }), 201


@admin_bp.route("/admin/customers/<org_id>/revoke", methods=["POST"])
def revoke_customer(org_id):
    """Révoque toutes les clés API d'un client."""
    if not current_app.config.get("ADMIN_SECRET"):
        return jsonify({"error": "AGENTGUARD_ADMIN_SECRET not configured"}), 404
    
    if not _verify_admin_secret():
        return jsonify({
            "error": "Admin secret required",
            "hint": "Use X-Admin-Secret header (never query params)",
        }), 403
    
    try:
        if is_postgres():
            conn = get_pg_conn()
            cur = conn.cursor()
            try:
                cur.execute(
                    "UPDATE api_keys SET active = FALSE WHERE org_id = %s",
                    (org_id,),
                )
                affected = cur.rowcount
                conn.commit()
            finally:
                conn.close()
        else:
            conn = sqlite3.connect(DB_SQLITE_PATH)
            cur = conn.cursor()
            try:
                cur.execute(
                    "UPDATE api_keys SET active = 0 WHERE org_id = ?",
                    (org_id,),
                )
                affected = cur.rowcount
                conn.commit()
            finally:
                conn.close()
    except Exception as e:
        logger.error("customer_revocation_db_failed", error=str(e))
        return jsonify({"error": "database error"}), 500
    
    # Audit
    try:
        from collector.audit_routes import get_audit_log, AuditEventType
        audit = get_audit_log()
        if audit:
            audit.log_event(
                event_type=AuditEventType.API_KEY_REVOKED,
                org_id=org_id,
                actor="admin",
                resource=f"api_key:{org_id}",
                action="revoked",
                details={
                    "keys_revoked": affected,
                    "ip": request.remote_addr,
                },
                risk_level="warning",
            )
    except Exception as e:
        logger.warning("audit_log_failed", error=str(e))
    
    logger.info("customer_revoked", org_id=org_id, keys_revoked=affected)
    
    return jsonify({"org_id": org_id, "keys_revoked": affected})
