"""Admin endpoints : customer management."""
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


@admin_bp.route("/api/key")
def show_key():
    admin_secret = current_app.config["ADMIN_SECRET"]
    if not admin_secret:
        return jsonify({"error": "AGENTGUARD_ADMIN_SECRET not configured"}), 404
    provided = request.headers.get("X-Admin-Secret", "")
    if provided and safe_compare(provided, admin_secret):
        return jsonify({"api_key": current_app.config["API_KEY"]})
    return jsonify({"error": "Admin secret required"}), 403


@admin_bp.route("/admin/customers", methods=["POST"])
def create_customer():
    admin_secret = current_app.config["ADMIN_SECRET"]
    if not admin_secret:
        return jsonify({"error": "AGENTGUARD_ADMIN_SECRET not configured"}), 404
    provided = request.headers.get("X-Admin-Secret", "") or request.args.get("admin", "")
    if not safe_compare(provided, admin_secret):
        return jsonify({"error": "Admin secret required"}), 403
    
    payload = request.json or {}
    org_name = payload.get("org_name", "").strip()
    plan = payload.get("plan", "free")
    if not org_name:
        return jsonify({"error": "org_name is required"}), 400
    if plan not in ("free", "pro", "startup", "enterprise"):
        return jsonify({"error": "plan must be one of: free, pro, startup, enterprise"}), 400
    
    # ✅ Créer les valeurs AVANT l'audit log
    org_id = f"org_{secrets.token_urlsafe(8)}"
    new_key = "ag_" + secrets.token_urlsafe(32)
    key_hash = hash_key(new_key)
    
    # ✅ Insert DB
    if is_postgres():
        conn = get_pg_conn()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO api_keys (key_hash, org_id, org_name, plan) VALUES (%s, %s, %s, %s)",
            (key_hash, org_id, org_name, plan),
        )
    else:
        conn = sqlite3.connect(DB_SQLITE_PATH)
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO api_keys (key_hash, org_id, org_name, plan) VALUES (?, ?, ?, ?)",
            (key_hash, org_id, org_name, plan),
        )
    conn.commit()
    conn.close()
    
    # ✅ Audit log APRÈS (org_id existe maintenant)
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
                details={"org_name": org_name, "plan": plan},
                risk_level="info",
            )
    except Exception:
        pass
    
    return jsonify({
        "org_id": org_id,
        "org_name": org_name,
        "plan": plan,
        "api_key": new_key,
        "warning": "Cette clé ne sera plus jamais affichée.",
    }), 201


@admin_bp.route("/admin/customers/<org_id>/revoke", methods=["POST"])
def revoke_customer(org_id):
    admin_secret = current_app.config["ADMIN_SECRET"]
    if not admin_secret:
        return jsonify({"error": "AGENTGUARD_ADMIN_SECRET not configured"}), 404
    provided = request.headers.get("X-Admin-Secret", "") or request.args.get("admin", "")
    if not safe_compare(provided, admin_secret):
        return jsonify({"error": "Admin secret required"}), 403
    
    if is_postgres():
        conn = get_pg_conn()
        cur = conn.cursor()
        cur.execute("UPDATE api_keys SET active = FALSE WHERE org_id = %s", (org_id,))
    else:
        conn = sqlite3.connect(DB_SQLITE_PATH)
        cur = conn.cursor()
        cur.execute("UPDATE api_keys SET active = 0 WHERE org_id = ?", (org_id,))
    affected = cur.rowcount
    conn.commit()
    conn.close()
    
    # Audit
    try:
        from collector.audit_routes import get_audit_log, AuditEventType
        audit = get_audit_log()
        if audit:
            audit.log_event(
                event_type=AuditEventType.API_KEY_REVOKED,
                org_id=org_id, actor="admin",
                resource=f"api_key:{org_id}",
                action="revoked",
                details={"keys_revoked": affected},
                risk_level="warning",
            )
    except Exception:
        pass
    
    return jsonify({"org_id": org_id, "keys_revoked": affected})
