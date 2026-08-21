"""Audit log routes + singleton instance."""
import os
import structlog
from flask import Blueprint, request, jsonify, g
from collector.auth import require_auth

logger = structlog.get_logger("agentguard.audit")
audit_bp = Blueprint("audit", __name__)

# Singleton audit log (lazy init)
_audit_log_instance = None


def get_audit_log():
    """Retourne l'instance singleton de l'audit log."""
    global _audit_log_instance
    if _audit_log_instance is None:
        try:
            from audit import ImmutableAuditLog
            from collector.db import is_postgres
            db_url = os.environ.get("DATABASE_URL") if is_postgres() else None
            signing_key = os.environ.get("CERBERE_SIGNING_KEY") or os.environ.get("AGENTGUARD_SIGNING_KEY", "")
            _audit_log_instance = ImmutableAuditLog(
                database_url=db_url,
                signing_key_pem=signing_key,
                sign_every=int(os.environ.get("AGENTGUARD_AUDIT_SIGN_EVERY", "100")),
            )
        except Exception as e:
            logger.warning("audit_log_init_failed", error=str(e))
            _audit_log_instance = None
    return _audit_log_instance


# Re-export pour usage dans les autres modules
try:
    from audit import AuditEventType
except ImportError:
    AuditEventType = None


@audit_bp.route("/api/audit/stats")
def audit_stats():
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401
    try:
        audit = get_audit_log()
        if not audit:
            return jsonify({"error": "Audit log not available"}), 503
        return jsonify(audit.get_stats())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@audit_bp.route("/api/audit/verify")
def audit_verify():
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401
    from datetime import datetime
    limit = request.args.get("limit", type=int)
    if limit and (limit < 1 or limit > 10000):
        return jsonify({"error": "limit must be between 1 and 10000"}), 400
    try:
        audit = get_audit_log()
        if not audit:
            return jsonify({"error": "Audit log not available"}), 503
        is_valid, report = audit.verify_chain(limit=limit)
        return jsonify({
            "valid": is_valid,
            "report": report,
            "verified_at": datetime.utcnow().isoformat(),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@audit_bp.route("/api/audit/query")
def audit_query():
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401
    try:
        audit = get_audit_log()
        if not audit:
            return jsonify({"error": "Audit log not available"}), 503
        entries = audit.query(
            org_id=g.org_id,  # isolation multi-tenant
            event_type=request.args.get("event_type"),
            risk_level=request.args.get("risk_level"),
            since=float(request.args.get("since", 0)) or None,
            until=float(request.args.get("until", 0)) or None,
            limit=min(int(request.args.get("limit", 100)), 1000),
        )
        return jsonify({"entries": entries, "count": len(entries)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
