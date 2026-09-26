import os
import time
from datetime import datetime
import structlog
from flask import request, jsonify, g, current_app, send_from_directory
from collector.api import api_bp
from collector.auth import require_auth
from collector.alerts import create_alert_rule, list_alert_rules, delete_alert_rule, VALID_METRICS, VALID_COMPARISONS

logger = structlog.get_logger("agentguard.api.misc")

@api_bp.route("/logo.svg")
def serve_logo():
    static_path = os.path.join(os.path.dirname(__file__), "static")
    try: return send_from_directory(static_path, "logo.svg", mimetype="image/svg+xml")
    except Exception as e:
        logger.warning("logo_serve_failed", error=str(e))
        fallback_svg = """<?xml version="1.0" encoding="UTF-8"?><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" width="100" height="100"><rect width="100" height="100" fill="#2563eb"/><text x="50" y="60" font-family="sans-serif" font-size="40" fill="white" text-anchor="middle">AG</text></svg>"""
        return fallback_svg, 200, {"Content-Type": "image/svg+xml"}

@api_bp.route("/favicon.ico")
def serve_favicon():
    static_path = os.path.join(os.path.dirname(__file__), "static")
    try: return send_from_directory(static_path, "logo.svg", mimetype="image/x-icon")
    except Exception: return "", 204

@api_bp.route("/health", methods=["GET"])
def health_check():
    checks = {}
    is_healthy = True
    try:
        start = time.time()
        from collector.db import get_db
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT 1")
        cursor.fetchone()
        latency = round((time.time() - start) * 1000, 2)
        checks["database"] = {"status": "ok", "latency_ms": latency}
    except Exception as e:
        checks["database"] = {"status": "error", "message": str(e)}
        is_healthy = False
    try:
        if hasattr(current_app, 'extensions') and 'limiter' in current_app.extensions:
            current_app.extensions['limiter'].storage.client.ping()
            checks["redis"] = {"status": "ok"}
    except Exception as e:
        checks["redis"] = {"status": "degraded", "message": str(e)}
    status_code = 200 if is_healthy else 503
    return jsonify({"status": "healthy" if is_healthy else "unhealthy", "timestamp": datetime.utcnow().isoformat(), "version": "0.2.1", "checks": checks}), status_code

@api_bp.route("/readiness", methods=["GET"])
def readiness_check():
    return jsonify({"ready": True, "timestamp": datetime.utcnow().isoformat()}), 200

@api_bp.route("/api/alert-rules", methods=["GET"])
def api_list_alert_rules():
    if not require_auth(): return jsonify({"error": "Unauthorized"}), 401
    org_id = getattr(g, "org_id", None)
    if not org_id: return jsonify({"error": "Organization context required"}), 400
    try:
        rules = list_alert_rules(org_id=org_id)
        return jsonify({"alert_rules": rules, "count": len(rules)}), 200
    except Exception as e:
        logger.error("alert_rules_list_failed", error=str(e), org_id=org_id)
        return jsonify({"error": "Failed to list alert rules"}), 500

@api_bp.route("/api/alert-rules", methods=["POST"])
def api_create_alert_rule():
    if not require_auth(): return jsonify({"error": "Unauthorized"}), 401
    org_id = getattr(g, "org_id", None)
    if not org_id: return jsonify({"error": "Organization context required"}), 400
    data = request.get_json(silent=True) or {}
    metric, comparison, threshold, label = data.get("metric"), data.get("comparison", "above"), data.get("threshold"), data.get("label")
    if metric not in VALID_METRICS: return jsonify({"error": f"metric must be one of {sorted(VALID_METRICS)}"}), 400
    if comparison not in VALID_COMPARISONS: return jsonify({"error": f"comparison must be one of {sorted(VALID_COMPARISONS)}"}), 400
    try: threshold = float(threshold)
    except (TypeError, ValueError): return jsonify({"error": "threshold must be a number"}), 400
    try:
        rule = create_alert_rule(org_id=org_id, metric=metric, comparison=comparison, threshold=threshold, label=label, created_by=getattr(g, "authenticated_user", None))
        return jsonify({"alert_rule": rule}), 201
    except ValueError as e: return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error("alert_rule_create_failed", error=str(e), org_id=org_id)
        return jsonify({"error": "Failed to create alert rule"}), 500

@api_bp.route("/api/alert-rules/<alert_id>", methods=["DELETE"])
def api_delete_alert_rule(alert_id):
    if not require_auth(): return jsonify({"error": "Unauthorized"}), 401
    org_id = getattr(g, "org_id", None)
    if not org_id: return jsonify({"error": "Organization context required"}), 400
    try:
        deleted = delete_alert_rule(alert_id, org_id=org_id)
        if not deleted: return jsonify({"error": "Alert rule not found"}), 404
        return jsonify({"status": "deleted", "alert_id": alert_id}), 200
    except Exception as e:
        logger.error("alert_rule_delete_failed", error=str(e), org_id=org_id)
        return jsonify({"error": "Failed to delete alert rule"}), 500
