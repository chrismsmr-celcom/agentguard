import json
import secrets
import structlog
from flask import request, jsonify, g
from collector.db import _db_run
from collector.api import api_bp
from collector.api.utils import _as_json, _iso_utc
from collector.auth import require_auth, require_human_auth

logger = structlog.get_logger("agentguard.api.approvals")

_APPROVAL_STATUSES = {"pending", "approved", "rejected"}

@api_bp.route("/api/approvals", methods=["GET"], endpoint="api_list_approvals")
def api_list_approvals():
    if not require_auth(): return jsonify({"error": "Unauthorized"}), 401
    org_id = getattr(g, "org_id", None) or "default"
    status = request.args.get("status", "pending")
    try: limit = max(1, min(int(request.args.get("limit", 50)), 200))
    except (TypeError, ValueError): limit = 50

    where, params = "org_id = ?", [org_id]
    if status in _APPROVAL_STATUSES:
        where += " AND status = ?"
        params.append(status)
    elif status == "history":
        where += " AND status <> 'pending'"
    elif status != "all":
        return jsonify({"error": "status must be pending, approved, rejected, history or all"}), 400
    order = "created_at ASC" if status == "pending" else "COALESCE(resolved_at, created_at) DESC"

    try:
        rows, _ = _db_run(f"SELECT id, agent_id, tool_name, params, reason, created_at, status, resolved_at, resolved_by FROM approval_requests WHERE {where} ORDER BY {order} LIMIT ?", (*params, limit), fetch="all")
        count_rows, _ = _db_run("SELECT status, COUNT(*) FROM approval_requests WHERE org_id = ? GROUP BY status", (org_id,), fetch="all")
    except Exception as e:
        logger.error("approval_list_failed", error=str(e), org_id=org_id)
        return jsonify({"error": f"Database error: {str(e)}"}), 500

    approvals = [{"id": r[0], "agent_id": r[1], "tool_name": r[2], "params": _as_json(r[3], {}), "reason": r[4], "created_at": _iso_utc(r[5]), "status": r[6], "resolved_at": _iso_utc(r[7]), "resolved_by": r[8]} for r in rows]
    counts = {"pending": 0, "approved": 0, "rejected": 0}
    for st, n in count_rows:
        if st in counts: counts[st] = int(n)
    return jsonify({"approvals": approvals, "count": len(approvals), "counts": counts}), 200

def _resolve_approval(approval_id, new_status):
    if not require_human_auth(): return jsonify({"error": "Human session required"}), 401
    org_id = g.org_id
    decided_by = getattr(g, "human_email", None) or f"org:{org_id}"
    try:
        row, _ = _db_run("SELECT agent_id, tool_name FROM approval_requests WHERE id = ? AND org_id = ?", (approval_id, org_id), fetch="one")
        _, n = _db_run("UPDATE approval_requests SET status = ?, resolved_at = CURRENT_TIMESTAMP, resolved_by = ? WHERE id = ? AND org_id = ? AND status = 'pending'", (new_status, decided_by, approval_id, org_id), commit=True)
    except Exception as e:
        logger.error("approval_resolve_failed", error=str(e), approval_id=approval_id, org_id=org_id)
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    if n == 0: return jsonify({"error": "Approval not found or already resolved"}), 404
    
    from collector.api.agents import _audit_human_action
    _audit_human_action("APPROVAL_GRANTED" if new_status == "approved" else "APPROVAL_REJECTED", f"approval:{approval_id}", new_status, {"approval_id": approval_id, "agent_id": row[0] if row else None, "tool_name": row[1] if row else None, "decided_by": decided_by})
    return jsonify({"status": new_status, "id": approval_id, "decided_by": decided_by}), 200

@api_bp.route("/api/approvals/<approval_id>/approve", methods=["POST"], endpoint="api_approve_approval")
def api_approve_approval(approval_id): return _resolve_approval(approval_id, "approved")

@api_bp.route("/api/approvals/<approval_id>/reject", methods=["POST"], endpoint="api_reject_approval")
def api_reject_approval(approval_id): return _resolve_approval(approval_id, "rejected")

@api_bp.route("/api/approvals/<approval_id>", methods=["GET"], endpoint="api_get_approval_status")
def api_get_approval_status(approval_id):
    if not require_auth(): return jsonify({"error": "Unauthorized"}), 401
    org_id = getattr(g, "org_id", None) or "default"
    try:
        row, _ = _db_run("SELECT id, status, resolved_by, resolved_at FROM approval_requests WHERE id = ? AND org_id = ?", (approval_id, org_id), fetch="one")
    except Exception as e: return jsonify({"error": f"Database error: {str(e)}"}), 500
    if not row: return jsonify({"error": "Approval not found"}), 404
    return jsonify({"id": row[0], "status": row[1], "resolved_by": row[2], "resolved_at": _iso_utc(row[3])}), 200

@api_bp.route("/api/approvals", methods=["POST"], endpoint="api_sdk_create_approval")
def hitl_sdk_create_approval():
    if not require_auth(): return jsonify({"error": "Unauthorized"}), 401
    from collector.api.agents import _reject_if_agent_disconnected, _request_agent_id
    refused = _reject_if_agent_disconnected()
    if refused: return refused

    data = request.get_json(silent=True) or {}
    approval_id = data.get("approval_id") or data.get("id")
    agent_id = data.get("agent_id") or _request_agent_id() or "unknown"
    tool_name = data.get("tool_name")
    params = data.get("params", {})
    reason = data.get("reason", "Approval required by policy")

    if not approval_id: return jsonify({"error": "approval_id is required"}), 400
    org_id = getattr(g, "org_id", None) or "default"
    try:
        _db_run("INSERT INTO approval_requests (id, org_id, agent_id, tool_name, params, reason, status) VALUES (?, ?, ?, ?, ?, ?, 'pending') ON CONFLICT (id) DO NOTHING", (str(approval_id)[:128], org_id, str(agent_id)[:64], tool_name, json.dumps(params), reason), commit=True)
        logger.warning("approval_request_created", approval_id=approval_id, tool=tool_name, org_id=org_id)
        
        try:
            org_email = getattr(g, "human_email", "admin@entreprise.com")
            logger.info("approval_alert_sent", to=org_email)
        except Exception as e:
            logger.error("approval_alert_failed", error=str(e))
        return jsonify({"status": "success", "id": approval_id}), 201
    except Exception as e:
        logger.error("approval_request_failed", error=str(e))
        return jsonify({"error": str(e)}), 500
