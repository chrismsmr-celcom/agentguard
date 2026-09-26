import re
import time
from datetime import datetime
import structlog
from flask import request, jsonify, g
from collector.api.utils import _db_run, _iso_utc  # <- CORRECTION ICI
from collector.api import api_bp
from collector.auth import require_auth, require_human_auth

logger = structlog.get_logger("agentguard.api.agents")

_AGENT_ID_RE = re.compile(r"^[A-Za-z0-9_.:@\- ]{1,64}$")
_AGENT_SEEN = {}
_AGENT_STATUS = {}
_AGENT_TOUCH_EVERY = 15.0
_INGEST_ENDPOINTS = {"api.receive_span", "api.decide", "api.api_sdk_create_approval"}
_AGENT_STATUS_TTL = 3.0

def _request_agent_id():
    raw = (request.headers.get("X-Agent-Id") or "").strip()
    if raw and _AGENT_ID_RE.match(raw): return raw
    identity = getattr(g, "agent_identity", None)
    if isinstance(identity, dict) and identity.get("agent_id"): return str(identity["agent_id"])[:64]
    key_name = getattr(g, "api_key_name", None)
    if key_name:
        safe = re.sub(r"[^A-Za-z0-9_.:@\- ]", "-", key_name).strip()[:58]
        if safe: return "key:" + safe
    return None

def _agent_status(org_id, agent_id):
    key = (org_id, agent_id)
    hit = _AGENT_STATUS.get(key)
    now = time.time()
    if hit and now - hit[0] < _AGENT_STATUS_TTL: return hit[1]
    try:
        row, _ = _db_run("SELECT status FROM connected_agents WHERE org_id = ? AND agent_id = ?", (org_id, agent_id), fetch="one")
    except Exception as exc:
        logger.warning("agent_status_lookup_failed", error=str(exc))
        return None
    status = row[0] if row else None
    _AGENT_STATUS[key] = (now, status)
    return status

def _reject_if_agent_disconnected():
    agent_id = _request_agent_id()
    org_id = getattr(g, "org_id", None)
    if agent_id and org_id and _agent_status(org_id, agent_id) == "disconnected":
        logger.warning("agent_request_refused_disconnected", agent_id=agent_id, org_id=org_id)
        return jsonify({"error": "agent_disconnected", "agent_id": agent_id, "message": "This agent was disconnected from the Cerbere dashboard."}), 403
    return None

def _touch_agent(org_id, agent_id, sdk_version=None, name=None):
    key = (org_id, agent_id)
    now = time.time()
    if now - _AGENT_SEEN.get(key, 0) < _AGENT_TOUCH_EVERY: return
    _AGENT_SEEN[key] = now
    _db_run("""
        INSERT INTO connected_agents (org_id, agent_id, name, sdk_version)
        VALUES (?, ?, ?, ?)
        ON CONFLICT (org_id, agent_id) DO UPDATE SET
            last_seen_at = CURRENT_TIMESTAMP,
            sdk_version = COALESCE(excluded.sdk_version, connected_agents.sdk_version)
    """, (org_id, agent_id, name or agent_id, sdk_version), commit=True)

@api_bp.after_app_request
def _register_agent_activity(response):
    try:
        endpoint = request.endpoint or ""
        if response.status_code < 400 and endpoint.startswith("api.") and (request.headers.get("X-Agent-Id") or endpoint in _INGEST_ENDPOINTS):
            org_id = getattr(g, "org_id", None)
            agent_id = _request_agent_id()
            if org_id and agent_id:
                sdk_version = (request.headers.get("X-Agent-Sdk") or "")[:32] or None
                name = getattr(g, "api_key_name", None) if agent_id.startswith("key:") else None
                _touch_agent(org_id, agent_id, sdk_version, name)
    except Exception as exc:
        logger.debug("agent_touch_failed", error=str(exc))
    return response

def _agent_state(status, last_seen):
    if status == "disconnected": return "disconnected"
    seen = _iso_utc(last_seen)
    if not seen: return "offline"
    try:
        dt = datetime.fromisoformat(seen.replace("Z", "+00:00"))
        idle = (datetime.now(dt.tzinfo) - dt).total_seconds()
    except ValueError: return "offline"
    if idle < 300: return "connected"
    if idle < 3600: return "idle"
    return "offline"

def _audit_human_action(event_name, resource, action, details):
    try:
        from collector.audit_routes import get_audit_log, AuditEventType
        audit = get_audit_log()
        if audit:
            audit.log_event(event_type=getattr(AuditEventType, event_name), org_id=g.org_id, actor=f"human:{getattr(g, 'human_email', None) or g.org_id}", resource=resource, action=action, details=details, risk_level="high")
    except Exception as exc:
        logger.warning("audit_log_failed", error=str(exc))

@api_bp.route("/api/agents", methods=["GET"], endpoint="api_list_agents")
def api_list_agents():
    if not require_auth(): return jsonify({"error": "Unauthorized"}), 401
    org_id = getattr(g, "org_id", None) or "default"
    try:
        rows, _ = _db_run("SELECT agent_id, name, status, sdk_version, first_seen_at, last_seen_at, disconnected_at, disconnected_by FROM connected_agents WHERE org_id = ? ORDER BY last_seen_at DESC", (org_id,), fetch="all")
        stat_rows, _ = _db_run("SELECT agent_id, COUNT(*), SUM(CASE WHEN blocked THEN 1 ELSE 0 END), COALESCE(SUM(cost_usd), 0) FROM spans WHERE org_id = ? AND agent_id IS NOT NULL GROUP BY agent_id", (org_id,), fetch="all")
        pend_rows, _ = _db_run("SELECT agent_id, COUNT(*) FROM approval_requests WHERE org_id = ? AND status = 'pending' GROUP BY agent_id", (org_id,), fetch="all")
    except Exception as exc:
        logger.error("agents_list_failed", error=str(exc), org_id=org_id)
        return jsonify({"error": f"Database error: {str(exc)}"}), 500

    stats = {r[0]: {"calls": int(r[1] or 0), "blocked": int(r[2] or 0), "cost_usd": float(r[3] or 0)} for r in stat_rows}
    pending = {r[0]: int(r[1] or 0) for r in pend_rows}
    agents, counts = [], {"connected": 0, "idle": 0, "offline": 0, "disconnected": 0}
    for r in rows:
        agent_id, name, status, sdk_version, first_seen, last_seen, disc_at, disc_by = r
        state = _agent_state(status, last_seen)
        counts[state] += 1
        st = stats.get(agent_id, {})
        agents.append({"agent_id": agent_id, "name": name or agent_id, "status": status, "state": state, "sdk_version": sdk_version, "first_seen_at": _iso_utc(first_seen), "last_seen_at": _iso_utc(last_seen), "disconnected_at": _iso_utc(disc_at), "disconnected_by": disc_by, "calls": st.get("calls", 0), "blocked": st.get("blocked", 0), "cost_usd": round(st.get("cost_usd", 0.0), 4), "pending_approvals": pending.get(agent_id, 0)})
    agents.sort(key=lambda a: a["agent_id"].lower())
    return jsonify({"agents": agents, "counts": counts, "total": len(agents)}), 200

def _set_agent_status(agent_id, new_status):
    if not require_human_auth(): return jsonify({"error": "Human session required"}), 401
    org_id = g.org_id
    actor = getattr(g, "human_email", None) or f"org:{org_id}"
    try:
        if new_status == "disconnected":
            _, n = _db_run("UPDATE connected_agents SET status = 'disconnected', disconnected_at = CURRENT_TIMESTAMP, disconnected_by = ? WHERE org_id = ? AND agent_id = ?", (actor, org_id, agent_id), commit=True)
        else:
            _, n = _db_run("UPDATE connected_agents SET status = 'connected', disconnected_at = NULL, disconnected_by = NULL WHERE org_id = ? AND agent_id = ?", (org_id, agent_id), commit=True)
    except Exception as exc:
        logger.error("agent_status_update_failed", error=str(exc), agent_id=agent_id)
        return jsonify({"error": f"Database error: {str(exc)}"}), 500
    if n == 0: return jsonify({"error": "Agent not found"}), 404
    _AGENT_STATUS.pop((org_id, agent_id), None)
    logger.warning("agent_status_changed", agent_id=agent_id, status=new_status, by=actor, org_id=org_id)
    _audit_human_action("AGENT_DISCONNECTED" if new_status == "disconnected" else "AGENT_RECONNECTED", f"agent:{agent_id}", new_status, {"agent_id": agent_id, "by": actor})
    return jsonify({"agent_id": agent_id, "status": new_status}), 200

@api_bp.route("/api/agents/<agent_id>/disconnect", methods=["POST"], endpoint="api_agent_disconnect")
def api_agent_disconnect(agent_id): return _set_agent_status(agent_id, "disconnected")

@api_bp.route("/api/agents/<agent_id>/reconnect", methods=["POST"], endpoint="api_agent_reconnect")
def api_agent_reconnect(agent_id): return _set_agent_status(agent_id, "connected")

TEST_AGENT_ID = "cerbere-test-agent"
def _ensure_test_agent(org_id):
    _db_run("INSERT INTO connected_agents (org_id, agent_id, name, status, sdk_version) VALUES (?, ?, ?, 'connected', ?) ON CONFLICT (org_id, agent_id) DO UPDATE SET last_seen_at = CURRENT_TIMESTAMP", (org_id, TEST_AGENT_ID, "Cerbere test agent", "test"), commit=True)

@api_bp.route("/api/agents/test", methods=["POST"], endpoint="api_test_agent")
def api_test_agent():
    if not require_human_auth(): return jsonify({"error": "Human session required"}), 401
    try: _ensure_test_agent(g.org_id)
    except Exception as exc: return jsonify({"error": f"Database error: {str(exc)}"}), 500
    return jsonify({"agent_id": TEST_AGENT_ID, "status": "connected"}), 201

@api_bp.route("/api/approvals/test", methods=["POST"], endpoint="api_test_approval")
def api_test_approval():
    if not require_human_auth(): return jsonify({"error": "Human session required"}), 401
    import secrets
    approval_id = "test_" + secrets.token_hex(4)
    try:
        _ensure_test_agent(g.org_id)
        _db_run("INSERT INTO approval_requests (id, org_id, agent_id, tool_name, params, reason, status) VALUES (?, ?, ?, ?, ?, ?, 'pending')", (approval_id, g.org_id, TEST_AGENT_ID, "send_email", '{"to": "partner@gmail.com", "subject": "Q3 customer export", "attachments": ["customers_q3.csv"]}', "Test request from the dashboard: external recipient on a personal domain"), commit=True)
    except Exception as exc: return jsonify({"error": f"Database error: {str(exc)}"}), 500
    return jsonify({"id": approval_id, "status": "pending"}), 201

@api_bp.route("/api/agent/status", methods=["GET"], endpoint="api_agent_status")
def api_agent_status():
    if not require_auth(): return jsonify({"error": "Unauthorized"}), 401
    agent_id = _request_agent_id()
    if not agent_id: return jsonify({"agent_id": None, "status": "connected"}), 200
    status = _agent_status(g.org_id, agent_id)
    return jsonify({"agent_id": agent_id, "status": "disconnected" if status == "disconnected" else "connected"}), 200
