import json
import sqlite3
import structlog
from flask import request, jsonify, g, current_app

from collector.extensions import limiter
from collector.db import get_db, is_postgres, redact_pii, sql_placeholder, _get_db_path
from collector.api import api_bp
from collector.api.utils import _db_run
from decision_engine import DecisionEngine

logger = structlog.get_logger("agentguard.api.spans")
decision_engine = DecisionEngine()

def _next_sequence_no(cur, p, session_id):
    cur.execute(f"SELECT COALESCE(MAX(sequence_no), 0) + 1 FROM events WHERE session_id = {p}", (session_id,))
    row = cur.fetchone()
    return int(row[0]) if row and row[0] is not None else 1

def _ensure_session(cur, p, session_id, org_id, agent_id, model, is_pg):
    cur.execute(f"SELECT 1 FROM agent_sessions WHERE id = {p}", (session_id,))
    if cur.fetchone():
        return
    cur.execute(
        f"""INSERT INTO agent_sessions (id, org_id, agent_id, status, model, environment)
            VALUES ({p}, {p}, {p}, {p}, {p}, {p})""",
        (session_id, org_id, agent_id or "unknown", "running", model, "production"),
    )

def _write_canonical_event(data, org_id, agent_id):
    """Insère une ligne dans `events` de manière idempotente."""
    session_id = data["trace_id"]
    checks = data.get("security_checks") or []
    failed = [c for c in checks if isinstance(c, dict) and not c.get("passed", True)]
    risk_contributors = [c.get("check_name", "unknown") for c in failed]

    span_type = data.get("span_type", "")
    actor = "TOOL" if "tool" in span_type else "MODEL"
    decision = "BLOCK" if data["blocked"] else "ALLOW"
    model = data.get("input_data", {}).get("model") if isinstance(data.get("input_data"), dict) else None

    p = sql_placeholder()
    is_pg = is_postgres()
    
    # FIX: timeout et WAL mode pour éviter "database is locked"
    if is_pg:
        conn = get_db()
    else:
        conn = sqlite3.connect(_get_db_path(), timeout=5.0)
        conn.execute("PRAGMA journal_mode=WAL;")

    cur = conn.cursor()
    try:
        _ensure_session(cur, p, session_id, org_id, agent_id, model, is_pg)
        seq = _next_sequence_no(cur, p, session_id)
        event_id = str(data['span_id'])
        
        # FIX: INSERT OR IGNORE / ON CONFLICT pour éviter "UNIQUE constraint failed"
        if is_pg:
            insert_sql = f"""
                INSERT INTO events (id, trace_id, session_id, agent_id, org_id, sequence_no,
                                    actor, type, tool_name, arguments, result,
                                    policy_chain, risk_contributors, decision, reason)
                VALUES ({p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p})
                ON CONFLICT (id) DO NOTHING
            """
        else:
            insert_sql = f"""
                INSERT OR IGNORE INTO events (id, trace_id, session_id, agent_id, org_id, sequence_no,
                                              actor, type, tool_name, arguments, result,
                                              policy_chain, risk_contributors, decision, reason)
                VALUES ({p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p})
            """

        cur.execute(insert_sql, (
            event_id, data["trace_id"], session_id, agent_id or "unknown", org_id, seq,
            actor, span_type, data.get("input_data", {}).get("tool_name") if isinstance(data.get("input_data"), dict) else None,
            json.dumps(data.get("input_data", {})), json.dumps(data.get("output_data", {})),
            json.dumps(checks), json.dumps(risk_contributors), decision, data.get("block_reason"),
        ))
        
        cur.execute(f"UPDATE agent_sessions SET last_event_id = {p}, status = {p} WHERE id = {p}",
                    (event_id, "blocked" if data["blocked"] else "running", session_id))
        conn.commit()
    except Exception as e:
        logger.warning("canonical_event_write_failed", error=str(e), span_id=event_id)
    finally:
        conn.close()

@api_bp.route("/span", methods=["POST"])
@limiter.limit(lambda: current_app.config["SPAN_RATE_LIMIT"])
def receive_span():
    from collector.api.agents import _reject_if_agent_disconnected, _request_agent_id
    refused = _reject_if_agent_disconnected()
    if refused:
        return refused
    span_agent_id = _request_agent_id()

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Body must be a JSON object"}), 400
    if len(request.get_data(cache=True)) > current_app.config["MAX_CONTENT_LENGTH"]:
        return jsonify({"error": "Payload too large"}), 413

    required_fields = ["trace_id", "span_id", "span_type", "timestamp", "latency_ms"]
    missing = [f for f in required_fields if f not in data]
    if missing:
        return jsonify({"error": f"Missing required field(s): {missing}"}), 400

    try:
        data["latency_ms"] = max(0.0, min(float(data.get("latency_ms", 0) or 0), 3.6e6))
        data["cost_usd"] = max(0.0, min(float(data.get("cost_usd", 0) or 0), 1e6))
        data["timestamp"] = float(data.get("timestamp", 0) or 0)
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid numeric field"}), 400

    try:
        data["input_tokens"] = max(0, int(float(data.get("input_tokens", 0) or 0)))
        data["output_tokens"] = max(0, int(float(data.get("output_tokens", 0) or 0)))
    except (TypeError, ValueError):
        data["input_tokens"] = 0
        data["output_tokens"] = 0

    data["trace_id"] = str(data["trace_id"])[:64]
    data["span_id"] = str(data["span_id"])[:64]
    data["span_type"] = str(data["span_type"])[:64]

    data.setdefault("input_data", {})
    data.setdefault("output_data", {})
    data.setdefault("security_checks", [])
    data.setdefault("blocked", False)

    detection_layer = None
    ml_score = None
    llm_score = None
    llm_reason = None

    if "metadata" in data and isinstance(data["metadata"], dict):
        detection_layer = data["metadata"].get("detection_layer") or data["metadata"].get("layer")
        ml_score = data["metadata"].get("ml_score")
        llm_score = data["metadata"].get("llm_score")
        llm_reason = data["metadata"].get("llm_reason")

    if not detection_layer and data.get("security_checks"):
        for check in data["security_checks"]:
            if isinstance(check, dict) and check.get("check_name") in ["prompt_injection", "llm_judge"]:
                meta = check.get("metadata", {}) or {}
                detection_layer = meta.get("layer")
                ml_score = meta.get("ml_score")
                llm_score = meta.get("llm_score")
                if check.get("details"):
                    llm_reason = check.get("details")
                break

    data["input_data"] = redact_pii(data.get("input_data", {}))
    data["output_data"] = redact_pii(data.get("output_data", {}))
    data["security_checks"] = redact_pii(data.get("security_checks", []))
    if data.get("block_reason"):
        data["block_reason"] = redact_pii(data["block_reason"])
    if "metadata" in data and data["metadata"] is not None:
        data["metadata"] = redact_pii(data["metadata"])
    if llm_reason and isinstance(llm_reason, str):
        llm_reason = redact_pii(llm_reason)

    model = data.get("input_data", {}).get("model") if isinstance(data.get("input_data"), dict) else None
    p = sql_placeholder()

    try:
        if is_postgres():
            conn = get_db()
            cur = conn.cursor()
            try:
                cur.execute(f"""
                    INSERT INTO spans (trace_id, span_id, span_type, timestamp, latency_ms,
                        input_data, output_data, security_checks, blocked, block_reason, cost_usd,
                        input_tokens, output_tokens, detection_layer, ml_score, llm_score, llm_reason, org_id, model, agent_id)
                    VALUES ({p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p})
                """, (data["trace_id"], data["span_id"], data["span_type"], data["timestamp"], data["latency_ms"],
                    json.dumps(data["input_data"]), json.dumps(data["output_data"]), json.dumps(data["security_checks"]),
                    data["blocked"], data.get("block_reason"), data["cost_usd"], data["input_tokens"], data["output_tokens"],
                    detection_layer, ml_score, llm_score, llm_reason, g.org_id, model, span_agent_id))
                conn.commit()
            finally:
                conn.close()
        else:
            # FIX: timeout et WAL mode
            conn = sqlite3.connect(_get_db_path(), timeout=5.0)
            conn.execute("PRAGMA journal_mode=WAL;")
            cur = conn.cursor()
            try:
                cur.execute(f"""
                    INSERT INTO spans (trace_id, span_id, span_type, timestamp, latency_ms,
                        input_data, output_data, security_checks, blocked, block_reason, cost_usd,
                        input_tokens, output_tokens, detection_layer, ml_score, llm_score, llm_reason, org_id, model, agent_id)
                    VALUES ({p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p})
                """, (data["trace_id"], data["span_id"], data["span_type"], data["timestamp"], data["latency_ms"],
                    json.dumps(data["input_data"]), json.dumps(data["output_data"]), json.dumps(data["security_checks"]),
                    1 if data["blocked"] else 0, data.get("block_reason"), data["cost_usd"],
                    data["input_tokens"], data["output_tokens"], detection_layer, ml_score, llm_score, llm_reason, g.org_id, model, span_agent_id))
                conn.commit()
            finally:
                conn.close()

        # L'écriture canonique est maintenant safe grâce à INSERT OR IGNORE
        _write_canonical_event(data, g.org_id, span_agent_id)
    except Exception as e:
        logger.error("span_ingestion_failed", error=str(e))
        return jsonify({"error": "Internal server error"}), 500

    if data["blocked"]:
        try:
            import alerting
            failed = [c for c in data["security_checks"] if isinstance(c, dict) and not c.get("passed", True)]
            worst = "high"
            for c in failed:
                r = c.get("risk_level", "low")
                if alerting.RISK_ORDER.get(r, 0) > alerting.RISK_ORDER.get(worst, 0):
                    worst = r
            alerting.send_alert({
                "check_name": failed[0].get("check_name", "unknown") if failed else "unknown",
                "risk_level": worst,
                "org_id": g.org_id,
                "trace_id": data["trace_id"],
                "model": model,
                "reason": data.get("block_reason") or "",
                "prompt": str((data.get("input_data") or {}).get("prompt", ""))[:200],
            })
        except Exception as e:
            logger.warning("alerting_failed", error=str(e))

    try:
        from collector.audit_routes import get_audit_log, AuditEventType
        audit = get_audit_log()
        if audit:
            if data.get("blocked"):
                audit.log_event(
                    event_type=AuditEventType.PROMPT_BLOCKED if data["span_type"] == "llm_call" else AuditEventType.TOOL_BLOCKED,
                    org_id=g.org_id, actor=f"agent:{g.org_id}", resource=f"span:{data['span_id']}",
                    action="blocked", details={"trace_id": data["trace_id"], "block_reason": data.get("block_reason", ""), "span_type": data["span_type"]},
                    risk_level="critical",
                )
            else:
                audit.log_event(
                    event_type=AuditEventType.SPAN_INGESTED, org_id=g.org_id, actor=f"agent:{g.org_id}",
                    resource=f"span:{data['span_id']}", action="ingested",
                    details={"trace_id": data["trace_id"], "span_type": data["span_type"], "cost_usd": data.get("cost_usd", 0)},
                    risk_level="info",
                )
    except Exception as e:
        logger.warning("audit_log_failed", error=str(e))

    return jsonify({"status": "ok"}), 201
