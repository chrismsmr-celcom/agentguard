"""API endpoints : spans, traces, metrics, queries, signed decisions."""

import json
import re
import secrets
import structlog
from flask import Blueprint, request, jsonify, g, current_app, send_from_directory
from datetime import datetime
import time
import sqlite3
import os

from collector.db import (
    get_db,
    get_sqlite_conn,
    dict_from_row,
    is_postgres,
    redact_pii,
    psycopg2,
    _get_db_path,
    sql_true,
    sql_false,
    sql_placeholder,
)
from collector.alerts import (
    create_alert_rule,
    list_alert_rules,
    delete_alert_rule,
    VALID_METRICS,
    VALID_COMPARISONS,
)

from collector.auth import require_auth, require_human_auth

logger = structlog.get_logger("agentguard.api")

from decision_engine import (
    DecisionEngine,
    DecisionRequest,
)

api_bp = Blueprint("api", __name__)

decision_engine = DecisionEngine()


def get_decision_signer():
    signer = current_app.extensions.get("agentguard_decision_signer")
    if signer is not None:
        return signer

    from signing import DecisionSigner

    signing_key = (
        os.environ.get("CERBERE_SIGNING_KEY")
        or os.environ.get("AGENTGUARD_SIGNING_KEY")
    )

    if not signing_key:
        raise RuntimeError(
            "CERBERE_SIGNING_KEY or AGENTGUARD_SIGNING_KEY is required"
        )

    signer = DecisionSigner(signing_key)
    current_app.extensions["agentguard_decision_signer"] = signer
    return signer


def is_server_registered_tool(tool_name):
    tool_name = str(tool_name or "").strip()
    if not tool_name:
        return False

    for policy in decision_engine.policies.values():
        if tool_name in getattr(policy, "blocked_tools", set()):
            continue

        allowed_tools = getattr(policy, "allowed_tools", None)
        if allowed_tools is not None and tool_name in allowed_tools:
            return True

    return False


# ═══════════════════════════════════════════════════════════════
# STATIC ASSETS (logo, favicon)
# ═══════════════════════════════════════════════════════════════

@api_bp.route("/logo.svg")
def serve_logo():
    static_path = os.path.join(os.path.dirname(__file__), "static")
    try:
        return send_from_directory(static_path, "logo.svg", mimetype="image/svg+xml")
    except Exception as e:
        logger.warning("logo_serve_failed", error=str(e))
        fallback_svg = """<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" width="100" height="100">
  <rect width="100" height="100" fill="#2563eb"/>
  <text x="50" y="60" font-family="sans-serif" font-size="40" fill="white" text-anchor="middle">AG</text>
</svg>"""
        return fallback_svg, 200, {"Content-Type": "image/svg+xml"}


@api_bp.route("/favicon.ico")
def serve_favicon():
    static_path = os.path.join(os.path.dirname(__file__), "static")
    try:
        return send_from_directory(static_path, "logo.svg", mimetype="image/x-icon")
    except Exception:
        return "", 204


def _as_json(value, default):
    """PostgreSQL (JSONB) renvoie déjà dict/list ; SQLite renvoie du texte.
    json.loads() sur un dict levait TypeError -> HTTP 500 sur /api/traces/<id> en prod."""
    if value is None or value == "":
        return default
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", "replace")
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


def _iso_utc(value):
    """Horodatage -> ISO 8601 UTC ('...Z'), que le navigateur sait parser."""
    if value is None:
        return None
    if hasattr(value, "isoformat"):
        text = value.isoformat()
    else:
        text = str(value).replace(" ", "T")
    if text.endswith("Z") or "+" in text[10:]:
        return text
    return text.split(".")[0] + "Z"


def _db_run(sql, params=(), fetch=None, commit=False):
    """Exécute une requête écrite avec des '?' (converti en %s pour PostgreSQL)."""
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(sql.replace("?", "%s") if is_postgres() else sql, params)
        out = None
        if fetch == "one":
            out = cur.fetchone()
        elif fetch == "all":
            out = cur.fetchall()
        rowcount = cur.rowcount
        if commit:
            conn.commit()
        return out, rowcount
    finally:
        conn.close()


# ═══════════════════════════════════════════════════════════════
# SPAN INGESTION
# ═══════════════════════════════════════════════════════════════

@api_bp.route("/span", methods=["POST"])
def receive_span():
    span_rate_limit = current_app.config["SPAN_RATE_LIMIT"]

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
        detection_layer = (
            data["metadata"].get("detection_layer")
            or data["metadata"].get("layer")
        )
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

    if is_postgres():
        conn = get_db()
        cur = conn.cursor()
        try:
            cur.execute(f"""
                INSERT INTO spans (
                    trace_id, span_id, span_type, timestamp, latency_ms,
                    input_data, output_data, security_checks, blocked,
                    block_reason, cost_usd, input_tokens, output_tokens,
                    detection_layer, ml_score, llm_score, llm_reason, org_id, model, agent_id
                ) VALUES ({p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p})
            """, (
                data["trace_id"], data["span_id"], data["span_type"],
                data["timestamp"], data["latency_ms"],
                json.dumps(data["input_data"]),
                json.dumps(data["output_data"]),
                json.dumps(data["security_checks"]),
                data["blocked"], data.get("block_reason"), data["cost_usd"],
                data["input_tokens"], data["output_tokens"],
                detection_layer, ml_score, llm_score, llm_reason, g.org_id, model, span_agent_id
            ))
            conn.commit()
        finally:
            conn.close()
    else:
        conn = sqlite3.connect(_get_db_path())
        cur = conn.cursor()
        try:
            cur.execute(f"""
                INSERT INTO spans (
                    trace_id, span_id, span_type, timestamp, latency_ms,
                    input_data, output_data, security_checks, blocked,
                    block_reason, cost_usd, input_tokens, output_tokens,
                    detection_layer, ml_score, llm_score, llm_reason, org_id, model, agent_id
                ) VALUES ({p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p})
            """, (
                data["trace_id"], data["span_id"], data["span_type"],
                data["timestamp"], data["latency_ms"],
                json.dumps(data["input_data"]),
                json.dumps(data["output_data"]),
                json.dumps(data["security_checks"]),
                1 if data["blocked"] else 0,
                data.get("block_reason"), data["cost_usd"],
                data["input_tokens"], data["output_tokens"],
                detection_layer, ml_score, llm_score, llm_reason, g.org_id, model, span_agent_id
            ))
            conn.commit()
        finally:
            conn.close()

    if data["blocked"]:
        try:
            import alerting
            failed = [c for c in data["security_checks"]
                      if isinstance(c, dict) and not c.get("passed", True)]
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
                    event_type=AuditEventType.PROMPT_BLOCKED if data["span_type"] == "llm_call"
                             else AuditEventType.TOOL_BLOCKED,
                    org_id=g.org_id,
                    actor=f"agent:{g.org_id}",
                    resource=f"span:{data['span_id']}",
                    action="blocked",
                    details={
                        "trace_id": data["trace_id"],
                        "block_reason": data.get("block_reason", ""),
                        "span_type": data["span_type"],
                    },
                    risk_level="critical",
                )
            else:
                audit.log_event(
                    event_type=AuditEventType.SPAN_INGESTED,
                    org_id=g.org_id,
                    actor=f"agent:{g.org_id}",
                    resource=f"span:{data['span_id']}",
                    action="ingested",
                    details={
                        "trace_id": data["trace_id"],
                        "span_type": data["span_type"],
                        "cost_usd": data.get("cost_usd", 0),
                    },
                    risk_level="info",
                )
    except Exception as e:
        logger.warning("audit_log_failed", error=str(e))

    return jsonify({"status": "ok"}), 201


# ═══════════════════════════════════════════════════════════════
# TRACES QUERIES
# ═══════════════════════════════════════════════════════════════

@api_bp.route("/api/traces")
def list_traces():
    p = sql_placeholder()
    if is_postgres():
        conn = get_db()
        cur = conn.cursor()
        concat_fn = "STRING_AGG(DISTINCT detection_layer, ',')"
        cur.execute(f"""
            SELECT trace_id, COUNT(*) as span_count,
                   SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked_count,
                   SUM(cost_usd) as total_cost,
                   MAX(created_at) as last_seen,
                   {concat_fn} as detection_layers
            FROM spans WHERE org_id = {p}
            GROUP BY trace_id
            ORDER BY last_seen DESC LIMIT 100
        """, (g.org_id,))
        rows = [dict_from_row(r, cur) for r in cur.fetchall()]
        conn.close()
    else:
        conn = sqlite3.connect(_get_db_path())
        cur = conn.cursor()
        try:
            concat_fn = "GROUP_CONCAT(DISTINCT detection_layer)"
            cur.execute(f"""
                SELECT trace_id, COUNT(*) as span_count,
                       SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked_count,
                       SUM(cost_usd) as total_cost,
                       MAX(created_at) as last_seen,
                       {concat_fn} as detection_layers
                FROM spans WHERE org_id = ?
                GROUP BY trace_id
                ORDER BY last_seen DESC LIMIT 100
            """, (g.org_id,))
            rows = [dict_from_row(r, cur) for r in cur.fetchall()]
        finally:
            conn.close()
    return jsonify(rows)


@api_bp.route("/api/traces/<trace_id>")
def get_trace(trace_id):
    p = sql_placeholder()
    if is_postgres():
        conn = get_db()
        cur = conn.cursor()
        cur.execute(f"SELECT * FROM spans WHERE trace_id = {p} AND org_id = {p} ORDER BY timestamp", (trace_id, g.org_id))
        rows = [dict_from_row(r, cur) for r in cur.fetchall()]
        conn.close()
    else:
        conn = sqlite3.connect(_get_db_path())
        cur = conn.cursor()
        try:
            cur.execute("SELECT * FROM spans WHERE trace_id = ? AND org_id = ? ORDER BY timestamp", (trace_id, g.org_id))
            rows = [dict_from_row(r, cur) for r in cur.fetchall()]
        finally:
            conn.close()

    for r in rows:
        r["input_data"] = _as_json(r["input_data"], {})
        r["output_data"] = _as_json(r["output_data"], {})
        r["security_checks"] = _as_json(r["security_checks"], [])
        r["blocked"] = bool(r["blocked"])
    return jsonify(rows)


# ═══════════════════════════════════════════════════════════════
# METRICS
# ═══════════════════════════════════════════════════════════════

@api_bp.route("/api/metrics")
def get_metrics():
    empty_metrics = {
        "total_spans": 0,
        "total_traces": 0,
        "blocked_operations": 0,
        "total_cost_usd": 0.0,
        "total_tokens": 0,
        "avg_latency_ms": 0.0,
        "avg_ml_score": 0.0,
        "avg_llm_score": 0.0,
        "llm_judge_count": 0,
        "risk_distribution": {"low": 0, "medium": 0, "high": 0, "critical": 0},
        "top_threats": [],
        "detection_layers": {},
        "version": "v6.0.0",
    }

    org_id = getattr(g, "org_id", None)
    if not org_id:
        logger.warning("metrics_no_org_id", endpoint=request.endpoint)
        empty_metrics["error"] = "no_org_id"
        return jsonify(empty_metrics), 200

    p = sql_placeholder()

    try:
        if is_postgres():
            conn = get_db()
        else:
            conn = sqlite3.connect(_get_db_path())

        cur = conn.cursor()
        try:
            cur.execute(f"SELECT COUNT(*) FROM spans WHERE org_id = {p}", (org_id,))
            total_spans = cur.fetchone()[0] or 0

            cur.execute(f"SELECT COUNT(DISTINCT trace_id) FROM spans WHERE org_id = {p}", (org_id,))
            total_traces = cur.fetchone()[0] or 0

            cur.execute(f"SELECT SUM(CASE WHEN blocked THEN 1 ELSE 0 END) FROM spans WHERE org_id = {p}", (org_id,))
            blocked = cur.fetchone()[0] or 0

            cur.execute(f"SELECT SUM(cost_usd) FROM spans WHERE org_id = {p}", (org_id,))
            total_cost = cur.fetchone()[0] or 0

            cur.execute(f"SELECT COALESCE(SUM(input_tokens + output_tokens), 0) FROM spans WHERE org_id = {p}", (org_id,))
            total_tokens = cur.fetchone()[0] or 0

            cur.execute(f"SELECT AVG(latency_ms) FROM spans WHERE latency_ms > 0 AND org_id = {p}", (org_id,))
            avg_latency = cur.fetchone()[0] or 0

            try:
                if is_postgres():
                    cur.execute("""
                        SELECT detection_layer, COUNT(*) as count
                        FROM spans WHERE detection_layer IS NOT NULL AND org_id = %s
                        GROUP BY detection_layer
                    """, (org_id,))
                else:
                    cur.execute("""
                        SELECT detection_layer, COUNT(*) as count
                        FROM spans WHERE detection_layer IS NOT NULL AND org_id = ?
                        GROUP BY detection_layer
                    """, (org_id,))
                detection_stats = {row[0]: row[1] for row in cur.fetchall()}
            except Exception as e:
                logger.warning("metrics_detection_query_failed", error=str(e))
                detection_stats = {}

            try:
                cur.execute(f"SELECT AVG(ml_score) FROM spans WHERE ml_score IS NOT NULL AND org_id = {p}", (org_id,))
                avg_ml_score = cur.fetchone()[0] or 0
                cur.execute(f"SELECT AVG(llm_score) FROM spans WHERE llm_score IS NOT NULL AND org_id = {p}", (org_id,))
                avg_llm_score = cur.fetchone()[0] or 0
                cur.execute(f"SELECT COUNT(*) FROM spans WHERE detection_layer = 'llm_judge' AND org_id = {p}", (org_id,))
                llm_count = cur.fetchone()[0] or 0
            except Exception as e:
                logger.warning("metrics_scores_query_failed", error=str(e))
                avg_ml_score = 0
                avg_llm_score = 0
                llm_count = 0

            risk_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
            try:
                if is_postgres():
                    cur.execute("""
                        SELECT jsonb_array_elements(security_checks) as check
                        FROM spans WHERE created_at > NOW() - INTERVAL '1 day' AND org_id = %s
                    """, (org_id,))
                    for row in cur.fetchall():
                        check = row[0] if isinstance(row[0], dict) else {}
                        level = check.get("risk_level", "low")
                        if level in risk_counts:
                            risk_counts[level] += 1
                else:
                    cur.execute("""
                        SELECT security_checks FROM spans
                        WHERE created_at > datetime('now', '-1 day') AND org_id = ?
                    """, (org_id,))
                    for row in cur.fetchall():
                        try:
                            checks = json.loads(row[0] or "[]")
                            for check in checks:
                                level = check.get("risk_level", "low")
                                if level in risk_counts:
                                    risk_counts[level] += 1
                        except Exception:
                            pass
            except Exception as e:
                logger.warning("metrics_risk_query_failed", error=str(e))

            try:
                cur.execute(f"""
                    SELECT block_reason, COUNT(*) as count
                    FROM spans WHERE blocked = {sql_true()} AND org_id = {p}
                    GROUP BY block_reason ORDER BY count DESC LIMIT 5
                """, (org_id,))
                top_threats = [{"reason": r[0], "count": r[1]} for r in cur.fetchall()]
            except Exception as e:
                logger.warning("metrics_threats_query_failed", error=str(e))
                top_threats = []

        finally:
            conn.close()

        return jsonify({
            "total_spans": total_spans,
            "total_traces": total_traces,
            "blocked_operations": blocked,
            "total_cost_usd": round(float(total_cost or 0), 6),
            "total_tokens": int(total_tokens),
            "avg_latency_ms": round(float(avg_latency or 0), 2),
            "avg_ml_score": round(float(avg_ml_score or 0), 3),
            "avg_llm_score": round(float(avg_llm_score or 0), 3),
            "llm_judge_count": llm_count,
            "risk_distribution": risk_counts,
            "top_threats": top_threats,
            "detection_layers": detection_stats,
            "version": "v6.0.0",
        })

    except Exception as e:
        logger.error("metrics_endpoint_failed", error=str(e), org_id=org_id)
        empty_metrics["error"] = str(e)[:200]
        return jsonify(empty_metrics), 200


# ═══════════════════════════════════════════════════════════════
# DETECTION STATS
# ═══════════════════════════════════════════════════════════════

@api_bp.route("/api/detection/stats")
def get_detection_stats():
    org_id = getattr(g, "org_id", None)
    if not org_id:
        logger.warning("detection_stats_no_org_id")
        return jsonify({"error": "no_org_id"}), 401

    p = sql_placeholder()

    if is_postgres():
        conn = get_db()
    else:
        conn = sqlite3.connect(_get_db_path())

    cur = conn.cursor()
    try:
        cur.execute(f"""
            SELECT detection_layer, COUNT(*) as count
            FROM spans WHERE detection_layer IS NOT NULL AND org_id = {p}
            GROUP BY detection_layer ORDER BY count DESC
        """, (org_id,))
        layer_distribution = [{"layer": r[0], "count": r[1]} for r in cur.fetchall()]

        cur.execute(f"""
            SELECT detection_layer, COUNT(*) as total, SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked
            FROM spans WHERE detection_layer IS NOT NULL AND org_id = {p}
            GROUP BY detection_layer
        """, (org_id,))
        layer_accuracy = [
            {"layer": r[0], "total": r[1], "blocked": r[2],
             "block_rate": round((r[2] / r[1] * 100) if r[1] > 0 else 0, 2)}
            for r in cur.fetchall()
        ]

        cur.execute(f"""
            SELECT
                CASE
                    WHEN ml_score >= 0.9 THEN '0.9-1.0'
                    WHEN ml_score >= 0.8 THEN '0.8-0.9'
                    WHEN ml_score >= 0.7 THEN '0.7-0.8'
                    WHEN ml_score >= 0.6 THEN '0.6-0.7'
                    WHEN ml_score >= 0.5 THEN '0.5-0.6'
                    ELSE '0.0-0.5'
                END as score_range, COUNT(*) as count
            FROM spans WHERE ml_score IS NOT NULL AND org_id = {p}
            GROUP BY score_range ORDER BY score_range DESC
        """, (org_id,))
        ml_score_distribution = [{"range": r[0], "count": r[1]} for r in cur.fetchall()]

        cur.execute(f"""
            SELECT
                CASE
                    WHEN llm_score >= 0.9 THEN 'high_risk'
                    WHEN llm_score >= 0.7 THEN 'medium_risk'
                    ELSE 'low_risk'
                END as risk_category, COUNT(*) as count
            FROM spans WHERE llm_score IS NOT NULL AND org_id = {p}
            GROUP BY risk_category
        """, (org_id,))
        llm_score_distribution = [{"category": r[0], "count": r[1]} for r in cur.fetchall()]

    finally:
        conn.close()

    return jsonify({
        "layer_distribution": layer_distribution,
        "layer_accuracy": layer_accuracy,
        "ml_score_distribution": ml_score_distribution,
        "llm_score_distribution": llm_score_distribution,
        "total_analyzed": sum(l["count"] for l in layer_distribution) if layer_distribution else 0,
    })


@api_bp.route("/api/llm/stats")
def get_llm_stats():
    p = sql_placeholder()
    if is_postgres():
        conn = get_db()
    else:
        conn = sqlite3.connect(_get_db_path())

    cur = conn.cursor()
    try:
        cur.execute(f"SELECT COUNT(*) FROM spans WHERE detection_layer = 'llm_judge' AND org_id = {p}", (g.org_id,))
        total_llm = cur.fetchone()[0] or 0

        cur.execute(f"""
            SELECT COUNT(*), SUM(CASE WHEN blocked THEN 1 ELSE 0 END)
            FROM spans WHERE detection_layer = 'llm_judge' AND org_id = {p}
        """, (g.org_id,))
        total, blocked = cur.fetchone()
        total = total or 0
        blocked = blocked or 0
        block_rate = round((blocked / total * 100), 2) if total else 0

        cur.execute(f"""
            SELECT llm_reason, COUNT(*) as count
            FROM spans WHERE llm_reason IS NOT NULL AND detection_layer = 'llm_judge' AND org_id = {p}
            GROUP BY llm_reason ORDER BY count DESC LIMIT 5
        """, (g.org_id,))
        top_reasons = [{"reason": r[0], "count": r[1]} for r in cur.fetchall()]

    finally:
        conn.close()

    return jsonify({
        "total_analyzed": total_llm,
        "block_rate": block_rate,
        "top_reasons": top_reasons,
        "status": "operational" if total_llm > 0 else "idle",
    })


# ═══════════════════════════════════════════════════════════════
# MODELS
# ═══════════════════════════════════════════════════════════════

@api_bp.route("/api/models")
def api_models():
    p = sql_placeholder()
    if is_postgres():
        conn = get_db()
        cur = conn.cursor()
    else:
        conn = sqlite3.connect(_get_db_path())
        cur = conn.cursor()

    try:
        cur.execute(f"""
            SELECT model, COUNT(*) as requests, AVG(latency_ms) as avg_latency,
                   SUM(cost_usd) as total_cost,
                   SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked_count,
                   COALESCE(SUM(input_tokens), 0) as input_tokens,
                   COALESCE(SUM(output_tokens), 0) as output_tokens
            FROM spans WHERE org_id = {p} AND model IS NOT NULL AND model != ''
            GROUP BY model ORDER BY requests DESC
        """, (g.org_id,))
        models = []
        for r in cur.fetchall():
            row = dict_from_row(r, cur) if is_postgres() else {
                "model": r[0], "requests": r[1], "avg_latency": r[2],
                "total_cost": r[3], "blocked_count": r[4],
                "input_tokens": r[5], "output_tokens": r[6],
            }
            models.append({
                "name": row.get("model"),
                "requests": row.get("requests"),
                "avg_latency_ms": round(float(row.get("avg_latency") or 0), 1),
                "total_cost_usd": round(float(row.get("total_cost") or 0), 6),
                "blocked_count": row.get("blocked_count"),
                "input_tokens": int(row.get("input_tokens") or 0),
                "output_tokens": int(row.get("output_tokens") or 0),
            })
    finally:
        conn.close()
    return jsonify(models)


# ═══════════════════════════════════════════════════════════════
# HEATMAP + BREAKDOWN
# ═══════════════════════════════════════════════════════════════

@api_bp.route("/api/heatmap")
def api_heatmap():
    if is_postgres():
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            SELECT EXTRACT(DAY FROM created_at)::int as day, EXTRACT(HOUR FROM created_at)::int as hour,
                   COUNT(*) as total, SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked
            FROM spans WHERE org_id = %s AND created_at > NOW() - INTERVAL '5 days'
            GROUP BY day, hour
        """, (g.org_id,))
        cells = [{"day": r[0], "hour": r[1], "total": r[2], "blocked": r[3] or 0} for r in cur.fetchall()]
        conn.close()
    else:
        conn = sqlite3.connect(_get_db_path())
        cur = conn.cursor()
        try:
            cur.execute("""
                SELECT CAST(strftime('%d', created_at) AS INTEGER) as day,
                       CAST(strftime('%H', created_at) AS INTEGER) as hour,
                       COUNT(*) as total,
                       SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked
                FROM spans WHERE org_id = ? AND created_at > datetime('now', '-5 days')
                GROUP BY day, hour
            """, (g.org_id,))
            cells = [{"day": r[0], "hour": r[1], "total": r[2], "blocked": r[3] or 0} for r in cur.fetchall()]
        finally:
            conn.close()
    return jsonify(cells)


@api_bp.route("/api/checks/breakdown")
def api_checks_breakdown():
    p = sql_placeholder()
    if is_postgres():
        conn = get_db()
    else:
        conn = sqlite3.connect(_get_db_path())

    cur = conn.cursor()
    try:
        cur.execute(f"SELECT security_checks FROM spans WHERE org_id = {p} AND security_checks IS NOT NULL", (g.org_id,))
        rows = cur.fetchall()
    finally:
        conn.close()

    breakdown = {}
    for row in rows:
        raw = row[0]
        try:
            checks = raw if isinstance(raw, list) else json.loads(raw)
        except Exception:
            continue
        for c in (checks or []):
            name = c.get("check_name", "unknown")
            entry = breakdown.setdefault(name, {"total": 0, "flagged": 0})
            entry["total"] += 1
            if not c.get("passed", True):
                entry["flagged"] += 1

    result = [
        {"check_name": name, "total": v["total"], "flagged": v["flagged"],
         "flag_rate": round(v["flagged"] / v["total"] * 100, 1) if v["total"] else 0}
        for name, v in breakdown.items()
    ]
    return jsonify(sorted(result, key=lambda x: -x["total"]))


@api_bp.route("/api/checks/daily")
def api_checks_daily():
    if is_postgres():
        conn = get_db()
        cur = conn.cursor()
        try:
            cur.execute("""
                SELECT DATE(created_at) as day, c->>'check_name' as name,
                       COUNT(*) as total,
                       SUM(CASE WHEN (c->>'passed')::boolean THEN 0 ELSE 1 END) as flagged
                FROM spans, jsonb_array_elements(security_checks) c
                WHERE org_id = %s AND created_at > NOW() - INTERVAL '14 days'
                GROUP BY day, name ORDER BY day
            """, (g.org_id,))
            rows = [{"day": str(r[0]), "name": r[1], "total": r[2], "flagged": r[3] or 0} for r in cur.fetchall()]
        except Exception:
            rows = []
        conn.close()
    else:
        conn = sqlite3.connect(_get_db_path())
        cur = conn.cursor()
        try:
            cur.execute("""
                SELECT DATE(created_at) as day, json_extract(c.value, '$.check_name') as name,
                       COUNT(*) as total,
                       SUM(CASE WHEN json_extract(c.value, '$.passed') = 1 THEN 0 ELSE 1 END) as flagged
                FROM spans, json_each(spans.security_checks) c
                WHERE org_id = ? AND created_at > datetime('now','-14 days')
                GROUP BY day, name ORDER BY day
            """, (g.org_id,))
            rows = [{"day": str(r[0]), "name": r[1], "total": r[2], "flagged": r[3] or 0} for r in cur.fetchall()]
        except Exception:
            rows = []
        finally:
            conn.close()
    return jsonify(rows)


@api_bp.route("/api/models/daily")
def api_models_daily():
    p = sql_placeholder()
    if is_postgres():
        conn = get_db()
        cur = conn.cursor()
        cur.execute(f"""
            SELECT DATE(created_at) as day, model, COUNT(*) as n
            FROM spans WHERE org_id = {p} AND model IS NOT NULL AND model != ''
              AND created_at > NOW() - INTERVAL '14 days'
            GROUP BY day, model ORDER BY day
        """, (g.org_id,))
        rows = [{"day": str(r[0]), "model": r[1], "n": r[2]} for r in cur.fetchall()]
        conn.close()
    else:
        conn = sqlite3.connect(_get_db_path())
        cur = conn.cursor()
        try:
            cur.execute(f"""
                SELECT DATE(created_at) as day, model, COUNT(*) as n
                FROM spans WHERE org_id = ? AND model IS NOT NULL AND model != ''
                  AND created_at > datetime('now', '-14 days')
                GROUP BY day, model ORDER BY day
            """, (g.org_id,))
            rows = [{"day": str(r[0]), "model": r[1], "n": r[2]} for r in cur.fetchall()]
        finally:
            conn.close()
    return jsonify(rows)


# ═══════════════════════════════════════════════════════════════
# COST / LATENCY / TRENDS
# ═══════════════════════════════════════════════════════════════

@api_bp.route("/api/spans/expensive")
def api_expensive_spans():
    p = sql_placeholder()
    if is_postgres():
        conn = get_db()
        cur = conn.cursor()
        try:
            cur.execute(f"""
                SELECT trace_id, span_id, span_type, model, cost_usd,
                       COALESCE(input_data->>'prompt', input_data->>'tool', '') AS prompt,
                       COALESCE(output_data->>'response', '') AS response,
                       input_tokens, output_tokens
                FROM spans WHERE org_id = {p} AND cost_usd > 0
                ORDER BY cost_usd DESC LIMIT 10
            """, (g.org_id,))
            rows = [
                {"trace_id": r[0], "span_id": r[1], "span_type": r[2], "model": r[3],
                 "cost_usd": r[4], "prompt": (r[5] or "")[:300], "response": (r[6] or "")[:300],
                 "input_tokens": r[7] or 0, "output_tokens": r[8] or 0}
                for r in cur.fetchall()
            ]
        except Exception:
            rows = []
        conn.close()
    else:
        conn = sqlite3.connect(_get_db_path())
        cur = conn.cursor()
        try:
            cur.execute(f"""
                SELECT trace_id, span_id, span_type, model, cost_usd,
                       COALESCE(json_extract(input_data, '$.prompt'), json_extract(input_data, '$.tool'), '') AS prompt,
                       COALESCE(json_extract(output_data, '$.response'), '') AS response,
                       input_tokens, output_tokens
                FROM spans WHERE org_id = ? AND cost_usd > 0
                ORDER BY cost_usd DESC LIMIT 10
            """, (g.org_id,))
            rows = [
                {"trace_id": r[0], "span_id": r[1], "span_type": r[2], "model": r[3],
                 "cost_usd": r[4], "prompt": (r[5] or "")[:300], "response": (r[6] or "")[:300],
                 "input_tokens": r[7] or 0, "output_tokens": r[8] or 0}
                for r in cur.fetchall()
            ]
        except Exception:
            rows = []
        finally:
            conn.close()
    return jsonify(rows)


@api_bp.route("/api/cost/trend")
def api_cost_trend():
    p = sql_placeholder()
    if is_postgres():
        conn = get_db()
        cur = conn.cursor()
        cur.execute(f"""
            SELECT DATE(created_at) as day, SUM(cost_usd) as cost,
                   COALESCE(SUM(input_tokens + output_tokens), 0) as tokens
            FROM spans WHERE org_id = {p} AND created_at > NOW() - INTERVAL '14 days'
            GROUP BY day ORDER BY day
        """, (g.org_id,))
        rows = [{"day": str(r[0]), "cost": round(float(r[1] or 0), 6), "tokens": int(r[2] or 0)} for r in cur.fetchall()]
        conn.close()
    else:
        conn = sqlite3.connect(_get_db_path())
        cur = conn.cursor()
        try:
            cur.execute(f"""
                SELECT DATE(created_at) as day, SUM(cost_usd) as cost,
                       COALESCE(SUM(input_tokens + output_tokens), 0) as tokens
                FROM spans WHERE org_id = ? AND created_at > datetime('now', '-14 days')
                GROUP BY day ORDER BY day
            """, (g.org_id,))
            rows = [{"day": str(r[0]), "cost": round(float(r[1] or 0), 6), "tokens": int(r[2] or 0)} for r in cur.fetchall()]
        finally:
            conn.close()
    return jsonify(rows)


@api_bp.route("/api/latency/distribution")
def api_latency_distribution():
    p = sql_placeholder()
    if is_postgres():
        conn = get_db()
    else:
        conn = sqlite3.connect(_get_db_path())

    cur = conn.cursor()
    try:
        cur.execute(f"SELECT latency_ms FROM spans WHERE org_id = {p} AND latency_ms > 0 ORDER BY latency_ms", (g.org_id,))
        values = [r[0] for r in cur.fetchall()]
    finally:
        conn.close()

    def pct(vals, q):
        if not vals:
            return 0
        idx = min(len(vals) - 1, int(len(vals) * q))
        return round(vals[idx], 1)

    return jsonify({
        "count": len(values),
        "p50": pct(values, 0.50), "p90": pct(values, 0.90),
        "p95": pct(values, 0.95), "p99": pct(values, 0.99),
        "min": round(min(values), 1) if values else 0,
        "max": round(max(values), 1) if values else 0,
    })


@api_bp.route("/api/events/recent")
def api_recent_events():
    p = sql_placeholder()
    if is_postgres():
        conn = get_db()
    else:
        conn = sqlite3.connect(_get_db_path())

    cur = conn.cursor()
    try:
        cur.execute(f"""
            SELECT span_type, detection_layer, blocked, block_reason, created_at, security_checks
            FROM spans WHERE org_id = {p} ORDER BY created_at DESC LIMIT 8
        """, (g.org_id,))
        events = []
        for r in cur.fetchall():
            try:
                checks = r[5] if isinstance(r[5], list) else json.loads(r[5] or "[]")
            except Exception:
                checks = []
            risk = "low"
            for c in checks:
                if c.get("risk_level") in ("high", "critical"):
                    risk = c.get("risk_level")
                    break
            events.append({
                "span_type": r[0], "layer": r[1] or "regex", "blocked": bool(r[2]),
                "reason": r[3], "created_at": str(r[4]), "risk": risk,
            })
    finally:
        conn.close()
    return jsonify(events)


@api_bp.route("/api/trend/daily")
def api_trend_daily():
    p = sql_placeholder()
    if is_postgres():
        conn = get_db()
        cur = conn.cursor()
        cur.execute(f"""
            SELECT DATE(created_at) as day, COUNT(*) as total,
                   SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked
            FROM spans WHERE org_id = {p} AND created_at > NOW() - INTERVAL '14 days'
            GROUP BY day ORDER BY day
        """, (g.org_id,))
        rows = [{"day": str(r[0]), "total": r[1], "blocked": r[2] or 0} for r in cur.fetchall()]
        conn.close()
    else:
        conn = sqlite3.connect(_get_db_path())
        cur = conn.cursor()
        try:
            cur.execute(f"""
                SELECT DATE(created_at) as day, COUNT(*) as total,
                       SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked
                FROM spans WHERE org_id = ? AND created_at > datetime('now', '-14 days')
                GROUP BY day ORDER BY day
            """, (g.org_id,))
            rows = [{"day": str(r[0]), "total": r[1], "blocked": r[2] or 0} for r in cur.fetchall()]
        finally:
            conn.close()
    return jsonify(rows)


# ═══════════════════════════════════════════════════════════════
# AUDIT TRAIL
# ═══════════════════════════════════════════════════════════════

@api_bp.route("/api/audit/trail")
def api_audit_trail():
    p = sql_placeholder()
    if is_postgres():
        conn = get_db()
        cur = conn.cursor()
        cur.execute(f"""
            SELECT created_at, trace_id, span_id, span_type, detection_layer, model, blocked,
                   COALESCE(input_data->>'prompt', input_data->>'tool', '') AS prompt
            FROM spans WHERE org_id = {p} ORDER BY created_at DESC LIMIT 50
        """, (g.org_id,))
        rows = [
            {"timestamp": str(r[0]), "trace_id": r[1], "span_id": r[2],
             "span_type": r[3], "layer": r[4] or "regex", "model": r[5] or "—",
             "blocked": bool(r[6]), "prompt": (r[7] or "")[:120]}
            for r in cur.fetchall()
        ]
        conn.close()
    else:
        conn = sqlite3.connect(_get_db_path())
        cur = conn.cursor()
        try:
            cur.execute(f"""
                SELECT created_at, trace_id, span_id, span_type, detection_layer, model, blocked,
                       COALESCE(json_extract(input_data, '$.prompt'), json_extract(input_data, '$.tool'), '') AS prompt
                FROM spans WHERE org_id = ? ORDER BY created_at DESC LIMIT 50
            """, (g.org_id,))
            rows = [
                {"timestamp": str(r[0]), "trace_id": r[1], "span_id": r[2],
                 "span_type": r[3], "layer": r[4] or "regex", "model": r[5] or "—",
                 "blocked": bool(r[6]), "prompt": (r[7] or "")[:120]}
                for r in cur.fetchall()
            ]
        finally:
            conn.close()
    return jsonify(rows)


# ═══════════════════════════════════════════════════════════════
# SIGNED DECISIONS (Ed25519)
# ═══════════════════════════════════════════════════════════════

@api_bp.route("/api/public-key")
def public_key():
    try:
        signer = get_decision_signer()
        return jsonify({"public_key_pem": signer.public_key_pem()}), 200
    except Exception as e:
        logger.error("public_key_unavailable", error=str(e))
        return jsonify({"error": "signing key is not configured"}), 503


@api_bp.route("/api/decide", methods=["POST"])
def decide():
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401

    refused = _reject_if_agent_disconnected()
    if refused:
        return refused

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Body must be a JSON object"}), 400

    tool_name = str(data.get("tool_name", "")).strip()

    if not tool_name:
        return jsonify({"error": "tool_name is required"}), 400

    params = data.get("params")
    if params is None:
        params = {}
    if not isinstance(params, dict):
        return jsonify({"error": "params must be an object"}), 400

    authenticated_agent_id = (
        getattr(g, "agent_id", None)
        or getattr(g, "api_key_id", None)
        or f"org:{g.org_id}"
    )

    requested_policy = data.get("policy")
    metadata = {"org_id": g.org_id, "source": "api_decide"}
    if requested_policy:
        metadata["policy"] = str(requested_policy)

    decision_request = DecisionRequest(
        agent_id=str(authenticated_agent_id),
        tool_name=tool_name,
        tool_category=str(data.get("tool_category", "read")),
        identity_trusted=True,
        model_score=float(data.get("model_score", 0.0) or 0.0),
        anomaly_score=float(data.get("anomaly_score", 0.0) or 0.0),
        taint_level=str(data.get("taint_level", "PUBLIC")).upper(),
        trajectory_length=int(data.get("trajectory_length", 0) or 0),
        previous_risky_actions=int(data.get("previous_risky_actions", 0) or 0),
        external_side_effect=bool(data.get("external_side_effect", False)),
        irreversible=bool(data.get("irreversible", False)),
        tool_registered=is_server_registered_tool(tool_name),
        metadata=metadata,
    )

    try:
        result = decision_engine.evaluate(decision_request)
    except Exception as exc:
        logger.exception("decision_engine_failed", error=str(exc), org_id=g.org_id, tool_name=tool_name)
        result = None
        try:
            signer = get_decision_signer()
            signed = signer.sign_decision({
                "request_id": secrets.token_hex(16),
                "action": "DENY",
                "policy_name": "fail_closed",
                "policy_version": 0,
                "reason": "Decision engine failure",
            })
            return jsonify(signed), 503
        except Exception:
            return jsonify({"error": "security decision unavailable"}), 503

    try:
        signer = get_decision_signer()
        signed = signer.sign_decision({
            "request_id": secrets.token_hex(16),
            "action": result.decision.value.upper(),
            "policy_name": result.policy,
            "policy_version": 1,
            "reason": "; ".join(result.reasons[:5]),
        })
        signed["risk_score"] = result.risk_score
        signed["risk_level"] = result.risk_level
        signed["reason_codes"] = result.reason_codes
        signed["enforcement"] = result.enforcement
        return jsonify(signed), 200
    except Exception as exc:
        logger.exception("decision_signing_failed", error=str(exc))
        return jsonify({"error": "security signing unavailable"}), 503


# ═══════════════════════════════════════════════════════════════
# HUMAN-IN-THE-LOOP — APPROVALS (Simple, unified schema)
# ═══════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════
# AGENT REGISTRY — agents connectés, kill switch depuis le dashboard
# ═══════════════════════════════════════════════════════════════

_AGENT_ID_RE = re.compile(r"^[A-Za-z0-9_.:@\- ]{1,64}$")
_AGENT_SEEN = {}      # (org, agent) -> dernier upsert (limite l'écriture en base)
_AGENT_STATUS = {}    # (org, agent) -> (ts, status) cache court de lecture
_AGENT_TOUCH_EVERY = 15.0
# Anciens SDK (sans en-tête) : seuls ces endpoints d'ingestion font apparaître l'agent
_INGEST_ENDPOINTS = {"api.receive_span", "api.decide", "api.api_sdk_create_approval"}
_AGENT_STATUS_TTL = 3.0


def _request_agent_id():
    """Identité déclarée par le SDK (en-tête X-Agent-Id) ou identité de la clé agent."""
    raw = (request.headers.get("X-Agent-Id") or "").strip()
    if raw and _AGENT_ID_RE.match(raw):
        return raw
    identity = getattr(g, "agent_identity", None)
    if isinstance(identity, dict) and identity.get("agent_id"):
        return str(identity["agent_id"])[:64]
    # SDK < 0.4.1 : pas d'en-tête X-Agent-Id -> l'agent est identifié par le nom de sa clé API
    key_name = getattr(g, "api_key_name", None)
    if key_name:
        safe = re.sub(r"[^A-Za-z0-9_.:@\- ]", "-", key_name).strip()[:58]
        if safe:
            return "key:" + safe
    return None


def _agent_status(org_id, agent_id):
    """'connected' | 'disconnected' | None (agent inconnu). Fail-open si la base est KO."""
    key = (org_id, agent_id)
    hit = _AGENT_STATUS.get(key)
    now = time.time()
    if hit and now - hit[0] < _AGENT_STATUS_TTL:
        return hit[1]
    try:
        row, _ = _db_run(
            "SELECT status FROM connected_agents WHERE org_id = ? AND agent_id = ?",
            (org_id, agent_id), fetch="one",
        )
    except Exception as exc:
        logger.warning("agent_status_lookup_failed", error=str(exc))
        return None
    status = row[0] if row else None
    _AGENT_STATUS[key] = (now, status)
    return status


def _reject_if_agent_disconnected():
    """403 si l'agent a été déconnecté depuis le dashboard (kill switch)."""
    agent_id = _request_agent_id()
    org_id = getattr(g, "org_id", None)
    if agent_id and org_id and _agent_status(org_id, agent_id) == "disconnected":
        logger.warning("agent_request_refused_disconnected", agent_id=agent_id, org_id=org_id)
        return jsonify({
            "error": "agent_disconnected",
            "agent_id": agent_id,
            "message": "This agent was disconnected from the Cerbere dashboard.",
        }), 403
    return None


def _touch_agent(org_id, agent_id, sdk_version=None, name=None):
    """Enregistre / rafraîchit l'agent (upsert), au plus une fois par _AGENT_TOUCH_EVERY s."""
    key = (org_id, agent_id)
    now = time.time()
    if now - _AGENT_SEEN.get(key, 0) < _AGENT_TOUCH_EVERY:
        return
    _AGENT_SEEN[key] = now
    _db_run(
        """
        INSERT INTO connected_agents (org_id, agent_id, name, sdk_version)
        VALUES (?, ?, ?, ?)
        ON CONFLICT (org_id, agent_id) DO UPDATE SET
            last_seen_at = CURRENT_TIMESTAMP,
            sdk_version = COALESCE(excluded.sdk_version, connected_agents.sdk_version)
        """,
        (org_id, agent_id, name or agent_id, sdk_version), commit=True,
    )


@api_bp.after_app_request
def _register_agent_activity(response):
    """Toute requête authentifiée d'un SDK (X-Agent-Id) alimente le registre des agents."""
    try:
        endpoint = request.endpoint or ""
        if (
            response.status_code < 400
            and endpoint.startswith("api.")
            and (request.headers.get("X-Agent-Id") or endpoint in _INGEST_ENDPOINTS)
        ):
            org_id = getattr(g, "org_id", None)
            agent_id = _request_agent_id()
            if org_id and agent_id:
                sdk_version = (request.headers.get("X-Agent-Sdk") or "")[:32] or None
                name = getattr(g, "api_key_name", None) if agent_id.startswith("key:") else None
                _touch_agent(org_id, agent_id, sdk_version, name)
    except Exception as exc:  # ne jamais casser une réponse pour de la télémétrie
        logger.debug("agent_touch_failed", error=str(exc))
    return response


def _agent_state(status, last_seen):
    if status == "disconnected":
        return "disconnected"
    seen = _iso_utc(last_seen)
    if not seen:
        return "offline"
    try:
        dt = datetime.fromisoformat(seen.replace("Z", "+00:00"))
        idle = (datetime.now(dt.tzinfo) - dt).total_seconds()
    except ValueError:
        return "offline"
    if idle < 300:
        return "connected"
    if idle < 3600:
        return "idle"
    return "offline"


def _audit_human_action(event_name, resource, action, details):
    """Trace best-effort dans l'audit trail infalsifiable (onglet Compliance Audit)."""
    try:
        from collector.audit_routes import get_audit_log, AuditEventType
        audit = get_audit_log()
        if audit:
            audit.log_event(
                event_type=getattr(AuditEventType, event_name),
                org_id=g.org_id,
                actor=f"human:{getattr(g, 'human_email', None) or g.org_id}",
                resource=resource,
                action=action,
                details=details,
                risk_level="high",
            )
    except Exception as exc:
        logger.warning("audit_log_failed", error=str(exc))


@api_bp.route("/api/agents", methods=["GET"], endpoint="api_list_agents")
def api_list_agents():
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401
    org_id = getattr(g, "org_id", None) or "default"

    try:
        rows, _ = _db_run(
            """
            SELECT agent_id, name, status, sdk_version, first_seen_at, last_seen_at,
                   disconnected_at, disconnected_by
            FROM connected_agents WHERE org_id = ?
            ORDER BY last_seen_at DESC
            """, (org_id,), fetch="all")
        stat_rows, _ = _db_run(
            """
            SELECT agent_id, COUNT(*),
                   SUM(CASE WHEN blocked THEN 1 ELSE 0 END),
                   COALESCE(SUM(cost_usd), 0)
            FROM spans WHERE org_id = ? AND agent_id IS NOT NULL
            GROUP BY agent_id
            """, (org_id,), fetch="all")
        pend_rows, _ = _db_run(
            """
            SELECT agent_id, COUNT(*) FROM approval_requests
            WHERE org_id = ? AND status = 'pending' GROUP BY agent_id
            """, (org_id,), fetch="all")
    except Exception as exc:
        logger.error("agents_list_failed", error=str(exc), org_id=org_id)
        return jsonify({"error": f"Database error: {str(exc)}"}), 500

    stats = {r[0]: {"calls": int(r[1] or 0), "blocked": int(r[2] or 0), "cost_usd": float(r[3] or 0)}
             for r in stat_rows}
    pending = {r[0]: int(r[1] or 0) for r in pend_rows}

    agents, counts = [], {"connected": 0, "idle": 0, "offline": 0, "disconnected": 0}
    for r in rows:
        agent_id, name, status, sdk_version, first_seen, last_seen, disc_at, disc_by = r
        state = _agent_state(status, last_seen)
        counts[state] += 1
        st = stats.get(agent_id, {})
        agents.append({
            "agent_id": agent_id,
            "name": name or agent_id,
            "status": status,
            "state": state,
            "sdk_version": sdk_version,
            "first_seen_at": _iso_utc(first_seen),
            "last_seen_at": _iso_utc(last_seen),
            "disconnected_at": _iso_utc(disc_at),
            "disconnected_by": disc_by,
            "calls": st.get("calls", 0),
            "blocked": st.get("blocked", 0),
            "cost_usd": round(st.get("cost_usd", 0.0), 4),
            "pending_approvals": pending.get(agent_id, 0),
        })
    agents.sort(key=lambda a: a["agent_id"].lower())   # ordre stable : le bouton ne bouge pas sous la souris
    return jsonify({"agents": agents, "counts": counts, "total": len(agents)}), 200


def _set_agent_status(agent_id, new_status):
    # Décision humaine uniquement : un agent ne doit pas pouvoir se (re)connecter lui-même.
    if not require_human_auth():
        return jsonify({"error": "Human session required"}), 401
    org_id = g.org_id
    actor = getattr(g, "human_email", None) or f"org:{org_id}"

    try:
        if new_status == "disconnected":
            _, n = _db_run(
                """UPDATE connected_agents
                   SET status = 'disconnected', disconnected_at = CURRENT_TIMESTAMP, disconnected_by = ?
                   WHERE org_id = ? AND agent_id = ?""",
                (actor, org_id, agent_id), commit=True)
        else:
            _, n = _db_run(
                """UPDATE connected_agents
                   SET status = 'connected', disconnected_at = NULL, disconnected_by = NULL
                   WHERE org_id = ? AND agent_id = ?""",
                (org_id, agent_id), commit=True)
    except Exception as exc:
        logger.error("agent_status_update_failed", error=str(exc), agent_id=agent_id)
        return jsonify({"error": f"Database error: {str(exc)}"}), 500

    if n == 0:
        return jsonify({"error": "Agent not found"}), 404

    _AGENT_STATUS.pop((org_id, agent_id), None)
    logger.warning("agent_status_changed", agent_id=agent_id, status=new_status, by=actor, org_id=org_id)
    _audit_human_action(
        "AGENT_DISCONNECTED" if new_status == "disconnected" else "AGENT_RECONNECTED",
        f"agent:{agent_id}", new_status, {"agent_id": agent_id, "by": actor})
    return jsonify({"agent_id": agent_id, "status": new_status}), 200


@api_bp.route("/api/agents/<agent_id>/disconnect", methods=["POST"], endpoint="api_agent_disconnect")
def api_agent_disconnect(agent_id):
    return _set_agent_status(agent_id, "disconnected")


@api_bp.route("/api/agents/<agent_id>/reconnect", methods=["POST"], endpoint="api_agent_reconnect")
def api_agent_reconnect(agent_id):
    return _set_agent_status(agent_id, "connected")


# ── Boutons "test" du dashboard : vérifier la chaîne complète sans écrire une ligne de code ──
TEST_AGENT_ID = "cerbere-test-agent"


def _ensure_test_agent(org_id):
    _db_run(
        """INSERT INTO connected_agents (org_id, agent_id, name, status, sdk_version)
           VALUES (?, ?, ?, 'connected', ?)
           ON CONFLICT (org_id, agent_id) DO UPDATE SET last_seen_at = CURRENT_TIMESTAMP""",
        (org_id, TEST_AGENT_ID, "Cerbere test agent", "test"), commit=True)


@api_bp.route("/api/agents/test", methods=["POST"], endpoint="api_test_agent")
def api_test_agent():
    if not require_human_auth():
        return jsonify({"error": "Human session required"}), 401
    try:
        _ensure_test_agent(g.org_id)
    except Exception as exc:
        return jsonify({"error": f"Database error: {str(exc)}"}), 500
    return jsonify({"agent_id": TEST_AGENT_ID, "status": "connected"}), 201


@api_bp.route("/api/approvals/test", methods=["POST"], endpoint="api_test_approval")
def api_test_approval():
    """Crée une demande d'approbation factice, pour voir la file et la décision de bout en bout."""
    if not require_human_auth():
        return jsonify({"error": "Human session required"}), 401
    approval_id = "test_" + secrets.token_hex(4)
    try:
        _ensure_test_agent(g.org_id)
        _db_run(
            """INSERT INTO approval_requests (id, org_id, agent_id, tool_name, params, reason, status)
               VALUES (?, ?, ?, ?, ?, ?, 'pending')""",
            (approval_id, g.org_id, TEST_AGENT_ID, "send_email",
             json.dumps({"to": "partner@gmail.com", "subject": "Q3 customer export",
                         "attachments": ["customers_q3.csv"]}),
             "Test request from the dashboard: external recipient on a personal domain"),
            commit=True)
    except Exception as exc:
        return jsonify({"error": f"Database error: {str(exc)}"}), 500
    return jsonify({"id": approval_id, "status": "pending"}), 201



@api_bp.route("/api/agent/status", methods=["GET"], endpoint="api_agent_status")
def api_agent_status():
    """Appelé par le SDK (clé API) pour savoir s'il a été déconnecté depuis le dashboard."""
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401
    agent_id = _request_agent_id()
    if not agent_id:
        return jsonify({"agent_id": None, "status": "connected"}), 200
    status = _agent_status(g.org_id, agent_id)
    return jsonify({
        "agent_id": agent_id,
        "status": "disconnected" if status == "disconnected" else "connected",
    }), 200


# ═══════════════════════════════════════════════════════════════
# HITL — file d'attente d'approbations
# ═══════════════════════════════════════════════════════════════

_APPROVAL_STATUSES = {"pending", "approved", "rejected"}


@api_bp.route("/api/approvals", methods=["GET"], endpoint="api_list_approvals")
def api_list_approvals():
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401

    org_id = getattr(g, "org_id", None) or "default"
    status = request.args.get("status", "pending")
    try:
        limit = max(1, min(int(request.args.get("limit", 50)), 200))
    except (TypeError, ValueError):
        limit = 50

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
        rows, _ = _db_run(
            f"""SELECT id, agent_id, tool_name, params, reason, created_at, status, resolved_at, resolved_by
                FROM approval_requests WHERE {where} ORDER BY {order} LIMIT ?""",
            (*params, limit), fetch="all")
        count_rows, _ = _db_run(
            "SELECT status, COUNT(*) FROM approval_requests WHERE org_id = ? GROUP BY status",
            (org_id,), fetch="all")
    except Exception as e:
        logger.error("approval_list_failed", error=str(e), org_id=org_id)
        return jsonify({"error": f"Database error: {str(e)}"}), 500

    approvals = [{
        "id": r[0],
        "agent_id": r[1],
        "tool_name": r[2],
        "params": _as_json(r[3], {}),
        "reason": r[4],
        "created_at": _iso_utc(r[5]),
        "status": r[6],
        "resolved_at": _iso_utc(r[7]),
        "resolved_by": r[8],
    } for r in rows]
    counts = {"pending": 0, "approved": 0, "rejected": 0}
    for st, n in count_rows:
        if st in counts:
            counts[st] = int(n)
    return jsonify({"approvals": approvals, "count": len(approvals), "counts": counts}), 200


def _resolve_approval(approval_id, new_status):
    # Un agent (clé API) ne doit JAMAIS pouvoir valider sa propre demande.
    if not require_human_auth():
        return jsonify({"error": "Human session required"}), 401

    org_id = g.org_id
    decided_by = getattr(g, "human_email", None) or f"org:{org_id}"
    try:
        row, _ = _db_run(
            "SELECT agent_id, tool_name FROM approval_requests WHERE id = ? AND org_id = ?",
            (approval_id, org_id), fetch="one")
        _, n = _db_run(
            """UPDATE approval_requests
               SET status = ?, resolved_at = CURRENT_TIMESTAMP, resolved_by = ?
               WHERE id = ? AND org_id = ? AND status = 'pending'""",
            (new_status, decided_by, approval_id, org_id), commit=True)
    except Exception as e:
        logger.error("approval_resolve_failed", error=str(e), approval_id=approval_id, org_id=org_id)
        return jsonify({"error": f"Database error: {str(e)}"}), 500

    if n == 0:
        return jsonify({"error": "Approval not found or already resolved"}), 404

    _audit_human_action(
        "APPROVAL_GRANTED" if new_status == "approved" else "APPROVAL_REJECTED",
        f"approval:{approval_id}", new_status,
        {"approval_id": approval_id, "agent_id": row[0] if row else None,
         "tool_name": row[1] if row else None, "decided_by": decided_by})
    return jsonify({"status": new_status, "id": approval_id, "decided_by": decided_by}), 200


@api_bp.route("/api/approvals/<approval_id>/approve", methods=["POST"], endpoint="api_approve_approval")
def api_approve_approval(approval_id):
    return _resolve_approval(approval_id, "approved")


@api_bp.route("/api/approvals/<approval_id>/reject", methods=["POST"], endpoint="api_reject_approval")
def api_reject_approval(approval_id):
    return _resolve_approval(approval_id, "rejected")


@api_bp.route("/api/approvals/<approval_id>", methods=["GET"], endpoint="api_get_approval_status")
def api_get_approval_status(approval_id):
    """Statut d'une demande — interrogé par le SDK pour savoir quand exécuter."""
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401
    
    org_id = getattr(g, "org_id", None) or "default"
    
    try:
        row, _ = _db_run(
            "SELECT id, status, resolved_by, resolved_at FROM approval_requests WHERE id = ? AND org_id = ?",
            (approval_id, org_id), fetch="one")
    except Exception as e:
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    
    if not row:
        return jsonify({"error": "Approval not found"}), 404
    
    return jsonify({
        "id": row[0],
        "status": row[1],
        "resolved_by": row[2],
        "resolved_at": _iso_utc(row[3])
    }), 200


@api_bp.route("/api/approvals", methods=["POST"], endpoint="api_sdk_create_approval")
def hitl_sdk_create_approval():
    # Sans require_auth(), g.org_id n'est jamais posé -> toutes les demandes
    # tombaient dans l'org 'default', invisibles pour le dashboard du client.
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401

    refused = _reject_if_agent_disconnected()
    if refused:
        return refused

    data = request.get_json(silent=True) or {}
    approval_id = data.get("approval_id") or data.get("id")
    agent_id = data.get("agent_id") or _request_agent_id() or "unknown"
    tool_name = data.get("tool_name")
    params = data.get("params", {})
    reason = data.get("reason", "Approval required by policy")

    if not approval_id:
        return jsonify({"error": "approval_id is required"}), 400

    org_id = getattr(g, "org_id", None) or "default"
    try:
        _db_run(
            """INSERT INTO approval_requests (id, org_id, agent_id, tool_name, params, reason, status)
               VALUES (?, ?, ?, ?, ?, ?, 'pending')
               ON CONFLICT (id) DO NOTHING""",
            (str(approval_id)[:128], org_id, str(agent_id)[:64], tool_name,
             json.dumps(params), reason), commit=True)
        logger.warning("approval_request_created", approval_id=approval_id, tool=tool_name, org_id=org_id)
         # --- NOUVEAU : Déclencher l'alerte Email/Webhook ---
        try:
            # Récupérer l'email de l'org (à adapter selon ta table users/orgs)
            org_email = getattr(g, "human_email", "admin@entreprise.com") 
            
            # Exemple avec un service d'envoi d'email (ex: Resend, SendGrid, ou SMTP)
            # requests.post("https://api.resend.com/emails", json={
            #     "from": "Cerbere <alertes@cerbereag.site>",
            #     "to": [org_email],
            #     "subject": f"🚨 Action requise : Approbation pour {tool_name}",
            #     "html": f"<p>L'agent <b>{agent_id}</b> demande l'exécution de <b>{tool_name}</b>.</p><p><a href='https://app.cerbereag.site'>Cliquez ici pour approuver ou rejeter</a></p>"
            # }, headers={"Authorization": "Bearer YOUR_RESEND_KEY"})
            
            logger.info("approval_alert_sent", to=org_email)
        except Exception as e:
            logger.error("approval_alert_failed", error=str(e))
        # ---------------------------------------------------

        return jsonify({"status": "success", "id": approval_id}), 201
        return jsonify({"status": "success", "id": approval_id}), 201
    except Exception as e:
        logger.error("approval_request_failed", error=str(e))
        return jsonify({"error": str(e)}), 500


# ═══════════════════════════════════════════════════════════════
# HEALTH / READINESS
# ═══════════════════════════════════════════════════════════════

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
    return jsonify({
        "status": "healthy" if is_healthy else "unhealthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "0.2.1",
        "checks": checks
    }), status_code


@api_bp.route("/readiness", methods=["GET"])
def readiness_check():
    return jsonify({"ready": True, "timestamp": datetime.utcnow().isoformat()}), 200


# ═══════════════════════════════════════════════════════════════
# ALERT RULES
# ═══════════════════════════════════════════════════════════════

@api_bp.route("/api/alert-rules", methods=["GET"])
def api_list_alert_rules():
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401

    org_id = getattr(g, "org_id", None)
    if not org_id:
        return jsonify({"error": "Organization context required"}), 400

    try:
        rules = list_alert_rules(org_id=org_id)
        return jsonify({"alert_rules": rules, "count": len(rules)}), 200
    except Exception as e:
        logger.error("alert_rules_list_failed", error=str(e), org_id=org_id)
        return jsonify({"error": "Failed to list alert rules"}), 500


@api_bp.route("/api/alert-rules", methods=["POST"])
def api_create_alert_rule():
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401

    org_id = getattr(g, "org_id", None)
    if not org_id:
        return jsonify({"error": "Organization context required"}), 400

    data = request.get_json(silent=True) or {}
    metric = data.get("metric")
    comparison = data.get("comparison", "above")
    threshold = data.get("threshold")
    label = data.get("label")

    if metric not in VALID_METRICS:
        return jsonify({"error": f"metric must be one of {sorted(VALID_METRICS)}"}), 400
    if comparison not in VALID_COMPARISONS:
        return jsonify({"error": f"comparison must be one of {sorted(VALID_COMPARISONS)}"}), 400
    try:
        threshold = float(threshold)
    except (TypeError, ValueError):
        return jsonify({"error": "threshold must be a number"}), 400

    try:
        rule = create_alert_rule(
            org_id=org_id,
            metric=metric,
            comparison=comparison,
            threshold=threshold,
            label=label,
            created_by=getattr(g, "authenticated_user", None),
        )
        return jsonify({"alert_rule": rule}), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error("alert_rule_create_failed", error=str(e), org_id=org_id)
        return jsonify({"error": "Failed to create alert rule"}), 500


@api_bp.route("/api/alert-rules/<alert_id>", methods=["DELETE"])
def api_delete_alert_rule(alert_id):
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401

    org_id = getattr(g, "org_id", None)
    if not org_id:
        return jsonify({"error": "Organization context required"}), 400

    try:
        deleted = delete_alert_rule(alert_id, org_id=org_id)
        if not deleted:
            return jsonify({"error": "Alert rule not found"}), 404
        return jsonify({"status": "deleted", "alert_id": alert_id}), 200
    except Exception as e:
        logger.error("alert_rule_delete_failed", error=str(e), org_id=org_id)
        return jsonify({"error": "Failed to delete alert rule"}), 500


