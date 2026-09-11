"""API endpoints : spans, traces, metrics, queries, signed decisions."""

import json
import secrets
import structlog
from flask import Blueprint, request, jsonify, g, current_app, send_from_directory
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
from collector.approvals import (
    get_approval,
    list_approvals,
    approve_approval,
    reject_approval,
)
import sqlite3
import os

logger = structlog.get_logger("agentguard.api")
api_bp = Blueprint("api", __name__)
from decision_engine import (
    DecisionEngine,
    DecisionRequest,
)
api_bp = Blueprint("api", __name__)
# Single authoritative runtime decision engine.
#
# IMPORTANT:
# This engine is intentionally created once per collector process.
# Policies should be registered here or loaded through a dedicated
# policy provider in production.
decision_engine = DecisionEngine()
# ═══════════════════════════════════════════════════════════════
# STATIC ASSETS (logo, favicon)
# ═══════════════════════════════════════════════════════════════

@api_bp.route("/logo.svg")
def serve_logo():
    """Serve AgentGuard logo SVG.

    Fixes dashboard 404 error on logo.svg resource.
    """
    static_path = os.path.join(os.path.dirname(__file__), "static")
    try:
        return send_from_directory(static_path, "logo.svg", mimetype="image/svg+xml")
    except Exception as e:
        logger.warning("logo_serve_failed", error=str(e))
        # Fallback : retourner un SVG minimal inline
        fallback_svg = """<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" width="100" height="100">
  <rect width="100" height="100" fill="#2563eb"/>
  <text x="50" y="60" font-family="sans-serif" font-size="40" fill="white" text-anchor="middle">AG</text>
</svg>"""
        return fallback_svg, 200, {"Content-Type": "image/svg+xml"}


@api_bp.route("/favicon.ico")
def serve_favicon():
    """Serve favicon (same logo SVG)."""
    static_path = os.path.join(os.path.dirname(__file__), "static")
    try:
        return send_from_directory(static_path, "logo.svg", mimetype="image/x-icon")
    except Exception:
        return "", 204  # No content


# ═══════════════════════════════════════════════════════════════
# SPAN INGESTION
# ═══════════════════════════════════════════════════════════════
# ✅ P0 FIX : removed @cross_origin(origins=["*"]) — /span now inherits
# the global CORS policy from app.py (strict in production).
@api_bp.route("/span", methods=["POST"])
def receive_span():
    """Ingestion de span (LLM call ou tool call)."""
    span_rate_limit = current_app.config["SPAN_RATE_LIMIT"]

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

    # ── Détection layer extraction (BEFORE redaction — these are non-PII metadata) ──
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

    # ✅ P0 FIX : PII + secrets redaction on ALL persisted fields
    # Before: only input_data/output_data were redacted.
    # Now: security_checks, block_reason, metadata, llm_reason too.
    data["input_data"] = redact_pii(data.get("input_data", {}))
    data["output_data"] = redact_pii(data.get("output_data", {}))
    data["security_checks"] = redact_pii(data.get("security_checks", []))
    if data.get("block_reason"):
        data["block_reason"] = redact_pii(data["block_reason"])
    if "metadata" in data and data["metadata"] is not None:
        data["metadata"] = redact_pii(data["metadata"])
    # llm_reason may contain PII echoed from LLM output
    if llm_reason and isinstance(llm_reason, str):
        llm_reason = redact_pii(llm_reason)

    model = data.get("input_data", {}).get("model") if isinstance(data.get("input_data"), dict) else None

    # DB insert — ✅ utilisation de _get_db_path() dynamique
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
                    detection_layer, ml_score, llm_score, llm_reason, org_id, model
                ) VALUES ({p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p})
            """, (
                data["trace_id"], data["span_id"], data["span_type"],
                data["timestamp"], data["latency_ms"],
                json.dumps(data["input_data"]),
                json.dumps(data["output_data"]),
                json.dumps(data["security_checks"]),
                data["blocked"], data.get("block_reason"), data["cost_usd"],
                data["input_tokens"], data["output_tokens"],
                detection_layer, ml_score, llm_score, llm_reason, g.org_id, model
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
                    detection_layer, ml_score, llm_score, llm_reason, org_id, model
                ) VALUES ({p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p})
            """, (
                data["trace_id"], data["span_id"], data["span_type"],
                data["timestamp"], data["latency_ms"],
                json.dumps(data["input_data"]),
                json.dumps(data["output_data"]),
                json.dumps(data["security_checks"]),
                1 if data["blocked"] else 0,
                data.get("block_reason"), data["cost_usd"],
                data["input_tokens"], data["output_tokens"],
                detection_layer, ml_score, llm_score, llm_reason, g.org_id, model
            ))
            conn.commit()
        finally:
            conn.close()

    # Alerting (uses already-redacted data)
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

    # ✅ Audit log APRÈS commit
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
        r["input_data"] = json.loads(r["input_data"] or "{}")
        r["output_data"] = json.loads(r["output_data"] or "{}")
        r["security_checks"] = json.loads(r["security_checks"] or "[]")
        r["blocked"] = bool(r["blocked"])
    return jsonify(rows)


# ═══════════════════════════════════════════════════════════════
# METRICS — ✅ ROBUST VERSION (fixes 500 errors)
# ═══════════════════════════════════════════════════════════════

@api_bp.route("/api/metrics")
def get_metrics():
    """Metrics endpoint — robust with comprehensive error handling.

    Fixes dashboard 500 error by:
    1. Guarding against missing g.org_id
    2. try/except around each DB query
    3. Returning empty metrics instead of 500 on failure
    """
    # ✅ Empty metrics template for fallback
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

    # ✅ Guard: ensure g.org_id is set
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
            # Total spans
            cur.execute(f"SELECT COUNT(*) FROM spans WHERE org_id = {p}", (org_id,))
            total_spans = cur.fetchone()[0] or 0

            # Total traces
            cur.execute(f"SELECT COUNT(DISTINCT trace_id) FROM spans WHERE org_id = {p}", (org_id,))
            total_traces = cur.fetchone()[0] or 0

            # Blocked
            cur.execute(f"SELECT SUM(CASE WHEN blocked THEN 1 ELSE 0 END) FROM spans WHERE org_id = {p}", (org_id,))
            blocked = cur.fetchone()[0] or 0

            # Total cost
            cur.execute(f"SELECT SUM(cost_usd) FROM spans WHERE org_id = {p}", (org_id,))
            total_cost = cur.fetchone()[0] or 0

            # Total tokens
            cur.execute(f"SELECT COALESCE(SUM(input_tokens + output_tokens), 0) FROM spans WHERE org_id = {p}", (org_id,))
            total_tokens = cur.fetchone()[0] or 0

            # Avg latency
            cur.execute(f"SELECT AVG(latency_ms) FROM spans WHERE latency_ms > 0 AND org_id = {p}", (org_id,))
            avg_latency = cur.fetchone()[0] or 0

            # Detection layers
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

            # ML scores
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

            # Risk distribution
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

            # Top threats
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
        # Return empty metrics instead of 500 — dashboard stays functional
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
# AUDIT TRAIL (legacy, pour dashboard)
# ═══════════════════════════════════════════════════════════════

@api_bp.route("/api/audit/trail")
def api_audit_trail():
    """Audit trail : 50 derniers événements avec prompt."""
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
# SIGNED DECISIONS (Ed25519) — Zero-trust authority
# ═══════════════════════════════════════════════════════════════

@api_bp.route("/api/public-key")
def public_key():
    """Retourne la clé publique (NON protégé, distribuable)."""
    try:
        from signing import DecisionSigner
        signing_key = os.environ.get("CERBERE_SIGNING_KEY") or os.environ.get("AGENTGUARD_SIGNING_KEY", "")
        signer = DecisionSigner(signing_key or None)
        return jsonify({"public_key_pem": signer.public_key_pem()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api_bp.route("/api/decide", methods=["POST"])
def decide():
    """
    Authoritative zero-trust runtime decision endpoint.

    The client may REQUEST a decision, but it never supplies
    the decision itself.

    Flow:

        authenticated request
                ↓
        server-side DecisionEngine
                ↓
        ALLOW / BLOCK / REQUIRE_APPROVAL
                ↓
        Ed25519 signature
    """

    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "error": "Body must be a JSON object"
        }), 400

    tool_name = str(data.get("tool_name", "")).strip()

    if not tool_name:
        return jsonify({
            "error": "tool_name is required"
        }), 400

    params = data.get("params")

    if params is None:
        params = {}

    if not isinstance(params, dict):
        return jsonify({
            "error": "params must be an object"
        }), 400

    # IMPORTANT:
    # Do NOT trust an arbitrary agent_id supplied by the client.
    #
    # The authenticated organization is the security boundary.
    #
    # If your auth middleware exposes a verified agent identity,
    # use it. Otherwise fall back to the organization identity.
    authenticated_agent_id = (
        getattr(g, "agent_id", None)
        or getattr(g, "api_key_id", None)
        or f"org:{g.org_id}"
    )

    requested_policy = data.get("policy")

    metadata = {
        "org_id": g.org_id,
        "source": "api_decide",
    }

    if requested_policy:
        metadata["policy"] = str(requested_policy)

    # Server-side decision request.
    decision_request = DecisionRequest(
        agent_id=str(authenticated_agent_id),
        tool_name=tool_name,
        tool_category=str(
            data.get("tool_category", "read")
        ),
        identity_trusted=True,
        model_score=float(data.get("model_score", 0.0) or 0.0),
        anomaly_score=float(data.get("anomaly_score", 0.0) or 0.0),
        taint_level=str(
            data.get("taint_level", "PUBLIC")
        ).upper(),
        trajectory_length=int(
            data.get("trajectory_length", 0) or 0
        ),
        previous_risky_actions=int(
            data.get("previous_risky_actions", 0) or 0
        ),
        external_side_effect=bool(
            data.get("external_side_effect", False)
        ),
        irreversible=bool(
            data.get("irreversible", False)
        ),
        tool_registered=bool(
            data.get("tool_registered", True)
        ),
        metadata=metadata,
    )

    # ──────────────────────────────────────────────
    # AUTHORITATIVE SERVER-SIDE DECISION
    # ──────────────────────────────────────────────

    try:
        result = decision_engine.evaluate(decision_request)

    except Exception as exc:
        logger.exception(
            "decision_engine_failed",
            error=str(exc),
            org_id=g.org_id,
            tool_name=tool_name,
        )

        # SECURITY:
        # If the decision engine itself fails,
        # NEVER return ALLOW.
        result = None

        try:
            from signing import DecisionSigner

            signing_key = (
                os.environ.get("CERBERE_SIGNING_KEY")
                or os.environ.get("AGENTGUARD_SIGNING_KEY")
            )

            if not signing_key:
                return jsonify({
                    "error": "decision engine unavailable"
                }), 503

            signer = DecisionSigner(signing_key)

            signed = signer.sign_decision({
                "request_id": secrets.token_hex(16),
                "action": "DENY",
                "policy_name": "fail_closed",
                "policy_version": 0,
                "reason": "Decision engine failure",
            })

            return jsonify(signed), 503

        except Exception:
            return jsonify({
                "error": "security decision unavailable"
            }), 503

    # ──────────────────────────────────────────────
    # SIGN SERVER DECISION
    # ──────────────────────────────────────────────

    try:
        from signing import DecisionSigner

        signing_key = (
            os.environ.get("CERBERE_SIGNING_KEY")
            or os.environ.get("AGENTGUARD_SIGNING_KEY")
        )

        if not signing_key:
            logger.error(
                "signing_key_missing_in_production"
            )

            return jsonify({
                "error": "security signing key is not configured"
            }), 503

        signer = DecisionSigner(signing_key)

        signed = signer.sign_decision({
            "request_id": secrets.token_hex(16),
            "action": result.decision.value.upper(),
            "policy_name": result.policy,
            "policy_version": 1,
            "reason": "; ".join(result.reasons[:5]),
        })

        # Include server-generated decision metadata.
        signed["risk_score"] = result.risk_score
        signed["risk_level"] = result.risk_level
        signed["reason_codes"] = result.reason_codes
        signed["enforcement"] = result.enforcement

        return jsonify(signed), 200

    except Exception as exc:
        logger.exception(
            "decision_signing_failed",
            error=str(exc),
        )

        return jsonify({
            "error": "security signing unavailable"
        }), 503

# ═══════════════════════════════════════════════════════════════
# HUMAN-IN-THE-LOOP — APPROVALS
# ═══════════════════════════════════════════════════════════════

@api_bp.route("/api/approvals", methods=["GET"])
def api_list_approvals():
    """
    List approval requests for the authenticated organization.

    Optional:
        ?status=pending
        ?status=approved
        ?status=rejected
        ?status=expired
        ?limit=50
    """
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401

    org_id = getattr(g, "org_id", None)

    if not org_id:
        return jsonify({"error": "Organization context required"}), 400

    status = request.args.get("status")
    limit = request.args.get("limit", 50)

    try:
        limit = int(limit)
    except (TypeError, ValueError):
        return jsonify({"error": "limit must be an integer"}), 400

    if status and status not in {"pending", "approved", "rejected", "expired"}:
        return jsonify({"error": "Invalid approval status"}), 400

    try:
        approvals = list_approvals(
            org_id=org_id,
            status=status,
            limit=limit,
        )

        return jsonify({
            "approvals": approvals,
            "count": len(approvals),
        }), 200

    except Exception as e:
        logger.error(
            "approval_list_failed",
            error=str(e),
            org_id=org_id,
        )
        return jsonify({"error": "Failed to list approvals"}), 500


@api_bp.route("/api/approvals/<approval_id>", methods=["GET"])
def api_get_approval(approval_id):
    """
    Get one approval request.

    The organization filter prevents cross-tenant access.
    """
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401

    org_id = getattr(g, "org_id", None)

    if not org_id:
        return jsonify({"error": "Organization context required"}), 400

    try:
        approval = get_approval(
            approval_id,
            org_id=org_id,
        )

        if approval is None:
            return jsonify({"error": "Approval not found"}), 404

        return jsonify(approval), 200

    except Exception as e:
        logger.error(
            "approval_get_failed",
            error=str(e),
            approval_id=approval_id,
            org_id=org_id,
        )
        return jsonify({"error": "Failed to retrieve approval"}), 500


@api_bp.route("/api/approvals/<approval_id>/approve", methods=["POST"])
def api_approve_approval(approval_id):
    """
    Approve a pending tool action.

    The action is NOT executed here.
    This endpoint only changes the approval state.
    """
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401

    org_id = getattr(g, "org_id", None)

    if not org_id:
        return jsonify({"error": "Organization context required"}), 400

    data = request.get_json(silent=True) or {}

    decision_reason = data.get("reason")

    # Best-effort human identity from the authenticated context.
    decided_by = (
        getattr(g, "user_id", None)
        or getattr(g, "identity_id", None)
        or getattr(g, "email", None)
        or f"org:{org_id}"
    )

    try:
        approval = approve_approval(
            approval_id,
            decided_by=str(decided_by),
            decision_reason=decision_reason,
            org_id=org_id,
        )

        # Audit lifecycle event.
        try:
            from collector.audit_routes import get_audit_log, AuditEventType

            audit = get_audit_log()

            if audit:
                audit.log_event(
                    event_type=getattr(
                        AuditEventType,
                        "APPROVAL_GRANTED",
                        AuditEventType.SPAN_INGESTED,
                    ),
                    org_id=org_id,
                    actor=str(decided_by),
                    resource=f"approval:{approval_id}",
                    action="approved",
                    details={
                        "approval_id": approval_id,
                        "tool_name": approval.get("tool_name"),
                        "agent_id": approval.get("agent_id"),
                        "trace_id": approval.get("trace_id"),
                        "decision_reason": decision_reason,
                    },
                    risk_level="high",
                )
        except Exception as audit_error:
            logger.warning(
                "approval_audit_failed",
                error=str(audit_error),
                approval_id=approval_id,
            )

        return jsonify({
            "status": "approved",
            "approval": approval,
        }), 200

    except KeyError:
        return jsonify({"error": "Approval not found"}), 404

    except ValueError as e:
        message = str(e)

        if "expired" in message.lower():
            return jsonify({
                "error": "Approval expired",
                "status": "expired",
            }), 409

        return jsonify({
            "error": message,
        }), 409

    except Exception as e:
        logger.error(
            "approval_approve_failed",
            error=str(e),
            approval_id=approval_id,
            org_id=org_id,
        )
        return jsonify({"error": "Failed to approve request"}), 500


@api_bp.route("/api/approvals/<approval_id>/reject", methods=["POST"])
def api_reject_approval(approval_id):
    """
    Reject a pending tool action.
    """
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401

    org_id = getattr(g, "org_id", None)

    if not org_id:
        return jsonify({"error": "Organization context required"}), 400

    data = request.get_json(silent=True) or {}

    decision_reason = data.get("reason")

    decided_by = (
        getattr(g, "user_id", None)
        or getattr(g, "identity_id", None)
        or getattr(g, "email", None)
        or f"org:{org_id}"
    )

    try:
        approval = reject_approval(
            approval_id,
            decided_by=str(decided_by),
            decision_reason=decision_reason,
            org_id=org_id,
        )

        # Audit lifecycle event.
        try:
            from collector.audit_routes import get_audit_log, AuditEventType

            audit = get_audit_log()

            if audit:
                audit.log_event(
                    event_type=getattr(
                        AuditEventType,
                        "APPROVAL_REJECTED",
                        AuditEventType.SPAN_INGESTED,
                    ),
                    org_id=org_id,
                    actor=str(decided_by),
                    resource=f"approval:{approval_id}",
                    action="rejected",
                    details={
                        "approval_id": approval_id,
                        "tool_name": approval.get("tool_name"),
                        "agent_id": approval.get("agent_id"),
                        "trace_id": approval.get("trace_id"),
                        "decision_reason": decision_reason,
                    },
                    risk_level="high",
                )
        except Exception as audit_error:
            logger.warning(
                "approval_audit_failed",
                error=str(audit_error),
                approval_id=approval_id,
            )

        return jsonify({
            "status": "rejected",
            "approval": approval,
        }), 200

    except KeyError:
        return jsonify({"error": "Approval not found"}), 404

    except ValueError as e:
        message = str(e)

        if "expired" in message.lower():
            return jsonify({
                "error": "Approval expired",
                "status": "expired",
            }), 409

        return jsonify({
            "error": message,
        }), 409

    except Exception as e:
        logger.error(
            "approval_reject_failed",
            error=str(e),
            approval_id=approval_id,
            org_id=org_id,
        )
        return jsonify({"error": "Failed to reject request"}), 500
