"""
API endpoints : spans, traces, metrics, queries, signed decisions.
"""
import json
import secrets
import structlog
from flask import Blueprint, request, jsonify, g, current_app
from flask_cors import cross_origin
from collector.db import get_db, dict_from_row, is_postgres, redact_pii, psycopg2
import sqlite3
import os

logger = structlog.get_logger("agentguard.api")
api_bp = Blueprint("api", __name__)

DB_SQLITE_PATH = os.environ.get("AGENTGUARD_DB_PATH", "/tmp/agentguard.db")


# ═══════════════════════════════════════════════════════════════
# SPAN INGESTION
# ═══════════════════════════════════════════════════════════════
@api_bp.route("/span", methods=["POST"])
@cross_origin(
    origins=["*"],
    allow_headers=["Content-Type", "X-API-Key"],
    supports_credentials=True,
)
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

    # PII redaction
    data["input_data"] = redact_pii(data.get("input_data", {}))
    data["output_data"] = redact_pii(data.get("output_data", {}))

    # Détection layer extraction
    detection_layer = None
    ml_score = None
    llm_score = None
    llm_reason = None

    if "metadata" in data:
        detection_layer = data.get("metadata", {}).get("detection_layer") or data.get("metadata", {}).get("layer")
        ml_score = data.get("metadata", {}).get("ml_score")
        llm_score = data.get("metadata", {}).get("llm_score")
        llm_reason = data.get("metadata", {}).get("llm_reason")

    if not detection_layer and data.get("security_checks"):
        for check in data["security_checks"]:
            if check.get("check_name") in ["prompt_injection", "llm_judge"]:
                detection_layer = check.get("metadata", {}).get("layer")
                ml_score = check.get("metadata", {}).get("ml_score")
                llm_score = check.get("metadata", {}).get("llm_score")
                llm_reason = check.get("details")
                break

    model = data.get("input_data", {}).get("model") if isinstance(data.get("input_data"), dict) else None

    # DB insert
    if is_postgres():
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO spans (
                trace_id, span_id, span_type, timestamp, latency_ms,
                input_data, output_data, security_checks, blocked,
                block_reason, cost_usd, input_tokens, output_tokens,
                detection_layer, ml_score, llm_score, llm_reason, org_id, model
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
    else:
        conn = sqlite3.connect(DB_SQLITE_PATH)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO spans (
                trace_id, span_id, span_type, timestamp, latency_ms,
                input_data, output_data, security_checks, blocked,
                block_reason, cost_usd, input_tokens, output_tokens,
                detection_layer, ml_score, llm_score, llm_reason, org_id, model
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
    conn.close()

    # Alerting
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
    conn = get_db()
    if is_postgres():
        cur = conn.cursor(row_factory=psycopg2.extras.RealDictCursor)
        org_filter = "%s"
        concat_fn = "STRING_AGG(DISTINCT detection_layer, ',')"
    else:
        cur = conn.cursor()
        org_filter = "?"
        concat_fn = "GROUP_CONCAT(DISTINCT detection_layer)"

    cur.execute(f"""
        SELECT trace_id, COUNT(*) as span_count,
               SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked_count,
               SUM(cost_usd) as total_cost,
               MAX(created_at) as last_seen,
               {concat_fn} as detection_layers
        FROM spans WHERE org_id = {org_filter}
        GROUP BY trace_id
        ORDER BY last_seen DESC LIMIT 100
    """, (g.org_id,))
    rows = [dict_from_row(r, is_postgres()) for r in cur.fetchall()]
    conn.close()
    return jsonify(rows)


@api_bp.route("/api/traces/<trace_id>")
def get_trace(trace_id):
    conn = get_db()
    if is_postgres():
        cur = conn.cursor(row_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT * FROM spans WHERE trace_id = %s AND org_id = %s ORDER BY timestamp", (trace_id, g.org_id))
    else:
        cur = conn.cursor()
        cur.execute("SELECT * FROM spans WHERE trace_id = ? AND org_id = ? ORDER BY timestamp", (trace_id, g.org_id))

    rows = [dict_from_row(r, is_postgres()) for r in cur.fetchall()]
    for r in rows:
        r["input_data"] = json.loads(r["input_data"] or "{}")
        r["output_data"] = json.loads(r["output_data"] or "{}")
        r["security_checks"] = json.loads(r["security_checks"] or "[]")
        r["blocked"] = bool(r["blocked"])
    conn.close()
    return jsonify(rows)


# ═══════════════════════════════════════════════════════════════
# METRICS
# ═══════════════════════════════════════════════════════════════
@api_bp.route("/api/metrics")
def get_metrics():
    conn = get_db()
    p = "%s" if is_postgres() else "?"
    cur = conn.cursor()

    cur.execute(f"SELECT COUNT(*) FROM spans WHERE org_id = {p}", (g.org_id,))
    total_spans = cur.fetchone()[0]
    cur.execute(f"SELECT COUNT(DISTINCT trace_id) FROM spans WHERE org_id = {p}", (g.org_id,))
    total_traces = cur.fetchone()[0]
    cur.execute(f"SELECT SUM(CASE WHEN blocked THEN 1 ELSE 0 END) FROM spans WHERE org_id = {p}", (g.org_id,))
    blocked = cur.fetchone()[0] or 0
    cur.execute(f"SELECT SUM(cost_usd) FROM spans WHERE org_id = {p}", (g.org_id,))
    total_cost = cur.fetchone()[0] or 0
    cur.execute(f"SELECT COALESCE(SUM(input_tokens + output_tokens), 0) FROM spans WHERE org_id = {p}", (g.org_id,))
    total_tokens = cur.fetchone()[0] or 0
    cur.execute(f"SELECT AVG(latency_ms) FROM spans WHERE latency_ms > 0 AND org_id = {p}", (g.org_id,))
    avg_latency = cur.fetchone()[0] or 0

    if is_postgres():
        cur.execute("""
            SELECT detection_layer, COUNT(*) as count
            FROM spans WHERE detection_layer IS NOT NULL AND org_id = %s
            GROUP BY detection_layer
        """, (g.org_id,))
    else:
        cur.execute("""
            SELECT detection_layer, COUNT(*) as count
            FROM spans WHERE detection_layer IS NOT NULL AND org_id = ?
            GROUP BY detection_layer
        """, (g.org_id,))
    detection_stats = {row[0]: row[1] for row in cur.fetchall()}

    cur.execute(f"SELECT AVG(ml_score) FROM spans WHERE ml_score IS NOT NULL AND org_id = {p}", (g.org_id,))
    avg_ml_score = cur.fetchone()[0] or 0
    cur.execute(f"SELECT AVG(llm_score) FROM spans WHERE llm_score IS NOT NULL AND org_id = {p}", (g.org_id,))
    avg_llm_score = cur.fetchone()[0] or 0
    cur.execute(f"SELECT COUNT(*) FROM spans WHERE detection_layer = 'llm_judge' AND org_id = {p}", (g.org_id,))
    llm_count = cur.fetchone()[0] or 0

    risk_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    if is_postgres():
        cur.execute("""
            SELECT jsonb_array_elements(security_checks) as check
            FROM spans WHERE created_at > NOW() - INTERVAL '1 day' AND org_id = %s
        """, (g.org_id,))
        for row in cur.fetchall():
            check = row[0] if isinstance(row[0], dict) else {}
            level = check.get("risk_level", "low")
            if level in risk_counts:
                risk_counts[level] += 1
    else:
        cur.execute("""
            SELECT security_checks FROM spans
            WHERE created_at > datetime('now', '-1 day') AND org_id = ?
        """, (g.org_id,))
        for row in cur.fetchall():
            try:
                checks = json.loads(row[0] or "[]")
                for check in checks:
                    level = check.get("risk_level", "low")
                    if level in risk_counts:
                        risk_counts[level] += 1
            except Exception:
                pass

    cur.execute(f"""
        SELECT block_reason, COUNT(*) as count
        FROM spans WHERE blocked = TRUE AND org_id = {p}
        GROUP BY block_reason ORDER BY count DESC LIMIT 5
    """, (g.org_id,))
    top_threats = [{"reason": r[0], "count": r[1]} for r in cur.fetchall()]

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


# ═══════════════════════════════════════════════════════════════
# DETECTION STATS
# ═══════════════════════════════════════════════════════════════
@api_bp.route("/api/detection/stats")
def get_detection_stats():
    conn = get_db()
    p = "%s" if is_postgres() else "?"
    cur = conn.cursor()

    cur.execute(f"""
        SELECT detection_layer, COUNT(*) as count
        FROM spans WHERE detection_layer IS NOT NULL AND org_id = {p}
        GROUP BY detection_layer ORDER BY count DESC
    """, (g.org_id,))
    layer_distribution = [{"layer": r[0], "count": r[1]} for r in cur.fetchall()]

    cur.execute(f"""
        SELECT detection_layer, COUNT(*) as total, SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked
        FROM spans WHERE detection_layer IS NOT NULL AND org_id = {p}
        GROUP BY detection_layer
    """, (g.org_id,))
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
    """, (g.org_id,))
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
    """, (g.org_id,))
    llm_score_distribution = [{"category": r[0], "count": r[1]} for r in cur.fetchall()]

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
    conn = get_db()
    cur = conn.cursor()
    p = "%s" if is_postgres() else "?"

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
    conn = get_db()
    p = "%s" if is_postgres() else "?"
    if is_postgres():
        cur = conn.cursor(row_factory=psycopg2.extras.RealDictCursor)
    else:
        cur = conn.cursor()

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
        row = dict(r) if is_postgres() else {
            "model": r[0], "requests": r[1], "avg_latency": r[2],
            "total_cost": r[3], "blocked_count": r[4],
            "input_tokens": r[5], "output_tokens": r[6],
        }
        models.append({
            "name": row["model"],
            "requests": row["requests"],
            "avg_latency_ms": round(float(row["avg_latency"] or 0), 1),
            "total_cost_usd": round(float(row["total_cost"] or 0), 6),
            "blocked_count": row["blocked_count"],
            "input_tokens": int(row.get("input_tokens") or 0),
            "output_tokens": int(row.get("output_tokens") or 0),
        })
    conn.close()
    return jsonify(models)


# ═══════════════════════════════════════════════════════════════
# HEATMAP + BREAKDOWN
# ═══════════════════════════════════════════════════════════════
@api_bp.route("/api/heatmap")
def api_heatmap():
    conn = get_db()
    cur = conn.cursor()
    if is_postgres():
        cur.execute("""
            SELECT EXTRACT(DAY FROM created_at)::int as day, EXTRACT(HOUR FROM created_at)::int as hour,
                   COUNT(*) as total, SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked
            FROM spans WHERE org_id = %s AND created_at > NOW() - INTERVAL '5 days'
            GROUP BY day, hour
        """, (g.org_id,))
    else:
        cur.execute("""
            SELECT CAST(strftime('%d', created_at) AS INTEGER) as day,
                   CAST(strftime('%H', created_at) AS INTEGER) as hour,
                   COUNT(*) as total,
                   SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked
            FROM spans WHERE org_id = ? AND created_at > datetime('now', '-5 days')
            GROUP BY day, hour
        """, (g.org_id,))
    cells = [{"day": r[0], "hour": r[1], "total": r[2], "blocked": r[3] or 0} for r in cur.fetchall()]
    conn.close()
    return jsonify(cells)


@api_bp.route("/api/checks/breakdown")
def api_checks_breakdown():
    conn = get_db()
    cur = conn.cursor()
    p = "%s" if is_postgres() else "?"
    cur.execute(f"SELECT security_checks FROM spans WHERE org_id = {p} AND security_checks IS NOT NULL", (g.org_id,))
    rows = cur.fetchall()
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
    conn = get_db()
    cur = conn.cursor()
    try:
        if is_postgres():
            cur.execute("""
                SELECT DATE(created_at) as day, c->>'check_name' as name,
                       COUNT(*) as total,
                       SUM(CASE WHEN (c->>'passed')::boolean THEN 0 ELSE 1 END) as flagged
                FROM spans, jsonb_array_elements(security_checks) c
                WHERE org_id = %s AND created_at > NOW() - INTERVAL '14 days'
                GROUP BY day, name ORDER BY day
            """, (g.org_id,))
        else:
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
    conn.close()
    return jsonify(rows)


@api_bp.route("/api/models/daily")
def api_models_daily():
    conn = get_db()
    cur = conn.cursor()
    p = "%s" if is_postgres() else "?"
    if is_postgres():
        cur.execute(f"""
            SELECT DATE(created_at) as day, model, COUNT(*) as n
            FROM spans WHERE org_id = {p} AND model IS NOT NULL AND model != ''
              AND created_at > NOW() - INTERVAL '14 days'
            GROUP BY day, model ORDER BY day
        """, (g.org_id,))
    else:
        cur.execute(f"""
            SELECT DATE(created_at) as day, model, COUNT(*) as n
            FROM spans WHERE org_id = {p} AND model IS NOT NULL AND model != ''
              AND created_at > datetime('now', '-14 days')
            GROUP BY day, model ORDER BY day
        """, (g.org_id,))
    rows = [{"day": str(r[0]), "model": r[1], "n": r[2]} for r in cur.fetchall()]
    conn.close()
    return jsonify(rows)


# ═══════════════════════════════════════════════════════════════
# COST / LATENCY / TRENDS
# ═══════════════════════════════════════════════════════════════
@api_bp.route("/api/spans/expensive")
def api_expensive_spans():
    conn = get_db()
    cur = conn.cursor()
    try:
        if is_postgres():
            cur.execute("""
                SELECT trace_id, span_id, span_type, model, cost_usd,
                       COALESCE(input_data->>'prompt', input_data->>'tool', '') AS prompt,
                       COALESCE(output_data->>'response', '') AS response,
                       input_tokens, output_tokens
                FROM spans WHERE org_id = %s AND cost_usd > 0
                ORDER BY cost_usd DESC LIMIT 10
            """, (g.org_id,))
        else:
            cur.execute("""
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
    conn.close()
    return jsonify(rows)


@api_bp.route("/api/cost/trend")
def api_cost_trend():
    conn = get_db()
    cur = conn.cursor()
    if is_postgres():
        cur.execute("""
            SELECT DATE(created_at) as day, SUM(cost_usd) as cost,
                   COALESCE(SUM(input_tokens + output_tokens), 0) as tokens
            FROM spans WHERE org_id = %s AND created_at > NOW() - INTERVAL '14 days'
            GROUP BY day ORDER BY day
        """, (g.org_id,))
    else:
        cur.execute("""
            SELECT DATE(created_at) as day, SUM(cost_usd) as cost,
                   COALESCE(SUM(input_tokens + output_tokens), 0) as tokens
            FROM spans WHERE org_id = ? AND created_at > datetime('now', '-14 days')
            GROUP BY day ORDER BY day
        """, (g.org_id,))
    rows = [{"day": str(r[0]), "cost": round(float(r[1] or 0), 6), "tokens": int(r[2] or 0)} for r in cur.fetchall()]
    conn.close()
    return jsonify(rows)


@api_bp.route("/api/latency/distribution")
def api_latency_distribution():
    conn = get_db()
    cur = conn.cursor()
    p = "%s" if is_postgres() else "?"
    cur.execute(f"SELECT latency_ms FROM spans WHERE org_id = {p} AND latency_ms > 0 ORDER BY latency_ms", (g.org_id,))
    values = [r[0] for r in cur.fetchall()]
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
    conn = get_db()
    cur = conn.cursor()
    p = "%s" if is_postgres() else "?"
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
    conn.close()
    return jsonify(events)


@api_bp.route("/api/trend/daily")
def api_trend_daily():
    conn = get_db()
    cur = conn.cursor()
    if is_postgres():
        cur.execute("""
            SELECT DATE(created_at) as day, COUNT(*) as total,
                   SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked
            FROM spans WHERE org_id = %s AND created_at > NOW() - INTERVAL '14 days'
            GROUP BY day ORDER BY day
        """, (g.org_id,))
    else:
        cur.execute("""
            SELECT DATE(created_at) as day, COUNT(*) as total,
                   SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked
            FROM spans WHERE org_id = ? AND created_at > datetime('now', '-14 days')
            GROUP BY day ORDER BY day
        """, (g.org_id,))
    rows = [{"day": str(r[0]), "total": r[1], "blocked": r[2] or 0} for r in cur.fetchall()]
    conn.close()
    return jsonify(rows)


# ═══════════════════════════════════════════════════════════════
# AUDIT TRAIL (legacy, pour dashboard)
# ═══════════════════════════════════════════════════════════════
@api_bp.route("/api/audit/trail")
def api_audit_trail():
    """Audit trail : 50 derniers événements avec prompt."""
    conn = get_db()
    cur = conn.cursor()
    if is_postgres():
        cur.execute("""
            SELECT created_at, trace_id, span_id, span_type, detection_layer, model, blocked,
                   COALESCE(input_data->>'prompt', input_data->>'tool', '') AS prompt
            FROM spans WHERE org_id = %s ORDER BY created_at DESC LIMIT 50
        """, (g.org_id,))
    else:
        cur.execute("""
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
    """Décision de sécurité signée (autorité zero-trust)."""
    data = request.get_json(silent=True) or {}
    tool_name = str(data.get("tool_name", ""))
    params = data.get("params", {}) or {}
    agent_id = str(data.get("agent_id", g.org_id))

    try:
        from policy import PolicyEngine
        engine = PolicyEngine(policies_dir=os.environ.get("CERBERE_POLICIES_DIR", "./policies"))
        pd = engine.evaluate_tool_call(agent_id, tool_name, params)
        action = pd.action.value
        reason = pd.reason
        policy_name = pd.policy_name
        policy_version = pd.policy_version
    except Exception as e:
        # Fail-closed
        action = "DENY"
        reason = f"policy_engine_error: {e}"
        policy_name = "fail_closed"
        policy_version = 0

    try:
        from signing import DecisionSigner
        signing_key = os.environ.get("CERBERE_SIGNING_KEY") or os.environ.get("AGENTGUARD_SIGNING_KEY", "")
        signer = DecisionSigner(signing_key or None)
        signed = signer.sign_decision({
            "request_id": secrets.token_hex(8),
            "action": action,
            "policy_name": policy_name,
            "policy_version": policy_version,
            "reason": reason,
        })
        return jsonify(signed)
    except Exception as e:
        logger.error("signing_failed", error=str(e))
        return jsonify({"error": "signing unavailable"}), 500
