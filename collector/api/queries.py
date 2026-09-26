import json
import sqlite3
import structlog
from flask import request, jsonify, g
from collector.db import get_db, is_postgres, dict_from_row, sql_placeholder, _get_db_path
from collector.api import api_bp
from collector.api.utils import _as_json, _iso_utc

logger = structlog.get_logger("agentguard.api.queries")

_EVENT_JSON_FIELDS = ["arguments", "arguments_sanitized", "result", "policy_chain", "risk_contributors"]

def _serialize_event(r, full=True):
    for f in _EVENT_JSON_FIELDS:
        r[f] = _as_json(r.get(f), {} if f != "risk_contributors" else [])
    if not full:
        for f in ("arguments", "arguments_sanitized", "result", "policy_chain"):
            r.pop(f, None)
    return r

@api_bp.route("/api/traces")
def list_traces():
    p = sql_placeholder()
    if is_postgres():
        conn = get_db()
        cur = conn.cursor()
        cur.execute(f"""
            SELECT trace_id, COUNT(*) as span_count, SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked_count,
                   SUM(cost_usd) as total_cost, MAX(created_at) as last_seen, STRING_AGG(DISTINCT detection_layer, ',') as detection_layers
            FROM spans WHERE org_id = {p} GROUP BY trace_id ORDER BY last_seen DESC LIMIT 100
        """, (g.org_id,))
        rows = [dict_from_row(r, cur) for r in cur.fetchall()]
        conn.close()
    else:
        conn = sqlite3.connect(_get_db_path(), timeout=5.0)
        cur = conn.cursor()
        try:
            cur.execute(f"""
                SELECT trace_id, COUNT(*) as span_count, SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked_count,
                       SUM(cost_usd) as total_cost, MAX(created_at) as last_seen, GROUP_CONCAT(DISTINCT detection_layer) as detection_layers
                FROM spans WHERE org_id = ? GROUP BY trace_id ORDER BY last_seen DESC LIMIT 100
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
        conn = sqlite3.connect(_get_db_path(), timeout=5.0)
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

@api_bp.route("/api/trajectory/<session_id>")
def get_trajectory(session_id):
    p = sql_placeholder()
    cols = """id, trace_id, session_id, agent_id, "timestamp", sequence_no,
              actor, type, tool_name, decision, reason, risk_score, risk_contributors,
              taint_level, prev_event_id, next_event_id"""
    if is_postgres():
        conn = get_db()
        cur = conn.cursor()
        cur.execute(f"SELECT {cols} FROM events WHERE session_id = {p} AND org_id = {p} ORDER BY sequence_no", (session_id, g.org_id))
        rows = [dict_from_row(r, cur) for r in cur.fetchall()]
        conn.close()
    else:
        conn = sqlite3.connect(_get_db_path(), timeout=5.0)
        cur = conn.cursor()
        try:
            cur.execute(f"SELECT {cols} FROM events WHERE session_id = ? AND org_id = ? ORDER BY sequence_no", (session_id, g.org_id))
            rows = [dict_from_row(r, cur) for r in cur.fetchall()]
        finally:
            conn.close()

    if not rows:
        return jsonify({"error": "Session not found or empty"}), 404
    rows = [_serialize_event(r, full=False) for r in rows]

    sess_cur_sql = f"SELECT status, risk_level, current_task, model, environment, agent_id FROM agent_sessions WHERE id = {p} AND org_id = {p}"
    if is_postgres():
        conn = get_db()
        cur = conn.cursor()
        cur.execute(sess_cur_sql, (session_id, g.org_id))
        session_row = dict_from_row(cur.fetchone(), cur)
        conn.close()
    else:
        conn = sqlite3.connect(_get_db_path(), timeout=5.0)
        cur = conn.cursor()
        try:
            cur.execute(sess_cur_sql.replace(p, "?"), (session_id, g.org_id))
            session_row = dict_from_row(cur.fetchone(), cur)
        finally:
            conn.close()
    return jsonify({"session_id": session_id, "session": session_row, "events": rows})

@api_bp.route("/api/events/<event_id>")
def get_event(event_id):
    p = sql_placeholder()
    if is_postgres():
        conn = get_db()
        cur = conn.cursor()
        cur.execute(f"SELECT * FROM events WHERE id = {p} AND org_id = {p}", (event_id, g.org_id))
        row = dict_from_row(cur.fetchone(), cur)
        conn.close()
    else:
        conn = sqlite3.connect(_get_db_path(), timeout=5.0)
        cur = conn.cursor()
        try:
            cur.execute("SELECT * FROM events WHERE id = ? AND org_id = ?", (event_id, g.org_id))
            row = dict_from_row(cur.fetchone(), cur)
        finally:
            conn.close()
    if not row:
        return jsonify({"error": "Event not found"}), 404
    return jsonify(_serialize_event(row, full=True))

@api_bp.route("/api/metrics")
def get_metrics():
    empty_metrics = {"total_spans": 0, "total_traces": 0, "blocked_operations": 0, "total_cost_usd": 0.0, "total_tokens": 0, "avg_latency_ms": 0.0, "avg_ml_score": 0.0, "avg_llm_score": 0.0, "llm_judge_count": 0, "risk_distribution": {"low": 0, "medium": 0, "high": 0, "critical": 0}, "top_threats": [], "detection_layers": {}, "version": "v6.0.0"}
    org_id = getattr(g, "org_id", None)
    if not org_id:
        empty_metrics["error"] = "no_org_id"
        return jsonify(empty_metrics), 200

    p = sql_placeholder()
    try:
        if is_postgres():
            conn = get_db()
        else:
            conn = sqlite3.connect(_get_db_path(), timeout=5.0)

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

            detection_stats = {}
            try:
                if is_postgres():
                    cur.execute("SELECT detection_layer, COUNT(*) as count FROM spans WHERE detection_layer IS NOT NULL AND org_id = %s GROUP BY detection_layer", (org_id,))
                else:
                    cur.execute("SELECT detection_layer, COUNT(*) as count FROM spans WHERE detection_layer IS NOT NULL AND org_id = ? GROUP BY detection_layer", (org_id,))
                detection_stats = {row[0]: row[1] for row in cur.fetchall()}
            except Exception as e:
                logger.warning("metrics_detection_query_failed", error=str(e))

            avg_ml_score, avg_llm_score, llm_count = 0, 0, 0
            try:
                cur.execute(f"SELECT AVG(ml_score) FROM spans WHERE ml_score IS NOT NULL AND org_id = {p}", (org_id,))
                avg_ml_score = cur.fetchone()[0] or 0
                cur.execute(f"SELECT AVG(llm_score) FROM spans WHERE llm_score IS NOT NULL AND org_id = {p}", (org_id,))
                avg_llm_score = cur.fetchone()[0] or 0
                cur.execute(f"SELECT COUNT(*) FROM spans WHERE detection_layer = 'llm_judge' AND org_id = {p}", (org_id,))
                llm_count = cur.fetchone()[0] or 0
            except Exception as e:
                logger.warning("metrics_scores_query_failed", error=str(e))

            risk_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
            try:
                if is_postgres():
                    cur.execute("SELECT jsonb_array_elements(security_checks) as check FROM spans WHERE created_at > NOW() - INTERVAL '1 day' AND org_id = %s", (org_id,))
                    for row in cur.fetchall():
                        check = row[0] if isinstance(row[0], dict) else {}
                        level = check.get("risk_level", "low")
                        if level in risk_counts: risk_counts[level] += 1
                else:
                    cur.execute("SELECT security_checks FROM spans WHERE created_at > datetime('now', '-1 day') AND org_id = ?", (org_id,))
                    for row in cur.fetchall():
                        try:
                            for check in json.loads(row[0] or "[]"):
                                level = check.get("risk_level", "low")
                                if level in risk_counts: risk_counts[level] += 1
                        except Exception: pass
            except Exception as e:
                logger.warning("metrics_risk_query_failed", error=str(e))

            top_threats = []
            try:
                cur.execute(f"SELECT block_reason, COUNT(*) as count FROM spans WHERE blocked = {('TRUE' if is_postgres() else '1')} AND org_id = {p} GROUP BY block_reason ORDER BY count DESC LIMIT 5", (org_id,))
                top_threats = [{"reason": r[0], "count": r[1]} for r in cur.fetchall()]
            except Exception as e:
                logger.warning("metrics_threats_query_failed", error=str(e))
        finally:
            conn.close()

        return jsonify({
            "total_spans": total_spans, "total_traces": total_traces, "blocked_operations": blocked,
            "total_cost_usd": round(float(total_cost or 0), 6), "total_tokens": int(total_tokens),
            "avg_latency_ms": round(float(avg_latency or 0), 2), "avg_ml_score": round(float(avg_ml_score or 0), 3),
            "avg_llm_score": round(float(avg_llm_score or 0), 3), "llm_judge_count": llm_count,
            "risk_distribution": risk_counts, "top_threats": top_threats, "detection_layers": detection_stats, "version": "v6.0.0",
        })
    except Exception as e:
        logger.error("metrics_endpoint_failed", error=str(e), org_id=org_id)
        empty_metrics["error"] = str(e)[:200]
        return jsonify(empty_metrics), 200

@api_bp.route("/api/detection/stats")
def get_detection_stats():
    org_id = getattr(g, "org_id", None)
    if not org_id: return jsonify({"error": "no_org_id"}), 401
    p = sql_placeholder()
    conn = get_db() if is_postgres() else sqlite3.connect(_get_db_path(), timeout=5.0)
    cur = conn.cursor()
    try:
        cur.execute(f"SELECT detection_layer, COUNT(*) as count FROM spans WHERE detection_layer IS NOT NULL AND org_id = {p} GROUP BY detection_layer ORDER BY count DESC", (org_id,))
        layer_distribution = [{"layer": r[0], "count": r[1]} for r in cur.fetchall()]
        cur.execute(f"SELECT detection_layer, COUNT(*) as total, SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked FROM spans WHERE detection_layer IS NOT NULL AND org_id = {p} GROUP BY detection_layer", (org_id,))
        layer_accuracy = [{"layer": r[0], "total": r[1], "blocked": r[2], "block_rate": round((r[2] / r[1] * 100) if r[1] > 0 else 0, 2)} for r in cur.fetchall()]
        cur.execute(f"SELECT CASE WHEN ml_score >= 0.9 THEN '0.9-1.0' WHEN ml_score >= 0.8 THEN '0.8-0.9' WHEN ml_score >= 0.7 THEN '0.7-0.8' WHEN ml_score >= 0.6 THEN '0.6-0.7' WHEN ml_score >= 0.5 THEN '0.5-0.6' ELSE '0.0-0.5' END as score_range, COUNT(*) as count FROM spans WHERE ml_score IS NOT NULL AND org_id = {p} GROUP BY score_range ORDER BY score_range DESC", (org_id,))
        ml_score_distribution = [{"range": r[0], "count": r[1]} for r in cur.fetchall()]
        cur.execute(f"SELECT CASE WHEN llm_score >= 0.9 THEN 'high_risk' WHEN llm_score >= 0.7 THEN 'medium_risk' ELSE 'low_risk' END as risk_category, COUNT(*) as count FROM spans WHERE llm_score IS NOT NULL AND org_id = {p} GROUP BY risk_category", (org_id,))
        llm_score_distribution = [{"category": r[0], "count": r[1]} for r in cur.fetchall()]
    finally:
        conn.close()
    return jsonify({"layer_distribution": layer_distribution, "layer_accuracy": layer_accuracy, "ml_score_distribution": ml_score_distribution, "llm_score_distribution": llm_score_distribution, "total_analyzed": sum(l["count"] for l in layer_distribution) if layer_distribution else 0})

@api_bp.route("/api/llm/stats")
def get_llm_stats():
    p = sql_placeholder()
    conn = get_db() if is_postgres() else sqlite3.connect(_get_db_path(), timeout=5.0)
    cur = conn.cursor()
    try:
        cur.execute(f"SELECT COUNT(*) FROM spans WHERE detection_layer = 'llm_judge' AND org_id = {p}", (g.org_id,))
        total_llm = cur.fetchone()[0] or 0
        cur.execute(f"SELECT COUNT(*), SUM(CASE WHEN blocked THEN 1 ELSE 0 END) FROM spans WHERE detection_layer = 'llm_judge' AND org_id = {p}", (g.org_id,))
        total, blocked = cur.fetchone()
        total, blocked = total or 0, blocked or 0
        block_rate = round((blocked / total * 100), 2) if total else 0
        cur.execute(f"SELECT llm_reason, COUNT(*) as count FROM spans WHERE llm_reason IS NOT NULL AND detection_layer = 'llm_judge' AND org_id = {p} GROUP BY llm_reason ORDER BY count DESC LIMIT 5", (g.org_id,))
        top_reasons = [{"reason": r[0], "count": r[1]} for r in cur.fetchall()]
    finally:
        conn.close()
    return jsonify({"total_analyzed": total_llm, "block_rate": block_rate, "top_reasons": top_reasons, "status": "operational" if total_llm > 0 else "idle"})

@api_bp.route("/api/models")
def api_models():
    p = sql_placeholder()
    conn = get_db() if is_postgres() else sqlite3.connect(_get_db_path(), timeout=5.0)
    cur = conn.cursor()
    try:
        cur.execute(f"""
            SELECT model, COUNT(*) as requests, AVG(latency_ms) as avg_latency, SUM(cost_usd) as total_cost,
                   SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked_count, COALESCE(SUM(input_tokens), 0) as input_tokens, COALESCE(SUM(output_tokens), 0) as output_tokens
            FROM spans WHERE org_id = {p} AND model IS NOT NULL AND model != '' GROUP BY model ORDER BY requests DESC
        """, (g.org_id,))
        models = []
        for r in cur.fetchall():
            row = dict_from_row(r, cur) if is_postgres() else {"model": r[0], "requests": r[1], "avg_latency": r[2], "total_cost": r[3], "blocked_count": r[4], "input_tokens": r[5], "output_tokens": r[6]}
            models.append({"name": row.get("model"), "requests": row.get("requests"), "avg_latency_ms": round(float(row.get("avg_latency") or 0), 1), "total_cost_usd": round(float(row.get("total_cost") or 0), 6), "blocked_count": row.get("blocked_count"), "input_tokens": int(row.get("input_tokens") or 0), "output_tokens": int(row.get("output_tokens") or 0)})
    finally:
        conn.close()
    return jsonify(models)

@api_bp.route("/api/heatmap")
def api_heatmap():
    if is_postgres():
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT EXTRACT(DAY FROM created_at)::int as day, EXTRACT(HOUR FROM created_at)::int as hour, COUNT(*) as total, SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked FROM spans WHERE org_id = %s AND created_at > NOW() - INTERVAL '5 days' GROUP BY day, hour", (g.org_id,))
        cells = [{"day": r[0], "hour": r[1], "total": r[2], "blocked": r[3] or 0} for r in cur.fetchall()]
        conn.close()
    else:
        conn = sqlite3.connect(_get_db_path(), timeout=5.0)
        cur = conn.cursor()
        try:
            cur.execute("SELECT CAST(strftime('%d', created_at) AS INTEGER) as day, CAST(strftime('%H', created_at) AS INTEGER) as hour, COUNT(*) as total, SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked FROM spans WHERE org_id = ? AND created_at > datetime('now', '-5 days') GROUP BY day, hour", (g.org_id,))
            cells = [{"day": r[0], "hour": r[1], "total": r[2], "blocked": r[3] or 0} for r in cur.fetchall()]
        finally:
            conn.close()
    return jsonify(cells)

@api_bp.route("/api/checks/breakdown")
def api_checks_breakdown():
    p = sql_placeholder()
    conn = get_db() if is_postgres() else sqlite3.connect(_get_db_path(), timeout=5.0)
    cur = conn.cursor()
    try:
        cur.execute(f"SELECT security_checks FROM spans WHERE org_id = {p} AND security_checks IS NOT NULL", (g.org_id,))
        rows = cur.fetchall()
    finally:
        conn.close()
    breakdown = {}
    for row in rows:
        try:
            checks = row[0] if isinstance(row[0], list) else json.loads(row[0])
        except Exception: continue
        for c in (checks or []):
            name = c.get("check_name", "unknown")
            entry = breakdown.setdefault(name, {"total": 0, "flagged": 0})
            entry["total"] += 1
            if not c.get("passed", True): entry["flagged"] += 1
    result = [{"check_name": name, "total": v["total"], "flagged": v["flagged"], "flag_rate": round(v["flagged"] / v["total"] * 100, 1) if v["total"] else 0} for name, v in breakdown.items()]
    return jsonify(sorted(result, key=lambda x: -x["total"]))

@api_bp.route("/api/checks/daily")
def api_checks_daily():
    if is_postgres():
        conn = get_db()
        cur = conn.cursor()
        try:
            cur.execute("SELECT DATE(created_at) as day, c->>'check_name' as name, COUNT(*) as total, SUM(CASE WHEN (c->>'passed')::boolean THEN 0 ELSE 1 END) as flagged FROM spans, jsonb_array_elements(security_checks) c WHERE org_id = %s AND created_at > NOW() - INTERVAL '14 days' GROUP BY day, name ORDER BY day", (g.org_id,))
            rows = [{"day": str(r[0]), "name": r[1], "total": r[2], "flagged": r[3] or 0} for r in cur.fetchall()]
        except Exception: rows = []
        conn.close()
    else:
        conn = sqlite3.connect(_get_db_path(), timeout=5.0)
        cur = conn.cursor()
        try:
            cur.execute("SELECT DATE(created_at) as day, json_extract(c.value, '$.check_name') as name, COUNT(*) as total, SUM(CASE WHEN json_extract(c.value, '$.passed') = 1 THEN 0 ELSE 1 END) as flagged FROM spans, json_each(spans.security_checks) c WHERE org_id = ? AND created_at > datetime('now','-14 days') GROUP BY day, name ORDER BY day", (g.org_id,))
            rows = [{"day": str(r[0]), "name": r[1], "total": r[2], "flagged": r[3] or 0} for r in cur.fetchall()]
        except Exception: rows = []
        finally: conn.close()
    return jsonify(rows)

@api_bp.route("/api/models/daily")
def api_models_daily():
    p = sql_placeholder()
    if is_postgres():
        conn = get_db()
        cur = conn.cursor()
        cur.execute(f"SELECT DATE(created_at) as day, model, COUNT(*) as n FROM spans WHERE org_id = {p} AND model IS NOT NULL AND model != '' AND created_at > NOW() - INTERVAL '14 days' GROUP BY day, model ORDER BY day", (g.org_id,))
        rows = [{"day": str(r[0]), "model": r[1], "n": r[2]} for r in cur.fetchall()]
        conn.close()
    else:
        conn = sqlite3.connect(_get_db_path(), timeout=5.0)
        cur = conn.cursor()
        try:
            cur.execute(f"SELECT DATE(created_at) as day, model, COUNT(*) as n FROM spans WHERE org_id = ? AND model IS NOT NULL AND model != '' AND created_at > datetime('now', '-14 days') GROUP BY day, model ORDER BY day", (g.org_id,))
            rows = [{"day": str(r[0]), "model": r[1], "n": r[2]} for r in cur.fetchall()]
        finally: conn.close()
    return jsonify(rows)

@api_bp.route("/api/spans/expensive")
def api_expensive_spans():
    p = sql_placeholder()
    if is_postgres():
        conn = get_db()
        cur = conn.cursor()
        try:
            cur.execute(f"SELECT trace_id, span_id, span_type, model, cost_usd, COALESCE(input_data->>'prompt', input_data->>'tool', '') AS prompt, COALESCE(output_data->>'response', '') AS response, input_tokens, output_tokens FROM spans WHERE org_id = {p} AND cost_usd > 0 ORDER BY cost_usd DESC LIMIT 10", (g.org_id,))
            rows = [{"trace_id": r[0], "span_id": r[1], "span_type": r[2], "model": r[3], "cost_usd": r[4], "prompt": (r[5] or "")[:300], "response": (r[6] or "")[:300], "input_tokens": r[7] or 0, "output_tokens": r[8] or 0} for r in cur.fetchall()]
        except Exception: rows = []
        conn.close()
    else:
        conn = sqlite3.connect(_get_db_path(), timeout=5.0)
        cur = conn.cursor()
        try:
            cur.execute(f"SELECT trace_id, span_id, span_type, model, cost_usd, COALESCE(json_extract(input_data, '$.prompt'), json_extract(input_data, '$.tool'), '') AS prompt, COALESCE(json_extract(output_data, '$.response'), '') AS response, input_tokens, output_tokens FROM spans WHERE org_id = ? AND cost_usd > 0 ORDER BY cost_usd DESC LIMIT 10", (g.org_id,))
            rows = [{"trace_id": r[0], "span_id": r[1], "span_type": r[2], "model": r[3], "cost_usd": r[4], "prompt": (r[5] or "")[:300], "response": (r[6] or "")[:300], "input_tokens": r[7] or 0, "output_tokens": r[8] or 0} for r in cur.fetchall()]
        except Exception: rows = []
        finally: conn.close()
    return jsonify(rows)

@api_bp.route("/api/cost/trend")
def api_cost_trend():
    p = sql_placeholder()
    if is_postgres():
        conn = get_db()
        cur = conn.cursor()
        cur.execute(f"SELECT DATE(created_at) as day, SUM(cost_usd) as cost, COALESCE(SUM(input_tokens + output_tokens), 0) as tokens FROM spans WHERE org_id = {p} AND created_at > NOW() - INTERVAL '14 days' GROUP BY day ORDER BY day", (g.org_id,))
        rows = [{"day": str(r[0]), "cost": round(float(r[1] or 0), 6), "tokens": int(r[2] or 0)} for r in cur.fetchall()]
        conn.close()
    else:
        conn = sqlite3.connect(_get_db_path(), timeout=5.0)
        cur = conn.cursor()
        try:
            cur.execute(f"SELECT DATE(created_at) as day, SUM(cost_usd) as cost, COALESCE(SUM(input_tokens + output_tokens), 0) as tokens FROM spans WHERE org_id = ? AND created_at > datetime('now', '-14 days') GROUP BY day ORDER BY day", (g.org_id,))
            rows = [{"day": str(r[0]), "cost": round(float(r[1] or 0), 6), "tokens": int(r[2] or 0)} for r in cur.fetchall()]
        finally: conn.close()
    return jsonify(rows)

@api_bp.route("/api/latency/distribution")
def api_latency_distribution():
    p = sql_placeholder()
    conn = get_db() if is_postgres() else sqlite3.connect(_get_db_path(), timeout=5.0)
    cur = conn.cursor()
    try:
        cur.execute(f"SELECT latency_ms FROM spans WHERE org_id = {p} AND latency_ms > 0 ORDER BY latency_ms", (g.org_id,))
        values = [r[0] for r in cur.fetchall()]
    finally: conn.close()
    def pct(vals, q):
        if not vals: return 0
        idx = min(len(vals) - 1, int(len(vals) * q))
        return round(vals[idx], 1)
    return jsonify({"count": len(values), "p50": pct(values, 0.50), "p90": pct(values, 0.90), "p95": pct(values, 0.95), "p99": pct(values, 0.99), "min": round(min(values), 1) if values else 0, "max": round(max(values), 1) if values else 0})

@api_bp.route("/api/events/recent")
def api_recent_events():
    p = sql_placeholder()
    conn = get_db() if is_postgres() else sqlite3.connect(_get_db_path(), timeout=5.0)
    cur = conn.cursor()
    try:
        cur.execute(f"SELECT span_type, detection_layer, blocked, block_reason, created_at, security_checks FROM spans WHERE org_id = {p} ORDER BY created_at DESC LIMIT 8", (g.org_id,))
        events = []
        for r in cur.fetchall():
            try: checks = r[5] if isinstance(r[5], list) else json.loads(r[5] or "[]")
            except Exception: checks = []
            risk = "low"
            for c in checks:
                if c.get("risk_level") in ("high", "critical"):
                    risk = c.get("risk_level")
                    break
            events.append({"span_type": r[0], "layer": r[1] or "regex", "blocked": bool(r[2]), "reason": r[3], "created_at": str(r[4]), "risk": risk})
    finally: conn.close()
    return jsonify(events)

@api_bp.route("/api/trend/daily")
def api_trend_daily():
    p = sql_placeholder()
    if is_postgres():
        conn = get_db()
        cur = conn.cursor()
        cur.execute(f"SELECT DATE(created_at) as day, COUNT(*) as total, SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked FROM spans WHERE org_id = {p} AND created_at > NOW() - INTERVAL '14 days' GROUP BY day ORDER BY day", (g.org_id,))
        rows = [{"day": str(r[0]), "total": r[1], "blocked": r[2] or 0} for r in cur.fetchall()]
        conn.close()
    else:
        conn = sqlite3.connect(_get_db_path(), timeout=5.0)
        cur = conn.cursor()
        try:
            cur.execute(f"SELECT DATE(created_at) as day, COUNT(*) as total, SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked FROM spans WHERE org_id = ? AND created_at > datetime('now', '-14 days') GROUP BY day ORDER BY day", (g.org_id,))
            rows = [{"day": str(r[0]), "total": r[1], "blocked": r[2] or 0} for r in cur.fetchall()]
        finally: conn.close()
    return jsonify(rows)

@api_bp.route("/api/audit/trail")
def api_audit_trail():
    p = sql_placeholder()
    if is_postgres():
        conn = get_db()
        cur = conn.cursor()
        cur.execute(f"SELECT created_at, trace_id, span_id, span_type, detection_layer, model, blocked, COALESCE(input_data->>'prompt', input_data->>'tool', '') AS prompt FROM spans WHERE org_id = {p} ORDER BY created_at DESC LIMIT 50", (g.org_id,))
        rows = [{"timestamp": str(r[0]), "trace_id": r[1], "span_id": r[2], "span_type": r[3], "layer": r[4] or "regex", "model": r[5] or "—", "blocked": bool(r[6]), "prompt": (r[7] or "")[:120]} for r in cur.fetchall()]
        conn.close()
    else:
        conn = sqlite3.connect(_get_db_path(), timeout=5.0)
        cur = conn.cursor()
        try:
            cur.execute(f"SELECT created_at, trace_id, span_id, span_type, detection_layer, model, blocked, COALESCE(json_extract(input_data, '$.prompt'), json_extract(input_data, '$.tool'), '') AS prompt FROM spans WHERE org_id = ? ORDER BY created_at DESC LIMIT 50", (g.org_id,))
            rows = [{"timestamp": str(r[0]), "trace_id": r[1], "span_id": r[2], "span_type": r[3], "layer": r[4] or "regex", "model": r[5] or "—", "blocked": bool(r[6]), "prompt": (r[7] or "")[:120]} for r in cur.fetchall()]
        finally: conn.close()
    return jsonify(rows)
