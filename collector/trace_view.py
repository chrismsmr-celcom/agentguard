"""Trace detail HTML view."""
import json
from flask import Blueprint, g, make_response
from markupsafe import escape as _esc
from collector.db import get_db, dict_from_row, is_postgres, psycopg2

trace_bp = Blueprint("trace", __name__)


@trace_bp.route("/trace/<trace_id>")
def trace_detail(trace_id):
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
    
    html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Trace Detail</title>
    <style>body{{font-family:-apple-system,sans-serif;background:#0b1121;color:#e2e8f0;padding:24px}}
    .back{{color:#38bdf8;text-decoration:none;font-size:.9rem;margin-bottom:20px;display:inline-block}}
    h1{{font-size:1.3rem;margin-bottom:20px}}
    .span-card{{background:#1e293b;border:1px solid #334155;border-radius:14px;padding:20px;margin-bottom:16px;border-left:4px solid #38bdf8}}
    .span-card.blocked{{border-left-color:#ef4444}}
    .span-type{{color:#38bdf8;font-weight:700;text-transform:uppercase;font-size:.75rem;letter-spacing:.05em}}
    .meta{{color:#64748b;font-size:.82rem;margin-top:4px}}
    pre{{background:#0f172a;padding:14px;border-radius:10px;overflow-x:auto;font-size:.82rem;line-height:1.5;border:1px solid #334155}}
    h3{{font-size:.85rem;color:#94a3b8;text-transform:uppercase;margin:16px 0 8px}}
    .check{{padding:10px 14px;margin:6px 0;border-radius:8px;font-size:.88rem}}
    .check-pass{{background:#22c55e15;border:1px solid #22c55e40}}
    .check-fail{{background:#ef444415;border:1px solid #ef444415}}</style></head><body>
    <a class="back" href="/">← Retour au Dashboard</a>
    <h1>Trace <code style="color:#94a3b8">{_esc(trace_id[:20])}…</code></h1>"""
    
    for row in rows:
        checks = row["security_checks"]
        blocked = bool(row["blocked"])
        layer = _esc(row.get("detection_layer") or "unknown")
        html += f"""
        <div class="span-card {'blocked' if blocked else ''}">
            <div class="span-type">{_esc(row['span_type'])} — {float(row['latency_ms']):.0f}ms — ${float(row['cost_usd']):.6f} · {layer.upper()}</div>
            <div class="meta">{_esc(str(row['created_at']))}</div>
            <h3>📥 Input</h3><pre>{_esc(json.dumps(row['input_data'], indent=2, ensure_ascii=False))}</pre>
            <h3>📤 Output</h3><pre>{_esc(json.dumps(row['output_data'], indent=2, ensure_ascii=False))}</pre>
            <h3>🛡️ Security Checks ({len(checks)})</h3>
            {''.join(f'<div class="check check-{"pass" if c["passed"] else "fail"}">{"✅" if c["passed"] else "🚨"} <strong>{_esc(c["check_name"])}</strong> — {_esc(c["risk_level"])}<br><span style="color:#94a3b8;font-size:.8rem">{_esc(c["details"])}</span></div>' for c in checks)}
        </div>"""
    html += "</body></html>"
    return make_response(html)
