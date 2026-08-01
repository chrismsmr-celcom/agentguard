"""
AgentGuard Collector — Reçoit les spans, stocke en SQLite, sert le dashboard.
Compatible Render.com (utilise la variable d'environnement PORT).
"""

import os
import json
import sqlite3
import time
from datetime import datetime
from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS  # AJOUTER

app = Flask(__name__)
CORS(app)  # AJOUTER — autorise toutes les origines
DB_PATH = "/tmp/agentguard.db"  # /tmp est writable sur Render

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS spans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            trace_id TEXT,
            span_id TEXT,
            span_type TEXT,
            timestamp REAL,
            latency_ms REAL,
            input_data TEXT,
            output_data TEXT,
            security_checks TEXT,
            blocked INTEGER,
            block_reason TEXT,
            cost_usd REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    c.execute("""
        CREATE INDEX IF NOT EXISTS idx_trace ON spans(trace_id)
    """)
    conn.commit()
    conn.close()

@app.route("/span", methods=["POST"])
def receive_span():
    data = request.json
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT INTO spans (trace_id, span_id, span_type, timestamp, latency_ms,
                          input_data, output_data, security_checks, blocked,
                          block_reason, cost_usd)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data["trace_id"],
        data["span_id"],
        data["span_type"],
        data["timestamp"],
        data["latency_ms"],
        json.dumps(data["input_data"]),
        json.dumps(data["output_data"]),
        json.dumps(data["security_checks"]),
        1 if data["blocked"] else 0,
        data.get("block_reason"),
        data["cost_usd"]
    ))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"}), 201

@app.route("/api/traces")
def list_traces():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("""
        SELECT trace_id, COUNT(*) as span_count, 
               SUM(blocked) as blocked_count,
               SUM(cost_usd) as total_cost,
               MAX(created_at) as last_seen
        FROM spans
        GROUP BY trace_id
        ORDER BY last_seen DESC
        LIMIT 100
    """)
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return jsonify(rows)

@app.route("/api/traces/<trace_id>")
def get_trace(trace_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM spans WHERE trace_id = ? ORDER BY timestamp", (trace_id,))
    rows = [dict(r) for r in c.fetchall()]
    for r in rows:
        r["input_data"] = json.loads(r["input_data"])
        r["output_data"] = json.loads(r["output_data"])
        r["security_checks"] = json.loads(r["security_checks"])
        r["blocked"] = bool(r["blocked"])
    conn.close()
    return jsonify(rows)

@app.route("/api/metrics")
def get_metrics():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("SELECT COUNT(*) FROM spans")
    total_spans = c.fetchone()[0]

    c.execute("SELECT COUNT(DISTINCT trace_id) FROM spans")
    total_traces = c.fetchone()[0]

    c.execute("SELECT SUM(blocked) FROM spans")
    blocked = c.fetchone()[0] or 0

    c.execute("SELECT SUM(cost_usd) FROM spans")
    total_cost = c.fetchone()[0] or 0

    c.execute("""
        SELECT json_extract(security_checks, '$') as checks
        FROM spans
    """)
    risk_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for row in c.fetchall():
        checks = json.loads(row[0])
        for check in checks:
            level = check.get("risk_level", "low")
            risk_counts[level] = risk_counts.get(level, 0) + 1

    conn.close()
    return jsonify({
        "total_spans": total_spans,
        "total_traces": total_traces,
        "blocked_operations": blocked,
        "total_cost_usd": round(total_cost, 6),
        "risk_distribution": risk_counts
    })

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>🛡️ AgentGuard Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; 
               background: #0f172a; color: #e2e8f0; padding: 20px; }
        h1 { color: #38bdf8; margin-bottom: 20px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }
        .card { background: #1e293b; padding: 20px; border-radius: 12px; border: 1px solid #334155; }
        .card h3 { color: #94a3b8; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 8px; }
        .card .value { font-size: 2rem; font-weight: 700; }
        .value.critical { color: #ef4444; }
        .value.high { color: #f97316; }
        .value.safe { color: #22c55e; }
        table { width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 12px; overflow: hidden; }
        th, td { padding: 12px 16px; text-align: left; border-bottom: 1px solid #334155; }
        th { background: #0f172a; color: #94a3b8; font-size: 0.8rem; text-transform: uppercase; }
        tr:hover { background: #334155; }
        .badge { padding: 4px 10px; border-radius: 20px; font-size: 0.75rem; font-weight: 600; }
        .badge-blocked { background: #ef444420; color: #ef4444; border: 1px solid #ef4444; }
        .badge-safe { background: #22c55e20; color: #22c55e; border: 1px solid #22c55e; }
        .trace-link { color: #38bdf8; text-decoration: none; }
        .trace-link:hover { text-decoration: underline; }
        .refresh { position: fixed; top: 20px; right: 20px; background: #38bdf8; color: #0f172a; 
                   border: none; padding: 10px 20px; border-radius: 8px; cursor: pointer; font-weight: 600; }
        .refresh:hover { background: #7dd3fc; }
    </style>
</head>
<body>
    <h1>🛡️ AgentGuard Dashboard</h1>
    <button class="refresh" onclick="location.reload()">🔄 Refresh</button>

    <div class="grid" id="metrics">
        <div class="card"><h3>Total Spans</h3><div class="value" id="total-spans">-</div></div>
        <div class="card"><h3>Traces</h3><div class="value" id="total-traces">-</div></div>
        <div class="card"><h3>Blocked</h3><div class="value critical" id="blocked">-</div></div>
        <div class="card"><h3>Cost (USD)</h3><div class="value" id="cost">-</div></div>
        <div class="card"><h3>High Risk</h3><div class="value high" id="high-risk">-</div></div>
        <div class="card"><h3>Critical</h3><div class="value critical" id="critical">-</div></div>
    </div>

    <h2 style="margin-bottom: 15px;">Recent Traces</h2>
    <table>
        <thead>
            <tr><th>Trace ID</th><th>Spans</th><th>Blocked</th><th>Cost</th><th>Last Seen</th><th>Action</th></tr>
        </thead>
        <tbody id="traces-body"></tbody>
    </table>

    <script>
        async function loadMetrics() {
            const r = await fetch('/api/metrics');
            const d = await r.json();
            document.getElementById('total-spans').textContent = d.total_spans;
            document.getElementById('total-traces').textContent = d.total_traces;
            document.getElementById('blocked').textContent = d.blocked_operations;
            document.getElementById('cost').textContent = '$' + d.total_cost_usd.toFixed(4);
            document.getElementById('high-risk').textContent = d.risk_distribution.high;
            document.getElementById('critical').textContent = d.risk_distribution.critical;
        }
        async function loadTraces() {
            const r = await fetch('/api/traces');
            const traces = await r.json();
            const tbody = document.getElementById('traces-body');
            tbody.innerHTML = traces.map(t => `
                <tr>
                    <td><code>${t.trace_id.substring(0,16)}...</code></td>
                    <td>${t.span_count}</td>
                    <td>${t.blocked_count > 0 ? '<span class="badge badge-blocked">BLOCKED</span>' : '<span class="badge badge-safe">SAFE</span>'}</td>
                    <td>$${t.total_cost?.toFixed(4) || '0.0000'}</td>
                    <td>${t.last_seen}</td>
                    <td><a class="trace-link" href="/trace/${t.trace_id}">View →</a></td>
                </tr>
            `).join('');
        }
        loadMetrics();
        loadTraces();
        setInterval(() => { loadMetrics(); loadTraces(); }, 3000);
    </script>
</body>
</html>
"""

@app.route("/")
def dashboard():
    return render_template_string(DASHBOARD_HTML)

@app.route("/trace/<trace_id>")
def trace_detail(trace_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM spans WHERE trace_id = ? ORDER BY timestamp", (trace_id,))
    rows = c.fetchall()
    conn.close()

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Trace Detail</title>
        <style>
            body { font-family: sans-serif; background: #0f172a; color: #e2e8f0; padding: 20px; }
            .span-card { background: #1e293b; padding: 20px; margin-bottom: 15px; border-radius: 12px; border-left: 4px solid #38bdf8; }
            .span-card.blocked { border-left-color: #ef4444; }
            .span-type { color: #38bdf8; font-weight: 700; text-transform: uppercase; font-size: 0.8rem; }
            .check { padding: 8px 12px; margin: 5px 0; border-radius: 6px; font-size: 0.9rem; }
            .check-pass { background: #22c55e20; border: 1px solid #22c55e; }
            .check-fail { background: #ef444420; border: 1px solid #ef4444; }
            pre { background: #0f172a; padding: 12px; border-radius: 8px; overflow-x: auto; font-size: 0.85rem; }
            .back { color: #38bdf8; text-decoration: none; margin-bottom: 20px; display: inline-block; }
        </style>
    </head>
    <body>
        <a class="back" href="/">← Back to Dashboard</a>
        <h1>Trace: """ + trace_id[:16] + """...</h1>
    """
    for row in rows:
        checks = json.loads(row["security_checks"])
        blocked = bool(row["blocked"])
        html += f"""
        <div class="span-card {'blocked' if blocked else ''}">
            <div class="span-type">{row["span_type"]} — {row["latency_ms"]:.0f}ms — ${row["cost_usd"]:.6f}</div>
            <h3 style="margin: 10px 0;">Input</h3>
            <pre>{json.dumps(json.loads(row["input_data"]), indent=2)}</pre>
            <h3 style="margin: 10px 0;">Output</h3>
            <pre>{json.dumps(json.loads(row["output_data"]), indent=2)}</pre>
            <h3 style="margin: 10px 0;">Security Checks</h3>
            {''.join(f'<div class="check check-{"pass" if c["passed"] else "fail"}">{"✅" if c["passed"] else "🚨"} {c["check_name"]} — {c["risk_level"]} — {c["details"]}</div>' for c in checks)}
        </div>
        """
    html += "</body></html>"
    return html

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 8080))
    print(f"🛡️ AgentGuard Collector running on http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
