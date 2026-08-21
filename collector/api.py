"""API endpoints : spans, traces, metrics, queries."""
import json
import structlog
from flask import Blueprint, request, jsonify, g, current_app
from flask_cors import cross_origin
from collector.db import get_db, dict_from_row, is_postgres, redact_pii, psycopg2
from collector.auth import require_auth

logger = structlog.get_logger("agentguard.api")
api_bp = Blueprint("api", __name__)


@api_bp.route("/span", methods=["POST"])
@cross_origin(origins=["*"], allow_headers=["Content-Type", "X-API-Key"], supports_credentials=True)
def receive_span():
    # ... (garde tout le code existant)
    # ✅ FIX : utilise logger au lieu de logger non défini
    # ✅ Audit log APRÈS commit, pas avant
    
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Body must be a JSON object"}), 400
    
    # ... validation ...
    
    # Commit DB
    conn.commit()
    conn.close()
    
    # ✅ v3.6 : Audit log (après le commit, dans try/except)
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


# ... (tous les autres endpoints : list_traces, get_trace, get_metrics, etc.)
# Copie-colle le code existant en changeant juste @app.route → @api_bp.route
