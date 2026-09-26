"""
HTTP API routes for HITL Approvals.
This module is strictly the HTTP layer. It delegates all business logic 
and database operations to the `collector.approval` module.
"""
import structlog
from flask import request, jsonify, g

# Importez le chemin réel de votre fichier approval.py (ajustez si nécessaire)
from collector.approval import (
    list_approvals,
    get_approval,
    approve_approval,
    reject_approval,
    create_approval,
    VALID_STATUSES
)
from collector.api import api_bp
from collector.auth import require_auth, require_human_auth
from collector.api.agents import _reject_if_agent_disconnected, _request_agent_id

logger = structlog.get_logger("agentguard.api.approvals")

@api_bp.route("/api/approvals", methods=["GET"])
def api_list_approvals():
    """Liste les demandes d'approbation avec filtres."""
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401
    
    org_id = getattr(g, "org_id", None)
    status = request.args.get("status", "pending")
    
    try:
        limit = max(1, min(int(request.args.get("limit", 50)), 200))
    except (TypeError, ValueError):
        limit = 50

    if status not in VALID_STATUSES and status not in ("history", "all"):
        return jsonify({"error": f"status must be one of: {', '.join(VALID_STATUSES)}, history, or all"}), 400

    try:
        # On délègue la logique complexe (filtrage, expiration auto) au module métier
        approvals = list_approvals(org_id=org_id, status=status if status in VALID_STATUSES else None, limit=limit)
        
        # Calcul des compteurs pour l'UI
        counts = {"pending": 0, "approved": 0, "rejected": 0, "expired": 0}
        all_for_counts = list_approvals(org_id=org_id, limit=1000) # Optimisable avec une requête COUNT dédiée si besoin
        for a in all_for_counts:
            st = a.get("status")
            if st in counts:
                counts[st] += 1

        return jsonify({
            "approvals": approvals, 
            "count": len(approvals), 
            "counts": counts
        }), 200
    except Exception as e:
        logger.error("approval_list_failed", error=str(e), org_id=org_id)
        return jsonify({"error": f"Database error: {str(e)}"}), 500


@api_bp.route("/api/approvals/<approval_id>", methods=["GET"])
def api_get_approval_status(approval_id):
    """Statut d'une demande spécifique — interrogé par le SDK pour savoir quand exécuter."""
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401
    
    org_id = getattr(g, "org_id", None)
    
    try:
        approval = get_approval(approval_id, org_id=org_id)
        if not approval:
            return jsonify({"error": "Approval not found"}), 404
        
        return jsonify({
            "id": approval["approval_id"],
            "status": approval["status"],
            "resolved_by": approval.get("decided_by"),
            "resolved_at": approval.get("decided_at"),
            "decision_reason": approval.get("decision_reason")
        }), 200
    except Exception as e:
        logger.error("approval_get_failed", error=str(e), approval_id=approval_id)
        return jsonify({"error": f"Database error: {str(e)}"}), 500


@api_bp.route("/api/approvals/<approval_id>/approve", methods=["POST"])
def api_approve_approval(approval_id):
    """Approuve une demande (réservé aux humains via le dashboard)."""
    if not require_human_auth():
        return jsonify({"error": "Human session required"}), 401
    
    org_id = getattr(g, "org_id", None)
    decided_by = getattr(g, "human_email", None) or f"org:{org_id}"
    decision_reason = request.get_json(silent=True) or {}
    reason_text = decision_reason.get("reason", "Approved via dashboard")

    try:
        result = approve_approval(
            approval_id, 
            decided_by=decided_by, 
            decision_reason=reason_text, 
            org_id=org_id
        )
        return jsonify({"status": result["status"], "id": result["approval_id"], "decided_by": decided_by}), 200
    except KeyError:
        return jsonify({"error": "Approval not found"}), 404
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error("approval_approve_failed", error=str(e), approval_id=approval_id)
        return jsonify({"error": f"Database error: {str(e)}"}), 500


@api_bp.route("/api/approvals/<approval_id>/reject", methods=["POST"])
def api_reject_approval(approval_id):
    """Rejette une demande (réservé aux humains via le dashboard)."""
    if not require_human_auth():
        return jsonify({"error": "Human session required"}), 401
    
    org_id = getattr(g, "org_id", None)
    decided_by = getattr(g, "human_email", None) or f"org:{org_id}"
    decision_reason = request.get_json(silent=True) or {}
    reason_text = decision_reason.get("reason", "Rejected via dashboard")

    try:
        result = reject_approval(
            approval_id, 
            decided_by=decided_by, 
            decision_reason=reason_text, 
            org_id=org_id
        )
        return jsonify({"status": result["status"], "id": result["approval_id"], "decided_by": decided_by}), 200
    except KeyError:
        return jsonify({"error": "Approval not found"}), 404
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error("approval_reject_failed", error=str(e), approval_id=approval_id)
        return jsonify({"error": f"Database error: {str(e)}"}), 500


@api_bp.route("/api/approvals", methods=["POST"])
def hitl_sdk_create_approval():
    """Crée une demande d'approbation (appelé par le SDK AgentGuard)."""
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401

    refused = _reject_if_agent_disconnected()
    if refused:
        return refused

    data = request.get_json(silent=True) or {}
    agent_id = data.get("agent_id") or _request_agent_id() or "unknown"
    tool_name = data.get("tool_name")
    arguments = data.get("arguments", data.get("params", {}))
    reason = data.get("reason", "Approval required by policy")
    trace_id = data.get("trace_id")
    span_id = data.get("span_id")
    session_id = data.get("session_id")

    if not tool_name:
        return jsonify({"error": "tool_name is required"}), 400

    org_id = getattr(g, "org_id", None) or "default"
    
    try:
        # Délégation propre au module métier qui gère le TTL, le hachage et l'insertion
        result = create_approval(
            tool_name=tool_name,
            arguments=arguments,
            org_id=org_id,
            agent_id=agent_id,
            session_id=session_id,
            trace_id=trace_id,
            span_id=span_id,
            reason=reason,
            policy_name=data.get("policy_name")
        )
        
        logger.warning("approval_request_created", approval_id=result["approval_id"], tool=tool_name, org_id=org_id)
        
        # Ici, vous pouvez ajouter votre logique d'envoi d'email/webhook d'alerte
        try:
            org_email = getattr(g, "human_email", "admin@entreprise.com")
            logger.info("approval_alert_sent", to=org_email, approval_id=result["approval_id"])
        except Exception as e:
            logger.error("approval_alert_failed", error=str(e))
            
        return jsonify({"status": "success", "id": result["approval_id"]}), 201
        
    except Exception as e:
        logger.error("approval_request_failed", error=str(e), org_id=org_id)
        return jsonify({"error": f"Failed to create approval: {str(e)}"}), 500
