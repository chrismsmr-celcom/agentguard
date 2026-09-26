import secrets
import structlog
from flask import request, jsonify, g, current_app
from collector.api import api_bp
from collector.auth import require_auth
from collector.api.agents import _reject_if_agent_disconnected
from decision_engine import DecisionEngine, DecisionRequest

logger = structlog.get_logger("agentguard.api.decisions")
decision_engine = DecisionEngine()

def get_decision_signer():
    signer = current_app.extensions.get("agentguard_decision_signer")
    if signer is not None: return signer
    from signing import DecisionSigner
    signing_key = os.environ.get("CERBERE_SIGNING_KEY") or os.environ.get("AGENTGUARD_SIGNING_KEY")
    if not signing_key: raise RuntimeError("CERBERE_SIGNING_KEY or AGENTGUARD_SIGNING_KEY is required")
    signer = DecisionSigner(signing_key)
    current_app.extensions["agentguard_decision_signer"] = signer
    return signer

def is_server_registered_tool(tool_name):
    tool_name = str(tool_name or "").strip()
    if not tool_name: return False
    for policy in decision_engine.policies.values():
        if tool_name in getattr(policy, "blocked_tools", set()): continue
        allowed_tools = getattr(policy, "allowed_tools", None)
        if allowed_tools is not None and tool_name in allowed_tools: return True
    return False

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
    if not require_auth(): return jsonify({"error": "Unauthorized"}), 401
    refused = _reject_if_agent_disconnected()
    if refused: return refused

    data = request.get_json(silent=True)
    if not isinstance(data, dict): return jsonify({"error": "Body must be a JSON object"}), 400

    tool_name = str(data.get("tool_name", "")).strip()
    if not tool_name: return jsonify({"error": "tool_name is required"}), 400

    params = data.get("params")
    if params is None: params = {}
    if not isinstance(params, dict): return jsonify({"error": "params must be an object"}), 400

    authenticated_agent_id = getattr(g, "agent_id", None) or getattr(g, "api_key_id", None) or f"org:{g.org_id}"
    requested_policy = data.get("policy")
    metadata = {"org_id": g.org_id, "source": "api_decide"}
    if requested_policy: metadata["policy"] = str(requested_policy)

    decision_request = DecisionRequest(
        agent_id=str(authenticated_agent_id), tool_name=tool_name, tool_category=str(data.get("tool_category", "read")),
        identity_trusted=True, model_score=float(data.get("model_score", 0.0) or 0.0), anomaly_score=float(data.get("anomaly_score", 0.0) or 0.0),
        taint_level=str(data.get("taint_level", "PUBLIC")).upper(), trajectory_length=int(data.get("trajectory_length", 0) or 0),
        previous_risky_actions=int(data.get("previous_risky_actions", 0) or 0), external_side_effect=bool(data.get("external_side_effect", False)),
        irreversible=bool(data.get("irreversible", False)), tool_registered=is_server_registered_tool(tool_name), metadata=metadata,
    )

    try: result = decision_engine.evaluate(decision_request)
    except Exception as exc:
        logger.exception("decision_engine_failed", error=str(exc), org_id=g.org_id, tool_name=tool_name)
        result = None
        try:
            signer = get_decision_signer()
            signed = signer.sign_decision({"request_id": secrets.token_hex(16), "action": "DENY", "policy_name": "fail_closed", "policy_version": 0, "reason": "Decision engine failure"})
            return jsonify(signed), 503
        except Exception: return jsonify({"error": "security decision unavailable"}), 503

    try:
        signer = get_decision_signer()
        signed = signer.sign_decision({"request_id": secrets.token_hex(16), "action": result.decision.value.upper(), "policy_name": result.policy, "policy_version": 1, "reason": "; ".join(result.reasons[:5])})
        signed["risk_score"] = result.risk_score
        signed["risk_level"] = result.risk_level
        signed["reason_codes"] = result.reason_codes
        signed["enforcement"] = result.enforcement
        return jsonify(signed), 200
    except Exception as exc:
        logger.exception("decision_signing_failed", error=str(exc))
        return jsonify({"error": "security signing unavailable"}), 503
