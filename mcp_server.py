"""
AgentGuard MCP Server
Permet aux agents IA compatibles MCP (Claude, Cursor, etc.) d'interroger 
les politiques de sécurité, de vérifier les prompts et d'autoriser les outils.
"""

import os
import json
import logging
from typing import Optional, Dict, Any

from mcp.server.fastmcp import FastMCP
from agentguard import AgentGuard, RiskLevel, SecurityAction

# Configuration du logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("agentguard.mcp")

# Initialisation du serveur MCP
mcp = FastMCP(
    name="AgentGuard Security",
    instructions="Serveur de sécurité runtime pour agents IA. Utilise ces outils pour vérifier les prompts et les appels d'outils avant exécution."
)

# Initialisation d'AgentGuard (mode standalone pour MCP)
# On désactive l'envoi au collector distant par défaut si non configuré, 
# pour que le MCP puisse tourner localement de manière autonome.
collector_url = os.getenv("AGENTGUARD_MCP_COLLECTOR_URL", "http://localhost:8080")
guard = AgentGuard(
    collector_url=collector_url,
    api_key=os.getenv("AGENTGUARD_API_KEY"),
    agent_id=os.getenv("AGENTGUARD_AGENT_ID", "mcp_client"),
    max_budget=float(os.getenv("AGENTGUARD_MAX_BUDGET", "10.0")),
    block_on_high=True
)

# ==============================================================================
# 🛠️ MCP TOOLS (Pour que l'agent IA vérifie ses actions)
# ==============================================================================

@mcp.tool()
def check_prompt_security(text: str) -> str:
    """
    Vérifie si un texte (prompt ou sortie LLM) contient des injections, 
    des fuites de PII ou des motifs malveillants.
    À appeler AVANT d'envoyer un prompt à un LLM ou d'afficher une réponse.
    
    Args:
        text: Le texte à analyser.
    Returns:
        Un JSON indiquant si le texte est sûr (is_safe: bool) et les détails des risques.
    """
    try:
        injection_check = guard.policy_engine.check_injection(text)
        pii_check = guard.policy_engine.check_pii(text)
        
        is_safe = injection_check.passed and pii_check.passed
        risks = []
        
        if not injection_check.passed:
            risks.append({"type": "injection", "level": injection_check.risk_level.value, "details": injection_check.details})
        if not pii_check.passed:
            risks.append({"type": "pii", "level": pii_check.risk_level.value, "details": pii_check.details})
            
        return json.dumps({
            "is_safe": is_safe,
            "action": "ALLOW" if is_safe else "BLOCK",
            "risks": risks,
            "message": "Text is safe to process." if is_safe else "Text contains security risks. Do not process."
        }, indent=2)
    except Exception as e:
        logger.error(f"Error in check_prompt_security: {e}")
        return json.dumps({"is_safe": False, "error": str(e), "message": "Security check failed. Defaulting to BLOCK."})


@mcp.tool()
def authorize_tool_call(tool_name: str, params_json: str, agent_id: Optional[str] = None) -> str:
    """
    Vérifie si un appel d'outil spécifique est autorisé par les politiques de sécurité 
    et le budget restant.
    À appeler AVANT d'exécuter un outil externe (ex: base de données, API, shell).
    
    Args:
        tool_name: Le nom de l'outil (ex: "execute_command", "send_email").
        params_json: Les paramètres de l'outil sous forme de chaîne JSON.
        agent_id: L'identifiant de l'agent (optionnel, utilise la valeur par défaut sinon).
    Returns:
        Un JSON indiquant si l'outil est autorisé (is_allowed: bool) et la raison.
    """
    try:
        params = json.loads(params_json)
        current_agent = agent_id or guard.agent_id
        budget_remaining = guard.max_budget - guard.total_spent
        
        check = guard.policy_engine.check_tool_policy(tool_name, params, budget_remaining)
        
        return json.dumps({
            "is_allowed": check.passed,
            "action": check.action.value,
            "risk_level": check.risk_level.value,
            "reason": check.details,
            "message": "Tool call authorized." if check.passed else f"Tool call blocked: {check.details}"
        }, indent=2)
    except json.JSONDecodeError:
        return json.dumps({"is_allowed": False, "error": "Invalid JSON in params_json", "message": "BLOCK"})
    except Exception as e:
        logger.error(f"Error in authorize_tool_call: {e}")
        return json.dumps({"is_allowed": False, "error": str(e), "message": "BLOCK"})


@mcp.tool()
def get_security_status(agent_id: Optional[str] = None) -> str:
    """
    Récupère l'état actuel de la sécurité et du budget pour l'agent.
    """
    try:
        report = guard.get_report()
        report["agent_id"] = agent_id or guard.agent_id
        return json.dumps(report, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})

# ==============================================================================
# 📚 MCP RESOURCES (Pour que l'agent IA lise le contexte de sécurité)
# ==============================================================================

@mcp.resource("agentguard://policies/summary")
def get_policies_summary() -> str:
    """
    Fournit un résumé des politiques de sécurité actives (outils autorisés/interdits).
    """
    allowed = list(guard.policy_engine._allowed_tools)
    return json.dumps({
        "policy_type": "tool_whitelist",
        "allowed_tools": allowed if allowed else ["ALL (No specific whitelist defined)"],
        "injection_detection": "ENABLED",
        "pii_detection": "ENABLED"
    }, indent=2)


# ==============================================================================
# 🚀 POINT D'ENTRÉE
# ==============================================================================

if __name__ == "__main__":
    # Le transport stdio est le standard pour les serveurs MCP locaux
    # Il permet à l'hôte (Claude Desktop, Cursor, etc.) de communiquer via stdin/stdout
    logger.info("Starting AgentGuard MCP Server on stdio...")
    mcp.run(transport='stdio')
