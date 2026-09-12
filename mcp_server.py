"""
CerbereAG MCP Server (Compatible MCP v1.x)
Serveur de sécurité runtime pour agents IA, permettant la vérification, 
l'anonymisation et l'estimation des coûts en temps réel.
"""

import os
import json
import logging
import re
import requests
import tiktoken
from typing import Optional

from mcp.server.fastmcp import FastMCP
from agentguard import AgentGuard

# Configuration du logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("cerbereag.mcp")

# Initialisation du serveur MCP
mcp = FastMCP(
    name="CerbereAG Security",
    instructions="Serveur de sécurité runtime pour agents IA. Utilise ces outils pour vérifier, anonymiser et estimer le coût des actions avant exécution."
)

# Initialisation d'AgentGuard
collector_url = os.getenv("AGENTGUARD_MCP_COLLECTOR_URL", "http://localhost:8080")
guard = AgentGuard(
    collector_url=collector_url,
    api_key=os.getenv("AGENTGUARD_API_KEY"),
    agent_id=os.getenv("AGENTGUARD_AGENT_ID", "cerbereag_mcp_client"),
    max_budget=float(os.getenv("AGENTGUARD_MAX_BUDGET", "10.0")),
    block_on_high=True
)

# ==============================================================================
# 🛠️ MCP TOOLS
# ==============================================================================

@mcp.tool()
def check_prompt_security(text: str) -> str:
    """Vérifie si un texte contient des injections, des fuites de PII ou des motifs malveillants."""
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
            "message": "Text is safe to process." if is_safe else "Text contains security risks."
        }, indent=2)
    except Exception as e:
        return json.dumps({"is_safe": False, "error": str(e), "message": "Security check failed."})


@mcp.tool()
def authorize_tool_call(tool_name: str, params_json: str, agent_id: Optional[str] = None) -> str:
    """Vérifie si un appel d'outil spécifique est autorisé par les politiques de sécurité et le budget."""
    try:
        params = json.loads(params_json)
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
        return json.dumps({"is_allowed": False, "error": str(e), "message": "BLOCK"})


@mcp.tool()
def redact_pii(text: str) -> str:
    """
    Anonymise les données sensibles (PII) dans un texte en les remplaçant par [REDACTED_TYPE].
    Utile pour nettoyer un contexte avant de l'envoyer à un LLM externe.
    """
    try:
        patterns = {
            "EMAIL": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "PHONE": r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
            "CREDIT_CARD": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
            "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
            "API_KEY": r"\b(?:sk-|pk-|api_|ghp_)[a-zA-Z0-9]{20,}\b"
        }
        
        redacted_text = text
        findings = []
        
        for ptype, pattern in patterns.items():
            if re.search(pattern, redacted_text, re.IGNORECASE):
                findings.append(ptype)
                redacted_text = re.sub(pattern, f"[REDACTED_{ptype}]", redacted_text, flags=re.IGNORECASE)
                
        return json.dumps({
            "original_had_pii": len(findings) > 0,
            "types_found": findings,
            "safe_text": redacted_text
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "safe_text": text})


@mcp.tool()
def get_audit_trail(limit: int = 10) -> str:
    """
    Récupère les dernières entrées du journal d'audit de sécurité depuis le Collector.
    Permet à l'agent de comprendre le contexte des blocages récents.
    """
    try:
        url = f"{collector_url}/api/traces?limit={limit}"
        headers = {"X-API-Key": os.getenv("AGENTGUARD_API_KEY", "")}
        response = requests.get(url, headers=headers, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            # On extrait juste les infos pertinentes pour ne pas surcharger le contexte de l'IA
            traces = data.get("traces", [])[:limit]
            return json.dumps({"status": "success", "count": len(traces), "recent_traces": traces}, indent=2)
        else:
            return json.dumps({"status": "error", "message": f"Collector returned HTTP {response.status_code}"})
    except Exception as e:
        return json.dumps({"status": "error", "message": f"Failed to connect to collector: {str(e)}"})


@mcp.tool()
def calculate_token_cost(model: str, text: str) -> str:
    """
    Estime le nombre de tokens et le coût en USD d'un texte pour un modèle LLM donné.
    Aide l'agent à respecter son budget avant d'envoyer une requête.
    """
    try:
        try:
            encoding = tiktoken.encoding_for_model(model)
        except KeyError:
            encoding = tiktoken.get_encoding("cl100k_base") # Fallback standard (GPT-4/Claude)
        
        tokens = len(encoding.encode(text))
        
        # Prix approximatifs pour 1000 tokens (Input)
        pricing_map = {
            "gpt-4o": 0.0025, "gpt-4o-mini": 0.00015,
            "gpt-3.5-turbo": 0.0005, "claude-3-5-sonnet": 0.003,
            "deepseek-chat": 0.00014, "deepseek-reasoner": 0.00055
        }
        
        model_key = model.lower()
        price_per_1k = pricing_map.get(model_key, 0.0025) # Default à GPT-4o si inconnu
        estimated_cost = (tokens / 1000) * price_per_1k
        
        return json.dumps({
            "model": model,
            "estimated_tokens": tokens,
            "price_per_1k_tokens_usd": price_per_1k,
            "estimated_cost_usd": round(estimated_cost, 6),
            "warning": "Cost exceeds 0.01 USD" if estimated_cost > 0.01 else "Cost is within normal limits"
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})


@mcp.resource("cerbereag://policies/summary")
def get_policies_summary() -> str:
    """Fournit un résumé des politiques de sécurité actives."""
    allowed = list(guard.policy_engine._allowed_tools)
    return json.dumps({
        "system": "CerbereAG",
        "allowed_tools": allowed if allowed else ["ALL (No specific whitelist defined)"],
        "injection_detection": "ENABLED",
        "pii_detection_and_redaction": "ENABLED"
    }, indent=2)


# ==============================================================================
# 🚀 POINT D'ENTRÉE (Pour pyproject.toml)
# ==============================================================================

def main():
    logger.info("Starting CerbereAG MCP Server (v1.x) on stdio...")
    mcp.run(transport='stdio')

if __name__ == "__main__":
    main()
