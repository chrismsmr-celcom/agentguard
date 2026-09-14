# mcp_server_sse.py
import os
import logging
from mcp.server.fastmcp import FastMCP

# Configuration du logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("cerbereag.sse")

# Récupère l'URL de ton collecteur central (hébergé par toi)
# Par défaut, il pointe vers une démo, mais en prod, ce sera ton vrai backend
COLLECTOR_URL = os.getenv("AGENTGUARD_COLLECTOR_URL", "https://api.ton-domaine.com")
API_KEY = os.getenv("AGENTGUARD_API_KEY", "")

# Initialisation du serveur MCP en mode distant
mcp = FastMCP("CerbereAG Security")

@mcp.tool()
def check_prompt_security(text: str) -> str:
    """Vérifie si un texte contient des injections ou des fuites de PII."""
    import requests
    try:
        # Appel à TON API centrale de sécurité (que tu as déjà construite)
        response = requests.post(
            f"{COLLECTOR_URL}/api/v1/check_prompt",
            json={"text": text},
            headers={"Authorization": f"Bearer {API_KEY}"}
        )
        return str(response.json())
    except Exception as e:
        return f"{{\"error\": \"Security check failed: {str(e)}\"}}"

@mcp.tool()
def get_agent_observability(agent_id: str) -> str:
    """Récupère les métriques de sécurité et d'observation d'un agent."""
    import requests
    try:
        response = requests.get(
            f"{COLLECTOR_URL}/api/v1/agents/{agent_id}/metrics",
            headers={"Authorization": f"Bearer {API_KEY}"}
        )
        return str(response.json())
    except Exception as e:
        return f"{{\"error\": \"Failed to fetch metrics: {str(e)}\"}}"

if __name__ == "__main__":
    # Lance le serveur en mode SSE sur le port 8080 (standard pour le cloud)
    logger.info("Starting CerbereAG MCP Server in SSE mode on port 8080...")
    mcp.run(transport="sse", host="0.0.0.0", port=8080)
