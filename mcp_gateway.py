"""
AgentGuard MCP Gateway — proxy MCP autonome (roadmap "MCP Gateway/Adapter").

Différence avec mcp_example.py :
  - mcp_example.py modifie le CODE de l'agent (wrap de sa ClientSession).
  - mcp_gateway.py NE MODIFIE RIEN côté agent. Il s'agit d'un vrai serveur
    MCP qui se fait passer pour le serveur cible : l'agent s'y connecte
    normalement (stdio), la gateway forward tools/list tel quel, et
    intercepte CHAQUE tools/call via AgentGuard avant de le transmettre au
    serveur MCP réel en amont (lui-même lancé en subprocess stdio).

Cas d'usage : plusieurs agents/équipes partagent les mêmes serveurs MCP
(filesystem, github, base de données...) et il faut UN point de contrôle
centralisé — cohérent avec le modèle /api/decide déjà en place côté
collector (décisions signées Ed25519, seul un DENY signé fait autorité).

Topologie :

    Agent (Claude Desktop, Claude Code, LangGraph, etc.)
        │  stdio MCP standard — aucune config spéciale côté agent,
        │  juste pointer vers "python mcp_gateway.py" au lieu du
        │  serveur MCP réel dans mcp_config.json / claude_desktop_config.json
        ▼
    AgentGuard MCP Gateway (ce fichier)
        │  tools/list  -> forward tel quel
        │  tools/call  -> guard.guard_tool_call() AVANT forward
        ▼
    Serveur MCP réel (subprocess stdio, ex: @modelcontextprotocol/server-github)

Installer : pip install mcp
Lancer    : python mcp_gateway.py -- npx -y @modelcontextprotocol/server-filesystem /tmp
            (tout ce qui suit "--" est la commande du serveur MCP réel à protéger)
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from agentguard_sdk import AgentGuard, SecurityException

SERVER_LABEL = os.environ.get("AGENTGUARD_MCP_SERVER_LABEL", "upstream")

guard = AgentGuard(
    collector_url=os.environ.get("AGENTGUARD_COLLECTOR_URL", "http://localhost:8080"),
    api_key=os.environ.get("AGENTGUARD_API_KEY"),
    policies=[
        {"type": "tool_whitelist", "allowed_tools": [f"mcp:{SERVER_LABEL}:*"]},
    ],
    max_budget=float(os.environ.get("AGENTGUARD_MAX_BUDGET", "5.0")),
    block_on_high=True,
)


async def run_gateway(upstream_command: list[str]) -> None:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import TextContent, Tool

    upstream_params = StdioServerParameters(
        command=upstream_command[0],
        args=upstream_command[1:],
    )

    gateway = Server(f"agentguard-mcp-gateway::{SERVER_LABEL}")

    async with stdio_client(upstream_params) as (up_read, up_write):
        async with ClientSession(up_read, up_write) as upstream:
            await upstream.initialize()

            @gateway.list_tools()
            async def list_tools() -> list[Tool]:
                # tools/list n'exécute rien côté agent -> pas besoin d'AgentGuard,
                # on forward tel quel ce que le serveur upstream annonce.
                result = await upstream.list_tools()
                return result.tools

            @gateway.call_tool()
            async def call_tool(name: str, arguments: dict) -> list[TextContent]:
                tool_name = f"mcp:{SERVER_LABEL}:{name}"

                try:
                    # Le point de contrôle : rien n'atteint le serveur MCP
                    # réel sans être passé par le Policy Engine + Runtime
                    # Risk Engine + (si configuré) le LLM Judge.
                    result = guard.guard_tool_call(
                        tool_name=tool_name,
                        params=dict(arguments or {}),
                        func=lambda: asyncio.run(
                            upstream.call_tool(name, arguments)
                        ),
                    )
                except SecurityException as exc:
                    return [TextContent(
                        type="text",
                        text=f"🛡️ Bloqué par AgentGuard : {exc}",
                    )]

                return result.content

            async with stdio_server() as (down_read, down_write):
                await gateway.run(
                    down_read,
                    down_write,
                    gateway.create_initialization_options(),
                )


if __name__ == "__main__":
    if "--" not in sys.argv:
        print(
            "Usage : python mcp_gateway.py -- <commande du serveur MCP réel>\n"
            "Exemple : python mcp_gateway.py -- npx -y "
            "@modelcontextprotocol/server-filesystem /tmp"
        )
        sys.exit(1)

    sep = sys.argv.index("--")
    upstream_cmd = sys.argv[sep + 1:]

    if not upstream_cmd:
        print("Aucune commande upstream fournie après --")
        sys.exit(1)

    try:
        asyncio.run(run_gateway(upstream_cmd))
    except ImportError:
        print("Le SDK MCP officiel n'est pas installé.\n  pip install mcp")
        sys.exit(1)
