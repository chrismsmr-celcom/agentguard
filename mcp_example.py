"""
Intégration AgentGuard + MCP (Model Context Protocol) — copier/coller et adapter.

Deux façons de brancher un agent qui parle MCP sur AgentGuard, du plus
simple au plus robuste :

  1. WRAPPER CLIENT (ce fichier) : tu as déjà un ClientSession MCP
     (stdio, SSE ou HTTP streamable — peu importe le transport, MCP
     l'abstrait) et tu veux que CHAQUE appel `tools/call` passe par
     guard.guard_tool_call avant de partir vers le serveur MCP réel.
     Zéro infra supplémentaire, ~1 ligne à ajouter à ton code existant.

  2. GATEWAY MCP (voir mcp_gateway.py) : tu veux un vrai proxy MCP,
     séparé du process de l'agent, qui s'intercale entre l'agent et
     N serveurs MCP en amont — utile quand plusieurs agents/équipes
     partagent les mêmes serveurs MCP et que tu veux un point de
     contrôle centralisé (comme /api/decide pour les policies signées).

Le principe est le même que pour LangChain/CrewAI (voir langchain_example.py,
crewai_example.py) : AgentGuard ne dépend JAMAIS du SDK MCP. Il expose juste
un point d'interception générique (guard_tool_call) et c'est à l'adapter de
brancher dessus. Si demain le SDK MCP change son API, seul CE fichier bouge —
pas agentguard_sdk.py.

Installer : pip install mcp
Lancer    : python mcp_example.py
"""
import asyncio
import os
import sys
from typing import Any, Optional

sys.path.insert(0, os.path.dirname(__file__))

from agentguard_sdk import AgentGuard, SecurityException

# ── 1. Init AgentGuard — la policy peut whitelister par serveur MCP ──
# Convention de nommage : "mcp:<server_label>:<tool_name>", ce qui permet
# au ToolCapabilities.allow/deny existant (policy/models.py, wildcards "*"
# déjà supportés) de scoper par serveur sans rien changer côté policy engine :
#   allow: ["mcp:github:*"]         -> autorise tous les tools du serveur github
#   deny:  ["mcp:filesystem:write*"] -> bloque les writes du serveur filesystem
guard = AgentGuard(
    collector_url=os.environ.get("AGENTGUARD_COLLECTOR_URL", "http://localhost:8080"),
    api_key=os.environ.get("AGENTGUARD_API_KEY"),
    policies=[
        {"type": "tool_whitelist", "allowed_tools": ["mcp:*"]},
    ],
    max_budget=5.0,
    block_on_high=True,
)


def guard_mcp_session(session: Any, guard: AgentGuard, server_label: str) -> Any:
    """
    Monkey-patch `session.call_tool` pour router chaque tool call MCP
    à travers AgentGuard avant exécution réelle.

    Fonctionne avec n'importe quel objet qui expose une coroutine
    `call_tool(name: str, arguments: dict | None)` — donc en pratique
    avec `mcp.ClientSession` (SDK officiel), mais aussi avec un client
    MCP maison qui respecte la même signature.

    Ne modifie ni la connexion ni le transport (stdio/SSE/HTTP) : la
    session continue de fonctionner normalement pour tools/list,
    resources/*, prompts/*, etc. Seul tools/call est intercepté.
    """
    original_call_tool = session.call_tool

    async def guarded_call_tool(name: str, arguments: Optional[dict] = None, **kwargs):
        tool_name = f"mcp:{server_label}:{name}"
        params = dict(arguments or {})

        # guard_tool_call est synchrone ; on l'exécute dans un thread pour
        # ne pas bloquer la boucle asyncio de l'agent le temps de l'appel
        # réseau vers le collector (/api/decide, LLM judge, etc.).
        def _run_guarded():
            return guard.guard_tool_call(
                tool_name=tool_name,
                params=params,
                func=lambda: asyncio.run_coroutine_threadsafe(
                    original_call_tool(name, arguments, **kwargs),
                    loop,
                ).result(),
            )

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _run_guarded)

    session.call_tool = guarded_call_tool
    return session


# ─────────────────────────────────────────────────────────────────
# EXEMPLE COMPLET — client stdio MCP branché sur AgentGuard
# ─────────────────────────────────────────────────────────────────
async def demo():
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    # N'importe quel serveur MCP standard fonctionne ici (filesystem,
    # github, slack, ta propre implémentation Composio, etc.)
    server_params = StdioServerParameters(
        command="npx",
        args=["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # ── Le seul changement requis dans du code MCP existant ──
            session = guard_mcp_session(session, guard, server_label="filesystem")

            tools = await session.list_tools()
            print(f"Outils exposés par le serveur MCP : {[t.name for t in tools.tools]}")

            try:
                result = await session.call_tool(
                    "read_file", {"path": "/tmp/does-not-exist-yet.txt"}
                )
                print(f"✅ Résultat : {result}")
            except SecurityException as e:
                print(f"🛡️ Bloqué par AgentGuard avant d'atteindre le serveur MCP : {e}")
            except FileNotFoundError:
                print("(fichier de démo absent, normal — le point important "
                      "est que l'appel a bien transité par AgentGuard)")


if __name__ == "__main__":
    try:
        asyncio.run(demo())
    except ImportError:
        print(
            "Le SDK MCP officiel n'est pas installé.\n"
            "  pip install mcp\n"
            "guard_mcp_session() ci-dessus fonctionne indépendamment de cette "
            "démo : branche-la sur ta propre ClientSession."
        )
