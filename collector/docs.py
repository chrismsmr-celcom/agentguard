"""
Routes pour la page de documentation publique.

Chaque section a un bouton "Copy for LLM" qui copie sa version Markdown
brute (pas le HTML rendu) — c'est ce qu'un agent consomme le mieux.
La même donnée alimente /documentation.md, une vue Markdown pure de
toute la page, pensée pour être fetchée directement par un agent plutôt
que scrapée depuis le HTML (convention proche de llms.txt).

Pour ajouter une section : ajoute une entrée à DOC_SECTIONS avec un id
unique, un titre, et son contenu en Markdown — le HTML affiché est
généré automatiquement depuis ce Markdown, donc il n'y a qu'une seule
source de vérité par section.
"""
import re
from flask import Blueprint, render_template_string, Response

docs_bp = Blueprint("docs", __name__)


# ═══════════════════════════════════════════════════════════════
# CONTENU — une seule source de vérité par section (Markdown)
# ═══════════════════════════════════════════════════════════════

DOC_SECTIONS = [
    {
        "id": "quickstart",
        "title": "Quick Start",
        "md": """## Quick Start

Two ways to use CerbereAG, depending on how your agent is built.

### Option 1 — Python SDK

```bash
pip install cerbere-ag
```

```python
from agentguard import AgentGuard

guard = AgentGuard(
    collector_url="https://app.cerbereag.site",
    api_key="ag-your-key",
    agent_id="my-agent",
)

@guard.guard_llm_call
def call_llm(messages, model):
    ...
```

### Option 2 — MCP server (Claude Desktop, Cursor, Cline, custom agents)

```bash
pip install cerbere-ag-mcp
```

See the [MCP Server section](#mcp) below for client configuration.
""",
    },
    {
        "id": "mcp",
        "title": "MCP Server",
        "md": """## MCP Server

If your agent runs inside an MCP-compatible client, add CerbereAG as a
tool server instead of wiring the SDK by hand.

### Claude Desktop — `claude_desktop_config.json`

```json
{
  "mcpServers": {
    "cerbereag": {
      "command": "cerbere-ag-mcp",
      "env": {
        "AGENTGUARD_MCP_COLLECTOR_URL": "https://app.cerbereag.site",
        "AGENTGUARD_API_KEY": "ag-your-key",
        "AGENTGUARD_AGENT_ID": "my-agent"
      }
    }
  }
}
```

### Cursor — `.cursor/mcp.json`

Same shape as above, in your project's `.cursor/mcp.json`.

### Claude Code (SSE, no local install)

```bash
claude mcp add cerbereag --transport sse https://app.cerbereag.site/mcp/sse
```

### Available tools

| Tool | Purpose |
|---|---|
| `check_prompt_security` | Detect prompt injection / PII in a piece of text |
| `authorize_tool_call` | Check if a planned tool call is allowed under policy + budget |
| `redact_pii` | Replace detected PII with `[REDACTED_TYPE]` placeholders |
| `get_audit_trail` | Fetch recent security audit log entries |
| `calculate_token_cost` | Estimate token count and USD cost for a model |
""",
    },
    {
        "id": "how-it-works",
        "title": "How detection works",
        "md": """## How detection works

CerbereAG checks every prompt and tool call against three layers,
in order — each one only runs if the previous one didn't already
reach a verdict:

1. **Pattern layer** — 120+ regex patterns (EN/FR/ES/DE/IT) covering
   direct injection, jailbreaks (DAN, developer mode, ...), system
   prompt extraction, data exfiltration, and dangerous commands.
   This is the fast, free, always-on layer.
2. **Policy layer** — tool-call authorization against your configured
   allowlist, scoped by `agent_id`, with a running budget cap.
   Decisions can be Ed25519-signed for zero-trust setups.
3. **LLM Judge (optional)** — for ambiguous cases, a secondary model
   call reviews the prompt. Off by default; only the first 2000
   characters are sent, never full conversation history.

A `BLOCK` decision raises a `SecurityException` in the SDK, or is
returned as a denial to the calling agent over MCP — the agent never
silently proceeds on a blocked action.
""",
    },
    {
        "id": "pricing",
        "title": "Plans & Pricing",
        "md": """## Plans & Pricing

| | Free | Pro |
|---|---|---|
| Agents | 2 | 5 |
| Real-time detection | ✅ | ✅ |
| Audit trail | ❌ | ✅ |
| Price | $0 | $49/mo |

Sign-up is required even on the Free plan (needed to issue your
`AGENTGUARD_API_KEY` and enforce the agent limit). See
[/billing](/billing) to upgrade — automated payment is being finalized,
manual upgrade available meanwhile.
""",
    },
]


def _md_to_html(md: str) -> str:
    """Minimal Markdown -> HTML for our own controlled content
    (headings, code fences, tables, bold, links, lists). Not a general
    Markdown parser — deliberately small, since we only ever render
    the fixed DOC_SECTIONS content above."""
    lines = md.strip("\n").split("\n")
    html, in_code, in_table, in_list, table_row_num = [], False, False, False, 0
    for line in lines:
        stripped = line.strip()
        if line.startswith("```"):
            html.append("</code></pre>" if in_code else "<pre><code>")
            in_code = not in_code
            continue
        if in_code:
            html.append(
                line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            )
            continue

        is_table_row = stripped.startswith("|") and stripped.endswith("|")
        is_separator_row = is_table_row and re.fullmatch(r"[|\-: ]+", stripped) is not None

        if is_table_row:
            if not in_table:
                html.append("<table>")
                in_table = True
                table_row_num = 0
            if is_separator_row:
                continue
            table_row_num += 1
            cells = [c.strip() for c in stripped.strip("|").split("|")]
            tag = "th" if table_row_num == 1 else "td"
            html.append("<tr>" + "".join(f"<{tag}>{c}</{tag}>" for c in cells) + "</tr>")
            continue
        elif in_table:
            html.append("</table>")
            in_table = False

        if line.startswith("### "):
            html.append(f"<h3>{line[4:]}</h3>")
        elif line.startswith("## "):
            html.append(f"<h2 id='{re.sub(r'[^a-z0-9]+', '-', line[3:].lower()).strip('-')}'>{line[3:]}</h2>")
        elif line.startswith("- ") or re.match(r"^\d+\. ", line):
            if not in_list:
                html.append("<ul>")
                in_list = True
            content = re.sub(r"^(-|\d+\.) ", "", line)
            html.append(f"<li>{content}</li>")
            continue
        elif in_list and not stripped:
            html.append("</ul>")
            in_list = False
        elif stripped:
            html.append(f"<p>{line}</p>")

        if in_list and not (line.startswith("- ") or re.match(r"^\d+\. ", line)):
            html.append("</ul>")
            in_list = False

    if in_table:
        html.append("</table>")
    if in_list:
        html.append("</ul>")

    out = "\n".join(html)
    out = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<a href="\2">\1</a>', out)
    out = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", out)
    out = re.sub(r"`([^`]+)`", r"<code>\1</code>", out)
    return out


DOC_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Documentation — Cerbere</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        :root {
            --bg-primary: #09090b; --bg-secondary: #18181b;
            --border-color: rgba(255, 255, 255, 0.08);
            --text-primary: #fafafa; --text-secondary: #a1a1aa; --text-muted: #71717a;
            --accent-red: #ef4444; --accent-orange: #f97316;
        }
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary); color: var(--text-primary);
            line-height: 1.6; -webkit-font-smoothing: antialiased;
        }
        .header { background: var(--bg-secondary); border-bottom: 1px solid var(--border-color); padding: 1.5rem 0; }
        .header-content { max-width: 900px; margin: 0 auto; padding: 0 2rem; display: flex; align-items: center; justify-content: space-between; gap: 12px; }
        .header-left { display: flex; align-items: center; gap: 12px; }
        .header-content img { width: 32px; height: 32px; }
        .header-content span { font-size: 18px; font-weight: 700; letter-spacing: -0.02em; }
        .header a.copy-all {
            font-size: 13px; font-weight: 500; color: var(--text-secondary);
            border: 1px solid var(--border-color); border-radius: 8px; padding: 8px 14px;
            text-decoration: none; cursor: pointer; background: transparent;
        }
        .header a.copy-all:hover { border-color: var(--accent-red); color: var(--text-primary); }
        .layout { max-width: 900px; margin: 3rem auto; padding: 0 2rem; display: grid; grid-template-columns: 180px 1fr; gap: 3rem; }
        nav { position: sticky; top: 2rem; align-self: start; }
        nav a { display: block; padding: 6px 0; color: var(--text-secondary); text-decoration: none; font-size: 14px; }
        nav a:hover { color: var(--accent-red); }
        h1 {
            font-size: 36px; font-weight: 700; margin-bottom: 2.5rem; letter-spacing: -0.02em;
            background: linear-gradient(135deg, var(--accent-red) 0%, var(--accent-orange) 100%);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;
        }
        section { margin-bottom: 3rem; border-bottom: 1px solid var(--border-color); padding-bottom: 2.5rem; }
        section:last-child { border-bottom: none; }
        .section-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.5rem; }
        h2 { font-size: 22px; font-weight: 600; color: var(--text-primary); }
        h3 { font-size: 16px; font-weight: 600; margin-top: 1.5rem; margin-bottom: 0.5rem; color: var(--text-primary); }
        p { color: var(--text-secondary); margin-bottom: 1rem; }
        ul { color: var(--text-secondary); margin: 0 0 1rem 1.5rem; }
        li { margin-bottom: 0.4rem; }
        code { background: rgba(255,255,255,0.06); padding: 2px 6px; border-radius: 4px; font-size: 13px; color: #fca5a5; }
        pre { background: #000; border: 1px solid var(--border-color); border-radius: 8px; padding: 1rem; overflow-x: auto; margin-bottom: 1rem; }
        pre code { background: none; padding: 0; color: #e4e4e7; font-size: 13px; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 1rem; font-size: 14px; }
        th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid var(--border-color); color: var(--text-secondary); }
        th { color: var(--text-primary); font-weight: 600; }
        a { color: var(--accent-red); }
        .copy-btn {
            font-size: 12px; font-weight: 500; color: var(--text-secondary);
            background: transparent; border: 1px solid var(--border-color); border-radius: 6px;
            padding: 6px 12px; cursor: pointer; white-space: nowrap;
        }
        .copy-btn:hover { border-color: var(--accent-red); color: var(--text-primary); }
        .copy-btn.copied { border-color: #10b981; color: #10b981; }
        @media (max-width: 720px) { .layout { grid-template-columns: 1fr; } nav { display: none; } }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <div class="header-left">
                <img src="/static/logo.svg" alt="Cerbere">
                <span>Documentation</span>
            </div>
            <button class="copy-all" onclick="copyAll()" id="copy-all-btn">Copy full page for LLM</button>
        </div>
    </div>
    <div class="layout">
        <nav>
            {% for s in sections %}<a href="#{{ s.id }}">{{ s.title }}</a>{% endfor %}
            <a href="/documentation.md">Raw Markdown ↗</a>
        </nav>
        <div>
            <h1>How CerbereAG works</h1>
            {% for s in sections %}
            <section id="{{ s.id }}">
                <div class="section-header">
                    <h2>{{ s.title }}</h2>
                    <button class="copy-btn" onclick="copySection('{{ s.id }}', this)">Copy for LLM</button>
                </div>
                {{ s.html|safe }}
                <script type="application/x-markdown" id="md-{{ s.id }}">{{ s.md }}</script>
            </section>
            {% endfor %}
        </div>
    </div>
    <script>
        function copySection(id, btn) {
            const md = document.getElementById('md-' + id).textContent;
            navigator.clipboard.writeText(md).then(() => {
                const original = btn.textContent;
                btn.textContent = 'Copied ✓';
                btn.classList.add('copied');
                setTimeout(() => { btn.textContent = original; btn.classList.remove('copied'); }, 1500);
            });
        }
        function copyAll() {
            const all = {{ sections|map(attribute='id')|list|tojson }}
                .map(id => document.getElementById('md-' + id).textContent)
                .join('\\n\\n---\\n\\n');
            navigator.clipboard.writeText(all).then(() => {
                const btn = document.getElementById('copy-all-btn');
                const original = btn.textContent;
                btn.textContent = 'Copied ✓';
                setTimeout(() => { btn.textContent = original; }, 1500);
            });
        }
    </script>
</body>
</html>
"""


def _rendered_sections():
    return [
        {"id": s["id"], "title": s["title"], "md": s["md"], "html": _md_to_html(s["md"])}
        for s in DOC_SECTIONS
    ]


@docs_bp.route("/documentation")
def documentation_page():
    return render_template_string(DOC_TEMPLATE, sections=_rendered_sections())


@docs_bp.route("/documentation.md")
def documentation_markdown():
    """Raw Markdown view of the whole page — meant to be fetched
    directly by an agent (curl/web_fetch), not scraped from HTML."""
    body = "\n\n---\n\n".join(s["md"] for s in DOC_SECTIONS)
    return Response(f"# CerbereAG Documentation\n\n{body}\n", mimetype="text/markdown")
