"""
Routes pour la page /devtools.

Un générateur de configuration MCP côté client (pas de backend impliqué :
tout se fait en JS dans le navigateur) + les commandes d'installation et
liens utiles pour un développeur qui intègre CerbereAG.
"""
from flask import Blueprint, render_template_string

devtools_bp = Blueprint("devtools", __name__)

DEVTOOLS_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DevTools — Cerbere</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        :root {
            --bg-primary: #09090b; --bg-secondary: #18181b;
            --border-color: rgba(255, 255, 255, 0.08); --border-hover: rgba(239, 68, 68, 0.5);
            --text-primary: #fafafa; --text-secondary: #a1a1aa; --text-muted: #71717a;
            --accent-red: #ef4444; --accent-orange: #f97316; --accent-glow: rgba(239, 68, 68, 0.15);
        }
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary); color: var(--text-primary);
            line-height: 1.6; -webkit-font-smoothing: antialiased;
        }
        .header { background: var(--bg-secondary); border-bottom: 1px solid var(--border-color); padding: 1.5rem 0; }
        .header-content { max-width: 800px; margin: 0 auto; padding: 0 2rem; display: flex; align-items: center; gap: 12px; }
        .header-content img { width: 32px; height: 32px; }
        .header-content span { font-size: 18px; font-weight: 700; letter-spacing: -0.02em; }
        .container { max-width: 800px; margin: 3rem auto; padding: 0 2rem; }
        h1 {
            font-size: 36px; font-weight: 700; margin-bottom: 0.5rem; letter-spacing: -0.02em;
            background: linear-gradient(135deg, var(--accent-red) 0%, var(--accent-orange) 100%);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;
        }
        .subtitle { color: var(--text-secondary); font-size: 15px; margin-bottom: 3rem; }
        .card { background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 12px; padding: 1.75rem; margin-bottom: 1.5rem; }
        .card h2 { font-size: 18px; font-weight: 600; margin-bottom: 1.25rem; }
        .field { margin-bottom: 1rem; }
        .field label { display: block; margin-bottom: 0.4rem; font-size: 13px; font-weight: 500; color: var(--text-secondary); }
        .field select, .field input {
            width: 100%; padding: 10px 12px; background: rgba(255,255,255,0.03);
            border: 1px solid var(--border-color); border-radius: 8px; color: var(--text-primary);
            font-size: 14px; font-family: inherit; outline: none;
        }
        .field select:focus, .field input:focus { border-color: var(--border-hover); box-shadow: 0 0 0 3px var(--accent-glow); }
        .field input::placeholder { color: var(--text-muted); }
        .row { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
        pre { background: #000; border: 1px solid var(--border-color); border-radius: 8px; padding: 1rem; overflow-x: auto; margin-top: 1rem; font-size: 13px; color: #e4e4e7; position: relative; }
        .copy-btn {
            position: absolute; top: 10px; right: 10px; font-size: 12px; font-weight: 500;
            color: var(--text-secondary); background: rgba(255,255,255,0.05); border: 1px solid var(--border-color);
            border-radius: 6px; padding: 5px 10px; cursor: pointer;
        }
        .copy-btn:hover { border-color: var(--accent-red); color: var(--text-primary); }
        .copy-btn.copied { border-color: #10b981; color: #10b981; }
        .links { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 0.75rem; }
        .links a {
            display: block; padding: 12px 14px; background: rgba(255,255,255,0.03); border: 1px solid var(--border-color);
            border-radius: 8px; color: var(--text-primary); text-decoration: none; font-size: 14px; font-weight: 500;
        }
        .links a:hover { border-color: var(--accent-red); }
        .links a span { display: block; color: var(--text-muted); font-size: 12px; font-weight: 400; margin-top: 2px; }
        .back { display: inline-block; margin-top: 1rem; color: var(--text-muted); text-decoration: none; font-size: 14px; }
        .back:hover { color: var(--text-primary); }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <img src="/static/logo.svg" alt="Cerbere">
            <span>DevTools</span>
        </div>
    </div>
    <div class="container">
        <h1>Developer tools</h1>
        <p class="subtitle">Generate a ready-to-paste MCP config, or grab the install command for your setup.</p>

        <div class="card">
            <h2>MCP config generator</h2>
            <div class="row">
                <div class="field">
                    <label for="client">Client</label>
                    <select id="client" onchange="render()">
                        <option value="claude_desktop">Claude Desktop</option>
                        <option value="cursor">Cursor</option>
                    </select>
                </div>
                <div class="field">
                    <label for="agent_id">Agent ID</label>
                    <input id="agent_id" value="my-agent" oninput="render()">
                </div>
            </div>
            <div class="row">
                <div class="field">
                    <label for="collector_url">Collector URL</label>
                    <input id="collector_url" value="https://app.cerbereag.site" oninput="render()">
                </div>
                <div class="field">
                    <label for="api_key">API key</label>
                    <input id="api_key" placeholder="ag-your-key" oninput="render()">
                </div>
            </div>
            <pre><button class="copy-btn" onclick="copyOut(this)">Copy</button><code id="output"></code></pre>
            <p class="subtitle" style="margin-top:0.75rem; margin-bottom:0;" id="filename-hint"></p>
        </div>

        <div class="card">
            <h2>Install commands</h2>
            <pre><button class="copy-btn" onclick="copyOut(this)">Copy</button><code>pip install cerbere-ag        # SDK, for wiring into your own agent code
pip install cerbere-ag-mcp    # MCP server, for Claude Code / Cursor / Cline</code></pre>
        </div>

        <div class="card">
            <h2>Links</h2>
            <div class="links">
                <a href="https://github.com/chrismsmr-celcom/agentguard">GitHub<span>Source & issues</span></a>
                <a href="https://pypi.org/project/cerbere-ag/">PyPI — SDK<span>cerbere-ag</span></a>
                <a href="https://pypi.org/project/cerbere-ag-mcp/">PyPI — MCP<span>cerbere-ag-mcp</span></a>
                <a href="/documentation">Documentation<span>Full guide</span></a>
                <a href="/billing">Plans & Pricing<span>Free / Pro</span></a>
            </div>
        </div>

        <a class="back" href="/documentation">← Back to documentation</a>
    </div>

    <script>
        function render() {
            const client = document.getElementById('client').value;
            const agentId = document.getElementById('agent_id').value || 'my-agent';
            const url = document.getElementById('collector_url').value || 'https://app.cerbereag.site';
            const key = document.getElementById('api_key').value || 'ag-your-key';

            const config = {
                mcpServers: {
                    cerbereag: {
                        command: "cerbere-ag-mcp",
                        env: {
                            AGENTGUARD_MCP_COLLECTOR_URL: url,
                            AGENTGUARD_API_KEY: key,
                            AGENTGUARD_AGENT_ID: agentId
                        }
                    }
                }
            };
            document.getElementById('output').textContent = JSON.stringify(config, null, 2);

            const hints = {
                claude_desktop: 'Paste into claude_desktop_config.json, then restart Claude Desktop.',
                cursor: 'Paste into .cursor/mcp.json in your project root.'
            };
            document.getElementById('filename-hint').textContent = hints[client];
        }
        function copyOut(btn) {
            const code = btn.parentElement.querySelector('code').textContent;
            navigator.clipboard.writeText(code).then(() => {
                const original = btn.textContent;
                btn.textContent = 'Copied ✓';
                btn.classList.add('copied');
                setTimeout(() => { btn.textContent = original; btn.classList.remove('copied'); }, 1500);
            });
        }
        render();
    </script>
</body>
</html>
"""


@devtools_bp.route("/devtools")
def devtools_page():
    return render_template_string(DEVTOOLS_TEMPLATE)
