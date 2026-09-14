# 🐕‍🦺 CerbereAG MCP Server

**Runtime security for AI agents — as an MCP server.**

CerbereAG MCP lets any MCP-compatible AI agent (Claude, Cursor, Cline, custom
agents built on the Anthropic API) check its own prompts and tool calls for
security risk in real time, using the [Model Context Protocol](https://modelcontextprotocol.io).

It wraps the [`cerbere-ag`](https://pypi.org/project/cerbere-ag/) SDK's
policy engine and exposes it as MCP tools, so an agent can call
`check_prompt_security` or `authorize_tool_call` the same way it would call
any other tool — no separate API integration required.

## 🚀 Quick start (30 seconds)

### 1. Install

```bash
pip install cerbere-ag-mcp
```

### 2. Configure your MCP client

**Claude Desktop** — add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "cerbereag": {
      "command": "cerbere-ag-mcp",
      "env": {
        "AGENTGUARD_MCP_COLLECTOR_URL": "https://YOUR_AGENTGUARD_HOST",
        "AGENTGUARD_API_KEY": "ag-your-key",
        "AGENTGUARD_AGENT_ID": "my-agent"
      }
    }
  }
}
```

**Cursor** — add to `.cursor/mcp.json` in your project:

```json
{
  "mcpServers": {
    "cerbereag": {
      "command": "cerbere-ag-mcp",
      "env": {
        "AGENTGUARD_MCP_COLLECTOR_URL": "https://YOUR_AGENTGUARD_HOST",
        "AGENTGUARD_API_KEY": "ag-your-key",
        "AGENTGUARD_AGENT_ID": "my-agent"
      }
    }
  }
}
```

Restart the client. The tools below become available to the agent
automatically — no code changes needed on your side.

## 🛠️ Available tools

| Tool | Purpose |
|---|---|
| `check_prompt_security(text)` | Checks a text for prompt injection patterns or PII leakage before it's sent onward. |
| `authorize_tool_call(tool_name, params_json, agent_id?)` | Checks whether a planned tool call is allowed under the active policy and remaining budget. |
| `redact_pii(text)` | Replaces detected PII (emails, phone numbers, card numbers, SSNs, API keys) with `[REDACTED_TYPE]` placeholders. |
| `get_audit_trail(limit?)` | Fetches the most recent entries from the security audit log on the Collector. |
| `calculate_token_cost(model, text)` | Estimates token count and USD cost for a piece of text against a given model's pricing. |

## 📚 Available resource

| Resource | Purpose |
|---|---|
| `cerbereag://policies/summary` | Returns a summary of the currently active tool allowlist and detection settings. |

## ⚙️ Configuration

| Environment variable | Required | Default | Description |
|---|---|---|---|
| `AGENTGUARD_MCP_COLLECTOR_URL` | No | `http://localhost:8080` | URL of your CerbereAG Collector instance. |
| `AGENTGUARD_API_KEY` | Recommended | — | API key used to authenticate against the Collector. |
| `AGENTGUARD_AGENT_ID` | No | `cerbereag_mcp_client` | Identifier used to scope policy and budget checks. |
| `AGENTGUARD_MAX_BUDGET` | No | `10.0` | Max USD spend before `authorize_tool_call` starts blocking on budget. |

## 🧩 Running it manually (for testing)

```bash
AGENTGUARD_MCP_COLLECTOR_URL=http://localhost:8080 \
AGENTGUARD_API_KEY=ag-your-key \
cerbere-ag-mcp
```

The server starts on stdio, as expected by MCP clients — it is not meant to
be run as a standalone HTTP service.

## 🔗 Related

* Core SDK (decorator-based integration for Python agents): [`cerbere-ag`](https://pypi.org/project/cerbere-ag/)
* Dashboard, policy docs, other framework integrations (LangGraph, CrewAI, Composio, HTTP gateway): [app.cerbereag.site](https://app.cerbereag.site)
* Source: [github.com/chrismsmr-celcom/agentguard](https://github.com/chrismsmr-celcom/agentguard)

