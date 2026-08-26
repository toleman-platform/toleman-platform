# Toleman MCP Server

Lets an MCP client (Claude Code, Claude Desktop, etc.) query and act on your
Toleman instance directly -- list targets, browse findings, check scan
status, trigger a scan.

A thin client over Toleman's [public API](https://geekshiv.github.io/toleman/documentation/reference/api)
(`/api/public/v1/*`), authenticated the same way any other public-API caller
is: a personal access token. It's a standalone process with its own
dependencies -- see the module docstring in `server.py` for why this isn't
embedded in the main backend (a real dependency conflict between the `mcp`
package and this project's pinned FastAPI/SQLModel versions).

## Setup

```bash
cd mcp-server
python3.12 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

Create a personal access token in Toleman: **Settings → Workspace → API
Tokens**. Read-only is enough for the read tools below; only `trigger_scan`
needs a read/write token.

## Available tools

| Tool | Scope | Description |
|---|---|---|
| `list_targets` | read | List targets in your accessible workspaces |
| `list_findings` | read | List findings, filterable by target/severity/state, paginated |
| `get_finding` | read | Full detail for one finding |
| `get_scan_status` | read | A scan's status/result |
| `trigger_scan` | read/write | Trigger a native scan against a target |

## Running

```bash
TOLEMAN_API_URL=http://localhost:8000 \
TOLEMAN_API_TOKEN=toleman_pat_... \
venv/bin/python server.py
```

Runs over stdio -- meant to be launched by an MCP client, not run standalone long-term.

### Claude Desktop / Claude Code config

```json
{
  "mcpServers": {
    "toleman": {
      "command": "/absolute/path/to/toleman-platform/mcp-server/venv/bin/python",
      "args": ["/absolute/path/to/toleman-platform/mcp-server/server.py"],
      "env": {
        "TOLEMAN_API_URL": "http://localhost:8000",
        "TOLEMAN_API_TOKEN": "toleman_pat_..."
      }
    }
  }
}
```
