# Toleman MCP Server

Lets an MCP client (Claude Code, Claude Desktop, or any other MCP-compatible
tool/agent) query and act on your Toleman instance directly: list targets,
browse findings, check/trigger scans, get a fix recommendation and open a PR
for it, and check a code snippet for vulnerabilities *while it's being
written*, before it's ever committed.

A thin client over Toleman's [public API](https://geekshiv.github.io/toleman/documentation/reference/api)
(`/api/public/v1/*`), authenticated the same way any other public-API caller
is: a personal access token. It's a standalone process with its own
dependencies; see the module docstring in `server.py` for why this isn't
embedded in the main backend (a real dependency conflict between the `mcp`
package and this project's pinned FastAPI/SQLModel versions).

## Available tools

| Tool | Scope | Description |
|---|---|---|
| `list_targets` | read | List targets in your accessible workspaces |
| `list_findings` | read | List findings, filterable by target/severity/state, paginated |
| `get_finding` | read | Full detail for one finding |
| `get_scan_status` | read | A scan's status/result |
| `trigger_scan` | read/write | Trigger a native scan against a target |
| `suggest_fix` | read | Fix recommendation (+ diff, where possible) for a finding; never writes anywhere |
| `raise_fix_pr` | read/write | Opens a PR for the exact patch a prior `suggest_fix` call returned |
| `check_code_for_vulnerabilities` | read | Scan a code snippet for vulnerabilities *before* it's written to a real file/commit |

`suggest_fix` + `raise_fix_pr` are deliberately two calls, not one: review
the recommendation/diff first, then explicitly open the PR for that *exact*
patch, never a freshly (and possibly differently) regenerated one. See
`app/api/findings.py`'s `FindingSuggestFixResponse` docstring in the main
backend for the full reasoning; the public API mirrors it exactly.

## Two ways to run it

### 1. Local (stdio) — one user, launched by your MCP client

The original, simplest setup: your MCP client (Claude Code, Claude Desktop)
launches this as a local subprocess and talks to it over stdio. One personal
access token for the whole process, read from an env var.

```bash
cd mcp-server
python3.12 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

Create a personal access token in Toleman: **Settings → Workspace → API
Tokens**. Read-only is enough for the read tools above; `trigger_scan` and
`raise_fix_pr` need a read/write token.

```bash
TOLEMAN_API_URL=http://localhost:8000 \
TOLEMAN_API_TOKEN=toleman_pat_... \
venv/bin/python server.py
```

#### Claude Desktop / Claude Code config

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

### 2. Remote (streamable-http) — a persistent, multi-tenant network service

No local install: any MCP client connects directly over HTTPS, authenticated
with its *own* personal access token passed as an `Authorization: Bearer
<token>` header on the MCP connection itself, not a fixed env var — many
different users can be connected to the same running server at once, each
scoped to their own Toleman access. See `server.py`'s module docstring
(`_resolve_token`) for exactly how a token is resolved per request.

```bash
TOLEMAN_MCP_TRANSPORT=streamable-http \
TOLEMAN_MCP_HOST=0.0.0.0 \
TOLEMAN_MCP_PORT=8080 \
TOLEMAN_API_URL=http://backend:8000 \
venv/bin/python server.py
```

`TOLEMAN_API_TOKEN` is **not** required (and, deployed this way, not even
meaningful) in this mode — leave it unset. The production deployment
(`geekshiv/toleman-deploy`) runs this behind Caddy at
`https://toleman-api.<domain>/mcp/`, so a client only needs a URL and a
personal access token, nothing to install.

#### Remote client config

```json
{
  "mcpServers": {
    "toleman": {
      "url": "https://toleman-api.example.com/mcp",
      "headers": {
        "Authorization": "Bearer toleman_pat_..."
      }
    }
  }
}
```

This repo's own `.mcp.json` (checked in at the repo root) has this same entry
pointed at the production deployment, reading the token from a
`TOLEMAN_API_TOKEN` env var rather than a hardcoded value, so it's safe to
commit — set that env var in your Claude Code client (or, for a Claude Code
on the web / remote environment, as an environment variable on the
environment itself; see the "Environment variables" section of
[the docs](https://code.claude.com/docs/en/claude-code-on-the-web)) and any
Claude Code session opened in this repo picks up the `toleman` MCP server
automatically (`.claude/settings.json` pre-trusts it via
`enabledMcpjsonServers`). Note that MCP servers are attached when a session
*starts* — adding or changing `TOLEMAN_API_TOKEN` takes effect on the next
new session, not the one already running.

## Development

```bash
pip install -r requirements-dev.txt
python -m pytest -v
```

Tests mock the public API over HTTP (`respx`) and construct a fake MCP
`Context` for both transports (see `tests/test_server.py`'s `_stdio_ctx`/
`_http_ctx`) — no live backend or real MCP client round-trip needed to run
them, though `check_code_for_vulnerabilities`' polling loop and the whole
streamable-http request/auth path have both been exercised against a real
running server + real MCP client during development (not part of the
automated suite, since it needs a live backend to call through to).
