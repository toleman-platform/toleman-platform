"""Rikugan MCP server (issue #108).

A thin translation layer between MCP tool calls and Rikugan's public API
(/api/public/v1/*, issue #109) -- deliberately NOT embedded in the main
FastAPI backend. The official `mcp` PyPI package requires
starlette>=0.39/pydantic>=2.8 across every released version (checked
0.9.1 through 2.0.0), which is incompatible with this project's pinned
fastapi==0.115.0 (needs starlette<0.39.0) and sqlmodel==0.0.22 (breaks on
pydantic>=2.10) -- see backend/requirements.txt and backend/Dockerfile
for why those pins exist. Running as a standalone process with its own
venv sidesteps that conflict entirely rather than forcing a much larger,
riskier upgrade of the backend's core web/ORM stack just to satisfy one
optional integration.

Runs over stdio (the standard transport for MCP servers launched by a
client like Claude Desktop/Code, not a long-running network service) --
authenticates to Rikugan using a personal access token (see
rikugan-docs Public API Reference), exactly like any other public-API
client.

A note on `mcp`'s own CVEs (checked at pin time, mcp==1.23.0): every
currently-known advisory against this package (GHSA-9h52-p55h-vw2f fixed
in 1.23.0; GHSA-jpw9-pfvf-9f58, GHSA-vj7q-gjh5-988w still open as of
1.23.0/latest 1.x) is scoped to the HTTP/SSE/WebSocket transport code
paths and the experimental task-handler feature -- none of which this
server invokes, since `mcp.run(transport="stdio")` below is the only
entry point exercised. `2.0.0` has none of these open, but requires
starlette/pydantic versions incompatible with this project (see above),
so isn't a real option yet. Re-check this comment before bumping to a
new 1.x release or when 2.0.0 stabilizes and its dependency floor is
re-evaluated.
"""
import os

import httpx
from mcp.server.fastmcp import FastMCP

RIKUGAN_API_URL = os.environ.get("RIKUGAN_API_URL", "http://localhost:8000").rstrip("/")
RIKUGAN_API_TOKEN = os.environ.get("RIKUGAN_API_TOKEN")

if not RIKUGAN_API_TOKEN:
    raise RuntimeError(
        "RIKUGAN_API_TOKEN is required -- create a personal access token at "
        "Settings > Workspace > API Tokens in your Rikugan instance and set it "
        "as an env var for this server."
    )

mcp = FastMCP("rikugan")


def _client() -> httpx.Client:
    return httpx.Client(
        base_url=f"{RIKUGAN_API_URL}/api/public/v1",
        headers={"Authorization": f"Bearer {RIKUGAN_API_TOKEN}"},
        timeout=30.0,
    )


@mcp.tool()
def list_targets() -> list[dict]:
    """List every target (scanned repo) in workspaces this token can access."""
    with _client() as c:
        r = c.get("/targets")
        r.raise_for_status()
        return r.json()


@mcp.tool()
def list_findings(
    target_id: int | None = None,
    severity: str | None = None,
    state: str | None = None,
    page: int = 1,
    page_size: int = 25,
) -> dict:
    """List findings, optionally filtered by target_id, severity
    (Critical/High/Medium/Low), or state (Open/Mitigated/Accepted Risk/
    False Positive/Won't Fix/Reopened). Paginated."""
    params = {"page": page, "page_size": page_size}
    if target_id is not None:
        params["target_id"] = target_id
    if severity is not None:
        params["severity"] = severity
    if state is not None:
        params["state"] = state
    with _client() as c:
        r = c.get("/findings", params=params)
        r.raise_for_status()
        return r.json()


@mcp.tool()
def get_finding(finding_id: int) -> dict:
    """Get full detail for a single finding by id."""
    with _client() as c:
        r = c.get(f"/findings/{finding_id}")
        r.raise_for_status()
        return r.json()


@mcp.tool()
def get_scan_status(scan_id: int) -> dict:
    """Get a scan's current status (running/completed/failed) and, once
    settled, its findings count and any error message."""
    with _client() as c:
        r = c.get(f"/scans/{scan_id}")
        r.raise_for_status()
        return r.json()


@mcp.tool()
def trigger_scan(target_id: int, tool: str) -> dict:
    """Trigger a native scan (semgrep/trivy/gitleaks/gosec) against a
    target. Requires a read_write-scoped token -- a read-only token gets
    a clear permission error, not a silent no-op. Returns immediately with
    a scan_id; poll get_scan_status(scan_id) for the result."""
    with _client() as c:
        r = c.post("/scans", params={"target_id": target_id, "tool": tool})
        r.raise_for_status()
        return r.json()


if __name__ == "__main__":
    mcp.run(transport="stdio")
