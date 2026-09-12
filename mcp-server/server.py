"""Toleman MCP server (issue #108; suggest_fix/raise_fix_pr/
check_code_for_vulnerabilities added as a #108 follow-up so a connected
agent can fix vulnerabilities, not just read about them, and catch a new
one *while it's being written* instead of only after a real scan finds it).

A thin translation layer between MCP tool calls and Toleman's public API
(/api/public/v1/*, issue #109); deliberately NOT embedded in the main
FastAPI backend. The official `mcp` PyPI package requires
starlette>=0.39/pydantic>=2.8 across every released version (checked
0.9.1 through 2.0.0), which is incompatible with this project's pinned
fastapi==0.115.0 (needs starlette<0.39.0) and sqlmodel==0.0.22 (breaks on
pydantic>=2.10); see backend/requirements.txt and backend/Dockerfile
for why those pins exist. Running as a standalone process with its own
venv sidesteps that conflict entirely rather than forcing a much larger,
riskier upgrade of the backend's core web/ORM stack just to satisfy one
optional integration.

Two transports, chosen by TOLEMAN_MCP_TRANSPORT:

  "stdio" (default) -- the standard transport for an MCP client (Claude
  Desktop/Code) to launch this as a local subprocess. One token for the
  whole process lifetime, read from TOLEMAN_API_TOKEN at startup.

  "streamable-http" -- runs as a persistent network service any MCP
  client can connect to directly (no local install), e.g. behind Caddy at
  https://toleman-api.<domain>/mcp/. Genuinely multi-tenant: many different
  callers, each with their own token, can be connected at once, so there
  is no single fixed token here. Every tool call instead reads its own
  `Authorization: Bearer <token>` straight off the incoming HTTP request
  (`ctx.request_context.request.headers`, populated by the `mcp` package's
  Streamable HTTP transport per request) and uses that -- exactly the
  token a caller authenticated their MCP connection with, same as any
  other public-API client. `stateless_http=True` because there is no
  reason for this server to pin a caller to one worker/session: every
  request already carries everything it needs (its own bearer token) to
  be handled independently.

A note on `mcp`'s own CVEs (checked at pin time, mcp==1.30.0, via
`pip-audit`): none open against this package at this version. Re-check
before bumping -- unlike the original stdio-only version of this file,
the HTTP transport is now a real code path here, not something
Streamable-HTTP-specific CVEs could be waved off as irrelevant to.
"""
import os
import time

import httpx
from mcp.server.fastmcp import Context, FastMCP
from mcp.server.fastmcp.exceptions import ToolError

TRANSPORT = os.environ.get("TOLEMAN_MCP_TRANSPORT", "stdio")
TOLEMAN_API_URL = os.environ.get("TOLEMAN_API_URL", "http://localhost:8000").rstrip("/")
# Only meaningful for stdio: the one token this whole process authenticates
# as. Streamable-HTTP mode is multi-tenant (see module docstring) and reads
# a token per-request instead, so it's fine -- expected, even -- for this to
# be unset when TRANSPORT != "stdio".
TOLEMAN_API_TOKEN = os.environ.get("TOLEMAN_API_TOKEN")

if TRANSPORT == "stdio" and not TOLEMAN_API_TOKEN:
    raise RuntimeError(
        "TOLEMAN_API_TOKEN is required for stdio mode, create a personal access token at "
        "Settings > Workspace > API Tokens in your Toleman instance and set it "
        "as an env var for this server."
    )

mcp = FastMCP(
    "toleman",
    host=os.environ.get("TOLEMAN_MCP_HOST", "127.0.0.1"),
    port=int(os.environ.get("TOLEMAN_MCP_PORT", "8080")),
    stateless_http=True,
)


def _resolve_token(ctx: Context) -> str:
    """The token this call authenticates to Toleman's public API with.

    In streamable-http mode, read straight off the incoming request's own
    Authorization header -- see the module docstring for why there's no
    single server-wide token in that mode. In stdio mode there's no HTTP
    request at all (`ctx.request_context.request` is None), so this falls
    back to the one token the whole process was started with.
    """
    request_context = ctx.request_context
    request = request_context.request if request_context is not None else None
    if request is not None:
        auth_header = request.headers.get("authorization", "")
        if not auth_header.lower().startswith("bearer "):
            raise ToolError(
                "This MCP connection is missing an `Authorization: Bearer <token>` header -- "
                "create a personal access token in Toleman (Settings > Workspace > API Tokens) "
                "and pass it when connecting."
            )
        return auth_header.split(" ", 1)[1].strip()
    if not TOLEMAN_API_TOKEN:
        raise ToolError("TOLEMAN_API_TOKEN is required when running over stdio.")
    return TOLEMAN_API_TOKEN


def _resolve_agent(ctx: Context) -> str:
    """Best-effort identity of the *software* making this call (Claude
    Code, Claude Desktop, some other MCP client, ...), forwarded to
    Toleman as X-MCP-Agent so app.core.mcp_audit's audit log can show more
    than just "some token was used" -- see McpAuditLog's own docstring.

    In stdio mode, `ctx.request_context.session.client_params` is the real
    thing: stdio does one genuine MCP `initialize` handshake per process
    lifetime, and the client's declared clientInfo (name/version) lands
    there. In streamable-http mode it's unreliable -- this server runs
    with `stateless_http=True` (module docstring explains why), which
    constructs each request's ServerSession already marked initialized
    (see mcp.server.session.ServerSession.__init__), so the real
    `initialize` request is never actually processed for an individual
    tool-call request and client_params stays None. The Authorization
    header proves a request is from *someone*, but nothing at the MCP
    protocol layer says *what software* sent it in this mode -- so this
    falls back to the plain HTTP User-Agent header instead, which every
    HTTP client sends regardless of MCP-level session state."""
    request_context = ctx.request_context
    request = request_context.request if request_context is not None else None
    if request is not None:
        return request.headers.get("user-agent", "unknown")
    client_params = request_context.session.client_params if request_context is not None else None
    if client_params is not None:
        return f"{client_params.clientInfo.name}/{client_params.clientInfo.version}"
    return "unknown"


def _client(token: str, agent: str) -> httpx.Client:
    return httpx.Client(
        base_url=f"{TOLEMAN_API_URL}/api/public/v1",
        headers={"Authorization": f"Bearer {token}", "X-MCP-Agent": agent},
        timeout=30.0,
    )


@mcp.tool()
def list_targets(ctx: Context) -> list[dict]:
    """List every target (scanned repo) in workspaces this token can access."""
    with _client(_resolve_token(ctx), _resolve_agent(ctx)) as c:
        r = c.get("/targets")
        r.raise_for_status()
        return r.json()


@mcp.tool()
def list_findings(
    ctx: Context,
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
    with _client(_resolve_token(ctx), _resolve_agent(ctx)) as c:
        r = c.get("/findings", params=params)
        r.raise_for_status()
        return r.json()


@mcp.tool()
def get_finding(ctx: Context, finding_id: int) -> dict:
    """Get full detail for a single finding by id."""
    with _client(_resolve_token(ctx), _resolve_agent(ctx)) as c:
        r = c.get(f"/findings/{finding_id}")
        r.raise_for_status()
        return r.json()


@mcp.tool()
def get_scan_status(ctx: Context, scan_id: int) -> dict:
    """Get a scan's current status (running/completed/failed) and, once
    settled, its findings count and any error message."""
    with _client(_resolve_token(ctx), _resolve_agent(ctx)) as c:
        r = c.get(f"/scans/{scan_id}")
        r.raise_for_status()
        return r.json()


@mcp.tool()
def trigger_scan(ctx: Context, target_id: int, tool: str) -> dict:
    """Trigger a native scan (semgrep/trivy/gitleaks/gosec) against a
    target. Requires a read_write-scoped token; a read-only token gets
    a clear permission error, not a silent no-op. Returns immediately with
    a scan_id; poll get_scan_status(scan_id) for the result."""
    with _client(_resolve_token(ctx), _resolve_agent(ctx)) as c:
        r = c.post("/scans", params={"target_id": target_id, "tool": tool})
        r.raise_for_status()
        return r.json()


@mcp.tool()
def suggest_fix(ctx: Context, finding_id: int) -> dict:
    """Get a fix recommendation for an existing finding -- AI-generated
    when Toleman has a provider configured, deterministic (OSV upgrade
    version, category-specific guidance) otherwise -- and, where a real
    patch could be built and verified against the file as it actually
    exists in the repo, a diff to review. Never writes anywhere: call
    raise_fix_pr with the exact fields this returns to actually open a PR
    for it. Requires only a read-scoped token.

    If `diff` comes back None (no AI provider configured on Toleman and no
    deterministic patch applied -- common for SAST findings when nothing's
    set up under Admin > Global Integrations), you don't need Toleman's own
    AI at all: read `recommendation` plus the finding's file_path/
    line_start/line_end (get_finding) and the target's repo_url/
    default_branch (get_target/list_targets), fix the flagged code yourself
    -- you already have the repo, if this is a Claude Code session working
    in it -- and call raise_fix_pr with strategy="mcp_client" and the full
    corrected file content. Toleman still opens the PR (it holds the GitHub
    App installation token); only the patch generation moves to you.

    If you conclude this finding is a false positive, already-mitigated,
    or an accepted risk rather than something to fix: do NOT "fix" it by
    adding a suppression comment (# nosemgrep, # noqa, # nosec,
    eslint-disable, checkov:skip, etc.) -- that silences the *scanner*,
    not the issue, so the finding vanishes from every future scan with no
    review and no audit trail. Toleman rejects a raise_fix_pr patch that
    does this anyway (see raise_fix_pr's docstring), so it isn't a
    shortcut, just a wasted call. Tell the user what you found and ask
    them to triage it themselves in Toleman (Findings page -> Triage ->
    False Positive / Accepted Risk / Won't Fix) -- that's a real,
    audited decision the platform already supports; nothing here does it
    on their behalf."""
    with _client(_resolve_token(ctx), _resolve_agent(ctx)) as c:
        r = c.post(f"/findings/{finding_id}/suggest-fix")
        r.raise_for_status()
        return r.json()


@mcp.tool()
def raise_fix_pr(
    ctx: Context,
    finding_id: int,
    file_path: str,
    new_content: str,
    ref: str,
    strategy: str,
    explanation: str = "",
) -> dict:
    """Opens a PR for a patch to `file_path` (which must match the
    finding's own file_path) on branch `ref`, committing `new_content` as
    that file's full new contents. Two ways to call this:

    1. Usual case: pass file_path/new_content/ref/strategy/explanation back
       *exactly* as a prior suggest_fix call returned them (strategy will
       be "ai" or "deterministic_sca"), so what's committed is guaranteed
       to match the diff already reviewed, not a freshly (and possibly
       differently) regenerated one.
    2. suggest_fix came back with diff=None (no Toleman AI provider
       configured, no deterministic patch available): read the file
       yourself, write the full corrected content, and call this with
       strategy="mcp_client" -- Toleman still opens the PR via its GitHub
       App installation token, it just isn't the one that generated the
       patch.

    Requires a read_write-scoped token, since this writes a branch/PR to
    the target's real GitHub repo.

    `new_content` must actually fix the issue: Toleman rejects (400) any
    patch that adds a scanner-suppression comment (# nosemgrep, # noqa,
    # nosec, eslint-disable, checkov:skip, ...) on the finding's own
    flagged line(s), whatever the strategy. If that's what you were about
    to do, stop -- see suggest_fix's docstring for what to do instead."""
    with _client(_resolve_token(ctx), _resolve_agent(ctx)) as c:
        r = c.post(
            f"/findings/{finding_id}/raise-pr",
            json={
                "file_path": file_path,
                "new_content": new_content,
                "ref": ref,
                "strategy": strategy,
                "explanation": explanation,
            },
        )
        r.raise_for_status()
        return r.json()


@mcp.tool()
def check_code_for_vulnerabilities(
    ctx: Context,
    filename: str,
    content: str,
    tools: list[str] | None = None,
    timeout_seconds: int = 30,
) -> dict:
    """Scan a code snippet for vulnerabilities BEFORE it's written to a
    real file or committed -- call this while drafting code, to catch a
    problem as it's introduced rather than waiting for a later scan of the
    finished repo to find it. `filename` only needs a realistic extension
    (e.g. "app.py"), it does not need to exist anywhere.

    Runs semgrep (SAST) + gitleaks (secrets) by default -- the common
    "did I just write something dangerous" case; pass `tools` (any of
    semgrep, semgrep-llm, gitleaks, checkov, tfsec, trivy-license, gosec)
    for something more specific, e.g. ["checkov", "tfsec"] for a Terraform
    snippet. Blocks until the scan completes or `timeout_seconds` elapses
    (usually a couple of seconds; semgrep's rule fetch on a cold cache is
    the one thing that can make it slower). Returns {"findings": [...]} --
    an empty list means clean, not "not checked." Requires only a
    read-scoped token; nothing here is persisted as a real Finding or
    tied to any target."""
    with _client(_resolve_token(ctx), _resolve_agent(ctx)) as c:
        payload: dict = {"filename": filename, "content": content}
        if tools is not None:
            payload["tools"] = tools
        r = c.post("/scan-snippet", json=payload)
        r.raise_for_status()
        run_id = r.json()["run_id"]

        deadline = time.monotonic() + timeout_seconds
        while True:
            poll = c.get(f"/scan-snippet/{run_id}")
            poll.raise_for_status()
            body = poll.json()
            if body["status"] == "completed":
                return {"findings": body["findings"]}
            if body["status"] == "failed":
                raise ToolError(f"snippet scan failed: {body['error']}")
            if time.monotonic() >= deadline:
                raise ToolError(
                    f"snippet scan timed out after {timeout_seconds}s (run_id={run_id}); "
                    "it may still be running -- try again in a moment"
                )
            time.sleep(1)


if __name__ == "__main__":
    mcp.run(transport="streamable-http" if TRANSPORT == "streamable-http" else "stdio")
