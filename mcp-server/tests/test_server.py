"""Tests for the Toleman MCP server (#108, extended by a #108 follow-up for
fix actions + pre-commit checking), mocked HTTP, no live backend needed.

Verifies each tool builds the right request against the public API (auth
header, path, params) and returns the parsed response; that TOLEMAN_API_TOKEN
is actually required at import time in stdio mode but NOT in streamable-http
mode; and that _resolve_token reads the right token from the right place in
each transport (module-level env var for stdio, the incoming HTTP request's
own Authorization header for streamable-http -- see server.py's module
docstring for why).
"""
import os
import subprocess
import sys
from types import SimpleNamespace

import httpx
import pytest
import respx

os.environ["TOLEMAN_API_TOKEN"] = "toleman_pat_test"
os.environ["TOLEMAN_API_URL"] = "http://localhost:8000"

import server  # noqa: E402


def _stdio_ctx(client_name: str = "claude-code", client_version: str = "1.0.0"):
    """A Context with no live HTTP request, same shape stdio mode gets.
    session.client_params IS populated here -- stdio does one real MCP
    `initialize` handshake per process lifetime, so the client's declared
    clientInfo is genuinely available (see server.py's _resolve_agent)."""
    client_params = SimpleNamespace(clientInfo=SimpleNamespace(name=client_name, version=client_version))
    return SimpleNamespace(
        request_context=SimpleNamespace(request=None, session=SimpleNamespace(client_params=client_params))
    )


def _http_ctx(authorization: str | None, user_agent: str | None = "test-mcp-client/1.0"):
    """A Context carrying a fake incoming HTTP request, same shape
    streamable-http mode gets (see server.py's _resolve_token/_resolve_agent).
    session.client_params is None here -- this server runs with
    stateless_http=True, which never actually processes a real `initialize`
    request per tool call (see _resolve_agent's docstring), so a real
    deployment never has it populated in this mode either."""
    headers = {} if authorization is None else {"authorization": authorization}
    if user_agent is not None:
        headers["user-agent"] = user_agent
    return SimpleNamespace(
        request_context=SimpleNamespace(
            request=SimpleNamespace(headers=headers), session=SimpleNamespace(client_params=None)
        )
    )


STDIO_CTX = _stdio_ctx()


@respx.mock
def test_list_targets_hits_correct_endpoint_with_bearer_auth():
    route = respx.get("http://localhost:8000/api/public/v1/targets").mock(
        return_value=httpx.Response(200, json=[{"id": 1, "name": "repo"}])
    )
    result = server.list_targets(STDIO_CTX)
    assert result == [{"id": 1, "name": "repo"}]
    assert route.calls.last.request.headers["authorization"] == "Bearer toleman_pat_test"


@respx.mock
def test_list_findings_passes_filters_as_query_params():
    route = respx.get("http://localhost:8000/api/public/v1/findings").mock(
        return_value=httpx.Response(200, json={"items": [], "total": 0})
    )
    server.list_findings(STDIO_CTX, target_id=4, severity="High", state="Open", page=2, page_size=10)
    request = route.calls.last.request
    assert request.url.params["target_id"] == "4"
    assert request.url.params["severity"] == "High"
    assert request.url.params["state"] == "Open"
    assert request.url.params["page"] == "2"
    assert request.url.params["page_size"] == "10"


@respx.mock
def test_get_finding_hits_correct_id():
    respx.get("http://localhost:8000/api/public/v1/findings/42").mock(
        return_value=httpx.Response(200, json={"id": 42, "title": "t"})
    )
    result = server.get_finding(STDIO_CTX, 42)
    assert result["id"] == 42


@respx.mock
def test_get_scan_status_hits_correct_id():
    respx.get("http://localhost:8000/api/public/v1/scans/7").mock(
        return_value=httpx.Response(200, json={"id": 7, "status": "completed"})
    )
    result = server.get_scan_status(STDIO_CTX, 7)
    assert result["status"] == "completed"


@respx.mock
def test_trigger_scan_posts_with_query_params():
    route = respx.post("http://localhost:8000/api/public/v1/scans").mock(
        return_value=httpx.Response(200, json={"scan_id": 99, "status": "running"})
    )
    result = server.trigger_scan(STDIO_CTX, target_id=6, tool="semgrep")
    assert result == {"scan_id": 99, "status": "running"}
    request = route.calls.last.request
    assert request.url.params["target_id"] == "6"
    assert request.url.params["tool"] == "semgrep"


@respx.mock
def test_write_scope_rejection_propagates_as_http_error():
    respx.post("http://localhost:8000/api/public/v1/scans").mock(
        return_value=httpx.Response(403, json={"detail": "this token is read-only"})
    )
    with pytest.raises(httpx.HTTPStatusError):
        server.trigger_scan(STDIO_CTX, target_id=6, tool="semgrep")


# ---------------------------------------------------------------------------
# suggest_fix / raise_fix_pr
# ---------------------------------------------------------------------------


@respx.mock
def test_suggest_fix_hits_correct_endpoint():
    respx.post("http://localhost:8000/api/public/v1/findings/12/suggest-fix").mock(
        return_value=httpx.Response(200, json={"recommendation": "Upgrade the package.", "diff": None})
    )
    result = server.suggest_fix(STDIO_CTX, 12)
    assert result["recommendation"] == "Upgrade the package."


@respx.mock
def test_raise_fix_pr_sends_the_exact_patch_fields():
    route = respx.post("http://localhost:8000/api/public/v1/findings/12/raise-pr").mock(
        return_value=httpx.Response(200, json={"pr_url": "https://github.com/a/b/pull/1", "pr_number": 1, "branch": "toleman/fix-1"})
    )
    result = server.raise_fix_pr(
        STDIO_CTX, 12, file_path="requirements.txt", new_content="x==2.0\n", ref="main",
        strategy="deterministic_sca", explanation="Upgrade x.",
    )
    assert result["pr_number"] == 1
    sent = route.calls.last.request.content
    import json
    body = json.loads(sent)
    assert body == {
        "file_path": "requirements.txt", "new_content": "x==2.0\n", "ref": "main",
        "strategy": "deterministic_sca", "explanation": "Upgrade x.",
    }


@respx.mock
def test_raise_fix_pr_accepts_mcp_client_strategy():
    """strategy is a plain str here (the backend's Literal is what actually
    gates the allowed values) -- this documents that "mcp_client" passes
    through unchanged, for the case where suggest_fix returned no diff and
    the calling agent (e.g. Claude Code, with the repo already checked out)
    read the flagged file and wrote the fix itself."""
    route = respx.post("http://localhost:8000/api/public/v1/findings/12/raise-pr").mock(
        return_value=httpx.Response(200, json={"pr_url": "https://github.com/a/b/pull/2", "pr_number": 2, "branch": "toleman/fix-2"})
    )
    result = server.raise_fix_pr(
        STDIO_CTX, 12, file_path="app.py", new_content="fixed content\n", ref="main",
        strategy="mcp_client", explanation="Read app.py directly and fixed the flagged line.",
    )
    assert result["pr_number"] == 2
    import json
    body = json.loads(route.calls.last.request.content)
    assert body["strategy"] == "mcp_client"


@respx.mock
def test_raise_fix_pr_propagates_502_as_http_error():
    respx.post("http://localhost:8000/api/public/v1/findings/12/raise-pr").mock(
        return_value=httpx.Response(502, json={"detail": "no GitHub App installed"})
    )
    with pytest.raises(httpx.HTTPStatusError):
        server.raise_fix_pr(STDIO_CTX, 12, file_path="x", new_content="x", ref="main", strategy="ai")


# ---------------------------------------------------------------------------
# check_code_for_vulnerabilities
# ---------------------------------------------------------------------------


@respx.mock
def test_check_code_polls_until_completed_and_returns_findings():
    respx.post("http://localhost:8000/api/public/v1/scan-snippet").mock(
        return_value=httpx.Response(200, json={"run_id": 5, "status": "running"})
    )
    poll_route = respx.get("http://localhost:8000/api/public/v1/scan-snippet/5")
    poll_route.side_effect = [
        httpx.Response(200, json={"id": 5, "status": "running", "filename": "app.py", "findings": None, "error": ""}),
        httpx.Response(200, json={"id": 5, "status": "completed", "filename": "app.py", "findings": [{"rule_id": "r1"}], "error": ""}),
    ]
    result = server.check_code_for_vulnerabilities(
        STDIO_CTX, filename="app.py", content="os.system(cmd)", timeout_seconds=5
    )
    assert result == {"findings": [{"rule_id": "r1"}]}


@respx.mock
def test_check_code_passes_custom_tools():
    route = respx.post("http://localhost:8000/api/public/v1/scan-snippet").mock(
        return_value=httpx.Response(200, json={"run_id": 6, "status": "running"})
    )
    respx.get("http://localhost:8000/api/public/v1/scan-snippet/6").mock(
        return_value=httpx.Response(200, json={"id": 6, "status": "completed", "filename": "main.tf", "findings": [], "error": ""})
    )
    server.check_code_for_vulnerabilities(
        STDIO_CTX, filename="main.tf", content="resource \"x\" {}", tools=["checkov", "tfsec"], timeout_seconds=5
    )
    import json
    assert json.loads(route.calls.last.request.content)["tools"] == ["checkov", "tfsec"]


@respx.mock
def test_check_code_raises_tool_error_on_failed_scan():
    respx.post("http://localhost:8000/api/public/v1/scan-snippet").mock(
        return_value=httpx.Response(200, json={"run_id": 7, "status": "running"})
    )
    respx.get("http://localhost:8000/api/public/v1/scan-snippet/7").mock(
        return_value=httpx.Response(200, json={"id": 7, "status": "failed", "filename": "app.py", "findings": None, "error": "semgrep exploded"})
    )
    from mcp.server.fastmcp.exceptions import ToolError
    with pytest.raises(ToolError, match="semgrep exploded"):
        server.check_code_for_vulnerabilities(STDIO_CTX, filename="app.py", content="x", timeout_seconds=5)


@respx.mock
def test_check_code_raises_tool_error_on_timeout(monkeypatch):
    respx.post("http://localhost:8000/api/public/v1/scan-snippet").mock(
        return_value=httpx.Response(200, json={"run_id": 8, "status": "running"})
    )
    respx.get("http://localhost:8000/api/public/v1/scan-snippet/8").mock(
        return_value=httpx.Response(200, json={"id": 8, "status": "running", "filename": "app.py", "findings": None, "error": ""})
    )
    monkeypatch.setattr(server.time, "sleep", lambda s: None)
    from mcp.server.fastmcp.exceptions import ToolError
    with pytest.raises(ToolError, match="timed out"):
        server.check_code_for_vulnerabilities(STDIO_CTX, filename="app.py", content="x", timeout_seconds=0)


# ---------------------------------------------------------------------------
# _resolve_token: stdio (module-level env var) vs streamable-http (per-
# request Authorization header) -- the core of the multi-tenant remote
# transport, see server.py's module docstring.
# ---------------------------------------------------------------------------


def test_resolve_token_uses_the_env_var_over_stdio():
    assert server._resolve_token(_stdio_ctx()) == "toleman_pat_test"


def test_resolve_token_uses_the_incoming_requests_own_bearer_header_over_http():
    assert server._resolve_token(_http_ctx("Bearer some-other-users-token")) == "some-other-users-token"


def test_resolve_token_is_case_insensitive_on_the_bearer_prefix():
    assert server._resolve_token(_http_ctx("bearer lowercase-token")) == "lowercase-token"


def test_resolve_token_rejects_a_missing_authorization_header_over_http():
    from mcp.server.fastmcp.exceptions import ToolError
    with pytest.raises(ToolError, match="Authorization"):
        server._resolve_token(_http_ctx(None))


def test_resolve_token_rejects_a_non_bearer_authorization_header_over_http():
    from mcp.server.fastmcp.exceptions import ToolError
    with pytest.raises(ToolError, match="Authorization"):
        server._resolve_token(_http_ctx("Basic dXNlcjpwYXNz"))


# ---------------------------------------------------------------------------
# _resolve_agent: stdio (real MCP clientInfo, since stdio does one genuine
# `initialize` handshake per process) vs streamable-http (User-Agent header
# -- client_params is never populated there, this server runs with
# stateless_http=True, see server.py's _resolve_agent docstring).
# ---------------------------------------------------------------------------


def test_resolve_agent_uses_mcp_client_info_over_stdio():
    assert server._resolve_agent(_stdio_ctx("claude-code", "2.1.268")) == "claude-code/2.1.268"


def test_resolve_agent_uses_the_user_agent_header_over_http():
    assert server._resolve_agent(_http_ctx("Bearer x", user_agent="claude-connector/1.0")) == "claude-connector/1.0"


def test_resolve_agent_falls_back_to_unknown_with_no_user_agent_header():
    assert server._resolve_agent(_http_ctx("Bearer x", user_agent=None)) == "unknown"


@respx.mock
def test_list_targets_forwards_agent_as_a_header():
    route = respx.get("http://localhost:8000/api/public/v1/targets").mock(return_value=httpx.Response(200, json=[]))
    server.list_targets(_http_ctx("Bearer x", user_agent="claude-code/2.1.268"))
    assert route.calls.last.request.headers["x-mcp-agent"] == "claude-code/2.1.268"


@respx.mock
def test_two_concurrent_http_callers_each_use_their_own_token():
    """The whole point of per-request token resolution: two different
    connected callers on the same running server must never share or leak
    each other's token."""
    route = respx.get("http://localhost:8000/api/public/v1/targets").mock(
        return_value=httpx.Response(200, json=[])
    )
    server.list_targets(_http_ctx("Bearer token-for-alice"))
    server.list_targets(_http_ctx("Bearer token-for-bob"))
    sent_tokens = [call.request.headers["authorization"] for call in route.calls]
    assert sent_tokens == ["Bearer token-for-alice", "Bearer token-for-bob"]


# ---------------------------------------------------------------------------
# Startup requirements per transport
# ---------------------------------------------------------------------------


def test_server_refuses_to_start_without_token_in_stdio_mode():
    env = {k: v for k, v in os.environ.items() if k != "TOLEMAN_API_TOKEN"}
    result = subprocess.run(
        [sys.executable, "-c", "import server"],
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "TOLEMAN_API_TOKEN is required" in result.stderr


def test_server_does_not_require_a_token_at_import_time_in_streamable_http_mode():
    """Streamable-http mode is multi-tenant (see module docstring): the
    server process itself needs no fixed token, only each connecting
    caller does, resolved per-request."""
    env = {k: v for k, v in os.environ.items() if k != "TOLEMAN_API_TOKEN"}
    env["TOLEMAN_MCP_TRANSPORT"] = "streamable-http"
    result = subprocess.run(
        [sys.executable, "-c", "import server"],
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
