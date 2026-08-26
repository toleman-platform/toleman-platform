"""Tests for the Toleman MCP server (#108) -- mocked HTTP, no live backend
needed. Verifies each tool builds the right request against the public API
(auth header, path, params) and returns the parsed response, plus that
TOLEMAN_API_TOKEN is actually required at import time.
"""
import os
import subprocess
import sys

import httpx
import pytest
import respx

os.environ["TOLEMAN_API_TOKEN"] = "toleman_pat_test"
os.environ["TOLEMAN_API_URL"] = "http://localhost:8000"

import server  # noqa: E402


@respx.mock
def test_list_targets_hits_correct_endpoint_with_bearer_auth():
    route = respx.get("http://localhost:8000/api/public/v1/targets").mock(
        return_value=httpx.Response(200, json=[{"id": 1, "name": "repo"}])
    )
    result = server.list_targets()
    assert result == [{"id": 1, "name": "repo"}]
    assert route.calls.last.request.headers["authorization"] == "Bearer toleman_pat_test"


@respx.mock
def test_list_findings_passes_filters_as_query_params():
    route = respx.get("http://localhost:8000/api/public/v1/findings").mock(
        return_value=httpx.Response(200, json={"items": [], "total": 0})
    )
    server.list_findings(target_id=4, severity="High", state="Open", page=2, page_size=10)
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
    result = server.get_finding(42)
    assert result["id"] == 42


@respx.mock
def test_get_scan_status_hits_correct_id():
    respx.get("http://localhost:8000/api/public/v1/scans/7").mock(
        return_value=httpx.Response(200, json={"id": 7, "status": "completed"})
    )
    result = server.get_scan_status(7)
    assert result["status"] == "completed"


@respx.mock
def test_trigger_scan_posts_with_query_params():
    route = respx.post("http://localhost:8000/api/public/v1/scans").mock(
        return_value=httpx.Response(200, json={"scan_id": 99, "status": "running"})
    )
    result = server.trigger_scan(target_id=6, tool="semgrep")
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
        server.trigger_scan(target_id=6, tool="semgrep")


def test_server_refuses_to_start_without_token():
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
