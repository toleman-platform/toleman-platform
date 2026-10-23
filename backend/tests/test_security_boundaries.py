"""Adversarial requests must exercise the same authorization as normal clients."""

from unittest.mock import Mock
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import pytest
import yaml
from sqlmodel import Session

from tests.conftest import _assign, _login, _make_finding, _make_target, _make_workspace
from app.core.config import Settings, settings, validate_production_secrets
from app.core.rate_limit import _reset_for_tests
from app.models.models import Target, UserRole, WorkspaceRole
from app.scanners import runner


@pytest.fixture(autouse=True)
def reset_limits():
    _reset_for_tests()
    yield
    _reset_for_tests()


@pytest.mark.parametrize("victim_role", [None, WorkspaceRole.VIEWER])
def test_target_write_cannot_authorize_against_query_workspace(client, engine, victim_role):
    own = _make_workspace(engine, "own")
    other = _make_workspace(engine, "other")
    target_id = _make_target(engine, other)
    _, uid = _login(client, engine)
    _assign(engine, uid, own, WorkspaceRole.DEVELOPER)
    if victim_role:
        _assign(engine, uid, other, victim_role)

    assert client.patch(f"/api/targets/{target_id}", json={"label": "Prod"}).status_code == 403
    response = client.patch(
        f"/api/targets/{target_id}?workspace_id={own}", json={"label": "Prod"}
    )
    assert response.status_code == 403
    with Session(engine) as session:
        assert session.get(Target, target_id).label != "Prod"


@pytest.mark.parametrize("override", ["workspace_id", "target_id"])
def test_finding_write_cannot_authorize_against_query_resource(client, engine, override):
    own = _make_workspace(engine, "own")
    other = _make_workspace(engine, "other")
    own_target = _make_target(engine, own, "own-target")
    other_target = _make_target(engine, other, "other-target")
    finding_id = _make_finding(engine, other_target)
    _, uid = _login(client, engine)
    _assign(engine, uid, own, WorkspaceRole.DEVELOPER)

    value = own if override == "workspace_id" else own_target
    response = client.post(
        f"/api/findings/{finding_id}/triage?to_state=Mitigated&{override}={value}"
    )
    assert response.status_code == 403


@pytest.mark.parametrize("path", ["workspace", "target"])
@pytest.mark.parametrize("role,expected", [(WorkspaceRole.VIEWER, 403), (WorkspaceRole.DEVELOPER, 200)])
def test_ingestion_key_requires_write_role(client, engine, path, role, expected):
    workspace_id = _make_workspace(engine)
    target_id = _make_target(engine, workspace_id)
    _, uid = _login(client, engine)
    _assign(engine, uid, workspace_id, role)
    url = (f"/api/workspaces/{workspace_id}/key" if path == "workspace"
           else f"/api/targets/{target_id}/workspace-key")
    response = client.get(url)
    assert response.status_code == expected
    if expected != 200:
        assert "api_key" not in response.json()


@pytest.mark.parametrize("action", ["scan", "raise-pr"])
@pytest.mark.parametrize("role,expected", [(WorkspaceRole.VIEWER, 403), (WorkspaceRole.DEVELOPER, 200)])
def test_personal_token_write_scope_cannot_elevate_workspace_role(client, engine, monkeypatch, action, role, expected):
    workspace_id = _make_workspace(engine)
    target_id = _make_target(engine, workspace_id)
    finding_id = _make_finding(engine, target_id)
    _, uid = _login(client, engine)
    _assign(engine, uid, workspace_id, role)
    token = client.post("/api/api-tokens", json={"name": "test", "scope": "read_write"}).json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    scan = Mock()
    raise_pr = Mock(return_value={"pr_url": "https://github.com/acme/repo/pull/1", "pr_number": 1, "branch": "fix"})
    monkeypatch.setattr("app.api.public_api.run_scan.delay", scan)
    monkeypatch.setattr("app.api.public_api.open_fix_pr", raise_pr)
    if action == "scan":
        response = client.post(f"/api/public/v1/scans?target_id={target_id}&tool=semgrep", headers=headers)
        effect = scan
    else:
        response = client.post(f"/api/public/v1/findings/{finding_id}/raise-pr", headers=headers, json={
            "file_path": "app/main.py", "new_content": "fixed = True", "ref": "main", "strategy": "mcp_client",
        })
        effect = raise_pr
    assert response.status_code == expected
    assert effect.call_count == (1 if expected == 200 else 0)


@pytest.mark.parametrize("surface", ["web-list", "web-detail", "api-list", "api-detail"])
def test_target_serialization_excludes_stored_credentials(client, engine, surface):
    workspace_id = _make_workspace(engine)
    target_id = _make_target(engine, workspace_id)
    with Session(engine) as session:
        target = session.get(Target, target_id)
        target.client_cert_ciphertext = "encrypted-cert-canary"
        target.client_key_ciphertext = "encrypted-key-canary"
        target.api_auth_header_value_ciphertext = "encrypted-header-canary"
        session.add(target)
        session.commit()
    _, uid = _login(client, engine)
    _assign(engine, uid, workspace_id, WorkspaceRole.VIEWER)
    if surface.startswith("api"):
        token = client.post("/api/api-tokens", json={"name": "read"}).json()["token"]
        url = "/api/public/v1/targets"
        headers = {"Authorization": f"Bearer {token}"}
    else:
        url, headers = "/api/targets", {}
    if surface.endswith("detail"):
        url += f"/{target_id}"
    response = client.get(url, headers=headers)
    assert response.status_code == 200
    for secret in ("encrypted-cert-canary", "encrypted-key-canary", "encrypted-header-canary"):
        assert secret not in response.text
    if surface == "web-detail":
        assert response.json()["client_cert_set"] is True
        assert response.json()["client_key_set"] is True


@pytest.mark.parametrize("field", ["session_secret", "admin_password"])
@pytest.mark.parametrize("value", ["", "   "])
def test_production_rejects_empty_secrets(field, value):
    kwargs = {"environment": "production", "session_secret": "test-signing-secret", "admin_password": "test-admin-password"}
    kwargs[field] = value
    with pytest.raises(RuntimeError, match="SESSION_SECRET|ADMIN_PASSWORD"):
        validate_production_secrets(Settings(_env_file=None, **kwargs))


@pytest.fixture()
def internal_http_service():
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(("GET", self.path))
            self.send_response(200)
            self.end_headers()

        def do_CONNECT(self):
            requests.append(("CONNECT", self.path))
            self.send_response(403)
            self.end_headers()

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=lambda: server.serve_forever(poll_interval=0.05), daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@pytest.mark.parametrize("field", ["api_base_url", "clone_proxy_url"])
def test_member_cannot_choose_worker_network_destination(client, engine, monkeypatch, tmp_path, internal_http_service, field):
    url, requests = internal_http_service
    workspace_id = _make_workspace(engine)
    target_id = _make_target(engine, workspace_id)
    _, uid = _login(client, engine)
    _assign(engine, uid, workspace_id, WorkspaceRole.DEVELOPER)
    response = client.patch(f"/api/targets/{target_id}", json={field: url})
    # On the vulnerable implementation, verify that the saved destination
    # really receives a server-side request. Only our loopback canary is used.
    if response.status_code == 200:
        if field == "api_base_url":
            assert client.put(f"/api/api-scan/{target_id}/credential", json={
                "header_name": "X-Audit", "header_value": "harmless-canary",
            }).status_code == 200
            assert client.post(f"/api/api-scan/{target_id}/credential/test").status_code == 200
        else:
            monkeypatch.setattr(settings, "scan_workdir", str(tmp_path / "clones"))
            monkeypatch.setenv("NO_PROXY", "")
            monkeypatch.setenv("no_proxy", "")
            with pytest.raises(Exception):
                runner.clone_repo("https://github.com/acme/repo", "main", proxy_url=url)
    assert response.status_code == 403, f"destination accepted; outbound canary requests: {requests}"
    assert requests == []


@pytest.mark.parametrize("service", ["backend", "celery-worker"])
def test_compose_forwards_production_environment(service):
    compose = yaml.safe_load((Path(__file__).resolve().parents[2] / "docker-compose.yml").read_text())
    assert compose["services"][service]["environment"].get("ENVIRONMENT") == "${ENVIRONMENT:-local}"


@pytest.mark.parametrize("field", ["api_base_url", "clone_proxy_url"])
@pytest.mark.parametrize("surface", ["web", "public"])
def test_destination_credentials_are_not_returned_to_viewers(client, engine, field, surface):
    workspace_id = _make_workspace(engine)
    target_id = _make_target(engine, workspace_id)
    with Session(engine) as session:
        target = session.get(Target, target_id)
        setattr(target, field, "https://audit-user:credential-canary@proxy.example.test:8443/path")
        session.add(target)
        session.commit()
    _, uid = _login(client, engine)
    _assign(engine, uid, workspace_id, WorkspaceRole.VIEWER)
    if surface == "public":
        token = client.post("/api/api-tokens", json={"name": "read"}).json()["token"]
        response = client.get(f"/api/public/v1/targets/{target_id}", headers={"Authorization": f"Bearer {token}"})
    else:
        response = client.get(f"/api/targets/{target_id}")
    assert response.status_code == 200
    assert "credential-canary" not in response.text
    assert "audit-user" not in response.text
    assert response.json()[field] == "https://proxy.example.test:8443/path"


@pytest.mark.parametrize("field", ["api_base_url", "clone_proxy_url"])
def test_destination_credentials_cannot_be_stored_in_plaintext(client, engine, field):
    workspace_id = _make_workspace(engine)
    target_id = _make_target(engine, workspace_id)
    _login(client, engine, role=UserRole.ADMIN)
    response = client.patch(f"/api/targets/{target_id}", json={
        field: "https://audit-user:credential-canary@proxy.example.test",
    })
    assert response.status_code == 422


@pytest.mark.parametrize("field", ["api_base_url", "clone_proxy_url"])
def test_administrator_can_configure_network_destination(client, engine, field):
    workspace_id = _make_workspace(engine)
    target_id = _make_target(engine, workspace_id)
    _login(client, engine, role=UserRole.ADMIN)
    response = client.patch(f"/api/targets/{target_id}", json={field: "https://service.example.test:8443/path"})
    assert response.status_code == 200
    assert response.json()[field] == "https://service.example.test:8443/path"
