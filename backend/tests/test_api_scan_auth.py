"""Authenticated active API scanning (#470).

Before this, run_nuclei took a URL list and nothing else, so every probe
was anonymous. Any route behind authentication answered 401, the scan
completed, and it reported zero findings -- an all-clear that was evidence
of nothing. These tests pin the credential path end to end, and pin the
two things about it that are easy to get quietly wrong:

  - the credential never reaches argv, because argv is readable by any
    local process through `ps`; it goes into a 0600 config file instead,
    and the file is deleted afterwards;
  - a credential that cannot be decrypted is an error, not a silent
    fallback to anonymous scanning. The fallback would produce exactly the
    false all-clear this feature exists to prevent, caused by a broken
    encryption key and indistinguishable from a clean API.
"""
import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core.api_scan_targets import ApiScanConfigError, build_scan_headers
from app.core.crypto import encrypt_secret
from app.core.security import create_session_token, hash_password
from app.main import app
from app.models.models import (
    Organization,
    Target,
    User,
    UserRole,
    Workspace,
    WorkspaceMembership,
    WorkspaceRole,
)
from app.scanners import runner


@pytest.fixture()
def engine():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(eng)
    return eng


@pytest.fixture()
def client(engine):
    def override_get_session():
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    original_engine = deps_module.engine
    deps_module.engine = engine
    c = TestClient(app)
    yield c
    app.dependency_overrides.clear()
    deps_module.engine = original_engine


def _make_target(engine, api_base_url="https://api.example.com"):
    with Session(engine) as session:
        org = Organization(name="Acme")
        session.add(org)
        session.commit()
        session.refresh(org)
        ws = Workspace(organization_id=org.id, name="ws", api_key="k")
        session.add(ws)
        session.commit()
        session.refresh(ws)
        t = Target(
            workspace_id=ws.id,
            name="t",
            repo_url="https://github.com/acme/app",
            api_base_url=api_base_url,
        )
        session.add(t)
        session.commit()
        session.refresh(t)
        return t.id, ws.id


def _login_developer(client, engine, workspace_id):
    with Session(engine) as session:
        user = User(
            email=f"dev-{id(object())}@example.com",
            name="Dev",
            password_hash=hash_password("whatever123"),
            role=UserRole.DEVELOPER,
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        session.add(
            WorkspaceMembership(user_id=user.id, workspace_id=workspace_id, role=WorkspaceRole.DEVELOPER)
        )
        session.commit()
        token = create_session_token(user.id, user.token_version)
    client.cookies.set("toleman_session", token)
    return client


# --- build_scan_headers ------------------------------------------------


def test_no_credential_means_anonymous_scanning(engine):
    """Anonymous is a supported mode, not a misconfiguration."""
    target_id, _ = _make_target(engine)
    with Session(engine) as session:
        assert build_scan_headers(session.get(Target, target_id)) == {}


def test_a_stored_credential_is_decrypted_for_the_scan(engine):
    target_id, _ = _make_target(engine)
    with Session(engine) as session:
        target = session.get(Target, target_id)
        target.api_auth_header_name = "Authorization"
        target.api_auth_header_value_ciphertext = encrypt_secret("Bearer s3cret")
        session.add(target)
        session.commit()
        session.refresh(target)

        assert build_scan_headers(target) == {"Authorization": "Bearer s3cret"}


def test_the_stored_value_is_not_the_plaintext(engine):
    """Encrypted at rest, same treatment as the GitHub App private key."""
    target_id, _ = _make_target(engine)
    with Session(engine) as session:
        target = session.get(Target, target_id)
        target.api_auth_header_value_ciphertext = encrypt_secret("Bearer s3cret")
        session.add(target)
        session.commit()
        session.refresh(target)
        assert "Bearer s3cret" not in target.api_auth_header_value_ciphertext


def test_an_undecryptable_credential_fails_loudly(engine):
    """Never fall back to anonymous: that produces a scan which 401s on
    every authenticated route and still reports success."""
    target_id, _ = _make_target(engine)
    with Session(engine) as session:
        target = session.get(Target, target_id)
        target.api_auth_header_name = "Authorization"
        target.api_auth_header_value_ciphertext = "not-a-fernet-token"
        session.add(target)
        session.commit()
        session.refresh(target)

        with pytest.raises(ApiScanConfigError):
            build_scan_headers(target)


# --- the header never reaches argv -------------------------------------


def test_the_credential_goes_into_a_0600_file_and_never_into_argv(monkeypatch, tmp_path):
    """argv is readable by any local process via `ps`. This is the whole
    reason run_nuclei uses nuclei's -config file rather than -H."""
    seen = {}

    def fake_run(cmd, **kwargs):
        seen["cmd"] = list(cmd)
        config_path = cmd[cmd.index("-config") + 1]
        seen["config_contents"] = open(config_path).read()
        seen["config_mode"] = os.stat(config_path).st_mode & 0o777
        seen["config_path"] = config_path

        class Proc:
            returncode = 0
            stdout = ""
            stderr = ""

        return Proc()

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    monkeypatch.setattr(runner, "nuclei_templates_present", lambda: False)

    runner.run_nuclei(["https://api.example.com/x"], headers={"Authorization": "Bearer s3cret"})

    assert "Bearer s3cret" not in " ".join(seen["cmd"])
    assert "Authorization: Bearer s3cret" in seen["config_contents"]
    assert seen["config_mode"] == 0o600
    assert not os.path.exists(seen["config_path"]), "the config file must not outlive the scan"


def test_no_config_flag_when_scanning_anonymously(monkeypatch):
    seen = {}

    def fake_run(cmd, **kwargs):
        seen["cmd"] = list(cmd)

        class Proc:
            returncode = 0
            stdout = ""
            stderr = ""

        return Proc()

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    monkeypatch.setattr(runner, "nuclei_templates_present", lambda: False)

    runner.run_nuclei(["https://api.example.com/x"])

    assert "-config" not in seen["cmd"]


# --- the API -----------------------------------------------------------


def test_credential_can_be_set_and_is_never_returned(client, engine):
    target_id, workspace_id = _make_target(engine)
    client = _login_developer(client, engine, workspace_id)

    res = client.put(
        f"/api/api-scan/{target_id}/credential",
        json={"header_name": "Authorization", "header_value": "Bearer s3cret"},
    )
    assert res.status_code == 200
    assert "s3cret" not in res.text

    status = client.get(f"/api/api-scan/{target_id}/credential")
    assert status.status_code == 200
    assert status.json() == {
        "target_id": target_id,
        "configured": True,
        "header_name": "Authorization",
    }
    # Not even masked: a mask still confirms the length.
    assert "s3cret" not in status.text


def test_credential_can_be_cleared(client, engine):
    target_id, workspace_id = _make_target(engine)
    client = _login_developer(client, engine, workspace_id)
    client.put(
        f"/api/api-scan/{target_id}/credential",
        json={"header_name": "Authorization", "header_value": "Bearer s3cret"},
    )

    res = client.delete(f"/api/api-scan/{target_id}/credential")

    assert res.status_code == 200
    assert res.json()["configured"] is False
    with Session(engine) as session:
        assert build_scan_headers(session.get(Target, target_id)) == {}


@pytest.mark.parametrize(
    "header_name",
    ["Auth\r\nX-Injected", "Auth: value", "", "a" * 65, "Auth Token"],
)
def test_header_names_that_could_inject_another_header_are_rejected(client, engine, header_name):
    """The name lands in a YAML config file as `name: value`. A name
    carrying CRLF or a colon would write a second header nobody asked
    for."""
    target_id, workspace_id = _make_target(engine)
    client = _login_developer(client, engine, workspace_id)

    res = client.put(
        f"/api/api-scan/{target_id}/credential",
        json={"header_name": header_name, "header_value": "x"},
    )

    assert res.status_code == 422


def test_header_value_with_a_newline_is_rejected(client, engine):
    target_id, workspace_id = _make_target(engine)
    client = _login_developer(client, engine, workspace_id)

    res = client.put(
        f"/api/api-scan/{target_id}/credential",
        json={"header_name": "Authorization", "header_value": "Bearer x\r\nX-Injected: y"},
    )

    assert res.status_code == 422


def test_testing_a_credential_reports_rejection(client, engine, monkeypatch):
    """The failure this catches is silent: a wrong token 401s every route
    and the scan still reports zero findings."""
    target_id, workspace_id = _make_target(engine)
    client = _login_developer(client, engine, workspace_id)
    client.put(
        f"/api/api-scan/{target_id}/credential",
        json={"header_name": "Authorization", "header_value": "Bearer wrong"},
    )

    import app.api.api_scan as api_scan_module

    class Resp:
        status_code = 401

    monkeypatch.setattr(api_scan_module.httpx, "get", lambda *a, **k: Resp())

    res = client.post(f"/api/api-scan/{target_id}/credential/test")

    assert res.status_code == 200
    assert res.json()["accepted"] is False
    assert res.json()["status_code"] == 401


def test_testing_a_credential_reports_acceptance(client, engine, monkeypatch):
    target_id, workspace_id = _make_target(engine)
    client = _login_developer(client, engine, workspace_id)
    client.put(
        f"/api/api-scan/{target_id}/credential",
        json={"header_name": "Authorization", "header_value": "Bearer right"},
    )

    import app.api.api_scan as api_scan_module

    class Resp:
        status_code = 200

    captured = {}

    def fake_get(url, headers=None, **kwargs):
        captured["url"] = url
        captured["headers"] = headers
        return Resp()

    monkeypatch.setattr(api_scan_module.httpx, "get", fake_get)

    res = client.post(f"/api/api-scan/{target_id}/credential/test")

    assert res.json()["accepted"] is True
    # The one host boundary active scanning has: the target's own
    # api_base_url, never a caller-supplied URL and never a discovered
    # route, which could be destructive.
    assert captured["url"] == "https://api.example.com"
    assert captured["headers"] == {"Authorization": "Bearer right"}


def test_testing_without_a_credential_is_a_400_not_an_anonymous_request(client, engine):
    target_id, workspace_id = _make_target(engine)
    client = _login_developer(client, engine, workspace_id)

    res = client.post(f"/api/api-scan/{target_id}/credential/test")

    assert res.status_code == 400


def test_setting_a_credential_needs_more_than_being_logged_in(client, engine):
    target_id, _workspace_id = _make_target(engine)
    _other_target, other_workspace_id = _make_target(engine)
    client = _login_developer(client, engine, other_workspace_id)

    res = client.put(
        f"/api/api-scan/{target_id}/credential",
        json={"header_name": "Authorization", "header_value": "Bearer s3cret"},
    )

    assert res.status_code == 403
