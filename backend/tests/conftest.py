"""Shared test setup.

Both fixtures here exist for #229, which gave the scanner runner two things
it did not have before: a per-run tool cache on disk, and a warm-up step
that shells out to trivy to download a vulnerability database. Neither
belongs in a unit-test run.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core.config import settings
from app.core.security import create_session_token, hash_password
from app.main import app
from app.models.models import (
    Finding,
    FindingState,
    Organization,
    PRGuardrailScan,
    Severity,
    Target,
    User,
    UserRole,
    Workspace,
    WorkspaceMembership,
    WorkspaceRole,
)
from app.scanners import runner


@pytest.fixture(autouse=True)
def _isolated_tool_cache(tmp_path_factory, monkeypatch):
    """Keep per-run scanner caches inside the test's own tmp directory.

    ``runner.run_tool`` now creates a cache under ``settings.tool_cache_dir``
    for trivy and semgrep. Left at its default that is a real path on the
    machine running the tests, so every test that exercises a scanner would
    create -- and, on a killed run, leave behind -- directories outside the
    sandbox. Pointing it at tmp_path per test also makes the cache
    assertions in test_scan_health.py mean something, rather than depending
    on whatever the host already had cached.
    """
    cache_dir = tmp_path_factory.mktemp("tool-cache")
    monkeypatch.setattr(settings, "tool_cache_dir", str(cache_dir))
    return cache_dir


@pytest.fixture(autouse=True)
def _no_database_warming(monkeypatch):
    """Never download a vulnerability database from a test.

    ``ensure_warm_trivy_db`` is called by ``run_scan`` and by the PR
    Guardrail executor, both of which several test modules drive with trivy
    in the tool list. On a developer machine that actually has trivy
    installed, the real function would shell out and fetch hundreds of
    megabytes mid-suite; on CI it would fail slowly instead. Neither is what
    those tests are checking.

    Tests that are specifically about warming call the real implementation
    directly (see test_scan_health.py, which captures it at import time), and
    tests about the call *site* patch this same attribute with their own
    spy -- both of which take precedence over this stub.
    """
    monkeypatch.setattr(
        runner, "ensure_warm_trivy_db", lambda *args, **kwargs: (False, "warming disabled in tests")
    )


# ---------------------------------------------------------------------------
# Issue #506: workspace-isolation fixture helpers, extracted from
# test_workspace_scoped_reads.py (the original #57 read-scoping suite) once a
# second and third test module needed the same in-memory-SQLite +
# session-token-login + real-WorkspaceMembership pattern. A plain
# `_login(client, engine)` with no `role=` override defaults to UserRole.USER
# (not ADMIN, unlike test_findings.py's own local `_login`) so a test that
# forgets to assign a workspace membership fails closed rather than passing
# vacuously as a global admin who bypasses every scope check.
# ---------------------------------------------------------------------------


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


def _login(client, engine, role=UserRole.USER, email=None):
    email = email or f"{role.value}-{id(object())}@example.com"
    with Session(engine) as session:
        user = User(email=email, name="Test", password_hash=hash_password("whatever123"), role=role)
        session.add(user)
        session.commit()
        session.refresh(user)
        uid = user.id
        token = create_session_token(user.id, user.token_version)
    client.cookies.set("toleman_session", token)
    return client, uid


def _make_workspace(engine, name="ws") -> int:
    with Session(engine) as session:
        org = Organization(name=f"org-{name}")
        session.add(org)
        session.commit()
        session.refresh(org)
        ws = Workspace(organization_id=org.id, name=name, api_key=f"key-{name}")
        session.add(ws)
        session.commit()
        session.refresh(ws)
        return ws.id


def _make_target(engine, workspace_id: int, name="target") -> int:
    with Session(engine) as session:
        target = Target(workspace_id=workspace_id, name=name, repo_url="https://github.com/acme/repo")
        session.add(target)
        session.commit()
        session.refresh(target)
        return target.id


def _make_finding(engine, target_id: int, **overrides) -> int:
    defaults = dict(
        target_id=target_id,
        dedup_hash=f"hash-{target_id}-{overrides.get('rule_id', 'r')}",
        tool="semgrep",
        rule_id="rule-1",
        title="Finding",
        file_path="app/main.py",
        severity=Severity.HIGH,
        state=FindingState.OPEN,
    )
    defaults.update(overrides)
    with Session(engine) as session:
        finding = Finding(**defaults)
        session.add(finding)
        session.commit()
        session.refresh(finding)
        return finding.id


def _make_pr_scan(engine, target_id: int, **overrides) -> int:
    defaults = dict(target_id=target_id, pr_number=1, branch="feature")
    defaults.update(overrides)
    with Session(engine) as session:
        scan = PRGuardrailScan(**defaults)
        session.add(scan)
        session.commit()
        session.refresh(scan)
        return scan.id


def _assign(engine, user_id: int, workspace_id: int, role: WorkspaceRole = WorkspaceRole.VIEWER):
    with Session(engine) as session:
        m = WorkspaceMembership(user_id=user_id, workspace_id=workspace_id, role=role)
        session.add(m)
        session.commit()
