"""Tests for issue #75 (Tool marketplace / health page):
  - GET /api/tools/registry returns every registered tool with a real
    (subprocess-based) health check and an `integrated` flag.
  - GET/PUT /api/tools/assignments (WorkspaceToolConfig CRUD): workspace
    scoping via accessible_workspace_ids, default-vs-saved distinction, and
    the SECURITY_ENGINEER-or-admin write gate (same shape as SlaRule).

Follows the same in-memory SQLite + TestClient + session-token-login
pattern as tests/test_sla_rules.py.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core.security import create_session_token, hash_password
from app.core.tool_registry import TOOL_REGISTRY
from app.main import app
from app.models.models import Organization, User, UserRole, Workspace, WorkspaceMembership, WorkspaceRole


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
    client.cookies.set("rikugan_session", token)
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


def _membership(engine, user_id, workspace_id, role):
    with Session(engine) as session:
        session.add(WorkspaceMembership(user_id=user_id, workspace_id=workspace_id, role=role))
        session.commit()


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

def test_registry_lists_every_tool_with_health_and_integration_flag(client, engine):
    client, _ = _login(client, engine, role=UserRole.ADMIN)
    res = client.get("/api/tools/registry")
    assert res.status_code == 200
    body = res.json()
    tools = {e["tool"] for e in body}
    assert tools == {e["tool"] for e in TOOL_REGISTRY}
    for entry in body:
        assert "installed" in entry
        assert "version" in entry
        assert "integrated" in entry
        assert "category" in entry
        assert "install_cmd" in entry
    # kics has no real TOOL_COMMANDS entry -- registry-only, not integrated.
    kics = next(e for e in body if e["tool"] == "kics")
    assert kics["integrated"] is False
    # semgrep is a real, wired-up scanner.
    semgrep = next(e for e in body if e["tool"] == "semgrep")
    assert semgrep["integrated"] is True


def test_health_endpoint_still_works_unchanged(client, engine):
    client, _ = _login(client, engine, role=UserRole.ADMIN)
    res = client.get("/api/tools/health")
    assert res.status_code == 200
    tools = {e["tool"] for e in res.json()}
    assert tools == {"semgrep", "gitleaks", "trivy", "gosec"}


# ---------------------------------------------------------------------------
# Assignments
# ---------------------------------------------------------------------------

def test_assignments_default_to_registry_defaults_with_no_saved_row(client, engine):
    ws_id = _make_workspace(engine)
    client, uid = _login(client, engine, role=UserRole.USER)
    _membership(engine, uid, ws_id, WorkspaceRole.VIEWER)

    res = client.get(f"/api/tools/assignments?workspace_id={ws_id}")
    assert res.status_code == 200
    body = res.json()
    assert len(body) == len(TOOL_REGISTRY)
    semgrep = next(a for a in body if a["tool"] == "semgrep")
    assert semgrep["is_default"] is True
    assert semgrep["on_demand_scan"] is True
    assert semgrep["ci_pipeline"] is True
    assert semgrep["api_scan"] is False
    kics = next(a for a in body if a["tool"] == "kics")
    assert kics["is_default"] is True
    assert kics["on_demand_scan"] is False  # not integrated -> defaults all off


def test_viewer_cannot_write_assignment(client, engine):
    ws_id = _make_workspace(engine)
    client, uid = _login(client, engine, role=UserRole.USER)
    _membership(engine, uid, ws_id, WorkspaceRole.VIEWER)

    res = client.put(
        "/api/tools/assignments",
        json={
            "workspace_id": ws_id,
            "tool": "semgrep",
            "on_demand_scan": False,
            "ci_pipeline": False,
            "api_scan": False,
            "pr_guardrail": False,
        },
    )
    assert res.status_code == 403


def test_security_engineer_can_save_assignment_and_it_persists(client, engine):
    ws_id = _make_workspace(engine)
    client, uid = _login(client, engine, role=UserRole.USER)
    _membership(engine, uid, ws_id, WorkspaceRole.SECURITY_ENGINEER)

    res = client.put(
        "/api/tools/assignments",
        json={
            "workspace_id": ws_id,
            "tool": "trivy",
            "on_demand_scan": True,
            "ci_pipeline": False,
            "api_scan": True,
            "pr_guardrail": False,
        },
    )
    assert res.status_code == 200
    saved = res.json()
    assert saved["is_default"] is False
    assert saved["ci_pipeline"] is False
    assert saved["api_scan"] is True

    # A second write to the same (workspace, tool) updates in place rather
    # than creating a duplicate row (the UniqueConstraint would otherwise
    # reject it) -- confirm via the list endpoint reflecting the update.
    res2 = client.put(
        "/api/tools/assignments",
        json={
            "workspace_id": ws_id,
            "tool": "trivy",
            "on_demand_scan": False,
            "ci_pipeline": False,
            "api_scan": False,
            "pr_guardrail": False,
        },
    )
    assert res2.status_code == 200

    listed = client.get(f"/api/tools/assignments?workspace_id={ws_id}").json()
    trivy = next(a for a in listed if a["tool"] == "trivy")
    assert trivy["is_default"] is False
    assert trivy["on_demand_scan"] is False
    assert trivy["api_scan"] is False


def test_unknown_tool_rejected(client, engine):
    ws_id = _make_workspace(engine)
    client, uid = _login(client, engine, role=UserRole.ADMIN)

    res = client.put(
        "/api/tools/assignments",
        json={
            "workspace_id": ws_id,
            "tool": "not-a-real-tool",
            "on_demand_scan": True,
            "ci_pipeline": True,
            "api_scan": False,
            "pr_guardrail": True,
        },
    )
    assert res.status_code == 422


def test_assignments_scoped_to_accessible_workspaces(client, engine):
    ws_a = _make_workspace(engine, "a")
    ws_b = _make_workspace(engine, "b")
    client, uid = _login(client, engine, role=UserRole.USER)
    _membership(engine, uid, ws_a, WorkspaceRole.VIEWER)
    # No membership in ws_b -- issue #57-style tenant isolation.

    res = client.get(f"/api/tools/assignments?workspace_id={ws_b}")
    assert res.status_code == 404


def test_admin_bypasses_workspace_membership_for_read_and_write(client, engine):
    ws_id = _make_workspace(engine)
    client, _ = _login(client, engine, role=UserRole.ADMIN)

    res = client.get(f"/api/tools/assignments?workspace_id={ws_id}")
    assert res.status_code == 200

    res2 = client.put(
        "/api/tools/assignments",
        json={
            "workspace_id": ws_id,
            "tool": "gitleaks",
            "on_demand_scan": True,
            "ci_pipeline": True,
            "api_scan": False,
            "pr_guardrail": True,
        },
    )
    assert res2.status_code == 200


# ---------------------------------------------------------------------------
# AI/ML catalog entries (issue #187)
# ---------------------------------------------------------------------------

AI_ML_TOOLS = {"modelscan", "garak", "medusa", "snyk-agent-scan", "cisco-aibom"}

# Of those, the ones still catalog-only. modelscan graduated out of this set
# in #186 when it got a real TOOL_COMMANDS entry -- the not-integrated
# assertions below deliberately failed at that moment, which is what they
# are for. Move a tool out of here when it gets wired up for real.
AI_ML_CATALOG_ONLY_TOOLS = AI_ML_TOOLS - {"modelscan"}


def test_ai_ml_tools_are_registered(client, engine):
    client, _ = _login(client, engine, role=UserRole.ADMIN)
    res = client.get("/api/tools/registry")
    assert res.status_code == 200
    by_tool = {t["tool"]: t for t in res.json()}
    assert AI_ML_TOOLS <= by_tool.keys()
    for tool in AI_ML_TOOLS:
        assert by_tool[tool]["category"] == "AI/ML"


def test_ai_ml_tools_report_as_not_integrated(client, engine):
    """None of them has a TOOL_COMMANDS entry yet, so `integrated` must be
    False -- the same invariant kics relies on. If someone wires one up for
    real, this assertion is the reminder to move it out of catalog-only."""
    client, _ = _login(client, engine, role=UserRole.ADMIN)
    by_tool = {t["tool"]: t for t in client.get("/api/tools/registry").json()}
    for tool in AI_ML_CATALOG_ONLY_TOOLS:
        assert by_tool[tool]["integrated"] is False, tool


def test_ai_ml_tools_default_every_usage_surface_off(client, engine):
    """Per default_usage_for()'s docstring: enabling a surface for a tool
    with nothing to run would be a silent no-op that misleads an admin into
    thinking it's active."""
    ws_id = _make_workspace(engine)
    client, _ = _login(client, engine, role=UserRole.ADMIN)
    assignments = client.get(f"/api/tools/assignments?workspace_id={ws_id}").json()
    by_tool = {a["tool"]: a for a in assignments}
    for tool in AI_ML_CATALOG_ONLY_TOOLS:
        entry = by_tool[tool]
        for surface in ("on_demand_scan", "ci_pipeline", "api_scan", "pr_guardrail"):
            assert entry[surface] is False, f"{tool}.{surface} defaulted on"


def test_ai_ml_entries_carry_install_and_docs_metadata(client, engine):
    """install_cmd is display-only text an admin copies and runs by hand
    (see tool_registry's module docstring), so an empty or missing one is a
    real defect rather than cosmetic."""
    client, _ = _login(client, engine, role=UserRole.ADMIN)
    by_tool = {t["tool"]: t for t in client.get("/api/tools/registry").json()}
    for tool in AI_ML_TOOLS:
        entry = by_tool[tool]
        assert entry["install_cmd"].strip()
        assert entry["docs_url"].startswith("https://")
        assert entry["description"].strip()


def test_medusa_entry_surfaces_its_agpl_licence(client, engine):
    """Every other bundled scanner is permissive; MEDUSA is AGPL-3.0. The
    licence has to be visible at the point an admin decides to install it,
    not buried in a PR description (see #182 for the parallel discussion)."""
    client, _ = _login(client, engine, role=UserRole.ADMIN)
    by_tool = {t["tool"]: t for t in client.get("/api/tools/registry").json()}
    assert "AGPL" in by_tool["medusa"]["description"]


def test_modelscan_is_integrated_after_186(client, engine):
    """Counterpart to the catalog-only assertions above: modelscan has a real
    TOOL_COMMANDS entry now, so it must report as integrated and default its
    usage surfaces ON like any other working scanner."""
    ws_id = _make_workspace(engine)
    client, _ = _login(client, engine, role=UserRole.ADMIN)

    by_tool = {t["tool"]: t for t in client.get("/api/tools/registry").json()}
    assert by_tool["modelscan"]["integrated"] is True

    assignments = {a["tool"]: a for a in client.get(f"/api/tools/assignments?workspace_id={ws_id}").json()}
    assert assignments["modelscan"]["on_demand_scan"] is True
