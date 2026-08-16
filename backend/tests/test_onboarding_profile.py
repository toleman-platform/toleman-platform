"""Tests for the first-run onboarding questionnaire (issue #203).

The rule under test throughout: answers may only *narrow* what runs, and
never silently. Every assertion about a disabled tool also asserts there is a
reason attached, because a scanner that stops running without an explanation
is the failure mode this feature must not have.
"""
import itertools

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core.onboarding_profile import recommend_tools
from app.core.security import create_session_token, hash_password
from app.main import app
from app.models.models import (
    OnboardingProfile,
    Organization,
    User,
    UserRole,
    Workspace,
    WorkspaceToolConfig,
)

_ids = itertools.count()


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
    original = deps_module.engine
    deps_module.engine = engine
    c = TestClient(app)
    yield c
    app.dependency_overrides.clear()
    deps_module.engine = original


def _login(client, engine, role=UserRole.ADMIN):
    with Session(engine) as session:
        user = User(
            email=f"u{next(_ids)}@example.com",
            name="T",
            password_hash=hash_password("whatever123"),
            role=role,
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        token = create_session_token(user.id, user.token_version)
    client.cookies.set("rikugan_session", token)
    return client


def _make_org_and_workspace(engine):
    with Session(engine) as session:
        org = Organization(name=f"org-{next(_ids)}")
        session.add(org)
        session.commit()
        session.refresh(org)
        ws = Workspace(organization_id=org.id, name="ws", api_key=f"k{next(_ids)}")
        session.add(ws)
        session.commit()
        session.refresh(ws)
        return org.id, ws.id


# ---------------------------------------------------------------------------
# Recommender
# ---------------------------------------------------------------------------


def _by_tool(recs):
    return {r.tool: r for r in recs}


def test_unanswered_questions_leave_everything_on():
    """"Not stated" is not "no". The safe default for a security scanner is
    to run, so a skipped question must never disable anything."""
    recs = _by_tool(recommend_tools(languages=[], uses_iac=None, builds_ai_features=None, ships_containers=None))
    assert all(r.enabled for r in recs.values())


def test_gosec_off_only_when_languages_stated_without_go():
    recs = _by_tool(recommend_tools(["python"], None, None, None))
    assert recs["gosec"].enabled is False
    assert "Go" in recs["gosec"].reason

    with_go = _by_tool(recommend_tools(["python", "go"], None, None, None))
    assert with_go["gosec"].enabled is True


def test_iac_scanners_off_only_on_an_explicit_no():
    off = _by_tool(recommend_tools([], uses_iac=False, builds_ai_features=None, ships_containers=None))
    assert off["checkov"].enabled is False and off["tfsec"].enabled is False

    unanswered = _by_tool(recommend_tools([], uses_iac=None, builds_ai_features=None, ships_containers=None))
    assert unanswered["checkov"].enabled is True and unanswered["tfsec"].enabled is True


def test_ai_tools_off_on_explicit_no_but_reason_says_detection_still_runs():
    """A "no" here is a default, not an override of #185's per-repo
    detection, and the reason has to say so or the operator will believe AI
    repos are being ignored entirely."""
    recs = _by_tool(recommend_tools([], None, builds_ai_features=False, ships_containers=None))
    for tool in ("modelscan", "semgrep-llm"):
        assert recs[tool].enabled is False
        assert "still checked" in recs[tool].reason


def test_language_agnostic_scanners_are_never_disabled():
    recs = _by_tool(recommend_tools(["ruby"], uses_iac=False, builds_ai_features=False, ships_containers=False))
    for always_on in ("semgrep", "gitleaks", "trivy", "trivy-license"):
        assert recs[always_on].enabled is True


def test_every_disabled_tool_carries_a_reason():
    recs = recommend_tools(["python"], uses_iac=False, builds_ai_features=False, ships_containers=False)
    for rec in recs:
        if not rec.enabled:
            assert rec.reason.strip(), rec.tool


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------


def test_fresh_deployment_prompts_the_admin(client, engine):
    _make_org_and_workspace(engine)
    _login(client, engine)
    body = client.get("/api/onboarding/profile").json()
    assert body["should_prompt"] is True
    assert body["exists"] is False


def test_non_admin_is_not_prompted(client, engine):
    _make_org_and_workspace(engine)
    _login(client, engine, role=UserRole.USER)
    assert client.get("/api/onboarding/profile").json()["should_prompt"] is False


def test_saving_answers_stops_the_prompt(client, engine):
    _make_org_and_workspace(engine)
    _login(client, engine)
    client.post("/api/onboarding/profile", json={"languages": ["go"], "skipped": False})
    assert client.get("/api/onboarding/profile").json()["should_prompt"] is False


def test_skipping_stops_the_prompt_and_disables_nothing(client, engine):
    """Skipping must keep current behaviour -- everything enabled."""
    org_id, ws_id = _make_org_and_workspace(engine)
    _login(client, engine)
    body = client.post(
        "/api/onboarding/profile",
        json={"languages": ["python"], "uses_iac": False, "skipped": True},
    ).json()

    assert body["applied"] == []
    assert client.get("/api/onboarding/profile").json()["should_prompt"] is False
    with Session(engine) as session:
        assert session.exec(select(WorkspaceToolConfig)).all() == []


def test_answers_write_through_to_workspace_tool_config(client, engine):
    """Enablement must flow through #75's existing mechanism, not a parallel
    switch, so Admin -> Tool Marketplace stays the single source of truth."""
    org_id, ws_id = _make_org_and_workspace(engine)
    _login(client, engine)
    client.post(
        "/api/onboarding/profile",
        json={"languages": ["python"], "uses_iac": False, "builds_ai_features": False, "skipped": False},
    )

    with Session(engine) as session:
        rows = {r.tool: r for r in session.exec(select(WorkspaceToolConfig)).all()}

    for tool in ("gosec", "checkov", "tfsec", "modelscan", "semgrep-llm"):
        assert tool in rows, tool
        assert rows[tool].on_demand_scan is False
        assert rows[tool].ci_pipeline is False
        assert rows[tool].pr_guardrail is False


def test_recommended_on_tools_get_no_row_so_defaults_stay_live(client, engine):
    """Writing an explicit "on" row would freeze today's default into every
    workspace, so a later change to default_usage_for would silently stop
    applying. Absence already means "use the default"."""
    _make_org_and_workspace(engine)
    _login(client, engine)
    client.post("/api/onboarding/profile", json={"languages": ["go"], "skipped": False})

    with Session(engine) as session:
        tools = {r.tool for r in session.exec(select(WorkspaceToolConfig)).all()}
    assert "semgrep" not in tools
    assert "gitleaks" not in tools


def test_answers_are_persisted_and_re_editable(client, engine):
    _make_org_and_workspace(engine)
    _login(client, engine)
    client.post(
        "/api/onboarding/profile",
        json={"languages": ["python"], "cloud_providers": ["aws"], "uses_iac": True, "skipped": False},
    )
    body = client.get("/api/onboarding/profile").json()
    assert body["languages"] == ["python"]
    assert body["cloud_providers"] == ["aws"]
    assert body["uses_iac"] is True

    client.post("/api/onboarding/profile", json={"languages": ["go"], "skipped": False})
    assert client.get("/api/onboarding/profile").json()["languages"] == ["go"]

    with Session(engine) as session:
        assert len(session.exec(select(OnboardingProfile)).all()) == 1


def test_unknown_answer_values_are_rejected(client, engine):
    _make_org_and_workspace(engine)
    _login(client, engine)
    assert client.post("/api/onboarding/profile", json={"languages": ["cobol"]}).status_code == 400
    assert client.post("/api/onboarding/profile", json={"cloud_providers": ["oracle"]}).status_code == 400
    assert (
        client.post("/api/onboarding/profile", json={"pr_enforcement_preference": "explode"}).status_code == 400
    )


def test_non_admin_cannot_save(client, engine):
    _make_org_and_workspace(engine)
    _login(client, engine, role=UserRole.USER)
    assert client.post("/api/onboarding/profile", json={"languages": ["go"]}).status_code == 403


def test_choices_are_served_from_the_backend(client, engine):
    _login(client, engine)
    body = client.get("/api/onboarding/choices").json()
    assert {c["value"] for c in body["languages"]} >= {"python", "go"}
    assert {c["value"] for c in body["pr_enforcement"]} == {"block", "alert"}


def test_recommendations_preview_does_not_apply_anything(client, engine):
    """The wizard shows consequences before committing -- turning scanners
    off should never be a surprise."""
    _make_org_and_workspace(engine)
    _login(client, engine)
    body = client.get("/api/onboarding/recommendations").json()
    assert "recommendations" in body and "summary" in body
    with Session(engine) as session:
        assert session.exec(select(WorkspaceToolConfig)).all() == []
