"""#232: wiring on_demand_scan and ci_pipeline to the same tools_for_surface
resolver PR Guardrail already used (#231). Until this, both were write-only
checkboxes -- persisted, served back, rendered ticked, never consulted.

on_demand_scan is a gate, not a default: the request always names one tool
explicitly (each UI button dispatches a specific tool), so there is no
"tools omitted" case to default. An explicitly requested but disabled tool
is refused loudly -- never silently run (that repeats GH-01) and never
silently swapped for something else (that drops what was actually asked
for, which is its own version of the same bug).

ci_pipeline is a generation-time default: it decides what a *newly
generated* workflow file contains. It has no effect on a workflow already
committed to a target's repo -- that file is a durable artifact on disk in
someone else's repository, and no assignment change can retroactively
rewrite it.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core.pipeline_workflow import generate_workflow_yaml
from app.core.security import create_session_token, hash_password
from app.main import app as fastapi_app
from app.models.models import (
    Finding,
    FindingState,
    Organization,
    Severity,
    Target,
    User,
    UserRole,
    Workspace,
    WorkspaceToolConfig,
)


@pytest.fixture()
def engine():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(eng)
    return eng


@pytest.fixture()
def client(engine):
    def override():
        with Session(engine) as session:
            yield session

    fastapi_app.dependency_overrides[get_session] = override
    original = deps_module.engine
    deps_module.engine = engine
    c = TestClient(fastapi_app)
    yield c
    fastapi_app.dependency_overrides.clear()
    deps_module.engine = original


def _admin(client, engine):
    with Session(engine) as session:
        u = User(email="a@e.com", name="A", password_hash=hash_password("whatever123"), role=UserRole.ADMIN)
        session.add(u)
        session.commit()
        session.refresh(u)
        token = create_session_token(u.id, u.token_version)
    client.cookies.set("toleman_session", token)
    return client


def _target(engine):
    with Session(engine) as session:
        org = Organization(name="o")
        session.add(org); session.commit(); session.refresh(org)
        ws = Workspace(organization_id=org.id, name="w", api_key="k")
        session.add(ws); session.commit(); session.refresh(ws)
        t = Target(name="t", repo_url="https://github.com/a/b", workspace_id=ws.id)
        session.add(t); session.commit(); session.refresh(t)
        return t.id, ws.id


def _disable(engine, workspace_id, tool, **surfaces):
    with Session(engine) as session:
        cfg = WorkspaceToolConfig(
            workspace_id=workspace_id, tool=tool,
            on_demand_scan=True, ci_pipeline=True, api_scan=False, pr_guardrail=True,
        )
        for k, v in surfaces.items():
            setattr(cfg, k, v)
        session.add(cfg)
        session.commit()


class TestOnDemandScanGate:
    def test_an_enabled_tool_still_dispatches(self, client, engine, monkeypatch):
        import app.api.scans as scans_module

        _admin(client, engine)
        tid, _ = _target(engine)
        monkeypatch.setattr(scans_module.run_scan, "delay", lambda **k: None)
        res = client.post(f"/api/scans/run?target_id={tid}&tool=semgrep")
        assert res.status_code == 202, res.text

    def test_an_explicitly_disabled_tool_is_refused_not_silently_run(self, client, engine, monkeypatch):
        """The core of GH-01: a disabled box must not have zero effect."""
        import app.api.scans as scans_module

        _admin(client, engine)
        tid, wsid = _target(engine)
        _disable(engine, wsid, "gitleaks", on_demand_scan=False)
        dispatched = []
        monkeypatch.setattr(scans_module.run_scan, "delay", lambda **k: dispatched.append(k))
        res = client.post(f"/api/scans/run?target_id={tid}&tool=gitleaks")
        assert res.status_code == 200
        assert "error" in res.json()
        assert "disabled" in res.json()["error"].lower()
        assert dispatched == [], "a disabled tool must never actually reach Celery"

    def test_disabled_tool_is_not_silently_swapped_for_another(self, client, engine, monkeypatch):
        """Refusing must not quietly substitute a different tool -- that
        would drop exactly what the caller asked for, the issue's second
        named failure mode."""
        import app.api.scans as scans_module

        _admin(client, engine)
        tid, wsid = _target(engine)
        _disable(engine, wsid, "gitleaks", on_demand_scan=False)
        dispatched = []
        monkeypatch.setattr(scans_module.run_scan, "delay", lambda **k: dispatched.append(k.get("tool")))
        client.post(f"/api/scans/run?target_id={tid}&tool=gitleaks")
        assert "semgrep" not in dispatched
        assert dispatched == []

    def test_public_api_module_imports_the_same_gate(self):
        """A second call site (app/api/public_api.py) exists specifically so
        a public-API token can't route around the same assignment as the
        internal endpoint -- verified by presence of the same guard rather
        than a full bearer-token round trip (exercised elsewhere, in
        test_public_api.py, and unrelated to what #232 changed)."""
        import inspect

        import app.api.public_api as public_api_module

        assert public_api_module.tools_for_surface is not None
        source = inspect.getsource(public_api_module.trigger_scan)
        assert "tools_for_surface" in source
        assert "on_demand_scan" in source


class TestCiPipelineDefault:
    def test_default_tool_set_is_unchanged_when_nothing_is_disabled(self, engine):
        """Byte-for-byte compatible with pre-#232 behavior when every
        default-enabled tool stays assigned on -- the common case."""
        tid, _ = _target(engine)
        with Session(engine) as session:
            target = session.get(Target, tid)
            result = generate_workflow_yaml(session, target)
        assert "semgrep:" in result["yaml"]
        assert "gitleaks:" in result["yaml"]
        assert "trivy:" in result["yaml"]

    def test_a_tool_disabled_for_ci_pipeline_is_excluded_from_a_new_workflow(self, engine):
        tid, wsid = _target(engine)
        _disable(engine, wsid, "trivy", ci_pipeline=False)
        with Session(engine) as session:
            target = session.get(Target, tid)
            result = generate_workflow_yaml(session, target)
        assert "semgrep:" in result["yaml"]
        assert "trivy:" not in result["yaml"]

    def test_gosec_still_requires_both_go_detection_and_assignment(self, engine):
        """Disabling gosec for ci_pipeline must exclude it even on a
        detected-Go target -- the assignment and the detection are both
        gates, neither overrides the other."""
        tid, wsid = _target(engine)
        with Session(engine) as session:
            session.add(Finding(
                target_id=tid, tool="gosec", rule_id="x", title="x", file_path="a.go",
                severity=Severity.LOW, state=FindingState.OPEN, dedup_hash="h1",
            ))
            session.commit()
        _disable(engine, wsid, "gosec", ci_pipeline=False)
        with Session(engine) as session:
            target = session.get(Target, tid)
            result = generate_workflow_yaml(session, target)
        assert "gosec:" not in result["yaml"]
        assert result["includes_gosec"] is False

    def test_custom_steps_still_bypass_the_assignment_as_before(self, engine):
        """#35's explicit `steps` param is a different, more specific
        override (a saved PipelineWorkflowTemplate) and is unchanged by
        #232 -- verifies the two features don't fight each other."""
        tid, wsid = _target(engine)
        _disable(engine, wsid, "trivy", ci_pipeline=False)
        with Session(engine) as session:
            target = session.get(Target, tid)
            result = generate_workflow_yaml(session, target, steps=["trivy"])
        assert "trivy:" in result["yaml"]

class TestApiScanGate:
    """Active API Scanning's dedicated check -- it cannot use
    tools_for_surface (see is_nuclei_enabled_for_api_scan's docstring), so
    it gets its own tests rather than piggybacking on TestOnDemandScanGate's."""

    def test_defaults_to_enabled_preserving_existing_behavior(self, engine):
        from app.core.tool_usage import is_nuclei_enabled_for_api_scan

        _, wsid = _target(engine)
        with Session(engine) as session:
            assert is_nuclei_enabled_for_api_scan(session, wsid) is True

    def test_an_explicit_saved_row_can_turn_it_off(self, engine):
        from app.core.tool_usage import is_nuclei_enabled_for_api_scan

        _, wsid = _target(engine)
        with Session(engine) as session:
            session.add(WorkspaceToolConfig(
                workspace_id=wsid, tool="nuclei",
                on_demand_scan=False, ci_pipeline=False, api_scan=False, pr_guardrail=False,
            ))
            session.commit()
        with Session(engine) as session:
            assert is_nuclei_enabled_for_api_scan(session, wsid) is False

    def test_endpoint_refuses_when_disabled(self, client, engine):
        _admin(client, engine)
        tid, wsid = _target(engine)
        with Session(engine) as session:
            session.add(WorkspaceToolConfig(
                workspace_id=wsid, tool="nuclei",
                on_demand_scan=False, ci_pipeline=False, api_scan=False, pr_guardrail=False,
            ))
            target = session.get(Target, tid)
            target.api_base_url = "https://api.example.com"
            session.add(target)
            session.commit()
        res = client.post(f"/api/api-scan/{tid}")
        assert res.status_code == 400
        assert "disabled" in res.json()["detail"].lower()

    def test_nuclei_is_never_selectable_through_tools_for_surface(self, engine):
        """The architectural reason this needed its own check at all."""
        from app.core.tool_usage import tools_for_surface

        _, wsid = _target(engine)
        with Session(engine) as session:
            allowed = tools_for_surface(session, wsid, "api_scan")
        assert "nuclei" not in allowed
        assert allowed == []
