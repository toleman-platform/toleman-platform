"""Tests for issue #66: per-target CI/CD pipeline integration, generating
a real GitHub Actions workflow (app.core.pipeline_workflow) and opening a PR
against the target's repo adding it (app.core.pipeline_pr,
POST /api/targets/{id}/pipeline-integrate)."""
import pytest
import yaml
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

import app.api.deps as deps_module
import app.api.targets as targets_module
from app.api.deps import get_session
from app.core.github_app import build_manifest
from app.core.pipeline_pr import PipelinePrError
from app.core.pipeline_workflow import generate_workflow_yaml
from app.core.security import create_session_token, hash_password
from app.main import app
from app.models.models import (
    Finding,
    FindingState,
    GitHubAppConfig,
    GitHubInstallation,
    Organization,
    Severity,
    Target,
    User,
    UserRole,
    Workspace,
)


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
    with Session(engine) as session:
        user = User(email=f"{role.value}@example.com", name="Test", password_hash=hash_password("whatever123"), role=role)
        session.add(user)
        session.commit()
        session.refresh(user)
        token = create_session_token(user.id, user.token_version)
    client.cookies.set("toleman_session", token)
    return client


def _make_target(session, name="gotest", repo_url="https://github.com/geekshiv/gotest") -> Target:
    org = Organization(name="default")
    session.add(org)
    session.commit()
    session.refresh(org)
    ws = Workspace(organization_id=org.id, name="default", api_key="k")
    session.add(ws)
    session.commit()
    session.refresh(ws)
    target = Target(workspace_id=ws.id, name=name, repo_url=repo_url)
    session.add(target)
    session.commit()
    session.refresh(target)
    return target


def _make_installation(
    session, workspace_id: int, account_login: str = "geekshiv", webhook_secret: str = "whsec"
) -> GitHubInstallation:
    """A GitHub App installation + its owning config, set up so
    app.core.github_app.target_has_pr_guardrail_coverage resolves real
    coverage for a target under ``workspace_id`` whose repo owner matches
    ``account_login`` -- the #245 double-scan block only fires once an
    installation genuinely covers the target, not just because the backend
    URL happens to be reachable."""
    config = GitHubAppConfig(
        app_id="1",
        slug="toleman-test",
        client_id="client",
        client_secret="secret",
        private_key_pem="pem",
        webhook_secret=webhook_secret,
        html_url="https://github.com/apps/toleman-test",
    )
    session.add(config)
    session.commit()
    session.refresh(config)
    installation = GitHubInstallation(
        installation_id=1,
        account_login=account_login,
        account_type="Organization",
        workspace_id=workspace_id,
        github_app_config_id=config.id,
    )
    session.add(installation)
    session.commit()
    session.refresh(installation)
    return installation


# --- GitHub App manifest: `workflows` permission --------------------------
#
# Confirmed live against a real installed App (geekshiv/gotest): writing
# under .github/workflows/ via the Contents API 403s with "Resource not
# accessible by integration" on contents:write alone, GitHub gates that
# path behind a separate `workflows` permission scope. Issue #66's PR-open
# flow needs it declared in the manifest so future App installs/reconfigures
# actually have it.


def test_manifest_requests_workflows_permission():
    manifest = build_manifest("https://app.example", "https://backend.example", "Dev", "tok")
    assert manifest["default_permissions"]["workflows"] == "write"
    # Still carries the pre-existing permissions issue #66 didn't touch.
    assert manifest["default_permissions"]["contents"] == "write"
    assert manifest["default_permissions"]["pull_requests"] == "write"


# --- generate_workflow_yaml: real templating, valid YAML -------------------


def test_generated_workflow_is_valid_yaml_and_target_specific(engine):
    with Session(engine) as session:
        target = _make_target(session)
        result = generate_workflow_yaml(session, target)

    parsed = yaml.safe_load(result["yaml"])
    assert "jobs" in parsed
    assert {"semgrep", "gitleaks", "trivy"}.issubset(parsed["jobs"].keys())
    assert f"/api/ingest/{target.id}" in result["yaml"]
    assert result["path"] == ".github/workflows/toleman-scan.yml"


def test_no_gosec_job_without_go_evidence(engine, monkeypatch):
    # No scan history -> falls back to GitHub's languages API (real network
    # call in generate_workflow_yaml). Stub that specific call so this test
    # is deterministic regardless of what language the fixture repo_url
    # happens to be, rather than depending on live GitHub state.
    import app.core.pipeline_workflow as pipeline_workflow_module

    monkeypatch.setattr(pipeline_workflow_module, "detect_languages", lambda session, target: [])

    with Session(engine) as session:
        target = _make_target(session)
        result = generate_workflow_yaml(session, target)
    parsed = yaml.safe_load(result["yaml"])
    assert "gosec" not in parsed["jobs"]
    assert result["includes_gosec"] is False


def test_gosec_job_included_when_target_has_gosec_scan_history(engine):
    with Session(engine) as session:
        target = _make_target(session)
        finding = Finding(
            target_id=target.id, dedup_hash="h1", tool="gosec", rule_id="G101",
            title="hardcoded creds", file_path="main.go", severity=Severity.HIGH,
            state=FindingState.OPEN,
        )
        session.add(finding)
        session.commit()

        result = generate_workflow_yaml(session, target)

    parsed = yaml.safe_load(result["yaml"])
    assert "gosec" in parsed["jobs"]
    assert result["includes_gosec"] is True
    assert result["detection_source"] == "scan_history"


def test_workflow_yaml_documents_localhost_reachability_constraint(engine):
    with Session(engine) as session:
        target = _make_target(session)
        result = generate_workflow_yaml(session, target)
    assert "TOLEMAN_API_URL" in result["yaml"]
    assert "localhost" in result["yaml"].lower()


def test_workflow_name_field_escapes_quotes_safely(engine):
    with Session(engine) as session:
        target = _make_target(session, name='weird "name"')
        result = generate_workflow_yaml(session, target)
    parsed = yaml.safe_load(result["yaml"])  # would raise if quoting broke
    assert 'weird "name"' in parsed["name"]


# --- GET /api/targets/{id}/pipeline-workflow --------------------------------


def test_get_pipeline_workflow_endpoint(client, engine):
    client = _login(client, engine)
    with Session(engine) as session:
        target = _make_target(session)

    res = client.get(f"/api/targets/{target.id}/pipeline-workflow")
    assert res.status_code == 200
    body = res.json()
    assert "jobs:" in body["yaml"]
    assert body["path"] == ".github/workflows/toleman-scan.yml"


def test_get_pipeline_workflow_404_for_missing_target(client, engine):
    client = _login(client, engine)
    res = client.get("/api/targets/9999/pipeline-workflow")
    assert res.status_code == 404


# --- POST /api/targets/{id}/pipeline-integrate ------------------------------


def test_pipeline_integrate_success_updates_target(client, engine, monkeypatch):
    client = _login(client, engine)
    with Session(engine) as session:
        target = _make_target(session)
        target_id = target.id

    def fake_open_pipeline_pr(session, target):
        return {"pr_url": "https://github.com/geekshiv/gotest/pull/42", "pr_number": 42, "branch": "osp/add-pipeline-scan-1"}

    monkeypatch.setattr(targets_module, "open_pipeline_pr", fake_open_pipeline_pr)

    res = client.post(f"/api/targets/{target_id}/pipeline-integrate")
    assert res.status_code == 200
    body = res.json()
    assert body["pipeline_integrated"] is True
    assert body["pipeline_pr_url"] == "https://github.com/geekshiv/gotest/pull/42"
    assert body["pr_number"] == 42

    with Session(engine) as session:
        refreshed = session.get(Target, target_id)
        assert refreshed.pipeline_integrated is True
        assert refreshed.pipeline_pr_url == "https://github.com/geekshiv/gotest/pull/42"


def test_pipeline_integrate_failure_returns_502_and_does_not_mark_integrated(client, engine, monkeypatch):
    client = _login(client, engine)
    with Session(engine) as session:
        target = _make_target(session)
        target_id = target.id

    def fake_open_pipeline_pr(session, target):
        raise PipelinePrError("No GitHub App installation found for this target's workspace.")

    monkeypatch.setattr(targets_module, "open_pipeline_pr", fake_open_pipeline_pr)

    res = client.post(f"/api/targets/{target_id}/pipeline-integrate")
    assert res.status_code == 502

    with Session(engine) as session:
        refreshed = session.get(Target, target_id)
        assert refreshed.pipeline_integrated is False
        assert refreshed.pipeline_pr_url is None


def test_pipeline_integrate_requires_developer_role(client, engine):
    client = _login(client, engine, role=UserRole.VIEWER)
    with Session(engine) as session:
        target = _make_target(session)
        target_id = target.id

    res = client.post(f"/api/targets/{target_id}/pipeline-integrate")
    assert res.status_code == 403


# --- #245's double-scan gap: Pipeline Integration vs. server-side PR
# Guardrail scanning the same PRs twice when both are enabled -------------


def test_pipeline_integrate_blocks_when_webhook_already_reachable(client, engine, monkeypatch):
    """Server-side PR Guardrail already scans every PR once GitHub can
    reach this backend AND a working, enabled installation actually covers
    this target's repo; opening the Actions-based Pipeline Integration PR
    too would double-scan every PR from then on. First-time integration
    (target.pipeline_integrated is still False) must not proceed silently."""
    client = _login(client, engine)
    with Session(engine) as session:
        target = _make_target(session)
        target_id = target.id
        _make_installation(session, target.workspace_id)

    monkeypatch.setattr(targets_module, "BACKEND_URL", "https://api.toleman.example.com")
    called = {}

    def fake_open_pipeline_pr(session, target):
        called["ran"] = True
        return {"pr_url": "x", "pr_number": 1, "branch": "b"}

    monkeypatch.setattr(targets_module, "open_pipeline_pr", fake_open_pipeline_pr)

    res = client.post(f"/api/targets/{target_id}/pipeline-integrate")
    assert res.status_code == 409
    assert "twice" in res.json()["detail"]
    assert "force=true" in res.json()["detail"]
    assert "ran" not in called

    with Session(engine) as session:
        refreshed = session.get(Target, target_id)
        assert refreshed.pipeline_integrated is False


def test_pipeline_integrate_force_bypasses_the_block(client, engine, monkeypatch):
    client = _login(client, engine)
    with Session(engine) as session:
        target = _make_target(session)
        target_id = target.id
        _make_installation(session, target.workspace_id)

    monkeypatch.setattr(targets_module, "BACKEND_URL", "https://api.toleman.example.com")

    def fake_open_pipeline_pr(session, target):
        return {"pr_url": "https://github.com/geekshiv/gotest/pull/7", "pr_number": 7, "branch": "b"}

    monkeypatch.setattr(targets_module, "open_pipeline_pr", fake_open_pipeline_pr)

    res = client.post(f"/api/targets/{target_id}/pipeline-integrate?force=true")
    assert res.status_code == 200
    assert res.json()["pipeline_integrated"] is True


def test_pipeline_integrate_reintegration_is_never_blocked(client, engine, monkeypatch):
    """The block only applies to a target's *first* integration. A repeat
    click (already pipeline_integrated) is a deliberate re-run, not the
    moment double-scanning gets turned on -- that decision was already
    made (with or without force) the first time."""
    client = _login(client, engine)
    with Session(engine) as session:
        target = _make_target(session)
        target.pipeline_integrated = True
        target.pipeline_pr_url = "https://github.com/geekshiv/gotest/pull/1"
        session.add(target)
        session.commit()
        target_id = target.id

    monkeypatch.setattr(targets_module, "BACKEND_URL", "https://api.toleman.example.com")

    def fake_open_pipeline_pr(session, target):
        return {"pr_url": "https://github.com/geekshiv/gotest/pull/8", "pr_number": 8, "branch": "b"}

    monkeypatch.setattr(targets_module, "open_pipeline_pr", fake_open_pipeline_pr)

    res = client.post(f"/api/targets/{target_id}/pipeline-integrate")
    assert res.status_code == 200


def test_pipeline_integrate_not_blocked_when_webhook_unreachable(client, engine, monkeypatch):
    """No block at all when the webhook path can't actually work (a
    localhost deployment) -- that's exactly the case Pipeline Integration
    exists for, not a redundant second implementation."""
    client = _login(client, engine)
    with Session(engine) as session:
        target = _make_target(session)
        target_id = target.id

    monkeypatch.setattr(targets_module, "BACKEND_URL", "http://localhost:8000")

    def fake_open_pipeline_pr(session, target):
        return {"pr_url": "https://github.com/geekshiv/gotest/pull/9", "pr_number": 9, "branch": "b"}

    monkeypatch.setattr(targets_module, "open_pipeline_pr", fake_open_pipeline_pr)

    res = client.post(f"/api/targets/{target_id}/pipeline-integrate")
    assert res.status_code == 200


# --- CodeRabbit review of #390: webhook_reachable() alone isn't proof PR
# Guardrail actually covers a target -- app.core.github_app.
# target_has_pr_guardrail_coverage also requires a resolvable installation,
# a configured webhook_secret, and enforcement_mode != "disabled". Getting
# this wrong the other way (treating reachability alone as sufficient) would
# block/skip Pipeline Integration for a target with *zero* real PR coverage
# from either path -- worse than the original double-scan gap. ------------


def test_pipeline_integrate_not_blocked_when_no_installation_resolves(client, engine, monkeypatch):
    """Backend reachable, but no GitHub App installation covers this
    target's repo at all (manually-added target, or an org that was never
    actually installed on): real coverage is absent, so Pipeline
    Integration must not be blocked."""
    client = _login(client, engine)
    with Session(engine) as session:
        # No GitHubInstallation row at all for this target's workspace --
        # resolve_installation_for_repo only falls back to a workspace's
        # sole installation when one actually exists, so an empty workspace
        # genuinely resolves to "no coverage" rather than a guess.
        target = _make_target(session)
        target_id = target.id

    monkeypatch.setattr(targets_module, "BACKEND_URL", "https://api.toleman.example.com")

    def fake_open_pipeline_pr(session, target):
        return {"pr_url": "https://github.com/geekshiv/gotest/pull/10", "pr_number": 10, "branch": "b"}

    monkeypatch.setattr(targets_module, "open_pipeline_pr", fake_open_pipeline_pr)

    res = client.post(f"/api/targets/{target_id}/pipeline-integrate")
    assert res.status_code == 200


def test_pipeline_integrate_not_blocked_when_no_webhook_secret_set(client, engine, monkeypatch):
    """An installation resolves, but its App has no webhook_secret
    configured yet -- every webhook delivery 401s, so nothing actually
    scans this target's PRs server-side. Must not be blocked."""
    client = _login(client, engine)
    with Session(engine) as session:
        target = _make_target(session)
        target_id = target.id
        _make_installation(session, target.workspace_id, webhook_secret="")

    monkeypatch.setattr(targets_module, "BACKEND_URL", "https://api.toleman.example.com")

    def fake_open_pipeline_pr(session, target):
        return {"pr_url": "https://github.com/geekshiv/gotest/pull/11", "pr_number": 11, "branch": "b"}

    monkeypatch.setattr(targets_module, "open_pipeline_pr", fake_open_pipeline_pr)

    res = client.post(f"/api/targets/{target_id}/pipeline-integrate")
    assert res.status_code == 200


def test_pipeline_integrate_not_blocked_when_enforcement_disabled(client, engine, monkeypatch):
    """A resolvable, fully-configured installation exists, but this
    target's effective enforcement_mode is "disabled" -- PR Guardrail is
    explicitly turned off for it, regardless of whether the webhook
    plumbing underneath works. Must not be blocked."""
    client = _login(client, engine)
    with Session(engine) as session:
        target = _make_target(session)
        target.enforcement_mode = "disabled"
        session.add(target)
        session.commit()
        target_id = target.id
        _make_installation(session, target.workspace_id)

    monkeypatch.setattr(targets_module, "BACKEND_URL", "https://api.toleman.example.com")

    def fake_open_pipeline_pr(session, target):
        return {"pr_url": "https://github.com/geekshiv/gotest/pull/12", "pr_number": 12, "branch": "b"}

    monkeypatch.setattr(targets_module, "open_pipeline_pr", fake_open_pipeline_pr)

    res = client.post(f"/api/targets/{target_id}/pipeline-integrate")
    assert res.status_code == 200
