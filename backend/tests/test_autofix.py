"""Tests for app.core.autofix and POST /api/findings/{id}/fix.

Follows the TestClient + in-memory SQLite harness pattern already
established in tests/test_ai.py and tests/test_remediation.py.

Layout mirrors the module's own two independent guarantees:
  * a recommendation is always produced (AI when configured, deterministic
    otherwise), never raising and never silently returning nothing
  * a patch is attempted only when it can be backed by a verified match
    against real file content -- the deterministic dependency-bump regexes
    are tested directly (unit-level, no DB/HTTP), and the AI-patch path's
    "reject anything that doesn't match exactly once" safety net is tested
    against both a hallucinated snippet and an ambiguous (repeated) one.
"""
import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

import app.api.deps as deps_module
import app.core.autofix as autofix
from app.api.deps import get_session
from app.core.security import create_session_token, hash_password
from app.main import app as fastapi_app
from app.models.models import (
    CveEnrichment,
    Finding,
    Organization,
    PlatformConfig,
    Severity,
    Target,
    User,
    UserRole,
    Workspace,
    WorkspaceMembership,
    WorkspaceRole,
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


def _login(client, engine, email="a@e.com", role=UserRole.ADMIN):
    with Session(engine) as session:
        u = User(email=email, name="A", password_hash=hash_password("whatever123"), role=role)
        session.add(u)
        session.commit()
        session.refresh(u)
        token = create_session_token(u.id, u.token_version)
    client.cookies.set("toleman_session", token)


def _make_target(engine) -> int:
    with Session(engine) as session:
        org = Organization(name="o")
        session.add(org)
        session.commit()
        session.refresh(org)
        ws = Workspace(organization_id=org.id, name="w", api_key="k")
        session.add(ws)
        session.commit()
        session.refresh(ws)
        target = Target(workspace_id=ws.id, name="t", repo_url="https://github.com/a/b")
        session.add(target)
        session.commit()
        session.refresh(target)
        return target.id


def _make_finding(engine, target_id: int, **overrides) -> int:
    with Session(engine) as session:
        defaults = dict(
            target_id=target_id,
            dedup_hash="hash-1",
            tool="semgrep",
            rule_id="sql-injection",
            title="SQL Injection",
            description="Unsanitized input reaches a raw query.",
            file_path="app.py",
            line_start=42,
            severity=Severity.HIGH,
        )
        defaults.update(overrides)
        finding = Finding(**defaults)
        session.add(finding)
        session.commit()
        session.refresh(finding)
        return finding.id


def _set_ai_config(engine, **kwargs) -> None:
    with Session(engine) as session:
        session.add(PlatformConfig(**kwargs))
        session.commit()


def _cve_row(engine, cve_id: str, fixed_versions: list[dict]) -> None:
    with Session(engine) as session:
        session.add(CveEnrichment(cve_id=cve_id, osv_found=True, fixed_versions=json.dumps(fixed_versions)))
        session.commit()


# ---------------------------------------------------------------------------
# Deterministic manifest version-bumpers (pure functions, no DB/HTTP)
# ---------------------------------------------------------------------------


def test_bump_requirements_txt_rewrites_pinned_version():
    content = "flask==1.0\nstarlette==0.39.0\nrequests==2.0\n"
    old, new = autofix._bump_requirements_txt(content, "starlette", "0.40.0")
    assert old == "starlette==0.39.0"
    assert new == "starlette==0.40.0"
    assert content.replace(old, new, 1) == "flask==1.0\nstarlette==0.40.0\nrequests==2.0\n"


def test_bump_requirements_txt_matches_dash_underscore_variants():
    content = "my_package>=1.0\n"
    result = autofix._bump_requirements_txt(content, "my-package", "2.0")
    assert result == ("my_package>=1.0", "my_package>=2.0")


def test_bump_requirements_txt_refuses_ambiguous_multiple_matches():
    content = "starlette==0.39.0\nstarlette==0.39.0\n"
    assert autofix._bump_requirements_txt(content, "starlette", "0.40.0") is None


def test_bump_requirements_txt_refuses_when_package_absent():
    content = "flask==1.0\n"
    assert autofix._bump_requirements_txt(content, "starlette", "0.40.0") is None


def test_bump_package_json_preserves_caret_prefix():
    content = '{"dependencies": {"lodash": "^4.17.15"}}'
    old, new = autofix._bump_package_json(content, "lodash", "4.17.21")
    assert old == '"lodash": "^4.17.15"'
    assert new == '"lodash": "^4.17.21"'


def test_bump_go_mod_adds_v_prefix_single_line_form():
    content = "module x\n\nrequire github.com/foo/bar v1.2.3\n"
    old, new = autofix._bump_go_mod(content, "github.com/foo/bar", "1.2.4")
    assert old == "require github.com/foo/bar v1.2.3"
    assert new == "require github.com/foo/bar v1.2.4"
    assert content.replace(old, new, 1) == "module x\n\nrequire github.com/foo/bar v1.2.4\n"


def test_bump_go_mod_adds_v_prefix_block_form():
    content = "module x\n\nrequire (\n\tgithub.com/foo/bar v1.2.3\n)\n"
    old, new = autofix._bump_go_mod(content, "github.com/foo/bar", "1.2.4")
    assert old == "\tgithub.com/foo/bar v1.2.3"
    assert new == "\tgithub.com/foo/bar v1.2.4"


def test_bumper_for_path_matches_by_basename_only():
    assert autofix._bumper_for_path("backend/requirements.txt") is autofix._bump_requirements_txt
    assert autofix._bumper_for_path("frontend/package.json") is autofix._bump_package_json
    assert autofix._bumper_for_path("go.sum") is None  # lockfile: deliberately unsupported


# ---------------------------------------------------------------------------
# Recommendation: always produced, AI first, deterministic fallback
# ---------------------------------------------------------------------------


def test_recommendation_falls_back_to_deterministic_upgrade_text(engine):
    with Session(engine) as session:
        target_id = _make_target(engine)
        finding = Finding(
            target_id=target_id, dedup_hash="h", tool="trivy", rule_id="CVE-2024-1", title="Vuln",
            file_path="requirements.txt", severity=Severity.HIGH, cve_id="CVE-2024-1",
        )
        session.add(finding)
        session.commit()
        session.refresh(finding)
    _cve_row(engine, "CVE-2024-1", [{"package": "starlette", "ecosystem": "PyPI", "fixed": "0.40.0"}])

    with Session(engine) as session:
        finding = session.get(Finding, finding.id)
        text = autofix.build_recommendation(session, finding)
    assert "0.40.0" in text
    assert "CVE-2024-1" in text


def test_recommendation_gives_static_guidance_for_secrets_with_no_ai(engine):
    target_id = _make_target(engine)
    finding_id = _make_finding(engine, target_id, tool="gitleaks", rule_id="generic-api-key")
    with Session(engine) as session:
        finding = session.get(Finding, finding_id)
        text = autofix.build_recommendation(session, finding)
    assert "rotate" in text.lower()


def test_recommendation_uses_ai_when_configured(engine, monkeypatch):
    target_id = _make_target(engine)
    finding_id = _make_finding(engine, target_id)
    _set_ai_config(engine, ai_provider="anthropic", anthropic_api_key="sk-ant-test")
    monkeypatch.setattr(autofix, "generate_text", lambda session, prompt, max_tokens=400: "Use parameterized queries.")

    with Session(engine) as session:
        finding = session.get(Finding, finding_id)
        text = autofix.build_recommendation(session, finding)
    assert text == "Use parameterized queries."


def test_recommendation_falls_back_when_ai_raises(engine, monkeypatch):
    target_id = _make_target(engine)
    finding_id = _make_finding(engine, target_id, tool="gitleaks")
    _set_ai_config(engine, ai_provider="anthropic", anthropic_api_key="sk-ant-test")

    def boom(session, prompt, max_tokens=400):
        raise RuntimeError("upstream down")

    monkeypatch.setattr(autofix, "generate_text", boom)

    with Session(engine) as session:
        finding = session.get(Finding, finding_id)
        text = autofix.build_recommendation(session, finding)
    assert "rotate" in text.lower()  # deterministic Secrets guidance, not a crash


# ---------------------------------------------------------------------------
# AI patch: rejects hallucinated / ambiguous snippets rather than guessing
# ---------------------------------------------------------------------------


def test_ai_patch_rejects_snippet_not_found_in_file(engine, monkeypatch):
    target_id = _make_target(engine)
    finding_id = _make_finding(engine, target_id)
    monkeypatch.setattr(autofix, "_fetch_file", lambda *a, **k: ("def f():\n    return 1\n", "sha1"))
    monkeypatch.setattr(
        autofix, "generate_text",
        lambda *a, **k: json.dumps({"old_code": "return 2", "new_code": "return 3", "explanation": "x"}),
    )
    with Session(engine) as session:
        finding = session.get(Finding, finding_id)
        target = session.get(Target, target_id)
        assert autofix._ai_patch(session, finding, target) is None


def test_ai_patch_rejects_ambiguous_snippet_appearing_twice(engine, monkeypatch):
    target_id = _make_target(engine)
    finding_id = _make_finding(engine, target_id)
    monkeypatch.setattr(autofix, "_fetch_file", lambda *a, **k: ("x = 1\nx = 1\n", "sha1"))
    monkeypatch.setattr(
        autofix, "generate_text",
        lambda *a, **k: json.dumps({"old_code": "x = 1", "new_code": "x = 2", "explanation": "x"}),
    )
    with Session(engine) as session:
        finding = session.get(Finding, finding_id)
        target = session.get(Target, target_id)
        assert autofix._ai_patch(session, finding, target) is None


def test_ai_patch_applies_unique_verified_match(engine, monkeypatch):
    target_id = _make_target(engine)
    finding_id = _make_finding(engine, target_id)
    monkeypatch.setattr(autofix, "_fetch_file", lambda *a, **k: ("query = f\"SELECT * FROM t WHERE id={x}\"\n", "sha1"))
    monkeypatch.setattr(
        autofix, "generate_text",
        lambda *a, **k: json.dumps({
            "old_code": 'query = f"SELECT * FROM t WHERE id={x}"',
            "new_code": 'query = "SELECT * FROM t WHERE id=%s"',
            "explanation": "Parameterize the query.",
        }),
    )
    with Session(engine) as session:
        finding = session.get(Finding, finding_id)
        target = session.get(Target, target_id)
        patch = autofix._ai_patch(session, finding, target)
    assert patch is not None
    assert patch.strategy == "ai"
    assert "%s" in patch.new_content
    assert patch.explanation == "Parameterize the query."


def test_build_patch_falls_back_to_deterministic_sca_when_ai_yields_nothing(engine, monkeypatch):
    target_id = _make_target(engine)
    with Session(engine) as session:
        finding = Finding(
            target_id=target_id, dedup_hash="h", tool="trivy", rule_id="CVE-2024-1", title="Vuln",
            file_path="requirements.txt", severity=Severity.HIGH, cve_id="CVE-2024-1",
        )
        session.add(finding)
        session.commit()
        session.refresh(finding)
        finding_id = finding.id
    _cve_row(engine, "CVE-2024-1", [{"package": "starlette", "ecosystem": "PyPI", "fixed": "0.40.0"}])
    _set_ai_config(engine, ai_provider="anthropic", anthropic_api_key="sk-ant-test")

    monkeypatch.setattr(autofix, "generate_text", lambda *a, **k: "not json at all")
    monkeypatch.setattr(autofix, "_fetch_file", lambda *a, **k: ("starlette==0.39.0\n", "sha1"))

    with Session(engine) as session:
        finding = session.get(Finding, finding_id)
        patch = autofix.build_patch(session, finding)
    assert patch is not None
    assert patch.strategy == "deterministic_sca"
    assert "0.40.0" in patch.new_content


def test_build_patch_returns_none_when_nothing_available(engine):
    target_id = _make_target(engine)
    finding_id = _make_finding(engine, target_id, tool="checkov")  # no AI, no CVE, no manifest match
    with Session(engine) as session:
        finding = session.get(Finding, finding_id)
        assert autofix.build_patch(session, finding) is None


# ---------------------------------------------------------------------------
# POST /api/findings/{id}/fix: mode dispatch end to end
# ---------------------------------------------------------------------------


def test_fix_endpoint_returns_recommendation_only_when_no_patch_possible(client, engine):
    _login(client, engine)
    target_id = _make_target(engine)
    finding_id = _make_finding(engine, target_id, tool="checkov", rule_id="CKV_AWS_1")

    resp = client.post(f"/api/findings/{finding_id}/fix")
    assert resp.status_code == 200
    body = resp.json()
    assert body["mode"] == "recommendation_only"
    assert body["recommendation"]
    assert body["diff"] is None
    assert body["pr_url"] is None


def test_fix_endpoint_returns_diff_when_no_github_app_installed(client, engine, monkeypatch):
    _login(client, engine)
    target_id = _make_target(engine)
    with Session(engine) as session:
        finding = Finding(
            target_id=target_id, dedup_hash="h", tool="trivy", rule_id="CVE-2024-1", title="Vuln",
            file_path="requirements.txt", severity=Severity.HIGH, cve_id="CVE-2024-1",
        )
        session.add(finding)
        session.commit()
        session.refresh(finding)
        finding_id = finding.id
    _cve_row(engine, "CVE-2024-1", [{"package": "starlette", "ecosystem": "PyPI", "fixed": "0.40.0"}])

    monkeypatch.setattr(autofix, "_fetch_file", lambda *a, **k: ("starlette==0.39.0\n", "sha1"))
    # No GitHub App installed for this workspace -> _installation_token_or_none
    # returns None -> open_fix_pr raises AutofixError -> endpoint falls back.

    resp = client.post(f"/api/findings/{finding_id}/fix")
    assert resp.status_code == 200
    body = resp.json()
    assert body["mode"] == "diff"
    assert body["strategy"] == "deterministic_sca"
    assert "starlette==0.40.0" in body["diff"]
    assert body["pr_url"] is None
    assert body["warning"]


def test_fix_endpoint_opens_pr_when_patch_and_app_available(client, engine, monkeypatch):
    _login(client, engine)
    target_id = _make_target(engine)
    with Session(engine) as session:
        finding = Finding(
            target_id=target_id, dedup_hash="h", tool="trivy", rule_id="CVE-2024-1", title="Vuln",
            file_path="requirements.txt", severity=Severity.HIGH, cve_id="CVE-2024-1",
        )
        session.add(finding)
        session.commit()
        session.refresh(finding)
        finding_id = finding.id
    _cve_row(engine, "CVE-2024-1", [{"package": "starlette", "ecosystem": "PyPI", "fixed": "0.40.0"}])

    monkeypatch.setattr(autofix, "_fetch_file", lambda *a, **k: ("starlette==0.39.0\n", "sha1"))
    monkeypatch.setattr(
        autofix, "open_fix_pr",
        lambda session, target, finding, patch: {"pr_url": "https://github.com/a/b/pull/1", "pr_number": 1, "branch": "toleman/fix-1"},
    )

    resp = client.post(f"/api/findings/{finding_id}/fix")
    assert resp.status_code == 200
    body = resp.json()
    assert body["mode"] == "pr"
    assert body["pr_url"] == "https://github.com/a/b/pull/1"
    assert body["pr_number"] == 1
    assert body["branch"] == "toleman/fix-1"
    assert body["warning"] is None


def test_fix_endpoint_returns_404_for_missing_finding(client, engine):
    _login(client, engine)
    resp = client.post("/api/findings/99999/fix")
    assert resp.status_code == 404


def test_fix_endpoint_requires_developer_role(client, engine):
    target_id = _make_target(engine)
    finding_id = _make_finding(engine, target_id)
    with Session(engine) as session:
        target = session.get(Target, target_id)
        workspace_id = target.workspace_id
        viewer = User(email="viewer@e.com", name="V", password_hash=hash_password("whatever123"), role=UserRole.VIEWER)
        session.add(viewer)
        session.commit()
        session.refresh(viewer)
        session.add(WorkspaceMembership(user_id=viewer.id, workspace_id=workspace_id, role=WorkspaceRole.VIEWER))
        session.commit()
        token = create_session_token(viewer.id, viewer.token_version)
    client.cookies.set("toleman_session", token)

    resp = client.post(f"/api/findings/{finding_id}/fix")
    assert resp.status_code == 403
