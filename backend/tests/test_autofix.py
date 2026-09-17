"""Tests for app.core.autofix and POST /api/findings/{id}/suggest-fix
and /raise-pr.

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
from sqlmodel import Session, SQLModel, create_engine, select

import app.api.deps as deps_module
import app.core.autofix as autofix
import app.core.remediation_autofix as remediation_autofix
from app.core.crypto import SecretDecryptionError
from app.api.deps import get_session
from app.core.remediation import group_remediations
from app.core.security import create_session_token, hash_password
from app.main import app as fastapi_app
from app.models.models import (
    CveEnrichment,
    Finding,
    Organization,
    PlatformConfig,
    RemediationFixPr,
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
# POST /api/findings/{id}/suggest-fix: generates only, never opens a PR
# ---------------------------------------------------------------------------


def test_suggest_fix_endpoint_returns_recommendation_only_when_no_patch_possible(client, engine):
    _login(client, engine)
    target_id = _make_target(engine)
    finding_id = _make_finding(engine, target_id, tool="checkov", rule_id="CKV_AWS_1")

    resp = client.post(f"/api/findings/{finding_id}/suggest-fix")
    assert resp.status_code == 200
    body = resp.json()
    assert body["recommendation"]
    assert body["diff"] is None
    assert body["new_content"] is None
    assert body["strategy"] is None


def test_suggest_fix_endpoint_returns_diff_and_never_calls_open_fix_pr(client, engine, monkeypatch):
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

    def fail_if_called(*a, **k):
        raise AssertionError("suggest-fix must never open a PR")

    monkeypatch.setattr(autofix, "open_fix_pr", fail_if_called)

    resp = client.post(f"/api/findings/{finding_id}/suggest-fix")
    assert resp.status_code == 200
    body = resp.json()
    assert body["strategy"] == "deterministic_sca"
    assert "starlette==0.40.0" in body["diff"]
    assert body["new_content"] == "starlette==0.40.0\n"
    assert body["file_path"] == "requirements.txt"
    assert body["ref"] == "main"


def test_suggest_fix_endpoint_returns_404_for_missing_finding(client, engine):
    _login(client, engine)
    resp = client.post("/api/findings/99999/suggest-fix")
    assert resp.status_code == 404


def test_suggest_fix_endpoint_does_not_require_developer_role(client, engine):
    """Read-only/generative, same permission level as /api/ai/analyze --
    any workspace member can ask for a suggestion; only raise-pr writes."""
    target_id = _make_target(engine)
    finding_id = _make_finding(engine, target_id, tool="checkov", rule_id="CKV_AWS_1")
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

    resp = client.post(f"/api/findings/{finding_id}/suggest-fix")
    assert resp.status_code == 200


def test_strategy_label_covers_every_known_strategy():
    assert autofix._strategy_label("ai") == "an AI-generated"
    assert autofix._strategy_label("deterministic_sca") == "a deterministic dependency-upgrade"
    assert autofix._strategy_label("mcp_client") == "an MCP-client-generated"
    # Unknown strategy degrades to a grammatically-valid generic label
    # rather than raising -- open_fix_pr should never fail on this alone.
    assert autofix._strategy_label("something_new") == "a"


# ---------------------------------------------------------------------------
# find_suppression_comment: a real incident (an MCP client "fixed" a finding
# by adding a bare `# nosemgrep` on the flagged line instead of fixing the
# actual issue) -- raise_fix_pr_endpoint must reject that, not just have a
# docstring asking callers not to.
# ---------------------------------------------------------------------------


def _finding_at(line_start=10, line_end=None, **overrides):
    defaults = dict(
        target_id=1, dedup_hash="h", tool="semgrep", rule_id="r", title="t",
        file_path="app.py", line_start=line_start, line_end=line_end, severity=Severity.HIGH,
    )
    defaults.update(overrides)
    return Finding(**defaults)


def test_find_suppression_comment_detects_nosemgrep_on_the_flagged_line():
    finding = _finding_at(line_start=2)
    content = "line 1\nsubprocess.run(cmd, shell=True)  # nosemgrep\nline 3\n"
    assert autofix.find_suppression_comment(content, finding) is not None


@pytest.mark.parametrize(
    "comment",
    ["# nosemgrep", "# nosem", "# noqa", "# nosec", "# pylint: disable=x", "// eslint-disable-next-line",
     "# checkov:skip=CKV_1", "# tfsec:ignore:x", "// nolint", "# gitleaks:allow", "# .trivyignore"],
)
def test_find_suppression_comment_covers_common_cross_language_directives(comment):
    finding = _finding_at(line_start=1)
    content = f"some vulnerable line here  {comment}\n"
    assert autofix.find_suppression_comment(content, finding) is not None


def test_find_suppression_comment_ignores_matches_outside_the_flagged_lines():
    """A legitimate fix elsewhere in the file that happens to mention one of
    these words (a docstring, an unrelated comment) must never be rejected --
    only the finding's own flagged line(s) are checked."""
    finding = _finding_at(line_start=5)
    content = "# this file has no noqa anywhere near line 5\n" * 3 + "line 4\nfixed_line_5\nline 6\n"
    assert autofix.find_suppression_comment(content, finding) is None


def test_find_suppression_comment_checks_the_full_line_range():
    finding = _finding_at(line_start=2, line_end=4)
    content = "line 1\nline 2\nline 3  # nosec\nline 4\nline 5\n"
    assert autofix.find_suppression_comment(content, finding) is not None


def test_find_suppression_comment_none_for_a_clean_fix():
    finding = _finding_at(line_start=2)
    content = "line 1\nsubprocess.run(cmd, shell=False)\nline 3\n"
    assert autofix.find_suppression_comment(content, finding) is None


def test_find_suppression_comment_returns_none_without_a_line_start():
    """A finding with no line_start (e.g. a manifest-level SCA finding) has
    no single line to check against -- always passes rather than raising."""
    finding = _finding_at(line_start=None)
    assert autofix.find_suppression_comment("anything  # nosemgrep\n", finding) is None


# ---------------------------------------------------------------------------
# POST /api/findings/{id}/raise-pr: opens the PR for a caller-supplied patch
# ---------------------------------------------------------------------------


def test_raise_pr_endpoint_opens_pr_for_the_supplied_patch(client, engine, monkeypatch):
    _login(client, engine)
    target_id = _make_target(engine)
    finding_id = _make_finding(engine, target_id, tool="trivy", file_path="requirements.txt")

    captured = {}

    def fake_open_fix_pr(session, target, finding, patch):
        captured["patch"] = patch
        return {"pr_url": "https://github.com/a/b/pull/1", "pr_number": 1, "branch": "toleman/fix-1"}

    monkeypatch.setattr("app.api.findings.open_fix_pr", fake_open_fix_pr)

    resp = client.post(
        f"/api/findings/{finding_id}/raise-pr",
        json={
            "file_path": "requirements.txt",
            "new_content": "starlette==0.40.0\n",
            "ref": "main",
            "strategy": "deterministic_sca",
            "explanation": "Upgrade starlette to 0.40.0.",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body == {"pr_url": "https://github.com/a/b/pull/1", "pr_number": 1, "branch": "toleman/fix-1"}
    assert captured["patch"].new_content == "starlette==0.40.0\n"
    assert captured["patch"].strategy == "deterministic_sca"


def test_raise_pr_endpoint_accepts_mcp_client_strategy(client, engine, monkeypatch):
    """strategy="mcp_client" is for a caller (an MCP client, typically
    Claude Code, when suggest-fix returned no diff) that read the flagged
    file itself and wrote its own fix rather than replaying a patch
    suggest-fix produced -- open_fix_pr doesn't care who generated
    new_content, so this just needs to pass RaiseFixPrRequest's Literal."""
    _login(client, engine)
    target_id = _make_target(engine)
    finding_id = _make_finding(engine, target_id, tool="trivy", file_path="requirements.txt")

    captured = {}

    def fake_open_fix_pr(session, target, finding, patch):
        captured["patch"] = patch
        return {"pr_url": "https://github.com/a/b/pull/2", "pr_number": 2, "branch": "toleman/fix-2"}

    monkeypatch.setattr("app.api.findings.open_fix_pr", fake_open_fix_pr)

    resp = client.post(
        f"/api/findings/{finding_id}/raise-pr",
        json={
            "file_path": "requirements.txt",
            "new_content": "starlette==0.41.0\n",
            "ref": "main",
            "strategy": "mcp_client",
            "explanation": "Read requirements.txt directly and bumped starlette.",
        },
    )
    assert resp.status_code == 200
    assert captured["patch"].strategy == "mcp_client"


def test_raise_pr_endpoint_rejects_unknown_strategy(client, engine):
    _login(client, engine)
    target_id = _make_target(engine)
    finding_id = _make_finding(engine, target_id, tool="trivy", file_path="requirements.txt")

    resp = client.post(
        f"/api/findings/{finding_id}/raise-pr",
        json={"file_path": "requirements.txt", "new_content": "x", "ref": "main", "strategy": "made_up"},
    )
    assert resp.status_code == 422


def test_raise_pr_endpoint_rejects_file_path_mismatch(client, engine):
    _login(client, engine)
    target_id = _make_target(engine)
    finding_id = _make_finding(engine, target_id, tool="trivy", file_path="requirements.txt")

    resp = client.post(
        f"/api/findings/{finding_id}/raise-pr",
        json={
            "file_path": "some/other/file.txt",
            "new_content": "x",
            "ref": "main",
            "strategy": "deterministic_sca",
        },
    )
    assert resp.status_code == 400


def test_raise_pr_endpoint_rejects_a_suppression_comment_on_the_flagged_line(client, engine, monkeypatch):
    _login(client, engine)
    target_id = _make_target(engine)
    finding_id = _make_finding(engine, target_id, tool="semgrep", file_path="app.py", line_start=2)

    called = {"open_fix_pr": False}
    monkeypatch.setattr("app.api.findings.open_fix_pr", lambda *a, **kw: called.update(open_fix_pr=True))

    resp = client.post(
        f"/api/findings/{finding_id}/raise-pr",
        json={
            "file_path": "app.py",
            "new_content": "line 1\nsubprocess.run(cmd, shell=True)  # nosemgrep\nline 3\n",
            "ref": "main",
            "strategy": "mcp_client",
        },
    )
    assert resp.status_code == 400
    assert "suppression comment" in resp.json()["detail"]
    # Never even reaches GitHub -- rejected before open_fix_pr is called.
    assert called["open_fix_pr"] is False


def test_raise_pr_endpoint_surfaces_autofix_error_as_502(client, engine, monkeypatch):
    _login(client, engine)
    target_id = _make_target(engine)
    finding_id = _make_finding(engine, target_id, tool="trivy", file_path="requirements.txt")

    def boom(session, target, finding, patch):
        raise autofix.AutofixError("no GitHub App installed")

    monkeypatch.setattr("app.api.findings.open_fix_pr", boom)

    resp = client.post(
        f"/api/findings/{finding_id}/raise-pr",
        json={
            "file_path": "requirements.txt",
            "new_content": "starlette==0.40.0\n",
            "ref": "main",
            "strategy": "deterministic_sca",
        },
    )
    assert resp.status_code == 502
    assert "no GitHub App installed" in resp.json()["detail"]


def test_raise_pr_endpoint_returns_404_for_missing_finding(client, engine):
    _login(client, engine)
    resp = client.post(
        "/api/findings/99999/raise-pr",
        json={"file_path": "x", "new_content": "x", "ref": "main", "strategy": "deterministic_sca"},
    )
    assert resp.status_code == 404


def test_raise_pr_endpoint_requires_developer_role(client, engine):
    target_id = _make_target(engine)
    finding_id = _make_finding(engine, target_id, tool="trivy", file_path="requirements.txt")
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

    resp = client.post(
        f"/api/findings/{finding_id}/raise-pr",
        json={
            "file_path": "requirements.txt",
            "new_content": "starlette==0.40.0\n",
            "ref": "main",
            "strategy": "deterministic_sca",
        },
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Package-level autofix (app.core.remediation_autofix): one PR per Fix Plan
# package upgrade, covering every finding it resolves, not the one-finding-
# at-a-time flow above (#247 follow-up).
# ---------------------------------------------------------------------------


def test_find_package_finding_files_groups_across_two_manifests(engine):
    """Two CVEs on the same package, findings pointing at two different
    manifests (e.g. requirements.txt and requirements-dev.txt) -- both have
    to be discovered, since PackageRemediation.fixes carries no file_path."""
    target_id = _make_target(engine)
    with Session(engine) as session:
        f1 = Finding(
            target_id=target_id, dedup_hash="h1", tool="trivy", rule_id="CVE-2024-1", title="Vuln",
            file_path="requirements.txt", severity=Severity.HIGH, cve_id="CVE-2024-1",
        )
        f2 = Finding(
            target_id=target_id, dedup_hash="h2", tool="trivy", rule_id="CVE-2024-1", title="Vuln",
            file_path="requirements-dev.txt", severity=Severity.HIGH, cve_id="CVE-2024-1",
        )
        session.add(f1)
        session.add(f2)
        session.commit()
        session.refresh(f1)
        session.refresh(f2)
        f1_id, f2_id = f1.id, f2.id
    _cve_row(engine, "CVE-2024-1", [{"package": "starlette", "ecosystem": "PyPI", "fixed": "0.40.0"}])

    plan = {
        "package": "starlette",
        "fixes": [
            {"finding_id": f1_id, "cve_id": "CVE-2024-1"},
            {"finding_id": f2_id, "cve_id": "CVE-2024-1"},
        ],
    }
    with Session(engine) as session:
        target = session.get(Target, target_id)
        grouped = remediation_autofix.find_package_finding_files(session, target, plan)
    assert set(grouped.keys()) == {("main", "requirements.txt"), ("main", "requirements-dev.txt")}


def test_build_package_patch_files_skips_unbumpable_succeeds_on_bumpable(engine, monkeypatch):
    """One of two requirements.txt files actually pins the package; the
    other doesn't (the bumper finds no match) and is skipped, not failed --
    only when NONE could be bumped does raise_package_fix_pr refuse."""
    target_id = _make_target(engine)
    with Session(engine) as session:
        f1 = Finding(
            target_id=target_id, dedup_hash="h1", tool="trivy", rule_id="CVE-2024-1", title="Vuln",
            file_path="requirements.txt", severity=Severity.HIGH, cve_id="CVE-2024-1",
        )
        f2 = Finding(
            target_id=target_id, dedup_hash="h2", tool="trivy", rule_id="CVE-2024-1", title="Vuln",
            file_path="backend/requirements.txt", severity=Severity.HIGH, cve_id="CVE-2024-1",
        )
        session.add(f1)
        session.add(f2)
        session.commit()
        session.refresh(f1)
        session.refresh(f2)
        f1_id, f2_id = f1.id, f2.id
    _cve_row(engine, "CVE-2024-1", [{"package": "starlette", "ecosystem": "PyPI", "fixed": "0.40.0"}])

    def fake_fetch(session, target, ref, path):
        if path == "requirements.txt":
            return "starlette==0.39.0\n", "sha1"
        return "flask==1.0\n", "sha2"  # no starlette pin here -- bumper finds no match

    monkeypatch.setattr(autofix, "_fetch_file", fake_fetch)

    plan = {
        "package": "starlette",
        "upgrade_to": "0.40.0",
        "fixes": [
            {"finding_id": f1_id, "cve_id": "CVE-2024-1"},
            {"finding_id": f2_id, "cve_id": "CVE-2024-1"},
        ],
    }
    with Session(engine) as session:
        target = session.get(Target, target_id)
        patches = remediation_autofix.build_package_patch_files(session, target, plan)
    assert len(patches) == 1
    _, file_path, new_content = patches[0]
    assert file_path == "requirements.txt"
    assert "starlette==0.40.0" in new_content


def test_raise_package_fix_pr_uses_package_level_version_not_per_finding_lowest(engine, monkeypatch):
    """Regression: two CVEs on the same package, each with a different
    lowest fix (0.38.0 and 0.40.0). The PR must bump to the PACKAGE-level
    upgrade_to -- the max of the two per-CVE minimums, i.e. the one version
    that actually clears both -- never to whichever finding
    autofix._sca_package_version happens to be asked about, which answers a
    narrower, single-finding question and would under-bump this package."""
    target_id = _make_target(engine)
    with Session(engine) as session:
        f1 = Finding(
            target_id=target_id, dedup_hash="h1", tool="trivy", rule_id="CVE-2024-1", title="Vuln 1",
            file_path="requirements.txt", severity=Severity.HIGH, cve_id="CVE-2024-1",
        )
        f2 = Finding(
            target_id=target_id, dedup_hash="h2", tool="trivy", rule_id="CVE-2024-2", title="Vuln 2",
            file_path="requirements.txt", severity=Severity.HIGH, cve_id="CVE-2024-2",
        )
        session.add(f1)
        session.add(f2)
        session.commit()
        session.refresh(f1)
        session.refresh(f2)
        f1_id, f2_id = f1.id, f2.id
    _cve_row(engine, "CVE-2024-1", [{"package": "starlette", "ecosystem": "PyPI", "fixed": "0.38.0"}])
    _cve_row(engine, "CVE-2024-2", [{"package": "starlette", "ecosystem": "PyPI", "fixed": "0.40.0"}])

    monkeypatch.setattr(autofix, "_fetch_file", lambda *a, **k: ("starlette==0.37.0\n", "sha1"))

    captured = {}

    def fake_commit(session, target, ref, branch_name, files, commit_message, pr_title, pr_body):
        captured["files"] = files
        captured["pr_title"] = pr_title
        return {"pr_url": "https://github.com/a/b/pull/9", "pr_number": 9, "branch": branch_name}

    monkeypatch.setattr(autofix, "_commit_files_and_open_pr", fake_commit)

    with Session(engine) as session:
        target = session.get(Target, target_id)
        plan = next(p for p in group_remediations(session, target_id) if p["package"] == "starlette")
        # Sanity: the plan itself already recommends the package-level
        # version, not either single CVE's own fix.
        assert plan["upgrade_to"] == "0.40.0"
        result = remediation_autofix.raise_package_fix_pr(session, target, plan, raised_by="user:a@e.com")

    assert result["pr_number"] == 9
    assert captured["files"] == [("requirements.txt", "starlette==0.40.0\n")]
    assert "0.40.0" in captured["pr_title"]

    with Session(engine) as session:
        row = session.exec(select(RemediationFixPr)).first()
    assert row.package == "starlette"
    assert row.upgrade_to == "0.40.0"
    assert row.raised_by == "user:a@e.com"
    assert sorted(json.loads(row.finding_ids)) == sorted([f1_id, f2_id])


def test_raise_package_fix_pr_is_idempotent_for_an_already_covered_package(engine, monkeypatch):
    """A second call for a package whose findings are already fully covered
    by a prior RemediationFixPr row must not open a second PR -- it raises
    AlreadyRaisedError carrying the FIRST PR's info, checked at
    raise_package_fix_pr's own boundary so every caller (manual endpoint,
    bulk batch, sweep) gets this protection for free."""
    target_id = _make_target(engine)
    with Session(engine) as session:
        f = Finding(
            target_id=target_id, dedup_hash="h1", tool="trivy", rule_id="CVE-2024-1", title="Vuln",
            file_path="requirements.txt", severity=Severity.HIGH, cve_id="CVE-2024-1",
        )
        session.add(f)
        session.commit()
        session.refresh(f)
        finding_id = f.id
    _cve_row(engine, "CVE-2024-1", [{"package": "starlette", "ecosystem": "PyPI", "fixed": "0.40.0"}])

    monkeypatch.setattr(autofix, "_fetch_file", lambda *a, **k: ("starlette==0.39.0\n", "sha1"))

    calls = {"n": 0}

    def fake_commit(session, target, ref, branch_name, files, commit_message, pr_title, pr_body):
        calls["n"] += 1
        return {"pr_url": f"https://github.com/a/b/pull/{calls['n']}", "pr_number": calls["n"], "branch": branch_name}

    monkeypatch.setattr(autofix, "_commit_files_and_open_pr", fake_commit)

    with Session(engine) as session:
        target = session.get(Target, target_id)
        plan = next(p for p in group_remediations(session, target_id) if p["package"] == "starlette")
        first = remediation_autofix.raise_package_fix_pr(session, target, plan, raised_by="user:a@e.com")
        assert first["pr_number"] == 1

        with pytest.raises(remediation_autofix.AlreadyRaisedError) as exc_info:
            remediation_autofix.raise_package_fix_pr(session, target, plan, raised_by="user:a@e.com")
        assert exc_info.value.pr_number == 1
        assert exc_info.value.pr_url == "https://github.com/a/b/pull/1"

    # Only the first call actually committed anything to GitHub.
    assert calls["n"] == 1
    with Session(engine) as session:
        rows = session.exec(select(RemediationFixPr)).all()
    assert len(rows) == 1


def test_raise_package_fix_pr_raises_again_for_a_genuinely_new_finding_on_the_same_package(engine, monkeypatch):
    """A second CVE lands on a package that already has a covering PR --
    the new finding is not a subset of what was covered, so this must
    raise a real second PR, not AlreadyRaisedError."""
    target_id = _make_target(engine)
    with Session(engine) as session:
        f1 = Finding(
            target_id=target_id, dedup_hash="h1", tool="trivy", rule_id="CVE-2024-1", title="Vuln 1",
            file_path="requirements.txt", severity=Severity.HIGH, cve_id="CVE-2024-1",
        )
        session.add(f1)
        session.commit()
        session.refresh(f1)
        f1_id = f1.id
    _cve_row(engine, "CVE-2024-1", [{"package": "starlette", "ecosystem": "PyPI", "fixed": "0.39.0"}])
    monkeypatch.setattr(autofix, "_fetch_file", lambda *a, **k: ("starlette==0.38.0\n", "sha1"))
    monkeypatch.setattr(
        autofix, "_commit_files_and_open_pr",
        lambda *a, **k: {"pr_url": "https://github.com/a/b/pull/1", "pr_number": 1, "branch": "b1"},
    )

    with Session(engine) as session:
        target = session.get(Target, target_id)
        plan = next(p for p in group_remediations(session, target_id) if p["package"] == "starlette")
        remediation_autofix.raise_package_fix_pr(session, target, plan, raised_by="user:a@e.com")

    with Session(engine) as session:
        f2 = Finding(
            target_id=target_id, dedup_hash="h2", tool="trivy", rule_id="CVE-2024-2", title="Vuln 2",
            file_path="requirements.txt", severity=Severity.HIGH, cve_id="CVE-2024-2",
        )
        session.add(f2)
        session.commit()
    _cve_row(engine, "CVE-2024-2", [{"package": "starlette", "ecosystem": "PyPI", "fixed": "0.40.0"}])
    monkeypatch.setattr(
        autofix, "_commit_files_and_open_pr",
        lambda *a, **k: {"pr_url": "https://github.com/a/b/pull/2", "pr_number": 2, "branch": "b2"},
    )

    with Session(engine) as session:
        target = session.get(Target, target_id)
        plan = next(p for p in group_remediations(session, target_id) if p["package"] == "starlette")
        second = remediation_autofix.raise_package_fix_pr(session, target, plan, raised_by="user:a@e.com")
    assert second["pr_number"] == 2


def test_raise_package_fix_pr_converts_a_secret_decryption_error_to_autofix_error(engine, monkeypatch):
    """The real production bug this pins down: a PLATFORM_ENCRYPTION_KEY
    mismatch decrypting a stored GitHub credential (SecretDecryptionError,
    a bare ValueError subclass, raised deep inside _fetch_file's token
    resolution) escaping raise_package_fix_pr uncaught would reach the API
    layer past every AutofixError handler, past CORSMiddleware, and
    Starlette's ServerErrorMiddleware would emit a bare response with no
    CORS headers at all -- which a browser's fetch() reports as a plain
    network failure, indistinguishable from the backend being unreachable.
    Must come back as a clean AutofixError instead, at both points that can
    raise it: reading the manifest and opening the PR."""
    target_id = _make_target(engine)
    with Session(engine) as session:
        f = Finding(
            target_id=target_id, dedup_hash="h1", tool="trivy", rule_id="CVE-2024-1", title="Vuln",
            file_path="requirements.txt", severity=Severity.HIGH, cve_id="CVE-2024-1",
        )
        session.add(f)
        session.commit()
    _cve_row(engine, "CVE-2024-1", [{"package": "starlette", "ecosystem": "PyPI", "fixed": "0.40.0"}])

    def boom(*a, **k):
        raise SecretDecryptionError("PLATFORM_ENCRYPTION_KEY mismatch")

    monkeypatch.setattr(autofix, "_fetch_file", boom)

    with Session(engine) as session:
        target = session.get(Target, target_id)
        plan = next(p for p in group_remediations(session, target_id) if p["package"] == "starlette")
        with pytest.raises(autofix.AutofixError, match="PLATFORM_ENCRYPTION_KEY"):
            remediation_autofix.raise_package_fix_pr(session, target, plan, raised_by="user:a@e.com")


def test_raise_package_fix_pr_converts_a_secret_decryption_error_opening_the_pr(engine, monkeypatch):
    """Same failure mode as the test above, at the second point it can
    happen: minting the GitHub App installation token (inside
    _commit_files_and_open_pr) rather than reading the manifest."""
    target_id = _make_target(engine)
    with Session(engine) as session:
        f = Finding(
            target_id=target_id, dedup_hash="h1", tool="trivy", rule_id="CVE-2024-1", title="Vuln",
            file_path="requirements.txt", severity=Severity.HIGH, cve_id="CVE-2024-1",
        )
        session.add(f)
        session.commit()
    _cve_row(engine, "CVE-2024-1", [{"package": "starlette", "ecosystem": "PyPI", "fixed": "0.40.0"}])
    monkeypatch.setattr(autofix, "_fetch_file", lambda *a, **k: ("starlette==0.39.0\n", "sha1"))

    def boom(*a, **k):
        raise SecretDecryptionError("PLATFORM_ENCRYPTION_KEY mismatch")

    monkeypatch.setattr(autofix, "_commit_files_and_open_pr", boom)

    with Session(engine) as session:
        target = session.get(Target, target_id)
        plan = next(p for p in group_remediations(session, target_id) if p["package"] == "starlette")
        with pytest.raises(autofix.AutofixError, match="PLATFORM_ENCRYPTION_KEY"):
            remediation_autofix.raise_package_fix_pr(session, target, plan, raised_by="user:a@e.com")


def test_raise_package_fix_pr_converts_any_unexpected_error_reading_the_manifest(engine, monkeypatch):
    """Defense in depth beyond the specific SecretDecryptionError case: no
    exception building a patch should be able to escape as anything other
    than AutofixError, regardless of what raised it."""
    target_id = _make_target(engine)
    with Session(engine) as session:
        f = Finding(
            target_id=target_id, dedup_hash="h1", tool="trivy", rule_id="CVE-2024-1", title="Vuln",
            file_path="requirements.txt", severity=Severity.HIGH, cve_id="CVE-2024-1",
        )
        session.add(f)
        session.commit()
    _cve_row(engine, "CVE-2024-1", [{"package": "starlette", "ecosystem": "PyPI", "fixed": "0.40.0"}])
    monkeypatch.setattr(autofix, "_fetch_file", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))

    with Session(engine) as session:
        target = session.get(Target, target_id)
        plan = next(p for p in group_remediations(session, target_id) if p["package"] == "starlette")
        with pytest.raises(autofix.AutofixError):
            remediation_autofix.raise_package_fix_pr(session, target, plan, raised_by="user:a@e.com")


def test_raise_package_fix_pr_refuses_when_no_manifest_could_be_bumped(engine, monkeypatch):
    target_id = _make_target(engine)
    with Session(engine) as session:
        f = Finding(
            target_id=target_id, dedup_hash="h1", tool="trivy", rule_id="CVE-2024-1", title="Vuln",
            file_path="requirements.txt", severity=Severity.HIGH, cve_id="CVE-2024-1",
        )
        session.add(f)
        session.commit()
    _cve_row(engine, "CVE-2024-1", [{"package": "starlette", "ecosystem": "PyPI", "fixed": "0.40.0"}])
    monkeypatch.setattr(autofix, "_fetch_file", lambda *a, **k: None)  # unreadable file

    with Session(engine) as session:
        target = session.get(Target, target_id)
        plan = next(p for p in group_remediations(session, target_id) if p["package"] == "starlette")
        with pytest.raises(autofix.AutofixError):
            remediation_autofix.raise_package_fix_pr(session, target, plan, raised_by="user:a@e.com")
