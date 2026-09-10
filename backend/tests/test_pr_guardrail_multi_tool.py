"""Tests for finding GH-01: PR Guardrail must run every tool the workspace
has assigned to the pr_guardrail surface, not a hardcoded semgrep.

The bug an external evaluation found: a test PR containing a hardcoded AWS
key, a Django secret key and a concatenated SQL query was scanned, and only
the SQL injection blocked. The secrets went straight through; because the
diff scanner was pinned to semgrep while the Tool Marketplace rendered a
*ticked* "PR guardrail" checkbox for Gitleaks, Trivy and gosec.

Boundary mocking follows tests/test_enforcement_mode.py: real dedup, policy,
enforcement and status logic; only the GitHub API, git clone, scanner
subprocess and outbound HTTP are faked.
"""
import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

from app.core import pr_guardrail_executor
from app.models.models import (
    Organization,
    PRGuardrailScan,
    PRGuardrailStatus,
    Scan,
    Target,
    Workspace,
    WorkspaceToolConfig,
)


@pytest.fixture()
def engine():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(eng)
    return eng


def _make_target(engine) -> int:
    with Session(engine) as session:
        org = Organization(name="org")
        session.add(org)
        session.commit()
        session.refresh(org)
        ws = Workspace(organization_id=org.id, name="ws", api_key="k")
        session.add(ws)
        session.commit()
        session.refresh(ws)
        t = Target(workspace_id=ws.id, name="repo", repo_url="https://github.com/acme/repo")
        session.add(t)
        session.commit()
        session.refresh(t)
        # These tests exercise the net-new diff itself, so they need an
        # established baseline (GH-07): without a completed default-branch
        # scan on record, execute_pr_guardrail_scan can't tell "nothing
        # known yet" from "diffed and clean" and skips the diff entirely.
        session.add(Scan(target_id=t.id, tool="semgrep", branch=t.default_branch, status="completed"))
        session.commit()
        return t.id


def _wire_boundaries(monkeypatch, tool_outputs, failing_tools=()):
    """Mock every external boundary. `tool_outputs` maps tool name -> the
    parsed findings that tool should produce; `failing_tools` names tools
    whose subprocess raises, standing in for a scanner that is missing or
    crashes."""
    monkeypatch.setattr(
        pr_guardrail_executor,
        "github_get",
        lambda path, **kwargs: type("R", (), {
            "raise_for_status": lambda self: None,
            "json": lambda self: {"head": {"ref": "feature", "sha": "deadbeef"}, "title": "a pr"},
        })(),
    )
    monkeypatch.setattr(pr_guardrail_executor, "resolve_github_token", lambda session, workspace_id, slug: None)
    monkeypatch.setattr(pr_guardrail_executor.runner, "clone_repo", lambda *a, **k: "/tmp/fake-repo")
    monkeypatch.setattr(pr_guardrail_executor.runner, "normalize_file_path", lambda fp, repo_path: fp)
    monkeypatch.setattr(pr_guardrail_executor, "_diff_new_endpoints", lambda session, target, repo_path: [])
    monkeypatch.setattr(pr_guardrail_executor, "_get_installation_token_or_none", lambda session, target: None)

    ran = []

    def fake_run_tool(tool, repo_path, paths=None):
        # `paths` mirrors the real runner.run_tool signature (#243). These
        # tests all exercise the unscoped path, so it should arrive as None.
        assert paths is None
        ran.append(tool)
        if tool in failing_tools:
            raise RuntimeError(f"{tool} exploded")
        return {"_tool": tool}

    monkeypatch.setattr(pr_guardrail_executor.runner, "run_tool", fake_run_tool)
    monkeypatch.setattr(
        pr_guardrail_executor.parsers,
        "PARSER_MAP",
        {t: (lambda raw, _t=t: list(tool_outputs.get(_t, []))) for t in tool_outputs},
    )

    posted_statuses = []
    monkeypatch.setattr(
        pr_guardrail_executor,
        "set_commit_status",
        lambda session, target, sha, state, description: posted_statuses.append((state, description)),
    )
    posted_comments = []
    monkeypatch.setattr(
        pr_guardrail_executor,
        "post_pr_comment",
        lambda session, target, pr_number, body: posted_comments.append(body),
    )
    return ran, posted_statuses, posted_comments


def _finding(rule_id, severity="High", file_path="app.py", line=1):
    return {
        "rule_id": rule_id,
        "title": rule_id,
        "file_path": file_path,
        "line_start": line,
        "severity": severity,
        "snippet": "",
    }


def test_secret_in_a_pr_blocks_it(engine, monkeypatch):
    """The exact reported failure: gitleaks finds a hardcoded AWS key and the
    PR must block. Before GH-01's fix gitleaks never ran and this passed."""
    target_id = _make_target(engine)
    ran, statuses, comments = _wire_boundaries(
        monkeypatch,
        {
            "semgrep": [],
            "gitleaks": [_finding("aws-access-token", severity="High", file_path="settings.py")],
            "trivy": [],
            "gosec": [],
        },
    )

    with Session(engine) as session:
        target = session.get(Target, target_id)
        result = pr_guardrail_executor.execute_pr_guardrail_scan(target, 4, session)

    assert "gitleaks" in ran, "gitleaks was assigned to pr_guardrail but never ran"
    assert result["status"] == PRGuardrailStatus.BLOCKED
    assert result["new_findings_count"] == 1
    assert result["new_findings"][0]["tool"] == "gitleaks"
    assert statuses[-1][0] == "failure"


def test_findings_from_several_tools_are_all_reported(engine, monkeypatch):
    target_id = _make_target(engine)
    _wire_boundaries(
        monkeypatch,
        {
            "semgrep": [_finding("sql-injection", file_path="db.py")],
            "gitleaks": [_finding("aws-access-token", file_path="settings.py")],
            "trivy": [_finding("CVE-2026-1", file_path="requirements.txt")],
            "gosec": [],
        },
    )

    with Session(engine) as session:
        target = session.get(Target, target_id)
        result = pr_guardrail_executor.execute_pr_guardrail_scan(target, 4, session)

    assert result["new_findings_count"] == 3
    assert {f["tool"] for f in result["new_findings"]} == {"semgrep", "gitleaks", "trivy"}


def test_a_tool_disabled_for_this_workspace_does_not_run(engine, monkeypatch):
    target_id = _make_target(engine)
    with Session(engine) as session:
        target = session.get(Target, target_id)
        session.add(WorkspaceToolConfig(workspace_id=target.workspace_id, tool="gitleaks", pr_guardrail=False))
        session.commit()

    ran, _, _ = _wire_boundaries(
        monkeypatch,
        {"semgrep": [], "gitleaks": [_finding("aws-access-token")], "trivy": [], "gosec": []},
    )

    with Session(engine) as session:
        target = session.get(Target, target_id)
        result = pr_guardrail_executor.execute_pr_guardrail_scan(target, 4, session)

    assert "gitleaks" not in ran
    # Operator turned it off deliberately, so its finding must not appear.
    assert result["new_findings_count"] == 0
    assert result["status"] == PRGuardrailStatus.PASSED


def test_a_failing_tool_never_reports_a_clean_pass_in_the_comment(engine, monkeypatch):
    """The PR comment must never render a partial scan as a plain all-clear:
    the failed tool is named and the tick is withheld, regardless of what
    the commit status ends up being (see the two tests below for that)."""
    target_id = _make_target(engine)
    ran, statuses, comments = _wire_boundaries(
        monkeypatch,
        {"semgrep": [], "gitleaks": [], "trivy": [], "gosec": []},
        failing_tools=("gitleaks",),
    )

    with Session(engine) as session:
        target = session.get(Target, target_id)
        result = pr_guardrail_executor.execute_pr_guardrail_scan(target, 4, session)

    body = comments[-1]
    assert "gitleaks" in body
    assert "not fully scanned" in body.lower()
    assert "✅" not in body, "a partial scan must not render the all-clear tick"

    with Session(engine) as session:
        scan = session.get(PRGuardrailScan, result["pr_scan_id"])
        assert scan.tools_failed == "gitleaks"
        assert "gitleaks" not in scan.tools_run.split(",")
        assert "semgrep" in scan.tools_run.split(",")


def test_a_failed_tool_with_nothing_blocking_does_not_fail_the_required_check(engine, monkeypatch):
    """A failed tool alongside zero net-new findings from the tools that did
    run is *incomplete*, not *broken* -- the PR comment still says so (see
    above), but the commit status (what actually gates merge as a required
    check) must not block on it. Without this, a workspace whose
    pr_guardrail assignment includes even one tool this deployment can never
    run (e.g. not installed) would fail every PR forever regardless of
    content, making the required check useless as a merge gate."""
    target_id = _make_target(engine)
    _, statuses, _ = _wire_boundaries(
        monkeypatch,
        {"semgrep": [], "gitleaks": [], "trivy": [], "gosec": []},
        failing_tools=("gitleaks",),
    )

    with Session(engine) as session:
        target = session.get(Target, target_id)
        pr_guardrail_executor.execute_pr_guardrail_scan(target, 4, session)

    state, description = statuses[-1]
    assert state == "success", "incomplete coverage with nothing blocking found must not fail the required check"
    assert "gitleaks" in description
    assert "failed to run" in description


def test_a_real_blocking_finding_still_fails_even_with_a_failed_tool(engine, monkeypatch):
    """The reverse must also hold: a genuine blocking finding from a tool
    that DID run is never masked by an unrelated tool's failure. Known
    danger always outranks incomplete coverage."""
    target_id = _make_target(engine)
    _, statuses, _ = _wire_boundaries(
        monkeypatch,
        {"semgrep": [_finding("sql-injection")], "gitleaks": [], "trivy": [], "gosec": []},
        failing_tools=("gitleaks",),
    )

    with Session(engine) as session:
        target = session.get(Target, target_id)
        pr_guardrail_executor.execute_pr_guardrail_scan(target, 4, session)

    state, description = statuses[-1]
    assert state == "failure", "a real blocking finding must still fail, even alongside a failed tool"
    assert "1 net-new finding" in description


def test_one_failing_tool_does_not_discard_the_others_findings(engine, monkeypatch):
    target_id = _make_target(engine)
    _wire_boundaries(
        monkeypatch,
        {"semgrep": [_finding("sql-injection")], "gitleaks": [], "trivy": [], "gosec": []},
        failing_tools=("trivy",),
    )

    with Session(engine) as session:
        target = session.get(Target, target_id)
        result = pr_guardrail_executor.execute_pr_guardrail_scan(target, 4, session)

    assert result["new_findings_count"] == 1
    assert result["new_findings"][0]["tool"] == "semgrep"


def test_scan_records_which_tools_ran(engine, monkeypatch):
    target_id = _make_target(engine)
    _wire_boundaries(monkeypatch, {"semgrep": [], "gitleaks": [], "trivy": [], "gosec": []})

    with Session(engine) as session:
        target = session.get(Target, target_id)
        result = pr_guardrail_executor.execute_pr_guardrail_scan(target, 4, session)

    with Session(engine) as session:
        scan = session.get(PRGuardrailScan, result["pr_scan_id"])
        assert scan.tools_failed == ""
        assert "semgrep" in scan.tools_run
        assert "gitleaks" in scan.tools_run


def test_same_rule_from_two_tools_is_not_deduped_away(engine, monkeypatch):
    """dedup_hash must incorporate the finding's own tool. Hashing every
    tool's output under one constant would let a gitleaks hit collide with a
    semgrep hit on the same file/line and silently vanish."""
    target_id = _make_target(engine)
    _wire_boundaries(
        monkeypatch,
        {
            "semgrep": [_finding("hardcoded-secret", file_path="settings.py", line=7)],
            "gitleaks": [_finding("hardcoded-secret", file_path="settings.py", line=7)],
            "trivy": [],
            "gosec": [],
        },
    )

    with Session(engine) as session:
        target = session.get(Target, target_id)
        result = pr_guardrail_executor.execute_pr_guardrail_scan(target, 4, session)

    assert result["new_findings_count"] == 2
    assert {f["tool"] for f in result["new_findings"]} == {"semgrep", "gitleaks"}
