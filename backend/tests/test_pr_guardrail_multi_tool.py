"""Tests for finding GH-01: PR Guardrail must run every tool the workspace
has assigned to the pr_guardrail surface, not a hardcoded semgrep.

The bug an external evaluation found: a test PR containing a hardcoded AWS
key, a Django secret key and a concatenated SQL query was scanned, and only
the SQL injection blocked. The secrets went straight through -- because the
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
        return t.id


def _wire_boundaries(monkeypatch, tool_outputs, failing_tools=()):
    """Mock every external boundary. `tool_outputs` maps tool name -> the
    parsed findings that tool should produce; `failing_tools` names tools
    whose subprocess raises, standing in for a scanner that is missing or
    crashes."""
    monkeypatch.setattr(
        pr_guardrail_executor,
        "github_get",
        lambda path: type("R", (), {
            "raise_for_status": lambda self: None,
            "json": lambda self: {"head": {"ref": "feature", "sha": "deadbeef"}, "title": "a pr"},
        })(),
    )
    monkeypatch.setattr(pr_guardrail_executor.runner, "clone_repo", lambda *a, **k: "/tmp/fake-repo")
    monkeypatch.setattr(pr_guardrail_executor.runner, "normalize_file_path", lambda fp, repo_path: fp)
    monkeypatch.setattr(pr_guardrail_executor, "_diff_new_endpoints", lambda session, target, repo_path: [])
    monkeypatch.setattr(pr_guardrail_executor, "_get_installation_token_or_none", lambda session, target: None)

    ran = []

    def fake_run_tool(tool, repo_path):
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


def test_a_failing_tool_never_reports_a_clean_pass(engine, monkeypatch):
    """The core honesty rule: if an assigned tool did not run, the PR was not
    fully checked, and neither the commit status nor the comment may say it
    was clean."""
    target_id = _make_target(engine)
    ran, statuses, comments = _wire_boundaries(
        monkeypatch,
        {"semgrep": [], "gitleaks": [], "trivy": [], "gosec": []},
        failing_tools=("gitleaks",),
    )

    with Session(engine) as session:
        target = session.get(Target, target_id)
        result = pr_guardrail_executor.execute_pr_guardrail_scan(target, 4, session)

    state, description = statuses[-1]
    assert state == "error", "a scan with a failed tool must not post success"
    assert "gitleaks" in description
    assert "not fully scanned" in description

    body = comments[-1]
    assert "gitleaks" in body
    assert "not fully scanned" in body.lower()
    assert "✅" not in body, "a partial scan must not render the all-clear tick"

    with Session(engine) as session:
        scan = session.get(PRGuardrailScan, result["pr_scan_id"])
        assert scan.tools_failed == "gitleaks"
        assert "gitleaks" not in scan.tools_run.split(",")
        assert "semgrep" in scan.tools_run.split(",")


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
