"""Tests for #401: a security reviewer approving a PR Guardrail ignore
request on one scan of a PR is a decision about that PR, not just that one
scan snapshot. Without carrying it forward, the next scan of the same PR
(e.g. after an unrelated commit) re-surfaces the identical finding as a
fresh row with ignore_status="none" -- net-new vs the default branch is
still technically correct, but it (a) keeps re-blocking the PR on a risk a
reviewer already accepted, and (b) renders in the PR comment looking like a
fresh, unaddressed issue nobody has seen.

Boundary mocking follows tests/test_pr_guardrail_multi_tool.py: real dedup,
policy, and status logic; only the GitHub API, git clone, scanner
subprocess and outbound HTTP are faked.
"""
import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

from app.core import pr_guardrail_executor
from app.core.time import utcnow
from app.models.models import (
    IgnoreStatus,
    Organization,
    PRGuardrailFinding,
    PRGuardrailStatus,
    Scan,
    Target,
    Workspace,
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
        # GH-07: a completed baseline scan must exist or the diff is skipped
        # entirely (see test_pr_guardrail_multi_tool.py's identical setup).
        session.add(Scan(target_id=t.id, tool="semgrep", branch=t.default_branch, status="completed"))
        session.commit()
        return t.id


def _wire_boundaries(monkeypatch, findings):
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
    monkeypatch.setattr(pr_guardrail_executor.runner, "run_tool", lambda tool, repo_path, paths=None: {"_tool": tool})
    monkeypatch.setattr(pr_guardrail_executor.parsers, "PARSER_MAP", {"semgrep": lambda raw: list(findings)})

    posted_comments = []
    monkeypatch.setattr(
        pr_guardrail_executor, "set_commit_status", lambda session, target, sha, state, description: None
    )
    monkeypatch.setattr(
        pr_guardrail_executor,
        "post_pr_comment",
        lambda session, target, pr_number, body: posted_comments.append(body),
    )
    return posted_comments


def _finding(rule_id="use-of-eval", severity="Critical", file_path="app.js", line=6):
    return {
        "rule_id": rule_id, "tool": "semgrep", "title": rule_id, "file_path": file_path,
        "line_start": line, "severity": severity, "snippet": "",
    }


def _approve(engine, finding_id: int, reviewer="sec@example.com"):
    with Session(engine) as session:
        finding = session.get(PRGuardrailFinding, finding_id)
        finding.ignore_status = IgnoreStatus.APPROVED
        finding.ignore_requested_by = "dev@example.com"
        finding.ignore_requested_reason = "accepted for this PR"
        finding.ignore_reviewed_by = reviewer
        finding.ignore_reviewed_at = utcnow()
        session.add(finding)
        session.commit()


def test_a_later_scan_of_the_same_pr_carries_forward_an_approved_ignore(engine, monkeypatch):
    target_id = _make_target(engine)
    _wire_boundaries(monkeypatch, [_finding()])

    with Session(engine) as session:
        target = session.get(Target, target_id)
        first = pr_guardrail_executor.execute_pr_guardrail_scan(target, 7, session)
    assert first["status"] == PRGuardrailStatus.BLOCKED
    # new_findings in the response is the summary dict shape
    # (finding_summary), which carries no id; fetch the persisted row instead.
    with Session(engine) as session:
        row = session.exec(
            select(PRGuardrailFinding).where(PRGuardrailFinding.pr_scan_id == first["pr_scan_id"])
        ).one()
        first_finding_id = row.id

    _approve(engine, first_finding_id)

    comments = _wire_boundaries(monkeypatch, [_finding()])
    with Session(engine) as session:
        target = session.get(Target, target_id)
        second = pr_guardrail_executor.execute_pr_guardrail_scan(target, 7, session)

    # The only blocking finding on this second scan was already approved on
    # the first -- must not keep the PR BLOCKED again.
    assert second["status"] == PRGuardrailStatus.PASSED

    with Session(engine) as session:
        second_row = session.exec(
            select(PRGuardrailFinding).where(PRGuardrailFinding.pr_scan_id == second["pr_scan_id"])
        ).one()
        assert second_row.ignore_status == IgnoreStatus.APPROVED
        assert second_row.ignore_reviewed_by == "sec@example.com"
        assert second_row.ignore_requested_reason == "accepted for this PR"

    # The posted comment must not offer "request ignore" again for a
    # finding a reviewer already approved -- that's indistinguishable from
    # the request having gone nowhere.
    assert "request ignore" not in comments[-1]
    assert "approved to ignore" in comments[-1]


def test_a_scan_of_a_different_pr_does_not_inherit_the_approval(engine, monkeypatch):
    """The carry-forward is scoped to the same PR; an identical finding
    surfacing on a completely different PR is a fresh issue, not something
    anyone has reviewed yet."""
    target_id = _make_target(engine)
    _wire_boundaries(monkeypatch, [_finding()])

    with Session(engine) as session:
        target = session.get(Target, target_id)
        first = pr_guardrail_executor.execute_pr_guardrail_scan(target, 7, session)
    with Session(engine) as session:
        row = session.exec(
            select(PRGuardrailFinding).where(PRGuardrailFinding.pr_scan_id == first["pr_scan_id"])
        ).one()
        first_finding_id = row.id
    _approve(engine, first_finding_id)

    _wire_boundaries(monkeypatch, [_finding()])
    with Session(engine) as session:
        target = session.get(Target, target_id)
        other_pr = pr_guardrail_executor.execute_pr_guardrail_scan(target, 99, session)

    assert other_pr["status"] == PRGuardrailStatus.BLOCKED
    with Session(engine) as session:
        row = session.exec(
            select(PRGuardrailFinding).where(PRGuardrailFinding.pr_scan_id == other_pr["pr_scan_id"])
        ).one()
        assert row.ignore_status == IgnoreStatus.NONE


def test_a_rejected_ignore_is_not_carried_forward(engine, monkeypatch):
    target_id = _make_target(engine)
    _wire_boundaries(monkeypatch, [_finding()])

    with Session(engine) as session:
        target = session.get(Target, target_id)
        first = pr_guardrail_executor.execute_pr_guardrail_scan(target, 7, session)
    with Session(engine) as session:
        row = session.exec(
            select(PRGuardrailFinding).where(PRGuardrailFinding.pr_scan_id == first["pr_scan_id"])
        ).one()
        row.ignore_status = IgnoreStatus.REJECTED
        row.ignore_reviewed_by = "sec@example.com"
        row.ignore_reviewed_at = utcnow()
        session.add(row)
        session.commit()

    _wire_boundaries(monkeypatch, [_finding()])
    with Session(engine) as session:
        target = session.get(Target, target_id)
        second = pr_guardrail_executor.execute_pr_guardrail_scan(target, 7, session)

    assert second["status"] == PRGuardrailStatus.BLOCKED
    with Session(engine) as session:
        row = session.exec(
            select(PRGuardrailFinding).where(PRGuardrailFinding.pr_scan_id == second["pr_scan_id"])
        ).one()
        assert row.ignore_status == IgnoreStatus.NONE
