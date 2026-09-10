"""Tests for findings GH-04 and GH-06; two places PR Guardrail reported
something it had not actually established.

GH-04: `set_commit_status()` was documented "best-effort: never raises" and
failed open into a container log. Enforcement resolution is carefully
fail-*closed* (conflicting groups resolve to the most restrictive), while the
transport carrying that decision to GitHub was fail-open and silent. A broken
installation token means PRs quietly stop being marked and nobody is told.

GH-06: the new-endpoint diff compared against previously-*known* endpoints,
so on a target's first PR scan (when nothing is known) the entire
repository looked new. An evaluator's PR touching one file was reported as
adding four endpoints across files it never touched. First-run noise, in the
most visible artefact the tool produces.

GH-07: the same bug, unfixed, in the finding diff GH-06 was modelled on.
compute_net_new() excludes findings whose dedup_hash is already Open on the
default branch; on a target whose default branch has never been scanned,
that "already Open" set is empty for the same reason it would be empty on a
branch that was scanned and found clean. A PR against a freshly-registered
repo -- necessarily the first PR that GitHub App ever sees -- got every
pre-existing finding across the whole repository reported and blocked as
introduced by that one PR, even in files it never touched.
"""

import httpx
import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

from app.core import pr_guardrail_executor
from app.models.models import ApiEndpoint, Organization, PRGuardrailScan, Scan, Target, Workspace


@pytest.fixture()
def engine():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(eng)
    return eng


@pytest.fixture()
def target_id(engine):
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


# ---------------------------------------------------------------------------
# GH-04: commit-status delivery failures must be visible
# ---------------------------------------------------------------------------


def test_successful_delivery_reports_no_error(engine, target_id, monkeypatch):
    monkeypatch.setattr(pr_guardrail_executor, "_get_installation_token_or_none", lambda s, t: "tok")
    monkeypatch.setattr(
        pr_guardrail_executor.httpx,
        "post",
        lambda *a, **k: type("R", (), {"status_code": 201, "text": ""})(),
    )

    with Session(engine) as session:
        target = session.get(Target, target_id)
        assert pr_guardrail_executor.set_commit_status(session, target, "sha", "success", "ok") == ""


def test_a_rejected_status_reports_why(engine, target_id, monkeypatch):
    monkeypatch.setattr(pr_guardrail_executor, "_get_installation_token_or_none", lambda s, t: "tok")
    monkeypatch.setattr(
        pr_guardrail_executor.httpx,
        "post",
        lambda *a, **k: type("R", (), {"status_code": 403, "text": "Resource not accessible"})(),
    )

    with Session(engine) as session:
        target = session.get(Target, target_id)
        reason = pr_guardrail_executor.set_commit_status(session, target, "sha", "failure", "blocked")

    assert reason, "a rejected commit status must not report success"
    assert "403" in reason
    assert "not marked on GitHub" in reason


def test_an_unreachable_github_reports_why(engine, target_id, monkeypatch):
    monkeypatch.setattr(pr_guardrail_executor, "_get_installation_token_or_none", lambda s, t: "tok")

    def boom(*a, **k):
        raise httpx.ConnectError("no route to host")

    monkeypatch.setattr(pr_guardrail_executor.httpx, "post", boom)

    with Session(engine) as session:
        target = session.get(Target, target_id)
        reason = pr_guardrail_executor.set_commit_status(session, target, "sha", "failure", "blocked")

    assert "ConnectError" in reason
    assert "not marked on GitHub" in reason


def test_a_delivery_failure_never_echoes_the_exception_text(engine, target_id, monkeypatch):
    """An httpx error can carry the request URL, and that URL is built with an
    installation token. The reason is surfaced in the UI, so it must name the
    failure type, never the exception's own message."""
    monkeypatch.setattr(pr_guardrail_executor, "_get_installation_token_or_none", lambda s, t: "tok")

    def boom(*a, **k):
        raise httpx.ConnectError("failed connecting to https://x-access-token:ghs_SUPERSECRET@api.github.com")

    monkeypatch.setattr(pr_guardrail_executor.httpx, "post", boom)

    with Session(engine) as session:
        target = session.get(Target, target_id)
        reason = pr_guardrail_executor.set_commit_status(session, target, "sha", "failure", "blocked")

    assert "ghs_SUPERSECRET" not in reason
    assert "x-access-token" not in reason


def test_no_app_installed_is_reported_not_silently_skipped(engine, target_id, monkeypatch):
    monkeypatch.setattr(pr_guardrail_executor, "_get_installation_token_or_none", lambda s, t: None)

    with Session(engine) as session:
        target = session.get(Target, target_id)
        reason = pr_guardrail_executor.set_commit_status(session, target, "sha", "success", "ok")

    assert "No GitHub App installed" in reason


def test_delivery_failure_still_returns_rather_than_raising(engine, target_id, monkeypatch):
    """Fail-open is deliberate: a GitHub outage must not abort a scan that
    already produced real findings. The change is that it is no longer
    *silent*, not that it now raises."""
    monkeypatch.setattr(pr_guardrail_executor, "_get_installation_token_or_none", lambda s, t: "tok")

    def boom(*a, **k):
        raise RuntimeError("anything at all")

    monkeypatch.setattr(pr_guardrail_executor.httpx, "post", boom)

    with Session(engine) as session:
        target = session.get(Target, target_id)
        # Must not raise.
        assert isinstance(pr_guardrail_executor.set_commit_status(session, target, "s", "success", "d"), str)


def test_scan_row_defaults_to_no_delivery_error(engine, target_id):
    with Session(engine) as session:
        scan = PRGuardrailScan(target_id=target_id, pr_number=1, branch="f")
        session.add(scan)
        session.commit()
        session.refresh(scan)
        assert scan.status_delivery_error == ""


# ---------------------------------------------------------------------------
# GH-06: no endpoint baseline is not "every endpoint is new"
# ---------------------------------------------------------------------------


def _discovered():
    return [
        {"method": "GET", "route": "/login", "file": "bad/vulpy.py", "line": 10},
        {"method": "POST", "route": "/login", "file": "good/vulpy.py", "line": 20},
    ]


def test_first_scan_with_no_baseline_reports_no_new_endpoints(engine, target_id, monkeypatch):
    """The reported bug: a PR touching one file was announced as adding four
    endpoints across files it never touched, because nothing was known yet."""
    monkeypatch.setattr(pr_guardrail_executor, "discover_endpoints", lambda repo_path: _discovered())

    with Session(engine) as session:
        target = session.get(Target, target_id)
        new = pr_guardrail_executor._diff_new_endpoints(session, target, "/tmp/repo")

    assert new == [], "with no baseline, nothing can be established as net-new"


def test_a_genuinely_new_endpoint_is_still_reported(engine, target_id, monkeypatch):
    """The fix must not silence the feature; once a baseline exists, a real
    net-new endpoint still surfaces."""
    with Session(engine) as session:
        target = session.get(Target, target_id)
        session.add(
            ApiEndpoint(
                target_id=target.id,
                branch=target.default_branch,
                method="GET",
                route="/login",
                file_path="bad/vulpy.py",
                framework="flask",
            )
        )
        session.commit()

    monkeypatch.setattr(pr_guardrail_executor, "discover_endpoints", lambda repo_path: _discovered())

    with Session(engine) as session:
        target = session.get(Target, target_id)
        new = pr_guardrail_executor._diff_new_endpoints(session, target, "/tmp/repo")

    assert len(new) == 1
    assert new[0]["route"] == "/login"
    assert new[0]["file"] == "good/vulpy.py"


def test_a_fully_known_repo_reports_nothing_new(engine, target_id, monkeypatch):
    with Session(engine) as session:
        target = session.get(Target, target_id)
        for d in _discovered():
            session.add(
                ApiEndpoint(
                    target_id=target.id,
                    branch=target.default_branch,
                    method=d["method"],
                    framework="flask",
                    route=d["route"],
                    file_path=d["file"],
                )
            )
        session.commit()

    monkeypatch.setattr(pr_guardrail_executor, "discover_endpoints", lambda repo_path: _discovered())

    with Session(engine) as session:
        target = session.get(Target, target_id)
        assert pr_guardrail_executor._diff_new_endpoints(session, target, "/tmp/repo") == []


def test_another_targets_baseline_does_not_count_as_this_ones(engine, target_id, monkeypatch):
    """A baseline belonging to a different target must not make this target
    look like it has one; that would reintroduce the bug in reverse,
    silently suppressing real endpoints on a genuine first scan."""
    with Session(engine) as session:
        other = Target(workspace_id=1, name="other", repo_url="https://github.com/acme/other")
        session.add(other)
        session.commit()
        session.refresh(other)
        session.add(
            ApiEndpoint(
                target_id=other.id, branch="main", method="GET", route="/x", file_path="a.py", framework="flask"
            )
        )
        session.commit()

    monkeypatch.setattr(pr_guardrail_executor, "discover_endpoints", lambda repo_path: _discovered())

    with Session(engine) as session:
        target = session.get(Target, target_id)
        assert pr_guardrail_executor._diff_new_endpoints(session, target, "/tmp/repo") == []


# ---------------------------------------------------------------------------
# GH-07: no finding baseline is not "every finding is new"
# ---------------------------------------------------------------------------


def test_no_scan_at_all_means_no_baseline(engine, target_id):
    with Session(engine) as session:
        target = session.get(Target, target_id)
        assert pr_guardrail_executor._has_baseline_scan(session, target) is False


def test_a_completed_scan_on_the_default_branch_is_a_baseline(engine, target_id):
    with Session(engine) as session:
        target = session.get(Target, target_id)
        session.add(Scan(target_id=target.id, tool="semgrep", branch=target.default_branch, status="completed"))
        session.commit()

    with Session(engine) as session:
        target = session.get(Target, target_id)
        assert pr_guardrail_executor._has_baseline_scan(session, target) is True


def test_a_still_running_scan_is_not_a_baseline_yet(engine, target_id):
    """An in-flight scan hasn't produced any Finding rows yet; treating it as
    a baseline would make the diff run against results that don't exist."""
    with Session(engine) as session:
        target = session.get(Target, target_id)
        session.add(Scan(target_id=target.id, tool="semgrep", branch=target.default_branch, status="running"))
        session.commit()

    with Session(engine) as session:
        target = session.get(Target, target_id)
        assert pr_guardrail_executor._has_baseline_scan(session, target) is False


def test_a_scan_of_a_different_branch_is_not_a_baseline(engine, target_id):
    with Session(engine) as session:
        target = session.get(Target, target_id)
        session.add(Scan(target_id=target.id, tool="semgrep", branch="some-feature-branch", status="completed"))
        session.commit()

    with Session(engine) as session:
        target = session.get(Target, target_id)
        assert pr_guardrail_executor._has_baseline_scan(session, target) is False


def test_another_targets_scan_does_not_count_as_this_ones_baseline(engine, target_id):
    with Session(engine) as session:
        other = Target(workspace_id=1, name="other", repo_url="https://github.com/acme/other")
        session.add(other)
        session.commit()
        session.refresh(other)
        session.add(Scan(target_id=other.id, tool="semgrep", branch=other.default_branch, status="completed"))
        session.commit()

    with Session(engine) as session:
        target = session.get(Target, target_id)
        assert pr_guardrail_executor._has_baseline_scan(session, target) is False


def test_render_comment_flags_missing_baseline_instead_of_a_clean_all_clear():
    body = pr_guardrail_executor.render_comment(
        [], [], PRGuardrailScan(id=1, target_id=1, pr_number=1, branch="f").status,
        target_id=1, pr_scan_id=1, baseline_missing=True,
    )
    assert "No baseline scan yet" in body
    assert "vs the default branch. ✅" not in body


def test_render_comment_without_baseline_missing_is_unchanged():
    """Default False must reproduce the pre-GH-07 output for existing callers."""
    body = pr_guardrail_executor.render_comment(
        [], [], PRGuardrailScan(id=1, target_id=1, pr_number=1, branch="f").status,
        target_id=1, pr_scan_id=1,
    )
    assert "No baseline scan yet" not in body
    assert "vs the default branch. ✅" in body
