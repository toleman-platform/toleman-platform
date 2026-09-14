"""Tests for GET /api/github/prs/{target_id}.

Two things the endpoint has to add to GitHub's own payload, both of which PR
History depends on:

* "merged" as a first-class state. GitHub reports only open/closed, but the
  dashboard's PR-state filter offers Merged and Closed separately, because
  merged and closed-without-merging are different outcomes to a reviewer.
* the target's latest PR Guardrail scan for each PR. `scan_status` used to be
  the hardcoded string "not scanned" on every row, including PRs this platform
  had scanned and blocked; and with no scan id on the row, the PR list had no
  way to expand into the vulnerabilities that scan found.

The GitHub API boundary is mocked the same way tests/test_github_org_activity.py
mocks it, monkeypatching the github_get symbol imported into app.api.github.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

import app.api.deps as deps_module
import app.api.github as github_module
from app.api.deps import get_session
from app.core.security import create_session_token, hash_password
from app.main import app
from app.models.models import (
    Organization,
    PRGuardrailScan,
    PRGuardrailStatus,
    Target,
    User,
    Workspace,
)
from app.core.time import utcnow


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


def _login(client, engine):
    with Session(engine) as session:
        user = User(email="user@example.com", name="Test User", password_hash=hash_password("whatever123"))
        session.add(user)
        session.commit()
        session.refresh(user)
        token = create_session_token(user.id)
    client.cookies.set("toleman_session", token)
    return client


def _make_target(engine) -> int:
    with Session(engine) as session:
        org = Organization(name="Org")
        session.add(org)
        session.commit()
        session.refresh(org)

        workspace = Workspace(organization_id=org.id, name="WS", api_key="key-prs")
        session.add(workspace)
        session.commit()
        session.refresh(workspace)

        target = Target(workspace_id=workspace.id, name="repo-a", repo_url="https://github.com/acme/repo-a.git")
        session.add(target)
        session.commit()
        session.refresh(target)
        return target.id


class _FakeResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload

    @property
    def text(self):
        return str(self._payload)


def _pr(number, state="open", merged_at=None):
    """Shaped as GitHub returns it: `state` is only ever open/closed upstream,
    and a merged PR is a closed one carrying merged_at."""
    return {
        "number": number,
        "title": f"PR {number}",
        "user": {"login": "dev"},
        "state": state,
        "created_at": "2026-09-01T00:00:00Z",
        "merged_at": merged_at,
        "html_url": f"https://github.com/acme/repo-a/pull/{number}",
    }


def _mock_prs(monkeypatch, prs):
    """Stands in for GitHub, honouring the `state` the endpoint asks for -- the
    filter being answered upstream rather than in the client is the point of
    the parameter, so a stub that ignored it would test nothing."""
    calls: list[dict] = []

    def fake_github_get(path, params=None, **kwargs):
        calls.append(params or {})
        wanted = (params or {}).get("state", "all")
        if wanted == "all":
            return _FakeResponse(200, prs)
        return _FakeResponse(200, [p for p in prs if p["state"] == wanted])

    monkeypatch.setattr(github_module, "github_get", fake_github_get)
    return calls


def _add_scan(engine, target_id, pr_number, **kwargs) -> int:
    with Session(engine) as session:
        scan = PRGuardrailScan(
            target_id=target_id,
            pr_number=pr_number,
            pr_title=f"PR {pr_number}",
            branch="feature",
            **kwargs,
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)
        return scan.id


def _rows(client, target_id, state="all"):
    resp = client.get(f"/api/github/prs/{target_id}", params={"state": state})
    assert resp.status_code == 200
    return {row["number"]: row for row in resp.json()}


def _mixed_prs():
    return [
        _pr(1, state="open"),
        _pr(2, state="closed", merged_at="2026-09-02T00:00:00Z"),
        _pr(3, state="closed"),
    ]


def test_merged_prs_report_merged_not_closed(client, engine, monkeypatch):
    """A merged PR is "closed" to GitHub. The state filter offers Merged and
    Closed as separate choices, so collapsing them here would put every merged
    PR under Closed."""
    _login(client, engine)
    target_id = _make_target(engine)
    _mock_prs(monkeypatch, _mixed_prs())

    rows = _rows(client, target_id)

    assert rows[1]["state"] == "open"
    assert rows[2]["state"] == "merged"
    assert rows[3]["state"] == "closed"


def test_state_filter_is_answered_by_github_not_by_trimming_a_page(client, engine, monkeypatch):
    """The reason this is a query parameter at all. GitHub returns PRs
    newest-created first, so on a repo that closes PRs faster than a page of
    them is opened (pallets/flask has no open PR in its 100 most recent), a
    page fetched for every state and then narrowed to open in the client is
    empty, and the dashboard reports "no open pull requests" on a repo full of
    them."""
    _login(client, engine)
    target_id = _make_target(engine)
    calls = _mock_prs(monkeypatch, _mixed_prs())

    assert set(_rows(client, target_id, "open")) == {1}

    assert calls[-1]["state"] == "open"


def test_merged_and_closed_both_ask_github_for_the_closed_set(client, engine, monkeypatch):
    """GitHub has no "merged" state, so both choices fetch closed PRs and are
    split apart here by merged_at."""
    _login(client, engine)
    target_id = _make_target(engine)
    calls = _mock_prs(monkeypatch, _mixed_prs())

    assert set(_rows(client, target_id, "merged")) == {2}
    assert calls[-1]["state"] == "closed"

    assert set(_rows(client, target_id, "closed")) == {3}
    assert calls[-1]["state"] == "closed"


def test_unknown_state_is_rejected_rather_than_silently_widened(client, engine, monkeypatch):
    """Falling back to "all" on a typo would answer a narrower question with a
    wider list, which is the failure this parameter exists to prevent."""
    _login(client, engine)
    target_id = _make_target(engine)
    _mock_prs(monkeypatch, _mixed_prs())

    resp = client.get(f"/api/github/prs/{target_id}", params={"state": "draft"})

    assert resp.status_code == 400


def test_state_defaults_to_open(client, engine, monkeypatch):
    _login(client, engine)
    target_id = _make_target(engine)
    calls = _mock_prs(monkeypatch, _mixed_prs())

    resp = client.get(f"/api/github/prs/{target_id}")

    assert resp.status_code == 200
    assert [row["number"] for row in resp.json()] == [1]
    assert calls[-1]["state"] == "open"


def test_unscanned_pr_reports_no_scan_rather_than_a_verdict(client, engine, monkeypatch):
    _login(client, engine)
    target_id = _make_target(engine)
    _mock_prs(monkeypatch, [_pr(1)])

    row = _rows(client, target_id)[1]

    assert row["scan_status"] == "not scanned"
    assert row["latest_scan_id"] is None
    assert row["new_findings_count"] == 0
    assert row["highest_new_severity"] is None


def test_scanned_pr_carries_its_verdict_and_findings(client, engine, monkeypatch):
    """The row a reviewer reads has to name the scan it is reporting, or the
    PR list cannot open onto the findings behind its own verdict."""
    _login(client, engine)
    target_id = _make_target(engine)
    scan_id = _add_scan(
        engine,
        target_id,
        1,
        status=PRGuardrailStatus.BLOCKED,
        new_findings_count=3,
        highest_new_severity="High",
        completed_at=utcnow(),
    )
    _mock_prs(monkeypatch, [_pr(1)])

    row = _rows(client, target_id)[1]

    assert row["scan_status"] == "blocked"
    assert row["latest_scan_id"] == scan_id
    assert row["new_findings_count"] == 3
    assert row["highest_new_severity"] == "High"


def test_rescanned_pr_reports_the_newest_scan(client, engine, monkeypatch):
    """A PR pushed to repeatedly accumulates one scan row per push, and only
    the newest describes the code being asked for today. Reporting an older
    one would show a fixed PR as still blocked."""
    _login(client, engine)
    target_id = _make_target(engine)
    _add_scan(engine, target_id, 1, status=PRGuardrailStatus.BLOCKED, new_findings_count=2)
    newest = _add_scan(engine, target_id, 1, status=PRGuardrailStatus.PASSED, new_findings_count=0)
    _mock_prs(monkeypatch, [_pr(1)])

    row = _rows(client, target_id)[1]

    assert row["latest_scan_id"] == newest
    assert row["scan_status"] == "passed"
    assert row["new_findings_count"] == 0


def test_scans_do_not_leak_across_prs(client, engine, monkeypatch):
    _login(client, engine)
    target_id = _make_target(engine)
    scan_for_1 = _add_scan(engine, target_id, 1, status=PRGuardrailStatus.BLOCKED, new_findings_count=1)
    _mock_prs(monkeypatch, [_pr(1), _pr(2)])

    rows = _rows(client, target_id)

    assert rows[1]["latest_scan_id"] == scan_for_1
    assert rows[2]["latest_scan_id"] is None
    assert rows[2]["scan_status"] == "not scanned"
