"""Tests for #383: one line flagged by several tools renders as one row.

A single hardcoded AWS key on README.md:7 is independently (and correctly)
detected by semgrep's generic.secrets.security.detected-aws-access-key-id-value
and gitleaks' aws-access-token. Both findings are real, both stay persisted,
both stay independently ignorable -- but rendering them as two top-level rows
and counting them as two net-new findings tells a reviewer there are two
problems to fix when there is one line and one fix.

What this is NOT: a dedup change. compute_dedup_hash still includes each
finding's own tool, and test_pr_guardrail_multi_tool.py::
test_same_rule_from_two_tools_is_not_deduped_away still has to pass exactly as
written -- collapsing across tools by content alone would let an unrelated
semgrep hit "match" a real gitleaks hit and silently vanish as not-net-new.
Everything here is about presentation on top of an unchanged set of rows.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core.pr_guardrail_executor import (
    COMMENT_MARKER,
    group_findings_by_location,
    render_comment,
)
from app.core.security import create_session_token, hash_password
from app.main import app
from app.models.models import (
    IgnoreStatus,
    Organization,
    PRGuardrailFinding,
    PRGuardrailScan,
    PRGuardrailStatus,
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


# Admin by default: accessible_workspace_ids gives a non-admin only the
# workspaces they hold a membership in, and these fixtures create a workspace
# with no members, so any other role would 404 out of the scan-scoped reads
# under test here for reasons that have nothing to do with grouping.
def _login(client, engine, role=UserRole.ADMIN):
    with Session(engine) as session:
        user = User(email=f"{role.value}@example.com", name="Test", password_hash=hash_password("whatever123"), role=role)
        session.add(user)
        session.commit()
        session.refresh(user)
        token = create_session_token(user.id, user.token_version)
    client.cookies.set("toleman_session", token)
    return client


# The reported case, as data: one secret, two tools, one line.
_SEMGREP_SECRET = dict(
    tool="semgrep",
    rule_id="generic.secrets.security.detected-aws-access-key-id-value",
    title="Detected AWS access key ID",
    file_path="README.md",
    line_start=7,
)
_GITLEAKS_SECRET = dict(
    tool="gitleaks",
    rule_id="aws-access-token",
    title="AWS access token",
    file_path="README.md",
    line_start=7,
)


def _finding(id, severity="High", **overrides) -> PRGuardrailFinding:
    fields = dict(
        pr_scan_id=1, tool="semgrep", rule_id="rule-1", title="A finding",
        file_path="a.py", line_start=10, severity=severity,
    )
    fields.update(overrides)
    return PRGuardrailFinding(id=id, **fields)


# --- group_findings_by_location() -------------------------------------------


def test_two_tools_on_one_line_are_one_group():
    findings = [_finding(1, **_SEMGREP_SECRET), _finding(2, **_GITLEAKS_SECRET)]

    groups = group_findings_by_location(findings)

    assert len(groups) == 1
    assert groups[0].tools == ["semgrep", "gitleaks"]
    assert [f.id for f in groups[0].findings] == [1, 2]
    assert groups[0].is_grouped


def test_two_tools_on_different_lines_stay_separate():
    findings = [
        _finding(1, **_SEMGREP_SECRET),
        _finding(2, **{**_GITLEAKS_SECRET, "line_start": 9}),
    ]

    groups = group_findings_by_location(findings)

    assert len(groups) == 2
    assert all(not g.is_grouped for g in groups)


def test_two_tools_on_the_same_line_of_different_files_stay_separate():
    findings = [
        _finding(1, **_SEMGREP_SECRET),
        _finding(2, **{**_GITLEAKS_SECRET, "file_path": "CONTRIBUTING.md"}),
    ]

    groups = group_findings_by_location(findings)

    assert len(groups) == 2


def test_one_tools_own_findings_on_one_line_stay_separate():
    """A tool reporting two rules on one line has already deduplicated its own
    output and is saying these are two findings. The confusing case #383 is
    about is one line reported by tools that don't know about each other."""
    findings = [
        _finding(1, rule_id="sql-injection", file_path="db.py", line_start=88),
        _finding(2, rule_id="tainted-input", file_path="db.py", line_start=88),
    ]

    groups = group_findings_by_location(findings)

    assert len(groups) == 2


def test_file_level_findings_never_group():
    """Two tools flagging "somewhere in requirements.txt" are usually flagging
    different packages; a row naming one of them would be actively misleading.
    A missing line number is not a location in the sense this grouping means."""
    findings = [
        _finding(1, tool="trivy", rule_id="CVE-2026-1", file_path="requirements.txt", line_start=None),
        _finding(2, tool="osv", rule_id="GHSA-xxxx", file_path="requirements.txt", line_start=None),
    ]

    groups = group_findings_by_location(findings)

    assert len(groups) == 2


def test_group_severity_is_the_highest_of_its_members():
    """Tools disagree about the same line routinely. Reporting the lowest
    would let a Critical finding sit inside a row labelled Medium, collapsed
    by default and counted in the wrong severity column."""
    findings = [
        _finding(1, severity="Medium", **_SEMGREP_SECRET),
        _finding(2, severity="Critical", **_GITLEAKS_SECRET),
    ]

    group = group_findings_by_location(findings)[0]

    assert group.severity == "Critical"
    assert group.primary.id == 2


def test_group_severity_ignores_an_unrankable_severity():
    findings = [
        _finding(1, severity="Low", **_SEMGREP_SECRET),
        _finding(2, severity="WEIRD", **_GITLEAKS_SECRET),
    ]

    assert group_findings_by_location(findings)[0].severity == "Low"


def test_grouping_preserves_every_finding():
    findings = [
        _finding(1, **_SEMGREP_SECRET),
        _finding(2, **_GITLEAKS_SECRET),
        _finding(3, rule_id="sql-injection", file_path="db.py", line_start=88),
    ]

    groups = group_findings_by_location(findings)

    assert sorted(f.id for g in groups for f in g.findings) == [1, 2, 3]


# --- render_comment() --------------------------------------------------------


def test_comment_renders_one_row_naming_both_tools():
    findings = [_finding(1, **_SEMGREP_SECRET), _finding(2, **_GITLEAKS_SECRET)]

    body = render_comment(findings, [], PRGuardrailStatus.BLOCKED, target_id=5, pr_scan_id=9)

    assert "found by: semgrep, gitleaks" in body
    # One row in the severity table, not two...
    assert "| 0 | 0 | 0 | 1 | 0 |" in body
    assert "**1 net-new vulnerability finding(s)**" in body
    # ...and the two detections behind it are disclosed, never silently
    # rounded down to one.
    assert "2 detections, grouped into 1 by location" in body
    # Each tool's own rule and title survive the collapse, one click away.
    assert "aws-access-token" in body
    assert "generic.secrets.security.detected-aws-access-key-id-value" in body


def test_comment_keeps_per_finding_ignore_links_inside_a_group():
    """The per-member "request ignore" cell has to stay byte-identical to the
    one an ungrouped row would carry: update_finding_status_in_pr_comment and
    revoke_finding_status_in_pr_comment patch a comment by swapping exactly
    that substring, so a grouped finding whose ignore is approved must still
    be findable in the rendered body."""
    findings = [_finding(1, **_SEMGREP_SECRET), _finding(2, **_GITLEAKS_SECRET)]

    body = render_comment(findings, [], PRGuardrailStatus.BLOCKED, target_id=5, pr_scan_id=9)

    assert "&middot; [request ignore](" in body
    assert "/ignore-request/9/1" in body
    assert "/ignore-request/9/2" in body


def test_comment_shows_an_already_approved_member_as_approved():
    findings = [
        _finding(1, **_SEMGREP_SECRET),
        _finding(2, ignore_status=IgnoreStatus.APPROVED, **_GITLEAKS_SECRET),
    ]

    body = render_comment(findings, [], PRGuardrailStatus.BLOCKED, target_id=5, pr_scan_id=9)

    assert "✅ approved to ignore" in body
    # The still-open member keeps its live link.
    assert "/ignore-request/9/1" in body


def test_comment_groups_under_the_highest_severity_section():
    findings = [
        _finding(1, severity="Medium", **_SEMGREP_SECRET),
        _finding(2, severity="Critical", **_GITLEAKS_SECRET),
    ]

    body = render_comment(findings, [], PRGuardrailStatus.BLOCKED, target_id=5, pr_scan_id=9)

    assert "<summary><strong>Critical</strong> (1)</summary>" in body
    assert "<strong>Medium</strong>" not in body
    assert "| 0 | 0 | 0 | 0 | 1 |" in body


def test_ungrouped_comment_is_unchanged():
    """Nothing groups in the overwhelmingly common case, and the comment must
    read exactly as it did before #383 -- including no grouping disclosure
    line at all."""
    findings = [
        _finding(1, severity="High", rule_id="sql-injection", file_path="db.py", line_start=88),
        _finding(2, severity="Low", rule_id="weak-hash", file_path="auth.py", line_start=12),
    ]

    body = render_comment(findings, [], PRGuardrailStatus.BLOCKED, target_id=5, pr_scan_id=9)

    assert body.startswith(COMMENT_MARKER)
    assert "**2 net-new vulnerability finding(s)**" in body
    assert "grouped into" not in body
    assert "found by:" not in body
    assert "| 0 | 1 | 0 | 1 | 0 |" in body


def test_two_tools_on_different_lines_still_count_as_two():
    findings = [
        _finding(1, **_SEMGREP_SECRET),
        _finding(2, **{**_GITLEAKS_SECRET, "line_start": 9}),
    ]

    body = render_comment(findings, [], PRGuardrailStatus.BLOCKED, target_id=5, pr_scan_id=9)

    assert "**2 net-new vulnerability finding(s)**" in body
    assert "found by:" not in body
    assert "grouped into" not in body


# --- GET /api/pr-guardrail/{id}/findings -------------------------------------


def _make_scan_with_findings(engine, rows: list[dict]) -> tuple[int, list[int]]:
    with Session(engine) as session:
        org = Organization(name="org")
        session.add(org)
        session.commit()
        session.refresh(org)
        ws = Workspace(organization_id=org.id, name="ws", api_key="key")
        session.add(ws)
        session.commit()
        session.refresh(ws)
        target = Target(workspace_id=ws.id, name="repo", repo_url="https://github.com/acme/repo")
        session.add(target)
        session.commit()
        session.refresh(target)

        scan = PRGuardrailScan(target_id=target.id, pr_number=3, branch="feature", status=PRGuardrailStatus.BLOCKED)
        session.add(scan)
        session.commit()
        session.refresh(scan)

        ids = []
        for row in rows:
            finding = PRGuardrailFinding(pr_scan_id=scan.id, severity=row.pop("severity", "High"), **row)
            session.add(finding)
            session.commit()
            session.refresh(finding)
            ids.append(finding.id)
        return scan.id, ids


def test_api_carries_the_grouping_so_the_ui_never_re_derives_it(client, engine):
    client = _login(client, engine)
    scan_id, (semgrep_id, gitleaks_id) = _make_scan_with_findings(
        engine, [dict(**_SEMGREP_SECRET, severity="Medium"), dict(**_GITLEAKS_SECRET, severity="Critical")]
    )

    res = client.get(f"/api/pr-guardrail/{scan_id}/findings")
    assert res.status_code == 200
    rows = res.json()

    # Still one row per finding: nothing is merged away server-side, and each
    # keeps its own id, rule and ignore state.
    assert {r["id"] for r in rows} == {semgrep_id, gitleaks_id}
    assert len({r["group_key"] for r in rows}) == 1
    for r in rows:
        assert r["group_size"] == 2
        assert r["group_tools"] == ["semgrep", "gitleaks"]
        # The group reports the highest severity even on the row whose own
        # severity is lower -- both facts are sent, neither overwrites the other.
        assert r["group_severity"] == "Critical"
        assert r["group_primary_id"] == gitleaks_id
    assert [r["severity"] for r in rows if r["id"] == semgrep_id] == ["Medium"]


def test_api_leaves_unrelated_findings_in_groups_of_one(client, engine):
    client = _login(client, engine)
    scan_id, ids = _make_scan_with_findings(
        engine,
        [
            dict(tool="semgrep", rule_id="sql-injection", title="SQLi", file_path="db.py", line_start=88),
            dict(tool="gitleaks", rule_id="aws-access-token", title="key", file_path="README.md", line_start=7),
        ],
    )

    rows = client.get(f"/api/pr-guardrail/{scan_id}/findings").json()

    assert len({r["group_key"] for r in rows}) == 2
    assert all(r["group_size"] == 1 for r in rows)


def test_ignoring_one_member_of_a_group_leaves_the_other_alone(client, engine):
    """Grouping is presentation. The ignore workflow stays per-finding all the
    way down: requesting an ignore on the semgrep row must not touch the
    gitleaks row it is rendered beside."""
    client = _login(client, engine)
    scan_id, (semgrep_id, gitleaks_id) = _make_scan_with_findings(
        engine, [dict(**_SEMGREP_SECRET), dict(**_GITLEAKS_SECRET)]
    )

    res = client.post(
        f"/api/pr-guardrail/findings/{semgrep_id}/request-ignore",
        json={"reason": "documented example key in a README"},
    )
    assert res.status_code == 200

    rows = {r["id"]: r for r in client.get(f"/api/pr-guardrail/{scan_id}/findings").json()}
    assert rows[semgrep_id]["ignore_status"] == "requested"
    assert rows[gitleaks_id]["ignore_status"] == "none"
    # Still one group: an ignore request changes a finding's state, not where
    # it is rendered.
    assert rows[semgrep_id]["group_key"] == rows[gitleaks_id]["group_key"]
