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
from sqlmodel import Session, SQLModel, create_engine, select

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core.pr_guardrail_executor import (
    COMMENT_MARKER,
    _approved_action_cell,
    _finding_ref_link,
    _patch_group_header_in_comment,
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


def test_line_zero_counts_as_no_line_number():
    """parse_trivy's CauseMetadata.StartLine and parse_iac's file_line_range[0]
    both report 0 for a file-level check. An `is not None` test would let 0
    through as a real location and merge two unrelated file-level findings
    that happen to share a manifest."""
    findings = [
        _finding(1, tool="trivy", rule_id="CVE-2026-1", file_path="requirements.txt", line_start=0),
        _finding(2, tool="checkov", rule_id="CKV_X", file_path="requirements.txt", line_start=0),
    ]

    groups = group_findings_by_location(findings)

    assert len(groups) == 2


def test_each_group_gets_its_own_key_even_at_one_location():
    """A location is not unique across groups: everything this function
    deliberately keeps apart shares a file/line. A key that was just the
    location would let any consumer re-merge exactly what was kept apart --
    three trivy CVEs on one manifest collapsing into one row, two of them
    hidden behind a toggle."""
    findings = [
        _finding(1, tool="trivy", rule_id="CVE-2026-1", file_path="requirements.txt", line_start=None),
        _finding(2, tool="trivy", rule_id="CVE-2026-2", file_path="requirements.txt", line_start=None),
        _finding(3, tool="trivy", rule_id="CVE-2026-3", file_path="requirements.txt", line_start=None),
    ]

    groups = group_findings_by_location(findings)

    assert len(groups) == 3
    assert len({g.key for g in groups}) == 3


def test_findings_with_no_file_path_never_group():
    """parse_sarif reports file_path "" for a result carrying no locations at
    all. "Line 12 of nowhere in particular" is not somewhere two tools can
    agree on; bucketing on it would merge findings whose only established
    connection is that neither could say where it was."""
    findings = [
        _finding(1, tool="semgrep", file_path="", line_start=12),
        _finding(2, tool="gitleaks", file_path="", line_start=12),
    ]

    groups = group_findings_by_location(findings)

    assert len(groups) == 2


def test_a_group_key_is_never_empty():
    """parse_sarif emits file_path "" for a result carrying no locations, and
    "" slips past a consumer's nullish check -- which would bucket every
    location-less finding in a scan into one row."""
    findings = [
        _finding(1, tool="semgrep", file_path="", line_start=None),
        _finding(2, tool="gitleaks", file_path="", line_start=None),
    ]

    groups = group_findings_by_location(findings)

    assert len(groups) == 2
    assert all(g.key for g in groups)
    assert len({g.key for g in groups}) == 2


def test_order_is_the_order_the_findings_arrived_in():
    """Nothing groups here, so the rendered order must be exactly the input
    order -- an earlier version bucketed by location first and hoisted the
    third finding up next to the first because they shared a line."""
    findings = [
        _finding(1, tool="semgrep", rule_id="a", file_path="db.py", line_start=88),
        _finding(2, tool="semgrep", rule_id="b", file_path="auth.py", line_start=12),
        _finding(3, tool="semgrep", rule_id="c", file_path="db.py", line_start=88),
    ]

    groups = group_findings_by_location(findings)

    assert [g.findings[0].id for g in groups] == [1, 2, 3]


def test_a_merged_group_sits_where_its_first_member_was():
    findings = [
        _finding(1, tool="semgrep", rule_id="a", file_path="auth.py", line_start=12),
        _finding(2, **_SEMGREP_SECRET),
        _finding(3, tool="trivy", rule_id="c", file_path="go.mod", line_start=4),
        _finding(4, **_GITLEAKS_SECRET),
    ]

    groups = group_findings_by_location(findings)

    assert [[f.id for f in g.findings] for g in groups] == [[1], [2, 4], [3]]


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
    # The still-open member keeps its live link, and the collapsed header
    # says one of the two is already dealt with.
    assert "/ignore-request/9/1" in body
    assert "2 findings (1 approved), expand below" in body


def test_a_fully_approved_group_does_not_look_untouched():
    """Both members already approved-to-ignore: the header must say so rather
    than reading exactly like a group nobody has looked at, with the approvals
    only visible after expanding -- the same failure #401 fixed for individual
    rows."""
    findings = [
        _finding(1, ignore_status=IgnoreStatus.APPROVED, **_SEMGREP_SECRET),
        _finding(2, ignore_status=IgnoreStatus.APPROVED, **_GITLEAKS_SECRET),
    ]

    body = render_comment(findings, [], PRGuardrailStatus.BLOCKED, target_id=5, pr_scan_id=9)

    assert "✅ all 2 approved to ignore" in body
    assert "expand below" not in body


def test_a_fully_approved_groups_header_cannot_steal_a_revoke_patch():
    """revoke_finding_status_in_pr_comment finds a row by the exact text
    _approved_action_cell(ref_link) produces and replaces it once. If the
    collapsed header emitted that same string for its primary member, the
    single replacement would land on the header and leave the member's own
    row still claiming the ignore is approved."""
    findings = [
        _finding(1, ignore_status=IgnoreStatus.APPROVED, **_SEMGREP_SECRET),
        _finding(2, ignore_status=IgnoreStatus.APPROVED, **_GITLEAKS_SECRET),
    ]

    body = render_comment(findings, [], PRGuardrailStatus.BLOCKED, target_id=5, pr_scan_id=9)

    for finding_id in (1, 2):
        cell = _approved_action_cell(_finding_ref_link(5, 9, finding_id))
        assert body.count(cell) == 1, "each member's approved cell must appear exactly once"
        # And the one occurrence is the member's own row in the expanded
        # table, not the collapsed header above it.
        assert body.index("| Tool | Severity | Rule | Title | Links |") < body.index(cell)


def test_comment_discloses_that_it_truncated():
    """`findings` is only the first MAX_NEW_FINDINGS_IN_RESPONSE of a scan's
    net-new set, and the comment used to present that page as the whole
    result. The headline then matches the commit status (which reports the
    full count on a truncated scan) instead of disagreeing with it for no
    visible reason."""
    findings = [_finding(1, **_SEMGREP_SECRET), _finding(2, **_GITLEAKS_SECRET)]

    body = render_comment(
        findings, [], PRGuardrailStatus.BLOCKED, target_id=5, pr_scan_id=9, total_findings=53
    )

    assert "**53 net-new vulnerability finding(s)**" in body
    assert "Showing the first 2 of 53 net-new findings" in body
    # The grouping of what *is* shown is still disclosed, in the same note.
    assert "grouped into 1 row(s) by location" in body


def test_comment_without_a_total_is_unchanged():
    """Default None means "what you were given is all there was", which is how
    every pre-existing caller behaves."""
    findings = [_finding(1, **_SEMGREP_SECRET), _finding(2, **_GITLEAKS_SECRET)]

    body = render_comment(findings, [], PRGuardrailStatus.BLOCKED, target_id=5, pr_scan_id=9)

    assert "Showing the first" not in body
    assert "**1 net-new vulnerability finding(s)**" in body


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


# --- the collapsed header's aggregate claim staying current ------------------
#
# Every other claim in a PR comment is owned by exactly one finding's cell,
# which update_/revoke_finding_status_in_pr_comment keep current. A group
# header is the first aggregate claim in the comment, and an aggregate goes
# stale when any one member changes.


def _render_scan_comment(session, scan_id: int, target_id: int = 5) -> str:
    findings = session.exec(
        select(PRGuardrailFinding)
        .where(PRGuardrailFinding.pr_scan_id == scan_id)
        .order_by(PRGuardrailFinding.id)
    ).all()
    return render_comment(
        list(findings), [], PRGuardrailStatus.BLOCKED, target_id=target_id, pr_scan_id=scan_id
    )


def _set_ignore_status(session, finding_id: int, status) -> PRGuardrailFinding:
    finding = session.get(PRGuardrailFinding, finding_id)
    finding.ignore_status = status
    session.add(finding)
    session.commit()
    session.refresh(finding)
    return finding


def test_a_revoke_stops_the_header_claiming_everything_is_approved(engine):
    """The one direction that produces a false claim rather than a merely
    lagging one: without the header patch the comment goes on saying all 2 are
    approved while the row below it offers a live "request ignore" link
    again."""
    scan_id, (semgrep_id, gitleaks_id) = _make_scan_with_findings(
        engine,
        [
            dict(**_SEMGREP_SECRET, ignore_status=IgnoreStatus.APPROVED),
            dict(**_GITLEAKS_SECRET, ignore_status=IgnoreStatus.APPROVED),
        ],
    )

    with Session(engine) as session:
        body = _render_scan_comment(session, scan_id)
        assert "✅ all 2 approved to ignore" in body

        revoked = _set_ignore_status(session, gitleaks_id, IgnoreStatus.REVOKED)
        patched = _patch_group_header_in_comment(session, 5, revoked, body)

    assert "✅ all 2 approved to ignore" not in patched
    assert "2 findings (1 approved), expand below" in patched


def test_the_header_tracks_the_approve_direction_too(engine):
    scan_id, (semgrep_id, _) = _make_scan_with_findings(
        engine, [dict(**_SEMGREP_SECRET), dict(**_GITLEAKS_SECRET)]
    )

    with Session(engine) as session:
        body = _render_scan_comment(session, scan_id)
        assert "2 findings, expand below" in body

        approved = _set_ignore_status(session, semgrep_id, IgnoreStatus.APPROVED)
        patched = _patch_group_header_in_comment(session, 5, approved, body)

    assert "2 findings (1 approved), expand below" in patched


def test_the_header_is_patched_from_any_approved_count(engine):
    """A group with three members passes through several header texts; each is
    a distinct exact string, so a later change finds whichever one the comment
    currently carries rather than only the all-approved one."""
    scan_id, ids = _make_scan_with_findings(
        engine,
        [
            dict(**_SEMGREP_SECRET, ignore_status=IgnoreStatus.APPROVED),
            dict(**_GITLEAKS_SECRET, ignore_status=IgnoreStatus.APPROVED),
            dict(tool="trufflehog", rule_id="aws-key", title="AWS key", file_path="README.md", line_start=7),
        ],
    )

    with Session(engine) as session:
        body = _render_scan_comment(session, scan_id)
        assert "3 findings (2 approved), expand below" in body

        revoked = _set_ignore_status(session, ids[0], IgnoreStatus.REVOKED)
        patched = _patch_group_header_in_comment(session, 5, revoked, body)

    assert "3 findings (1 approved), expand below" in patched
    assert "(2 approved)" not in patched


def test_the_header_patch_leaves_an_ungrouped_finding_alone(engine):
    scan_id, (finding_id,) = _make_scan_with_findings(
        engine, [dict(**_SEMGREP_SECRET, ignore_status=IgnoreStatus.APPROVED)]
    )

    with Session(engine) as session:
        body = _render_scan_comment(session, scan_id)
        revoked = _set_ignore_status(session, finding_id, IgnoreStatus.REVOKED)
        patched = _patch_group_header_in_comment(session, 5, revoked, body)

    assert patched == body


def test_api_carries_the_grouping_so_the_ui_never_re_derives_it(client, engine):
    client = _login(client, engine)
    scan_id, (semgrep_id, gitleaks_id) = _make_scan_with_findings(
        engine, [dict(**_SEMGREP_SECRET, severity="Medium"), dict(**_GITLEAKS_SECRET, severity="Critical")]
    )

    res = client.get(f"/api/pr-guardrail/{scan_id}/findings")
    assert res.status_code == 200
    rows = res.json()

    # Still one row per finding: nothing is merged away server-side, and each
    # keeps its own id, rule, severity and ignore state.
    assert {r["id"] for r in rows} == {semgrep_id, gitleaks_id}
    # Membership is what travels: one shared key, and a size saying how many
    # rows belong to it.
    assert len({r["group_key"] for r in rows}) == 1
    assert all(r["group_size"] == 2 for r in rows)
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


def test_api_returns_findings_in_a_stable_order(client, engine):
    """group_key carries the group's first member's id, so it is a function of
    position, not just of location: an unordered SELECT could key the same
    group off a different member between two fetches and remount (and so
    collapse) a group the user had just expanded. SQLite happens to return
    insertion order anyway, so this asserts the contract rather than proving
    it -- the ORDER BY in the query is what makes it true on Postgres, where
    an UPDATE (which is exactly what the ignore workflow does to these rows)
    can relocate one."""
    client = _login(client, engine)
    scan_id, ids = _make_scan_with_findings(
        engine,
        [
            dict(tool="semgrep", rule_id=f"rule-{n}", title=f"r{n}", file_path=f"f{n}.py", line_start=n)
            for n in (1, 2, 3)
        ],
    )

    rows = client.get(f"/api/pr-guardrail/{scan_id}/findings").json()

    assert [r["id"] for r in rows] == sorted(ids)


def test_api_gives_same_location_findings_that_must_not_merge_distinct_keys(client, engine):
    """The shape that broke the UI: three trivy CVEs on one manifest, all with
    no line number, are three groups the backend deliberately keeps apart. If
    they shared a key, a consumer bucketing on it would collapse them into one
    row and hide two CVEs behind a toggle."""
    client = _login(client, engine)
    scan_id, ids = _make_scan_with_findings(
        engine,
        [
            dict(tool="trivy", rule_id=f"CVE-2026-{n}", title=f"CVE-2026-{n}", file_path="requirements.txt", line_start=None)
            for n in (1, 2, 3)
        ],
    )

    rows = client.get(f"/api/pr-guardrail/{scan_id}/findings").json()

    assert len(rows) == 3
    assert len({r["group_key"] for r in rows}) == 3
    assert all(r["group_size"] == 1 for r in rows)
    assert all(r["group_key"] for r in rows)


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
