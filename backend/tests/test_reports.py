"""Tests for GET /api/reports/posture (CSV + PDF compliance/audit exports).

Follows the same in-memory SQLite + dependency_override pattern used in
tests/test_findings.py; no shared conftest exists for this yet either.
"""
import csv
import io
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core.security import create_session_token, hash_password
from app.core.time import utcnow
from app.main import app
from app.api.reports import (
    APPLIED_FILTERS_HEADING,
    EXCLUDED_MARKER,
    NO_FILTER_VALUE,
    REPORT_SECTIONS,
    SECTION_MANIFEST_HEADING,
    UNFILTERED_SUMMARY,
)
from app.models.models import (
    Finding,
    FindingState,
    Group,
    Organization,
    SbomComponent,
    Scan,
    Severity,
    Target,
    TargetGroup,
    User,
    UserRole,
    Workspace,
    WorkspaceMembership,
    WorkspaceRole,
)


@pytest.fixture()
def engine():
    eng = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(eng)
    return eng


@pytest.fixture()
def client(engine):
    def override_get_session():
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session

    original_deps_engine = deps_module.engine
    deps_module.engine = engine

    c = TestClient(app)
    yield c
    app.dependency_overrides.clear()
    deps_module.engine = original_deps_engine


def _login(client, engine, email="user@example.com", password="whatever123", role=UserRole.ADMIN):
    with Session(engine) as session:
        user = User(email=email, name="Test User", password_hash=hash_password(password), role=role)
        session.add(user)
        session.commit()
        session.refresh(user)
        uid = user.id
        token = create_session_token(user.id)
    client.cookies.set("toleman_session", token)
    return client, uid


def _assign(engine, user_id: int, workspace_id: int, role: WorkspaceRole = WorkspaceRole.DEVELOPER):
    with Session(engine) as session:
        session.add(WorkspaceMembership(user_id=user_id, workspace_id=workspace_id, role=role))
        session.commit()


def _make_target(engine, name="Target A", default_branch="main") -> int:
    with Session(engine) as session:
        org = Organization(name="Org")
        session.add(org)
        session.commit()
        session.refresh(org)

        workspace = Workspace(organization_id=org.id, name="WS", api_key=f"key-{name}")
        session.add(workspace)
        session.commit()
        session.refresh(workspace)

        target = Target(
            workspace_id=workspace.id,
            name=name,
            repo_url=f"https://example.com/{name}.git",
            default_branch=default_branch,
        )
        session.add(target)
        session.commit()
        session.refresh(target)
        return target.id


def _make_target_ws(engine, name="Target A", default_branch="main", **overrides) -> tuple[int, int]:
    """Same as _make_target but also returns the workspace_id it created,
    so tests can assign a WorkspaceMembership to it. `overrides` sets any
    other Target column (#302's environment/owner filters need them)."""
    with Session(engine) as session:
        org = Organization(name="Org")
        session.add(org)
        session.commit()
        session.refresh(org)

        workspace = Workspace(organization_id=org.id, name="WS", api_key=f"key-{name}")
        session.add(workspace)
        session.commit()
        session.refresh(workspace)

        target = Target(
            workspace_id=workspace.id,
            name=name,
            repo_url=f"https://example.com/{name}.git",
            default_branch=default_branch,
            **overrides,
        )
        session.add(target)
        session.commit()
        session.refresh(target)
        return target.id, workspace.id


def _make_group(engine, workspace_id: int, name="production") -> int:
    with Session(engine) as session:
        group = Group(workspace_id=workspace_id, name=name)
        session.add(group)
        session.commit()
        session.refresh(group)
        return group.id


def _assign_group(engine, target_id: int, group_id: int) -> None:
    with Session(engine) as session:
        session.add(TargetGroup(target_id=target_id, group_id=group_id))
        session.commit()


def _make_finding(engine, target_id, **overrides) -> int:
    defaults = dict(
        target_id=target_id,
        dedup_hash=f"hash-{overrides.get('title', 'x')}-{overrides.get('rule_id', 'r')}-{overrides.get('branch', 'main')}",
        tool="semgrep",
        rule_id="rule-1",
        title="SQL Injection",
        file_path="app/main.py",
        severity=Severity.HIGH,
        priority_score=50,
        state=FindingState.OPEN,
        branch="main",
    )
    defaults.update(overrides)
    with Session(engine) as session:
        finding = Finding(**defaults)
        session.add(finding)
        session.commit()
        session.refresh(finding)
        return finding.id


def _make_scan(engine, target_id, **overrides) -> int:
    defaults = dict(
        target_id=target_id,
        tool="semgrep",
        branch="main",
        status="completed",
        findings_count=2,
    )
    defaults.update(overrides)
    with Session(engine) as session:
        scan = Scan(**defaults)
        session.add(scan)
        session.commit()
        session.refresh(scan)
        return scan.id


def _make_sbom_component(engine, target_id, **overrides) -> int:
    defaults = dict(
        target_id=target_id,
        branch="main",
        name="requests",
        version="2.31.0",
        package_type="pip",
        purl="pkg:pypi/requests@2.31.0",
    )
    defaults.update(overrides)
    with Session(engine) as session:
        c = SbomComponent(**defaults)
        session.add(c)
        session.commit()
        session.refresh(c)
        return c.id


def test_posture_csv_requires_auth(client):
    res = client.get("/api/reports/posture?format=csv")
    assert res.status_code in (401, 403)


def test_posture_csv_for_single_target_reflects_real_findings(client, engine):
    _login(client, engine)
    target_id = _make_target(engine, name="govwa")
    _make_finding(engine, target_id, title="SQL Injection", severity=Severity.CRITICAL, state=FindingState.OPEN)
    _make_finding(engine, target_id, title="XSS", rule_id="rule-2", severity=Severity.HIGH, state=FindingState.OPEN)
    _make_finding(engine, target_id, title="Old secret", rule_id="rule-3", severity=Severity.HIGH, state=FindingState.MITIGATED)
    _make_scan(engine, target_id, tool="semgrep", status="completed", findings_count=3)
    _make_sbom_component(engine, target_id)

    res = client.get(f"/api/reports/posture?target_id={target_id}&format=csv")
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("text/csv")
    assert "attachment" in res.headers["content-disposition"]
    assert "govwa" in res.headers["content-disposition"]

    text = res.text
    rows = list(csv.reader(io.StringIO(text)))

    # Real severity/state counts must appear verbatim, not fabricated.
    assert any(r[:3] == ["govwa", "Critical", "Open"] and r[3] == "1" for r in rows)
    assert any(r[:3] == ["govwa", "High", "Open"] and r[3] == "1" for r in rows)
    assert any(r[:3] == ["govwa", "High", "Mitigated"] and r[3] == "1" for r in rows)

    # Scan coverage row for the seeded semgrep scan.
    assert any(r[:2] == ["govwa", "semgrep"] and r[6] == "3" for r in rows if len(r) > 6)

    # SBOM summary row.
    assert any(r[:2] == ["govwa", "1"] for r in rows)


def test_posture_csv_open_finding_age_matches_seeded_first_seen(client, engine):
    _login(client, engine)
    target_id = _make_target(engine, name="gotest")
    old_time = utcnow() - timedelta(days=45)
    with Session(engine) as session:
        f = Finding(
            target_id=target_id,
            dedup_hash="h1",
            tool="trivy",
            rule_id="CVE-2021-1234",
            title="Vulnerable dependency",
            file_path="go.mod",
            severity=Severity.MEDIUM,
            state=FindingState.OPEN,
            branch="main",
            first_seen=old_time,
            last_seen=old_time,
        )
        session.add(f)
        session.commit()

    res = client.get(f"/api/reports/posture?target_id={target_id}&format=csv")
    assert res.status_code == 200
    rows = list(csv.reader(io.StringIO(res.text)))

    age_row = next(r for r in rows if r[:2] == ["gotest", "Medium"] and len(r) == 9)
    open_count, avg_age, oldest_age = age_row[2], float(age_row[3]), int(age_row[4])
    assert open_count == "1"
    assert 44 <= avg_age <= 46
    assert 44 <= oldest_age <= 46
    assert age_row[7] == "1"  # falls in the 31-90d bucket


def test_posture_csv_org_wide_omits_target_id_and_covers_all_targets(client, engine):
    _login(client, engine)
    t1 = _make_target(engine, name="vulpy")
    t2 = _make_target(engine, name="gotest")
    _make_finding(engine, t1, title="Hardcoded secret", severity=Severity.CRITICAL)
    _make_finding(engine, t2, title="CVE-2020-0001", severity=Severity.LOW)

    res = client.get("/api/reports/posture?format=csv")
    assert res.status_code == 200
    assert "org-wide" in res.headers["content-disposition"]

    rows = list(csv.reader(io.StringIO(res.text)))
    names = {r[1] for r in rows if len(r) >= 5 and r[0].isdigit()}
    assert "vulpy" in names
    assert "gotest" in names


def test_posture_csv_404s_for_unknown_target(client, engine):
    _login(client, engine)
    res = client.get("/api/reports/posture?target_id=99999&format=csv")
    assert res.status_code == 404


def test_posture_pdf_is_a_real_parseable_pdf_with_correct_content_type(client, engine):
    _login(client, engine)
    target_id = _make_target(engine, name="gotest")
    _make_finding(engine, target_id, title="SQL Injection", severity=Severity.CRITICAL)
    _make_scan(engine, target_id, tool="gosec", findings_count=1)

    res = client.get(f"/api/reports/posture?target_id={target_id}&format=pdf")
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/pdf"
    assert "attachment" in res.headers["content-disposition"]

    body = res.content
    assert len(body) > 500
    assert body[:4] == b"%PDF"
    assert body.rstrip().endswith(b"%%EOF")

    # Parse it back for real with pypdf to prove it's not a mislabeled text
    # file; extracted text should contain the real seeded finding data.
    from pypdf import PdfReader

    reader = PdfReader(io.BytesIO(body))
    assert len(reader.pages) >= 1
    full_text = "\n".join(page.extract_text() for page in reader.pages)
    assert "gotest" in full_text
    assert "Critical" in full_text


# ---------------------------------------------------------------------------
# Issue #86: the org-wide posture export must scope to the caller's
# workspaces via accessible_workspace_ids(), the same helper #57 applied to
# dashboard/findings/targets; reports.py just wasn't in scope for that PR.
# Two real workspaces, a non-admin caller who is only a member of one of
# them: the other workspace's findings must not appear in the response body.
# ---------------------------------------------------------------------------

def test_posture_csv_org_wide_excludes_other_workspaces_data_for_non_admin(client, engine):
    target_a, ws_a = _make_target_ws(engine, name="repo-a")
    target_b, ws_b = _make_target_ws(engine, name="repo-b")
    _make_finding(engine, target_a, title="Secret in repo A", severity=Severity.CRITICAL, state=FindingState.OPEN)
    _make_finding(engine, target_b, title="Secret in repo B", severity=Severity.CRITICAL, state=FindingState.OPEN)
    _make_scan(engine, target_a, tool="gitleaks", findings_count=1)
    _make_scan(engine, target_b, tool="gitleaks", findings_count=1)

    _, uid = _login(client, engine, email="member-a@example.com", role=UserRole.DEVELOPER)
    _assign(engine, uid, ws_a, WorkspaceRole.DEVELOPER)  # only a member of workspace A

    res = client.get("/api/reports/posture?format=csv")
    assert res.status_code == 200
    rows = list(csv.reader(io.StringIO(res.text)))

    # Real content assertion, not just "no error": workspace A's target and
    # finding are present, workspace B's are provably absent from the body.
    target_names = {r[1] for r in rows if len(r) >= 5 and r[0].isdigit()}
    assert target_names == {"repo-a"}
    assert "repo-b" not in res.text
    assert "Secret in repo B" not in res.text

    totals_row = next(r for r in rows if r[:2] == ["Critical", "Open"])
    assert totals_row[2] == "1"  # only repo-a's finding counted, not both workspaces'


def test_posture_csv_org_wide_admin_still_sees_every_workspace(client, engine):
    target_a, ws_a = _make_target_ws(engine, name="repo-a2")
    target_b, ws_b = _make_target_ws(engine, name="repo-b2")
    _make_finding(engine, target_a, title="Finding A", severity=Severity.HIGH)
    _make_finding(engine, target_b, title="Finding B", severity=Severity.HIGH)

    _login(client, engine, email="admin@example.com", role=UserRole.ADMIN)

    res = client.get("/api/reports/posture?format=csv")
    assert res.status_code == 200
    rows = list(csv.reader(io.StringIO(res.text)))
    target_names = {r[1] for r in rows if len(r) >= 5 and r[0].isdigit()}
    assert target_names == {"repo-a2", "repo-b2"}


def test_posture_csv_org_wide_empty_for_user_with_no_workspace_membership(client, engine):
    target_a, ws_a = _make_target_ws(engine, name="repo-a3")
    _make_finding(engine, target_a, title="Finding A", severity=Severity.HIGH)

    _login(client, engine, email="nomember@example.com", role=UserRole.DEVELOPER)  # zero memberships

    res = client.get("/api/reports/posture?format=csv")
    assert res.status_code == 200
    rows = list(csv.reader(io.StringIO(res.text)))
    target_names = {r[1] for r in rows if len(r) >= 5 and r[0].isdigit()}
    assert target_names == set()
    assert "repo-a3" not in res.text


def test_posture_specific_target_id_outside_caller_workspace_404s(client, engine):
    target_a, ws_a = _make_target_ws(engine, name="repo-a4")
    target_b, ws_b = _make_target_ws(engine, name="repo-b4")

    _, uid = _login(client, engine, email="member-a4@example.com", role=UserRole.DEVELOPER)
    _assign(engine, uid, ws_a, WorkspaceRole.DEVELOPER)

    # Caller can fetch their own workspace's target...
    res_ok = client.get(f"/api/reports/posture?target_id={target_a}&format=csv")
    assert res_ok.status_code == 200

    # ...but not another workspace's target, even by guessing its id.
    res_forbidden = client.get(f"/api/reports/posture?target_id={target_b}&format=csv")
    assert res_forbidden.status_code == 404


# ---------------------------------------------------------------------------
# Issue #302: filters + selectable sections.
#
# Two properties are load-bearing throughout these tests:
#
#  * a filter must actually narrow the *contents* of the document, not just
#    be accepted by the endpoint, and
#  * whatever was narrowed or left out must be stated on the document, in
#    both formats. A filtered report that reads like a full one is an
#    audit-evidence problem, so "the header says so" is as much part of the
#    feature as the filtering itself.
# ---------------------------------------------------------------------------

def _rows(res) -> list[list[str]]:
    return list(csv.reader(io.StringIO(res.text)))


def _kv(rows: list[list[str]], label: str) -> str:
    """Value of the first two-column row whose first cell is `label` --
    covers both the report header (Generated At/Scope/...) and the Applied
    Filters block, which share that shape."""
    return next(r[1] for r in rows if len(r) >= 2 and r[0] == label)


def _applied_filters(rows: list[list[str]]) -> dict[str, str]:
    """The Applied Filters block as a dict, read from the block's own
    heading down to the next blank row, so a row elsewhere in the document
    can't be mistaken for a filter."""
    start = next(i for i, r in enumerate(rows) if r[:1] == [APPLIED_FILTERS_HEADING])
    out: dict[str, str] = {}
    for r in rows[start + 2 :]:  # +2 skips the heading and the column header
        if not r or not r[0]:
            break
        out[r[0]] = r[1] if len(r) > 1 else ""
    return out


def _section_statuses(rows: list[list[str]]) -> dict[str, str]:
    start = next(i for i, r in enumerate(rows) if r[:1] == [SECTION_MANIFEST_HEADING])
    out: dict[str, str] = {}
    for r in rows[start + 2 :]:
        if not r or not r[0]:
            break
        out[r[0]] = r[1] if len(r) > 1 else ""
    return out


def _csv_headings(rows: list[list[str]]) -> list[str]:
    """Every single-cell row, i.e. the section headings and markers."""
    return [r[0] for r in rows if len(r) == 1 and r[0]]


def _breakdown(rows: list[list[str]], target: str) -> set[tuple[str, str]]:
    """(severity, state) pairs from the per-target finding-counts section.

    Keyed on the row being exactly four cells wide: every other section
    that leads with a target name has a different width (targets 5, scan
    coverage 7, open-age 9, SBOM 3), so this cannot accidentally scoop up a
    'never scanned' coverage row and read its branch as a severity.
    """
    return {(r[1], r[2]) for r in rows if len(r) == 4 and r[0] == target}


def _severities(rows: list[list[str]], target: str) -> set[str]:
    return {severity for severity, _ in _breakdown(rows, target)}


def _pdf_text(body: bytes) -> str:
    from pypdf import PdfReader

    reader = PdfReader(io.BytesIO(body))
    return "\n".join(page.extract_text() for page in reader.pages)


# --- filters narrow the contents -------------------------------------------

def test_posture_csv_severity_filter_narrows_finding_rows(client, engine):
    _login(client, engine)
    target_id = _make_target(engine, name="sevfilter")
    _make_finding(engine, target_id, title="Crit", rule_id="r1", severity=Severity.CRITICAL)
    _make_finding(engine, target_id, title="Low one", rule_id="r2", severity=Severity.LOW)

    res = client.get(f"/api/reports/posture?target_id={target_id}&format=csv&severity=Critical")
    assert res.status_code == 200
    rows = _rows(res)

    assert any(r[:3] == ["sevfilter", "Critical", "Open"] and r[3] == "1" for r in rows if len(r) == 4)
    # The Low finding is genuinely gone from the counts, not merely unlabelled.
    assert _breakdown(rows, "sevfilter") == {("Critical", "Open")}
    assert _applied_filters(rows)["Severity"] == "Critical"


def test_posture_csv_multi_value_severity_filter_keeps_both(client, engine):
    _login(client, engine)
    target_id = _make_target(engine, name="multisev")
    _make_finding(engine, target_id, title="Crit", rule_id="r1", severity=Severity.CRITICAL)
    _make_finding(engine, target_id, title="High one", rule_id="r2", severity=Severity.HIGH)
    _make_finding(engine, target_id, title="Low one", rule_id="r3", severity=Severity.LOW)

    res = client.get(
        f"/api/reports/posture?target_id={target_id}&format=csv&severity=Critical&severity=High"
    )
    rows = _rows(res)
    assert _severities(rows, "multisev") == {"Critical", "High"}
    assert _applied_filters(rows)["Severity"] == "Critical, High"


def test_posture_csv_state_filter_narrows_finding_rows(client, engine):
    _login(client, engine)
    target_id = _make_target(engine, name="statefilter")
    _make_finding(engine, target_id, title="Open one", rule_id="r1", state=FindingState.OPEN)
    _make_finding(engine, target_id, title="Done", rule_id="r2", state=FindingState.MITIGATED)

    res = client.get(f"/api/reports/posture?target_id={target_id}&format=csv&state=Mitigated")
    rows = _rows(res)
    assert _breakdown(rows, "statefilter") == {("High", "Mitigated")}
    # The open-age section is empty under a resolved-only filter, and that
    # is the honest answer rather than the unfiltered open-finding count.
    assert not any(len(r) == 9 and r[0] == "statefilter" for r in rows)
    assert _applied_filters(rows)["Finding state"] == "Mitigated"


def test_posture_csv_tool_filter_narrows_finding_rows(client, engine):
    _login(client, engine)
    target_id = _make_target(engine, name="toolfilter")
    _make_finding(engine, target_id, title="Sast", rule_id="r1", tool="semgrep", severity=Severity.HIGH)
    _make_finding(engine, target_id, title="Sca", rule_id="r2", tool="trivy", severity=Severity.LOW)

    res = client.get(f"/api/reports/posture?target_id={target_id}&format=csv&tool=trivy")
    rows = _rows(res)
    assert _severities(rows, "toolfilter") == {"Low"}  # only the trivy finding survived
    assert _applied_filters(rows)["Tool"] == "trivy"


def test_posture_csv_category_filter_uses_the_same_mapping_as_findings(client, engine):
    """`category` is derived from `tool` via app.core.tool_registry, and the
    report shares findings.apply_category_filter rather than re-deriving it,
    so SCA here means exactly what SCA means on the Findings page."""
    _login(client, engine)
    target_id = _make_target(engine, name="catfilter")
    _make_finding(engine, target_id, title="Sast", rule_id="r1", tool="semgrep", severity=Severity.HIGH)
    _make_finding(engine, target_id, title="Sca", rule_id="r2", tool="trivy", severity=Severity.LOW)

    res = client.get(f"/api/reports/posture?target_id={target_id}&format=csv&category=SCA")
    rows = _rows(res)
    assert _severities(rows, "catfilter") == {"Low"}
    assert _applied_filters(rows)["Category"] == "SCA"


def test_posture_csv_unknown_category_is_rejected_not_silently_empty(client, engine):
    """A typo'd category would otherwise narrow the report to nothing and
    read as a clean bill of health."""
    _login(client, engine)
    target_id = _make_target(engine, name="badcat")
    res = client.get(f"/api/reports/posture?target_id={target_id}&format=csv&category=Nonsense")
    assert res.status_code == 400


def test_posture_csv_environment_filter_narrows_targets(client, engine):
    _login(client, engine)
    prod, _ = _make_target_ws(engine, name="prod-repo", environment="production")
    staging, _ = _make_target_ws(engine, name="staging-repo", environment="staging")
    _make_finding(engine, prod, title="Prod finding", rule_id="r1")
    _make_finding(engine, staging, title="Staging finding", rule_id="r2")

    res = client.get("/api/reports/posture?format=csv&environment=production")
    rows = _rows(res)
    names = {r[1] for r in rows if len(r) >= 5 and r[0].isdigit()}
    assert names == {"prod-repo"}
    # A target-level filter narrows every section, scan coverage and SBOM
    # summary included, so the excluded repo is nowhere in the document.
    assert "staging-repo" not in res.text
    assert _applied_filters(rows)["Environment"] == "production"


def test_posture_csv_owner_filter_narrows_targets(client, engine):
    _login(client, engine)
    mine, _ = _make_target_ws(engine, name="team-a-repo", owner="team-a")
    theirs, _ = _make_target_ws(engine, name="team-b-repo", owner="team-b")
    _make_finding(engine, mine, title="A", rule_id="r1")
    _make_finding(engine, theirs, title="B", rule_id="r2")

    res = client.get("/api/reports/posture?format=csv&owner=team-a")
    rows = _rows(res)
    names = {r[1] for r in rows if len(r) >= 5 and r[0].isdigit()}
    assert names == {"team-a-repo"}
    assert _applied_filters(rows)["Owner"] == "team-a"


def test_posture_csv_group_filter_narrows_targets_and_names_the_group(client, engine):
    _login(client, engine)
    in_group, ws = _make_target_ws(engine, name="pci-repo")
    out_of_group, _ = _make_target_ws(engine, name="other-repo")
    group_id = _make_group(engine, ws, name="PCI-scope")
    _assign_group(engine, in_group, group_id)
    _make_finding(engine, in_group, title="In scope", rule_id="r1")
    _make_finding(engine, out_of_group, title="Out of scope", rule_id="r2")

    res = client.get(f"/api/reports/posture?format=csv&group_id={group_id}")
    rows = _rows(res)
    names = {r[1] for r in rows if len(r) >= 5 and r[0].isdigit()}
    assert names == {"pci-repo"}
    assert "other-repo" not in res.text
    # The group is named, not printed as a raw id nobody reading the
    # document could check.
    assert _applied_filters(rows)["Repo group"] == "PCI-scope"


def test_posture_csv_date_window_covers_findings_open_across_the_range(client, engine):
    """The window tests the finding's own [first_seen, last_seen] span, not a
    single timestamp: a critical finding first seen before the range and
    still present inside it is exactly what a period report must show."""
    _login(client, engine)
    target_id = _make_target(engine, name="windowed")
    now = utcnow()
    _make_finding(
        engine,
        target_id,
        title="Long running",
        rule_id="r1",
        severity=Severity.CRITICAL,
        first_seen=now - timedelta(days=200),
        last_seen=now - timedelta(days=10),
    )
    _make_finding(
        engine,
        target_id,
        title="Closed long ago",
        rule_id="r2",
        severity=Severity.LOW,
        first_seen=now - timedelta(days=400),
        last_seen=now - timedelta(days=300),
    )

    start = (now - timedelta(days=60)).date().isoformat()
    end = now.date().isoformat()
    res = client.get(
        f"/api/reports/posture?target_id={target_id}&format=csv&date_from={start}&date_to={end}"
    )
    rows = _rows(res)
    # Still-present-in-window finding kept; the one that stopped being seen
    # a year ago is dropped.
    assert _severities(rows, "windowed") == {"Critical"}
    assert start in _applied_filters(rows)["Finding window"]
    assert end in _applied_filters(rows)["Finding window"]


def test_posture_csv_rejects_a_backwards_date_window(client, engine):
    _login(client, engine)
    target_id = _make_target(engine, name="badwindow")
    res = client.get(
        f"/api/reports/posture?target_id={target_id}&format=csv"
        "&date_from=2026-09-01&date_to=2026-08-01"
    )
    assert res.status_code == 400


# --- filters never widen what the caller can see ---------------------------

def test_posture_filters_cannot_reach_another_workspaces_findings(client, engine):
    """#57/#86 still holds under #302's filters: the report's rows come from
    the same _filtered_findings_query the Findings page uses, so a filter is
    a narrowing operation on what the caller could already see, never a way
    to select rows from outside it."""
    target_a, ws_a = _make_target_ws(engine, name="ws-a-repo", environment="production", owner="team-x")
    target_b, ws_b = _make_target_ws(engine, name="ws-b-repo", environment="production", owner="team-x")
    _make_finding(engine, target_a, title="A crit", rule_id="r1", severity=Severity.CRITICAL)
    _make_finding(engine, target_b, title="B crit", rule_id="r2", severity=Severity.CRITICAL)

    _, uid = _login(client, engine, email="scoped@example.com", role=UserRole.DEVELOPER)
    _assign(engine, uid, ws_a, WorkspaceRole.DEVELOPER)

    res = client.get(
        "/api/reports/posture?format=csv&severity=Critical&environment=production&owner=team-x"
    )
    assert res.status_code == 200
    rows = _rows(res)
    names = {r[1] for r in rows if len(r) >= 5 and r[0].isdigit()}
    assert names == {"ws-a-repo"}
    assert "ws-b-repo" not in res.text
    assert "B crit" not in res.text

    totals_row = next(r for r in rows if r[:2] == ["Critical", "Open"])
    assert totals_row[2] == "1"  # not 2


def test_posture_named_target_outside_the_other_filters_returns_an_empty_report(client, engine):
    """A named target that doesn't match the other target-level filters
    yields an empty report rather than quietly ignoring the filters -- the
    document says which filters were applied, so empty is readable."""
    _login(client, engine)
    target_id, _ = _make_target_ws(engine, name="dev-only", environment="dev")
    # A second target carrying the environment being filtered for, so this
    # exercises "the named repo is not in production" rather than the
    # separate "production isn't a recorded environment at all" rejection.
    _make_target_ws(engine, name="prod-only", environment="production")
    _make_finding(engine, target_id, title="Something", rule_id="r1")

    res = client.get(f"/api/reports/posture?target_id={target_id}&format=csv&environment=production")
    assert res.status_code == 200
    rows = _rows(res)
    assert _kv(rows, "Target Count") == "0"
    # Still filed under the repo that was asked for, so the download is
    # traceable to the request that produced it.
    assert "dev-only" in res.headers["content-disposition"]


# --- the applied-filters header ------------------------------------------

def test_posture_csv_states_its_filters_even_when_unfiltered(client, engine):
    """The block is unconditional. On an unfiltered report "Severity: (all)"
    is a positive statement that nothing was hidden; a block that appeared
    only when filters were active would be indistinguishable, on a full
    report, from one that had simply failed to render."""
    _login(client, engine)
    target_id = _make_target(engine, name="plain")
    _make_finding(engine, target_id, title="X", rule_id="r1")

    res = client.get(f"/api/reports/posture?target_id={target_id}&format=csv")
    rows = _rows(res)
    assert _kv(rows, "Filters Applied") == UNFILTERED_SUMMARY

    applied = _applied_filters(rows)
    for label in ("Repo group", "Environment", "Owner", "Severity", "Finding state", "Tool", "Category"):
        assert applied[label] == NO_FILTER_VALUE, label
    assert applied["Finding window"] == NO_FILTER_VALUE
    # And it says which sections a filter actually bites on.
    assert "scan coverage" in applied["Note"].lower()


def test_posture_csv_counts_the_active_filters_in_the_header(client, engine):
    _login(client, engine)
    target_id = _make_target(engine, name="counted")
    _make_finding(engine, target_id, title="X", rule_id="r1", severity=Severity.CRITICAL)

    res = client.get(
        f"/api/reports/posture?target_id={target_id}&format=csv&severity=Critical&tool=semgrep"
    )
    rows = _rows(res)
    summary = _kv(rows, "Filters Applied")
    assert summary.startswith("2 filters applied")
    assert APPLIED_FILTERS_HEADING in summary


def test_posture_pdf_states_its_filters_on_the_document(client, engine):
    _login(client, engine)
    target_id = _make_target(engine, name="pdffiltered")
    _make_finding(engine, target_id, title="Crit", rule_id="r1", severity=Severity.CRITICAL)
    _make_finding(engine, target_id, title="Lowish", rule_id="r2", severity=Severity.LOW)

    res = client.get(f"/api/reports/posture?target_id={target_id}&format=pdf&severity=Critical")
    assert res.status_code == 200
    assert res.content[:4] == b"%PDF"

    text = _pdf_text(res.content)
    assert APPLIED_FILTERS_HEADING in text
    assert "Critical" in text
    # The filtered-out severity appears nowhere on the page; the report does
    # not quietly include what its own header says it excluded.
    assert "Low" not in text


# --- section selection ----------------------------------------------------

def test_posture_sections_catalog_lists_every_renderable_section(client, engine):
    _login(client, engine)
    res = client.get("/api/reports/sections")
    assert res.status_code == 200
    catalog = res.json()
    assert [s["key"] for s in catalog] == [s.key for s in REPORT_SECTIONS]
    assert all(s["label"] and s["description"] for s in catalog)


def test_posture_csv_section_selection_is_honoured_and_exclusions_are_recorded(client, engine):
    _login(client, engine)
    target_id = _make_target(engine, name="sectioned")
    _make_finding(engine, target_id, title="X", rule_id="r1", severity=Severity.CRITICAL)
    _make_scan(engine, target_id, tool="semgrep", findings_count=1)
    _make_sbom_component(engine, target_id)

    res = client.get(
        f"/api/reports/posture?target_id={target_id}&format=csv&sections=targets&sections=totals"
    )
    assert res.status_code == 200
    rows = _rows(res)

    statuses = _section_statuses(rows)
    included_labels = {s.label for s in REPORT_SECTIONS if s.key in ("targets", "totals")}
    for label, status in statuses.items():
        assert status == ("Included" if label in included_labels else "Excluded"), label

    # Every heading is still present -- an excluded section is *marked*
    # excluded, never simply missing, because an absent heading and an empty
    # one look identical to whoever reads the document.
    headings = _csv_headings(rows)
    for spec in REPORT_SECTIONS:
        assert spec.csv_heading in headings
    assert headings.count(EXCLUDED_MARKER) == len(REPORT_SECTIONS) - 2

    # And the excluded sections' data really is gone.
    assert "Component Count" not in res.text  # the SBOM section's column header
    assert "semgrep" not in res.text  # the scan coverage row
    # ...while the included ones are intact.
    assert any(r[:2] == ["Critical", "Open"] for r in rows)
    assert any(len(r) >= 5 and r[1] == "sectioned" for r in rows)


def test_posture_pdf_section_selection_is_honoured_and_exclusions_are_recorded(client, engine):
    _login(client, engine)
    target_id = _make_target(engine, name="pdfsectioned")
    _make_finding(engine, target_id, title="X", rule_id="r1", severity=Severity.CRITICAL)
    _make_sbom_component(engine, target_id)

    res = client.get(f"/api/reports/posture?target_id={target_id}&format=pdf&sections=totals")
    assert res.status_code == 200
    text = _pdf_text(res.content)

    assert SECTION_MANIFEST_HEADING in text
    assert "Excluded" in text
    assert "excluded from this report" in text.lower()
    # The kept section's real data is there...
    assert "Critical" in text
    # ...and the dropped section keeps its heading as a marker while its
    # contents do not appear.
    assert "SBOM Component Summary" in text
    assert "Component Count" not in text


def test_posture_rejects_an_unknown_section(client, engine):
    _login(client, engine)
    target_id = _make_target(engine, name="badsection")
    res = client.get(f"/api/reports/posture?target_id={target_id}&format=csv&sections=not_a_section")
    assert res.status_code == 400


def test_posture_rejects_an_empty_section_selection(client, engine):
    _login(client, engine)
    target_id = _make_target(engine, name="nosections")
    res = client.get(f"/api/reports/posture?target_id={target_id}&format=csv&sections=")
    assert res.status_code == 400


# --- the default is still the report this endpoint always produced ---------

def test_posture_csv_default_still_renders_every_section_with_the_same_rows(client, engine):
    """No filters and no section selection: the same sections, in the same
    order, with the same rows as before #302. Only the two honesty blocks
    are new, and they say the report is unfiltered and complete."""
    _login(client, engine)
    target_id = _make_target(engine, name="unchanged")
    _make_finding(engine, target_id, title="SQL Injection", rule_id="r1", severity=Severity.CRITICAL)
    _make_finding(
        engine, target_id, title="XSS", rule_id="r2", severity=Severity.HIGH, state=FindingState.MITIGATED
    )
    _make_scan(engine, target_id, tool="semgrep", status="completed", findings_count=2)
    _make_sbom_component(engine, target_id)

    res = client.get(f"/api/reports/posture?target_id={target_id}&format=csv")
    assert res.status_code == 200
    rows = _rows(res)

    headings = _csv_headings(rows)
    section_headings = {s.csv_heading for s in REPORT_SECTIONS}
    assert [h for h in headings if h in section_headings] == [s.csv_heading for s in REPORT_SECTIONS]
    assert EXCLUDED_MARKER not in headings
    assert set(_section_statuses(rows).values()) == {"Included"}
    assert _kv(rows, "Filters Applied") == UNFILTERED_SUMMARY
    assert _kv(rows, "Sections Included").startswith(f"{len(REPORT_SECTIONS)} of {len(REPORT_SECTIONS)}")

    # The pre-#302 row assertions, unchanged.
    assert any(r[:3] == ["unchanged", "Critical", "Open"] and r[3] == "1" for r in rows if len(r) > 3)
    assert any(r[:3] == ["unchanged", "High", "Mitigated"] and r[3] == "1" for r in rows if len(r) > 3)
    assert any(r[:2] == ["unchanged", "semgrep"] and r[6] == "2" for r in rows if len(r) > 6)
    assert any(r[:2] == ["unchanged", "1"] for r in rows)


def test_posture_default_filename_is_unchanged_and_narrowing_marks_it(client, engine):
    """The filename carries the narrowing too: these files get attached to
    tickets and mailed to auditors, where the name is often all anyone reads
    before opening it."""
    _login(client, engine)
    target_id = _make_target(engine, name="namecheck")

    plain = client.get(f"/api/reports/posture?target_id={target_id}&format=csv")
    disposition = plain.headers["content-disposition"]
    assert "namecheck" in disposition
    assert "filtered" not in disposition
    assert "sections" not in disposition

    narrowed = client.get(
        f"/api/reports/posture?target_id={target_id}&format=csv&severity=Critical&sections=totals"
    )
    narrowed_disposition = narrowed.headers["content-disposition"]
    assert "filtered" in narrowed_disposition
    assert f"1of{len(REPORT_SECTIONS)}-sections" in narrowed_disposition


def test_posture_filename_does_not_let_a_target_name_steer_the_header(client, engine):
    """Target names are user-supplied and end up in Content-Disposition."""
    _login(client, engine)
    target_id = _make_target(engine, name='ev"il; filename=other')
    res = client.get(f"/api/reports/posture?target_id={target_id}&format=csv")
    assert res.status_code == 200
    disposition = res.headers["content-disposition"]
    assert disposition.count('"') == 2
    assert "filename=other" not in disposition


def test_posture_filename_keeps_a_non_ascii_target_name(client, engine):
    """Sanitising to ASCII alone is safe but lossy: every non-Latin repo
    would file under one identical placeholder name. RFC 6266 sends both --
    an ASCII fallback and the real percent-encoded UTF-8 name."""
    _login(client, engine)
    target_id = _make_target(engine, name="日本語")
    res = client.get(f"/api/reports/posture?target_id={target_id}&format=csv")
    assert res.status_code == 200
    disposition = res.headers["content-disposition"]
    assert "%E6%97%A5%E6%9C%AC%E8%AA%9E" in disposition
    assert 'filename="toleman-posture-report-' in disposition


# --- workspace scoping of the group filter itself --------------------------

def test_posture_group_filter_does_not_leak_another_workspaces_group_name(client, engine):
    """The Applied Filters block prints the group's *name*, so the lookup
    behind it has to be workspace-scoped or the honesty header becomes an
    enumeration oracle: walk ?group_id=1..N and read other tenants' group
    names straight off the document."""
    _, ws_a = _make_target_ws(engine, name="mine")
    _, ws_b = _make_target_ws(engine, name="theirs")
    their_group = _make_group(engine, ws_b, name="ACME-SECRET-PROJECT")

    _, uid = _login(client, engine, email="nosy@example.com", role=UserRole.DEVELOPER)
    _assign(engine, uid, ws_a, WorkspaceRole.DEVELOPER)

    res = client.get(f"/api/reports/posture?format=csv&group_id={their_group}")
    assert res.status_code == 404
    assert "ACME-SECRET-PROJECT" not in res.text


def test_posture_group_filter_404s_for_an_unknown_group(client, engine):
    _login(client, engine)
    res = client.get("/api/reports/posture?format=csv&group_id=99999")
    assert res.status_code == 404


def test_posture_admin_can_still_filter_by_any_group(client, engine):
    target_id, ws = _make_target_ws(engine, name="admin-visible")
    group_id = _make_group(engine, ws, name="prod")
    _assign_group(engine, target_id, group_id)
    _login(client, engine, email="admin2@example.com", role=UserRole.ADMIN)

    res = client.get(f"/api/reports/posture?format=csv&group_id={group_id}")
    assert res.status_code == 200
    assert _applied_filters(_rows(res))["Repo group"] == "prod"


# --- unknown free-text filter values are rejected, not silently empty ------

@pytest.mark.parametrize(
    "param,value",
    [("tool", "semgrepp"), ("environment", "producton"), ("owner", "team-typo")],
)
def test_posture_rejects_a_typo_in_a_free_text_filter(client, engine, param, value):
    """A typo would otherwise narrow the report to nothing and come back as
    a 200 that reads like a clean bill of health, with the Applied Filters
    block faithfully printing the typo as though it meant something."""
    _login(client, engine)
    target_id, _ = _make_target_ws(engine, name="typo-repo", environment="production", owner="team-a")
    _make_finding(engine, target_id, title="X", rule_id="r1", tool="semgrep")

    res = client.get(f"/api/reports/posture?target_id={target_id}&format=csv&{param}={value}")
    assert res.status_code == 400


def test_posture_accepts_a_registry_tool_with_no_findings_yet(client, engine):
    """A configured-but-not-yet-run scanner is a legitimate (empty)
    question, unlike a misspelling of one, so `tool` validates against the
    tool registry as well as the caller's own facets."""
    _login(client, engine)
    target_id = _make_target(engine, name="unscanned")
    _make_finding(engine, target_id, title="X", rule_id="r1", tool="semgrep")

    res = client.get(f"/api/reports/posture?target_id={target_id}&format=csv&tool=trivy")
    assert res.status_code == 200
    assert _breakdown(_rows(res), "unscanned") == set()


def test_posture_empty_section_selection_reports_the_right_problem(client, engine):
    """`?sections=` parses as [""], not [], so the blank has to be stripped
    before the unknown-section check or this reports the wrong error."""
    _login(client, engine)
    target_id = _make_target(engine, name="emptysections")
    res = client.get(f"/api/reports/posture?target_id={target_id}&format=csv&sections=")
    assert res.status_code == 400
    assert "at least one report section" in res.json()["detail"]


# --- a dated report says what is and is not as-of that date ----------------

def test_posture_ages_and_scan_coverage_are_measured_at_the_window_end(client, engine):
    """A Q1 report generated in September must not show 250-day ages and
    September scans. Ages are measured to the window's end and scan coverage
    stops there."""
    _login(client, engine)
    target_id = _make_target(engine, name="asof")
    now = utcnow()
    _make_finding(
        engine,
        target_id,
        title="Old open",
        rule_id="r1",
        severity=Severity.CRITICAL,
        first_seen=now - timedelta(days=300),
        last_seen=now,
    )
    _make_scan(engine, target_id, tool="semgrep", started_at=now - timedelta(days=250), findings_count=1)
    _make_scan(engine, target_id, tool="trivy", started_at=now - timedelta(days=5), findings_count=0)

    window_end = (now - timedelta(days=200)).date().isoformat()
    res = client.get(f"/api/reports/posture?target_id={target_id}&format=csv&date_to={window_end}")
    assert res.status_code == 200
    rows = _rows(res)

    # Age is ~100 days (300 - 200), not ~300: measured to the window's end.
    age_row = next(r for r in rows if len(r) == 9 and r[0] == "asof")
    assert 99 <= int(age_row[4]) <= 101

    # The scan that ran after the window is not presented as coverage for it.
    scan_tools = {r[1] for r in rows if len(r) == 7 and r[0] == "asof"}
    assert scan_tools == {"semgrep"}

    assert _kv(rows, "Figures As Of").startswith(window_end)


def test_posture_discloses_what_is_not_reconstructed_as_of_the_window(client, engine):
    """Triage state and the SBOM summary cannot be reconstructed for a past
    date (no state history is stored), so the document says so rather than
    letting a dated report imply a full snapshot."""
    _login(client, engine)
    target_id = _make_target(engine, name="disclosed")
    _make_finding(engine, target_id, title="X", rule_id="r1")

    res = client.get(f"/api/reports/posture?target_id={target_id}&format=csv&date_to=2026-01-31")
    rows = _rows(res)
    note = _applied_filters(rows)["Point-in-time note"]
    assert "triage state" in note
    assert "SBOM component summary" in note

    pdf = client.get(f"/api/reports/posture?target_id={target_id}&format=pdf&date_to=2026-01-31")
    text = _pdf_text(pdf.content)
    assert "Figures as of" in text
    assert "current-state" in text


def test_posture_undated_report_is_still_as_of_now(client, engine):
    """No window means as_of is generation time, so the scan-coverage bound
    is a no-op and nothing about a default export changes."""
    _login(client, engine)
    target_id = _make_target(engine, name="undated")
    _make_scan(engine, target_id, tool="semgrep", findings_count=1)

    rows = _rows(client.get(f"/api/reports/posture?target_id={target_id}&format=csv"))
    assert _kv(rows, "Figures As Of") == _kv(rows, "Generated At")
    assert any(r[:2] == ["undated", "semgrep"] for r in rows if len(r) == 7)


# --- an empty report says it is an empty scope, not a clean result ---------

def test_posture_empty_result_is_labelled_as_an_empty_scope(client, engine):
    """"No targets matched" and "no problems found" produce identical blank
    tables. The document has to say which one it is -- a reader should not
    have to infer it from Target Count: 0."""
    _login(client, engine)
    dev_target, _ = _make_target_ws(engine, name="dev-thing", environment="dev")
    _make_target_ws(engine, name="prod-thing", environment="production")
    _make_finding(engine, dev_target, title="X", rule_id="r1")

    # A named target excluded by another target-level filter: filters were
    # applied and honoured, and nothing matched.
    res = client.get(f"/api/reports/posture?target_id={dev_target}&format=csv&environment=production")
    assert res.status_code == 200
    rows = _rows(res)
    assert _kv(rows, "Target Count") == "0"
    result = _kv(rows, "Result")
    assert "No targets matched the applied filters" in result
    assert "not a clean result" in result

    pdf = client.get(f"/api/reports/posture?target_id={dev_target}&format=pdf&environment=production")
    assert "No targets matched" in _pdf_text(pdf.content)


def test_posture_non_empty_report_carries_no_empty_scope_note(client, engine):
    _login(client, engine)
    target_id = _make_target(engine, name="populated")
    _make_finding(engine, target_id, title="X", rule_id="r1")

    rows = _rows(client.get(f"/api/reports/posture?target_id={target_id}&format=csv"))
    assert not any(len(r) >= 1 and r[0] == "Result" for r in rows)


def test_posture_scope_label_does_not_claim_all_targets_when_narrowed(client, engine):
    """"org-wide (all targets)" on a report narrowed to one repo group
    contradicts the Applied Filters block three rows below it."""
    _login(client, engine)
    target_id, ws = _make_target_ws(engine, name="grouped", environment="production")
    group_id = _make_group(engine, ws, name="PCI")
    _assign_group(engine, target_id, group_id)

    rows = _rows(client.get(f"/api/reports/posture?format=csv&group_id={group_id}&environment=production"))
    scope = _kv(rows, "Scope")
    assert "all targets" not in scope
    assert "narrowed by" in scope
    assert "PCI" in scope

    plain = _rows(client.get("/api/reports/posture?format=csv"))
    assert _kv(plain, "Scope") == "org-wide (all targets)"
