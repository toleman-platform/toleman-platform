"""Tests for GET /api/findings/groups, the grouped ("one row per decision")
view of the findings list, plus the `rule_id`, `new_since_days` and `sort`
parameters that view leans on.

Same in-memory SQLite + dependency_override pattern as tests/test_findings.py.
"""
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
from app.models.models import (
    Finding,
    FindingState,
    Organization,
    Severity,
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
    original_deps_engine = deps_module.engine
    deps_module.engine = engine

    c = TestClient(app)
    yield c
    app.dependency_overrides.clear()
    deps_module.engine = original_deps_engine


def _login(client, engine, email="user@example.com", password="whatever123"):
    with Session(engine) as session:
        user = User(email=email, name="Test User", password_hash=hash_password(password))
        session.add(user)
        session.commit()
        session.refresh(user)
        token = create_session_token(user.id)
    client.cookies.set("toleman_session", token)
    return client


def _make_target(engine, name="Target A") -> int:
    with Session(engine) as session:
        org = Organization(name=f"Org {name}")
        session.add(org)
        session.commit()
        session.refresh(org)

        workspace = Workspace(organization_id=org.id, name=f"WS {name}", api_key=f"key-{name}")
        session.add(workspace)
        session.commit()
        session.refresh(workspace)

        target = Target(workspace_id=workspace.id, name=name, repo_url="https://example.com/repo.git")
        session.add(target)
        session.commit()
        session.refresh(target)
        return target.id


_seq = 0


def _make_finding(engine, target_id, **overrides) -> int:
    global _seq
    _seq += 1
    defaults = dict(
        target_id=target_id,
        dedup_hash=f"hash-{_seq}",
        tool="trivy-license",
        rule_id="license:LGPL-3.0-or-later",
        title="LGPL-3.0-or-later license detected in @img/sharp-libvips-linux-arm",
        file_path="frontend/package-lock.json",
        severity=Severity.HIGH,
        priority_score=320,
        state=FindingState.OPEN,
    )
    defaults.update(overrides)
    with Session(engine) as session:
        finding = Finding(**defaults)
        session.add(finding)
        session.commit()
        session.refresh(finding)
        return finding.id


def _seed_licence_family(engine, target_id, count=11):
    """`count` packages under one licence: the real shape of the sharp rows."""
    for i in range(count):
        _make_finding(
            engine,
            target_id,
            title=f"LGPL-3.0-or-later license detected in @img/sharp-libvips-pkg-{i}",
            file_path="frontend/package-lock.json",
        )


# --------------------------------------------------------------------------
# grouping
# --------------------------------------------------------------------------


def test_one_licence_many_packages_collapses_to_one_group(client, engine):
    target_id = _make_target(engine)
    _login(client, engine)
    _seed_licence_family(engine, target_id, count=11)

    body = client.get("/api/findings/groups").json()

    assert body["total"] == 1
    assert body["total_findings"] == 11
    group = body["items"][0]
    assert group["rule_id"] == "license:LGPL-3.0-or-later"
    assert group["finding_count"] == 11
    assert group["grouped"] is True


def test_total_findings_matches_the_flat_list(client, engine):
    """The grouped view must not look like findings disappeared."""
    target_id = _make_target(engine)
    _login(client, engine)
    _seed_licence_family(engine, target_id, count=7)
    _make_finding(engine, target_id, tool="semgrep", rule_id="python.sqli", title="SQL injection")

    grouped = client.get("/api/findings/groups").json()
    flat = client.get("/api/findings").json()

    assert grouped["total"] == 2
    assert grouped["total_findings"] == flat["total"] == 8


def test_different_licences_are_different_groups(client, engine):
    target_id = _make_target(engine)
    _login(client, engine)
    _make_finding(engine, target_id, rule_id="license:LGPL-3.0-or-later")
    _make_finding(engine, target_id, rule_id="license:LGPL-3.0-only", title="LGPL-3.0-only in psycopg")

    body = client.get("/api/findings/groups").json()

    assert body["total"] == 2
    assert {g["rule_id"] for g in body["items"]} == {"license:LGPL-3.0-or-later", "license:LGPL-3.0-only"}


def test_secrets_are_never_grouped(client, engine):
    """One leaked credential is one incident, not an instance of a rule."""
    target_id = _make_target(engine)
    _login(client, engine)
    for i in range(3):
        _make_finding(
            engine,
            target_id,
            tool="gitleaks",
            rule_id="aws-access-key",
            title=f"AWS key in config-{i}.py",
            file_path=f"config-{i}.py",
            severity=Severity.CRITICAL,
        )

    body = client.get("/api/findings/groups").json()

    assert body["total"] == 3, "three secrets must stay three rows"
    assert all(g["grouped"] is False for g in body["items"])


def test_group_severity_is_the_highest_member_not_the_first(client, engine):
    target_id = _make_target(engine)
    _login(client, engine)
    _make_finding(engine, target_id, severity=Severity.LOW, priority_score=40)
    _make_finding(engine, target_id, severity=Severity.CRITICAL, priority_score=400)
    _make_finding(engine, target_id, severity=Severity.MEDIUM, priority_score=120)

    group = client.get("/api/findings/groups").json()["items"][0]

    assert group["severity"] == "Critical"
    assert group["max_priority_score"] == 400


def test_group_counts_distinct_targets_and_files(client, engine):
    target_a = _make_target(engine, name="A")
    _login(client, engine)
    _make_finding(engine, target_a, file_path="a/lock.json")
    _make_finding(engine, target_a, file_path="a/lock.json")
    _make_finding(engine, target_a, file_path="b/lock.json")

    group = client.get("/api/findings/groups").json()["items"][0]

    assert group["finding_count"] == 3
    assert group["target_count"] == 1
    assert group["file_count"] == 2


def test_group_reports_oldest_first_seen(client, engine):
    target_id = _make_target(engine)
    _login(client, engine)
    old = utcnow() - timedelta(days=64)
    _make_finding(engine, target_id, first_seen=old)
    _make_finding(engine, target_id, first_seen=utcnow())

    group = client.get("/api/findings/groups").json()["items"][0]

    assert group["oldest_first_seen"].startswith(old.strftime("%Y-%m-%d"))


def test_group_counts_kev_members(client, engine):
    target_id = _make_target(engine)
    _login(client, engine)
    _make_finding(engine, target_id, tool="trivy", rule_id="CVE-2024-1", cve_id="CVE-2024-1", kev_listed=True)
    _make_finding(engine, target_id, tool="trivy", rule_id="CVE-2024-1", cve_id="CVE-2024-1", kev_listed=False)

    group = client.get("/api/findings/groups").json()["items"][0]

    assert group["kev_count"] == 1


# --------------------------------------------------------------------------
# filters apply identically to both views
# --------------------------------------------------------------------------


def test_group_respects_severity_filter(client, engine):
    target_id = _make_target(engine)
    _login(client, engine)
    _make_finding(engine, target_id, severity=Severity.HIGH)
    _make_finding(engine, target_id, rule_id="license:MIT", severity=Severity.LOW, title="MIT detected")

    body = client.get("/api/findings/groups?severity=High").json()

    assert body["total"] == 1
    assert body["items"][0]["rule_id"] == "license:LGPL-3.0-or-later"


def test_group_respects_category_filter(client, engine):
    target_id = _make_target(engine)
    _login(client, engine)
    _make_finding(engine, target_id)
    _make_finding(engine, target_id, tool="semgrep", rule_id="python.sqli", title="SQLi")

    body = client.get("/api/findings/groups?category=License").json()

    assert body["total"] == 1
    assert body["items"][0]["category"] == "License"


def test_group_excludes_findings_from_other_workspaces(client, engine):
    """The representative is picked from the caller's own filtered query."""
    mine = _make_target(engine, name="Mine")
    theirs = _make_target(engine, name="Theirs")
    _make_finding(engine, theirs, title="Not mine", severity=Severity.CRITICAL)
    _make_finding(engine, mine, title="Mine")

    with Session(engine) as session:
        # Explicitly not an admin: User.role defaults to ADMIN, and
        # accessible_workspace_ids returns None (sees everything) for admins,
        # so a default-constructed user would pass this test without the
        # scoping ever being exercised.
        user = User(
            email="scoped@example.com",
            name="Scoped",
            password_hash=hash_password("whatever123"),
            role=UserRole.SECURITY_ENGINEER,
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        target = session.get(Target, mine)
        from app.models.models import WorkspaceMembership, WorkspaceRole

        session.add(
            WorkspaceMembership(workspace_id=target.workspace_id, user_id=user.id, role=WorkspaceRole.SECURITY_ENGINEER)
        )
        session.commit()
        token = create_session_token(user.id)
    client.cookies.set("toleman_session", token)

    body = client.get("/api/findings/groups").json()

    assert body["total_findings"] == 1
    assert body["items"][0]["title"] == "Mine"


# --------------------------------------------------------------------------
# expanding a group
# --------------------------------------------------------------------------


def test_rule_id_filter_returns_a_groups_members(client, engine):
    target_id = _make_target(engine)
    _login(client, engine)
    _seed_licence_family(engine, target_id, count=4)
    _make_finding(engine, target_id, rule_id="license:MIT", title="MIT detected")

    body = client.get("/api/findings?tool=trivy-license&rule_id=license:LGPL-3.0-or-later").json()

    assert body["total"] == 4
    assert all(item["rule_id"] == "license:LGPL-3.0-or-later" for item in body["items"])


# --------------------------------------------------------------------------
# sort and recency
# --------------------------------------------------------------------------


def test_sort_by_blast_radius_puts_the_widest_group_first(client, engine):
    target_id = _make_target(engine)
    _login(client, engine)
    _seed_licence_family(engine, target_id, count=6)
    _make_finding(engine, target_id, rule_id="license:MIT", title="MIT", priority_score=999)

    body = client.get("/api/findings/groups?sort=blast_radius").json()

    assert body["items"][0]["rule_id"] == "license:LGPL-3.0-or-later"
    assert body["items"][0]["finding_count"] == 6


def test_default_sort_is_exploitability(client, engine):
    target_id = _make_target(engine)
    _login(client, engine)
    _seed_licence_family(engine, target_id, count=6)
    _make_finding(engine, target_id, rule_id="license:MIT", title="MIT", priority_score=999)

    body = client.get("/api/findings/groups").json()

    assert body["items"][0]["rule_id"] == "license:MIT", "highest score leads by default"


def test_sort_by_age_puts_the_oldest_group_first(client, engine):
    target_id = _make_target(engine)
    _login(client, engine)
    _make_finding(engine, target_id, rule_id="license:MIT", title="MIT", first_seen=utcnow() - timedelta(days=2))
    _make_finding(engine, target_id, first_seen=utcnow() - timedelta(days=90))

    body = client.get("/api/findings/groups?sort=age").json()

    assert body["items"][0]["rule_id"] == "license:LGPL-3.0-or-later"


def test_new_since_days_narrows_to_recent_findings(client, engine):
    target_id = _make_target(engine)
    _login(client, engine)
    _make_finding(engine, target_id, rule_id="license:MIT", title="MIT", first_seen=utcnow() - timedelta(days=40))
    _make_finding(engine, target_id, first_seen=utcnow() - timedelta(hours=2))

    body = client.get("/api/findings/groups?new_since_days=7").json()

    assert body["total"] == 1
    assert body["items"][0]["rule_id"] == "license:LGPL-3.0-or-later"


def test_new_since_days_zero_is_treated_as_one_day(client, engine):
    """`?new_since_days=0` must not mean "nothing ever matched"."""
    target_id = _make_target(engine)
    _login(client, engine)
    _make_finding(engine, target_id, first_seen=utcnow() - timedelta(hours=1))

    body = client.get("/api/findings/groups?new_since_days=0").json()

    assert body["total"] == 1


# --------------------------------------------------------------------------
# pagination
# --------------------------------------------------------------------------


def test_groups_paginate_without_losing_rows(client, engine):
    target_id = _make_target(engine)
    _login(client, engine)
    for i in range(9):
        _make_finding(engine, target_id, rule_id=f"license:LIC-{i}", title=f"LIC-{i}", priority_score=100 + i)

    first = client.get("/api/findings/groups?page=1&page_size=4").json()
    second = client.get("/api/findings/groups?page=2&page_size=4").json()
    third = client.get("/api/findings/groups?page=3&page_size=4").json()

    assert first["total"] == 9
    seen = [g["rule_id"] for g in first["items"] + second["items"] + third["items"]]
    assert len(seen) == 9
    assert len(set(seen)) == 9, "a group must not appear on two pages"


def test_empty_result_set_is_an_empty_page_not_an_error(client, engine):
    _make_target(engine)
    _login(client, engine)

    body = client.get("/api/findings/groups").json()

    assert body == {"items": [], "total": 0, "total_findings": 0, "truncated": False}


# --------------------------------------------------------------------------
# ordering is total, not merely sorted
# --------------------------------------------------------------------------


def test_identical_ungrouped_rows_keep_a_stable_total_order(client, engine):
    """Three secrets under one rule tie on every visible sort key.

    They share tool, rule_id, severity and score, so an order that tiebreaks on
    rule_id alone leaves them in whatever order the database returned -- stable
    on SQLite, unspecified on Postgres. Paged two at a time that lets one
    secret appear twice and another never appear.
    """
    target_id = _make_target(engine)
    _login(client, engine)
    for i in range(3):
        _make_finding(
            engine,
            target_id,
            tool="gitleaks",
            rule_id="aws-access-key",
            title=f"AWS key in config-{i}.py",
            file_path=f"config-{i}.py",
            severity=Severity.CRITICAL,
            priority_score=320,
        )

    first = client.get("/api/findings/groups?page=1&page_size=2").json()
    second = client.get("/api/findings/groups?page=2&page_size=2").json()

    seen = [g["representative_id"] for g in first["items"] + second["items"]]
    assert len(seen) == 3
    assert len(set(seen)) == 3, "a secret must not appear on two pages while another is dropped"

    # And the same request twice must agree with itself.
    again = client.get("/api/findings/groups?page=1&page_size=2").json()
    assert [g["representative_id"] for g in again["items"]] == [g["representative_id"] for g in first["items"]]


def test_recent_means_newly_found_in_both_views(client, engine):
    """`sort=recent` must not mean first_seen in one view and last_seen in the other."""
    target_id = _make_target(engine)
    _login(client, engine)
    # Found long ago, re-detected by today's scan: not newly found.
    _make_finding(
        engine,
        target_id,
        rule_id="license:MIT",
        title="MIT",
        first_seen=utcnow() - timedelta(days=200),
        last_seen=utcnow(),
    )
    _make_finding(engine, target_id, first_seen=utcnow() - timedelta(days=1), last_seen=utcnow())

    grouped = client.get("/api/findings/groups?sort=recent").json()
    flat = client.get("/api/findings?sort=recent").json()

    assert grouped["items"][0]["rule_id"] == "license:LGPL-3.0-or-later"
    assert flat["items"][0]["rule_id"] == "license:LGPL-3.0-or-later"


def test_measured_zero_epss_is_not_reported_as_unknown(client, engine):
    """0.0 is an answer -- "no predicted exploitation" -- not an absence of one."""
    target_id = _make_target(engine)
    _login(client, engine)
    _make_finding(engine, target_id, tool="trivy", rule_id="CVE-2024-9", cve_id="CVE-2024-9", epss_score=0.0)

    group = client.get("/api/findings/groups").json()["items"][0]

    assert group["max_epss"] == 0.0


def test_untruncated_result_says_so(client, engine):
    target_id = _make_target(engine)
    _login(client, engine)
    _seed_licence_family(engine, target_id, count=3)

    assert client.get("/api/findings/groups").json()["truncated"] is False
