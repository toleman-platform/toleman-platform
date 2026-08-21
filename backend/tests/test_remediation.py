"""Grouped remediation (#247).

The findings list shows N rows against one package and leaves the reader to
work out they collapse into a single version bump. On this repo's own
requirements.txt that was 34 rows versus 6 actions.

Two ways this feature could lie, and both are what these tests are for:

* Recommending a bigger upgrade than the evidence supports. The answer must
  be the *lowest* version clearing every grouped CVE -- not the newest
  release, and not one CVE's fix applied to all of them.
* Rounding up. If three of five CVEs on a package have a fix and two do not,
  "upgrade to X fixes 3 issues, 2 remain" is true; "upgrading fixes this
  package" is not.
"""

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core.remediation import group_remediations, parse_version
from app.core.security import create_session_token, hash_password
from app.main import app as fastapi_app
from app.models.models import (
    CveEnrichment,
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


def _admin(client, engine):
    with Session(engine) as session:
        u = User(email="a@e.com", name="A", password_hash=hash_password("whatever123"), role=UserRole.ADMIN)
        session.add(u)
        session.commit()
        session.refresh(u)
        token = create_session_token(u.id, u.token_version)
    client.cookies.set("rikugan_session", token)
    return client


def _target(engine):
    with Session(engine) as session:
        org = Organization(name="o")
        session.add(org); session.commit(); session.refresh(org)
        ws = Workspace(organization_id=org.id, name="w", api_key="k")
        session.add(ws); session.commit(); session.refresh(ws)
        t = Target(name="t", repo_url="https://github.com/a/b", workspace_id=ws.id)
        session.add(t); session.commit(); session.refresh(t)
        return t.id


def _finding(engine, target_id, cve_id, severity=Severity.HIGH, fixes=None, osv_found=True):
    """fixes: list of (package, version) this CVE's advisory offers, or None
    for an advisory with no fix at all."""
    with Session(engine) as session:
        session.add(Finding(
            target_id=target_id, tool="trivy", rule_id=cve_id, title=f"{cve_id} in dep",
            file_path="requirements.txt", severity=severity, cve_id=cve_id,
            state=FindingState.OPEN,
            # NOT NULL in the schema, and unique per finding -- reusing one
            # value here would make two findings collide rather than group.
            dedup_hash=f"hash-{cve_id}",
        ))
        payload = [{"package": p, "ecosystem": "PyPI", "fixed": v} for p, v in (fixes or [])]
        session.add(CveEnrichment(
            cve_id=cve_id, osv_found=osv_found,
            fixed_versions=json.dumps(payload) if payload else None,
        ))
        session.commit()


class TestVersionOrdering:
    def test_numeric_segments_compare_numerically(self):
        """0.9.0 is below 0.10.0. String ordering gets this backwards, and
        getting it backwards recommends a downgrade."""
        assert parse_version("0.9.0") < parse_version("0.10.0")

    def test_patch_ordering(self):
        assert parse_version("1.2.3") < parse_version("1.2.10")

    def test_non_numeric_does_not_raise(self):
        parse_version("2024-01-15")
        parse_version("1.0.0-rc1")

    def test_mixed_forms_are_comparable(self):
        assert parse_version("1.0.0") < parse_version("1.0.1")


class TestGrouping:
    def test_several_cves_on_one_package_become_one_upgrade(self, engine):
        tid = _target(engine)
        _finding(engine, tid, "CVE-1", fixes=[("starlette", "0.38.0")])
        _finding(engine, tid, "CVE-2", fixes=[("starlette", "0.40.0")])
        _finding(engine, tid, "CVE-3", fixes=[("starlette", "0.39.0")])
        with Session(engine) as session:
            groups = group_remediations(session, tid)
        assert len(groups) == 1
        assert groups[0]["package"] == "starlette"
        assert groups[0]["fixes_count"] == 3

    def test_recommends_the_lowest_version_that_clears_everything(self, engine):
        """0.40.0, not 0.38.0 (leaves CVE-2 open) and not something newer
        (a bigger jump than the evidence supports)."""
        tid = _target(engine)
        _finding(engine, tid, "CVE-1", fixes=[("starlette", "0.38.0")])
        _finding(engine, tid, "CVE-2", fixes=[("starlette", "0.40.0")])
        with Session(engine) as session:
            groups = group_remediations(session, tid)
        assert groups[0]["upgrade_to"] == "0.40.0"

    def test_picks_each_cves_smallest_fix_before_taking_the_max(self, engine):
        """A CVE offering 0.38.0 or 0.50.0 is cleared by 0.38.0. Taking the
        max within a CVE would recommend 0.50.0 for no reason."""
        tid = _target(engine)
        _finding(engine, tid, "CVE-1", fixes=[("starlette", "0.50.0"), ("starlette", "0.38.0")])
        with Session(engine) as session:
            groups = group_remediations(session, tid)
        assert groups[0]["upgrade_to"] == "0.38.0"

    def test_numeric_ordering_is_used_for_the_recommendation(self, engine):
        tid = _target(engine)
        _finding(engine, tid, "CVE-1", fixes=[("pkg", "0.9.0")])
        _finding(engine, tid, "CVE-2", fixes=[("pkg", "0.10.0")])
        with Session(engine) as session:
            groups = group_remediations(session, tid)
        assert groups[0]["upgrade_to"] == "0.10.0"

    def test_different_packages_stay_separate(self, engine):
        tid = _target(engine)
        _finding(engine, tid, "CVE-1", fixes=[("starlette", "0.40.0")])
        _finding(engine, tid, "CVE-2", fixes=[("jinja2", "3.1.5")])
        with Session(engine) as session:
            groups = group_remediations(session, tid)
        assert {g["package"] for g in groups} == {"starlette", "jinja2"}

    def test_most_findings_closed_ranks_first(self, engine):
        tid = _target(engine)
        _finding(engine, tid, "CVE-1", fixes=[("many", "1.0")])
        _finding(engine, tid, "CVE-2", fixes=[("many", "1.0")])
        _finding(engine, tid, "CVE-3", fixes=[("few", "2.0")])
        with Session(engine) as session:
            groups = group_remediations(session, tid)
        assert groups[0]["package"] == "many"

    def test_highest_severity_is_reported(self, engine):
        tid = _target(engine)
        _finding(engine, tid, "CVE-1", severity=Severity.LOW, fixes=[("pkg", "1.0")])
        _finding(engine, tid, "CVE-2", severity=Severity.CRITICAL, fixes=[("pkg", "1.0")])
        with Session(engine) as session:
            groups = group_remediations(session, tid)
        assert groups[0]["highest_severity"] == "Critical"


class TestDoesNotOverstate:
    def test_a_package_with_no_fixable_cve_is_not_offered_as_a_remediation(self, engine):
        """Not a remediation, just bad news. It belongs in the findings list,
        not in an action card with an upgrade button."""
        tid = _target(engine)
        _finding(engine, tid, "CVE-1", fixes=None)
        with Session(engine) as session:
            assert group_remediations(session, tid) == []

    def test_findings_with_no_advisory_are_not_guessed_into_a_package(self, engine):
        """Attributing an unknown CVE to a package would send someone to
        upgrade something unrelated."""
        tid = _target(engine)
        _finding(engine, tid, "CVE-1", fixes=[("starlette", "0.40.0")])
        _finding(engine, tid, "CVE-2", osv_found=False)
        with Session(engine) as session:
            groups = group_remediations(session, tid)
        assert groups[0]["fixes_count"] == 1
        assert all(f["cve_id"] != "CVE-2" for f in groups[0]["fixes"])

    def test_closed_findings_are_excluded(self, engine):
        tid = _target(engine)
        _finding(engine, tid, "CVE-1", fixes=[("pkg", "1.0")])
        with Session(engine) as session:
            f = session.exec(__import__("sqlmodel").select(Finding)).first()
            f.state = FindingState.FALSE_POSITIVE
            session.add(f)
            session.commit()
            assert group_remediations(session, tid) == []

    def test_empty_target_returns_nothing_rather_than_erroring(self, engine):
        tid = _target(engine)
        with Session(engine) as session:
            assert group_remediations(session, tid) == []


class TestApi:
    def test_endpoint_returns_groups(self, client, engine):
        _admin(client, engine)
        tid = _target(engine)
        _finding(engine, tid, "CVE-1", fixes=[("starlette", "0.40.0")])
        res = client.get(f"/api/findings/remediations?target_id={tid}")
        assert res.status_code == 200, res.text
        assert res.json()[0]["package"] == "starlette"

    def test_unknown_target_is_404(self, client, engine):
        _admin(client, engine)
        assert client.get("/api/findings/remediations?target_id=9999").status_code == 404

    def test_requires_authentication(self, client, engine):
        tid = _target(engine)
        assert client.get(f"/api/findings/remediations?target_id={tid}").status_code in (401, 403)
