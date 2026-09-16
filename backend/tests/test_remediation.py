"""Grouped remediation (#247).

The findings list shows N rows against one package and leaves the reader to
work out they collapse into a single version bump. On this repo's own
requirements.txt that was 34 rows versus 6 actions.

Two ways this feature could lie, and both are what these tests are for:

* Recommending a bigger upgrade than the evidence supports. The answer must
  be the *lowest* version clearing every grouped CVE, not the newest
  release, and not one CVE's fix applied to all of them.
* Rounding up. If three of five CVEs on a package have a fix and two do not,
  "upgrade to X fixes 3 issues, 2 remain" is true; "upgrading fixes this
  package" is not.

A third, which is what `TestEnrichmentCoverage` is for: answering the empty
case with a confident negative. No plans can mean nothing was ever looked up
for these CVEs, or that advisories were looked up and none names a fixed
version. The counts must keep those apart, because the caller renders a
sentence either way and only one of them is true.
"""

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core.remediation import group_remediations, parse_version, remediation_plan
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
    client.cookies.set("toleman_session", token)
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


def _finding(engine, target_id, cve_id, severity=Severity.HIGH, fixes=None, osv_found=True,
             enrich=True, suffix="", package_name=None):
    """fixes: list of (package, version) this CVE's advisory offers, or None
    for an advisory with no fix at all. A `package` of None in `fixes`
    simulates an OSV record with no package name; `package_name` gives the
    Finding itself trivy's attribution for that case.

    enrich=False writes the finding with NO CveEnrichment row at all -- the
    state a target is in before anything has been looked up, which is
    indistinguishable from "no fix exists" unless the coverage numbers say
    otherwise. Also the way to add a second finding on an already-enriched
    CVE, since CveEnrichment.cve_id is unique."""
    with Session(engine) as session:
        session.add(Finding(
            target_id=target_id, tool="trivy", rule_id=cve_id, title=f"{cve_id} in dep",
            file_path="requirements.txt", severity=severity, cve_id=cve_id,
            state=FindingState.OPEN, package_name=package_name,
            # NOT NULL in the schema, and unique per finding; reusing one
            # value here would make two findings collide rather than group.
            dedup_hash=f"hash-{cve_id}{suffix}",
        ))
        if enrich:
            payload = [{"package": p, "ecosystem": "PyPI", "fixed": v} for p, v in (fixes or [])]
            session.add(CveEnrichment(
                cve_id=cve_id, osv_found=osv_found,
                fixed_versions=json.dumps(payload) if payload else None,
            ))
        session.commit()


def _non_cve_finding(engine, target_id, rule_id="python.lang.security.audit"):
    """A SAST-shaped open finding: no cve_id, so the fix plan cannot see it."""
    with Session(engine) as session:
        session.add(Finding(
            target_id=target_id, tool="semgrep", rule_id=rule_id, title="Unsafe eval",
            file_path="app/main.py", severity=Severity.HIGH, cve_id=None,
            state=FindingState.OPEN, dedup_hash=f"hash-{rule_id}",
        ))
        session.commit()


def _plan(engine, target_id):
    with Session(engine) as session:
        return remediation_plan(session, target_id)


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

    def test_falls_back_to_the_findings_own_package_when_osv_names_none(self, engine):
        """#521: a CVE-ID-keyed OSV/NVD lookup often returns a fixed version
        with no package name at all (unlike the ecosystem-native GHSA/PYSEC
        advisory, which normally has one). Trivy already knows which
        package it flagged, so that -- not a guess -- fills the gap."""
        tid = _target(engine)
        _finding(engine, tid, "CVE-1", fixes=[(None, "1.4.1")], package_name="loader-utils")
        with Session(engine) as session:
            groups = group_remediations(session, tid)
        assert len(groups) == 1
        assert groups[0]["package"] == "loader-utils"
        assert groups[0]["upgrade_to"] == "1.4.1"

    def test_no_fallback_and_no_osv_package_drops_the_finding(self, engine):
        """The conservative default still holds when there is nothing to
        attribute the fix to -- neither OSV nor the finding itself names a
        package, so this must not invent one."""
        tid = _target(engine)
        _finding(engine, tid, "CVE-1", fixes=[(None, "1.4.1")], package_name=None)
        with Session(engine) as session:
            groups = group_remediations(session, tid)
        assert groups == []

    def test_osvs_own_package_name_wins_over_the_fallback(self, engine):
        """The fallback only fills a gap; it must never override an
        advisory that already names its own package."""
        tid = _target(engine)
        _finding(engine, tid, "CVE-1", fixes=[("starlette", "0.40.0")], package_name="not-starlette")
        with Session(engine) as session:
            groups = group_remediations(session, tid)
        assert len(groups) == 1
        assert groups[0]["package"] == "starlette"


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


class TestEnrichmentCoverage:
    """(#247) What an empty plan is allowed to claim.

    `plans == []` is the same answer for "nobody has looked these CVEs up"
    and for "every advisory was read and none offers a fixed version". These
    pin the counts that separate them, because the UI renders a different
    sentence for each and the wrong one is a confident negative about data
    that was never measured.
    """

    def test_a_target_with_no_cve_findings_reports_zero_across_the_board(self, engine):
        tid = _target(engine)
        _non_cve_finding(engine, tid)
        result = _plan(engine, tid)
        assert result["plans"] == []
        # Not "no fixes": there is nothing here this feature can even see.
        assert result["coverage"] == {
            "cve_findings": 0,
            "distinct_cves": 0,
            "enriched_findings": 0,
            "findings_with_advisory": 0,
            "findings_with_fix_data": 0,
        }

    def test_cves_present_but_never_enriched_reports_zero_enriched(self, engine):
        """The defect this exists for: 2 open CVEs, nothing looked up, empty
        plan. Nothing is known about fixes, so nothing may be claimed."""
        tid = _target(engine)
        _finding(engine, tid, "CVE-1", enrich=False)
        _finding(engine, tid, "CVE-2", enrich=False)
        result = _plan(engine, tid)
        assert result["plans"] == []
        assert result["coverage"] == {
            "cve_findings": 2,
            "distinct_cves": 2,
            "enriched_findings": 0,
            "findings_with_advisory": 0,
            "findings_with_fix_data": 0,
        }

    def test_an_advisory_with_no_fixed_version_is_a_measured_no_fix(self, engine):
        """OSV answered for this CVE and its record names no fixed version.
        This is the one empty case that is genuinely about fixes."""
        tid = _target(engine)
        _finding(engine, tid, "CVE-1", fixes=None, osv_found=True)
        result = _plan(engine, tid)
        assert result["plans"] == []
        assert result["coverage"] == {
            "cve_findings": 1,
            "distinct_cves": 1,
            "enriched_findings": 1,
            "findings_with_advisory": 1,
            "findings_with_fix_data": 0,
        }

    def test_a_cached_failed_lookup_is_not_counted_as_an_advisory(self, engine):
        """app.core.cve_enrichment caches a both-sources-not-found row when
        the upstream fetch fails, and never re-fetches it. That row proves
        something was attempted; it is not an advisory, and counting it as
        one would turn an outage into "no fix exists"."""
        tid = _target(engine)
        _finding(engine, tid, "CVE-1", fixes=None, osv_found=False)
        coverage = _plan(engine, tid)["coverage"]
        assert coverage["enriched_findings"] == 1
        assert coverage["findings_with_advisory"] == 0
        assert coverage["findings_with_fix_data"] == 0

    def test_partial_coverage_travels_with_the_plans_it_produced(self, engine):
        """One fixable, one advisory-without-a-fix, one never looked up. The
        plan is real and incomplete at the same time, and both halves have to
        be readable from the response."""
        tid = _target(engine)
        _finding(engine, tid, "CVE-1", fixes=[("starlette", "0.40.0")])
        _finding(engine, tid, "CVE-2", fixes=None, osv_found=True)
        _finding(engine, tid, "CVE-3", enrich=False)
        result = _plan(engine, tid)
        assert [p["package"] for p in result["plans"]] == ["starlette"]
        assert result["coverage"] == {
            "cve_findings": 3,
            "distinct_cves": 3,
            "enriched_findings": 2,
            "findings_with_advisory": 2,
            "findings_with_fix_data": 1,
        }

    def test_findings_are_counted_per_finding_and_cves_per_cve(self, engine):
        """Two findings on the same CVE are two findings and one CVE; the
        plan counts findings, so the coverage has to as well."""
        tid = _target(engine)
        _finding(engine, tid, "CVE-1", fixes=[("pkg", "1.0")])
        _finding(engine, tid, "CVE-1", enrich=False, suffix="-second")
        coverage = _plan(engine, tid)["coverage"]
        assert coverage["cve_findings"] == 2
        assert coverage["distinct_cves"] == 1
        assert coverage["enriched_findings"] == 2
        assert coverage["findings_with_fix_data"] == 2

    def test_closed_findings_are_outside_the_coverage_numbers(self, engine):
        """Coverage describes the same population the plan is built from:
        open findings. A triaged-away CVE is not an uncovered one."""
        tid = _target(engine)
        _finding(engine, tid, "CVE-1", fixes=[("pkg", "1.0")])
        with Session(engine) as session:
            f = session.exec(select(Finding)).first()
            f.state = FindingState.FALSE_POSITIVE
            session.add(f)
            session.commit()
        coverage = _plan(engine, tid)["coverage"]
        assert coverage["cve_findings"] == 0
        assert coverage["enriched_findings"] == 0

    def test_the_plans_shipped_with_the_coverage_are_the_real_grouping(self, engine):
        """Adding coverage must not have quietly forked the grouping: the
        same lowest-version-that-clears-everything answer, alongside counts
        that describe the findings it was built from."""
        tid = _target(engine)
        _finding(engine, tid, "CVE-1", fixes=[("starlette", "0.38.0")])
        _finding(engine, tid, "CVE-2", fixes=[("starlette", "0.40.0")])
        result = _plan(engine, tid)
        assert [(p["package"], p["upgrade_to"], p["fixes_count"]) for p in result["plans"]] == [
            ("starlette", "0.40.0", 2)
        ]
        assert result["coverage"]["findings_with_fix_data"] == 2

    def test_fix_data_counted_via_the_findings_own_package_fallback(self, engine):
        """#521: an advisory with a fixed version but no package name still
        counts as fix data once the finding's own trivy-reported package
        fills the gap -- coverage must not drift from what the plan built."""
        tid = _target(engine)
        _finding(engine, tid, "CVE-1", fixes=[(None, "1.4.1")], package_name="loader-utils")
        result = _plan(engine, tid)
        assert len(result["plans"]) == 1
        assert result["coverage"] == {
            "cve_findings": 1,
            "distinct_cves": 1,
            "enriched_findings": 1,
            "findings_with_advisory": 1,
            "findings_with_fix_data": 1,
        }


class TestApi:
    def test_endpoint_returns_groups(self, client, engine):
        _admin(client, engine)
        tid = _target(engine)
        _finding(engine, tid, "CVE-1", fixes=[("starlette", "0.40.0")])
        res = client.get(f"/api/findings/remediations?target_id={tid}")
        assert res.status_code == 200, res.text
        assert res.json()["plans"][0]["package"] == "starlette"

    def test_endpoint_reports_coverage_alongside_the_plans(self, client, engine):
        """An empty `plans` with 2 unenriched CVEs behind it: the response
        has to carry enough for the caller to say so instead of asserting
        that no upgrade resolves them."""
        _admin(client, engine)
        tid = _target(engine)
        _finding(engine, tid, "CVE-1", enrich=False)
        _finding(engine, tid, "CVE-2", enrich=False)
        res = client.get(f"/api/findings/remediations?target_id={tid}")
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["plans"] == []
        assert body["coverage"] == {
            "cve_findings": 2,
            "distinct_cves": 2,
            "enriched_findings": 0,
            "findings_with_advisory": 0,
            "findings_with_fix_data": 0,
        }

    def test_unknown_target_is_404(self, client, engine):
        _admin(client, engine)
        assert client.get("/api/findings/remediations?target_id=9999").status_code == 404

    def test_requires_authentication(self, client, engine):
        tid = _target(engine)
        assert client.get(f"/api/findings/remediations?target_id={tid}").status_code in (401, 403)
