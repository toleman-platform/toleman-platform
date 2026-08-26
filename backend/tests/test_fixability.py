"""Fixability verdict (#246).

Severity says which finding is worst. It does not say which one a developer
can actually close today, and that is the question someone staring at 40
findings is really asking.

The load-bearing part is the third value. `unknown` must never be rendered
as, filtered as, or collapsed into `no_known_fix`: enrichment is best-effort
and network-dependent, so "we did not establish a fix" and "there is no fix"
are different claims. Telling someone "nothing you can do" about a CVE we
never looked up is the same class of false statement as reporting an unrun
scan as clean.
"""

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core.security import create_session_token, hash_password
from app.main import app as fastapi_app
from app.models.models import UserRole

from app.core.fixability import (
    FIXABLE,
    NO_KNOWN_FIX,
    UNKNOWN,
    fixability_for_enrichment,
    fixed_version_summary,
)
from app.models.models import CveEnrichment, Finding, User


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

    fastapi_app.dependency_overrides[get_session] = override_get_session
    original_engine = deps_module.engine
    deps_module.engine = engine
    c = TestClient(fastapi_app)
    yield c
    fastapi_app.dependency_overrides.clear()
    deps_module.engine = original_engine


def _login(client, engine, role=UserRole.USER):
    with Session(engine) as session:
        user = User(email=f"{role.value}@example.com", name="T",
                    password_hash=hash_password("whatever123"), role=role)
        session.add(user)
        session.commit()
        session.refresh(user)
        token = create_session_token(user.id, user.token_version)
    client.cookies.set("toleman_session", token)
    return client


def enrichment(osv_found=True, fixed=None):
    return CveEnrichment(
        cve_id="CVE-2024-0001",
        osv_found=osv_found,
        fixed_versions=json.dumps(fixed) if fixed is not None else None,
    )


class TestVerdict:
    def test_advisory_with_a_fix_is_fixable(self):
        row = enrichment(fixed=[{"package": "starlette", "ecosystem": "PyPI", "fixed": "0.40.0"}])
        assert fixability_for_enrichment(row) == FIXABLE

    def test_advisory_without_a_fix_is_no_known_fix(self):
        assert fixability_for_enrichment(enrichment(fixed=[])) == NO_KNOWN_FIX
        assert fixability_for_enrichment(enrichment(fixed=None)) == NO_KNOWN_FIX

    def test_no_advisory_resolved_is_unknown_not_no_fix(self):
        """The distinction the whole feature turns on. osv_found False means
        the lookup failed or never ran -- saying "no known fix" there would
        tell someone nothing can be done about something we never checked."""
        assert fixability_for_enrichment(enrichment(osv_found=False)) == UNKNOWN

    def test_missing_enrichment_row_is_unknown(self):
        assert fixability_for_enrichment(None) == UNKNOWN

    def test_corrupt_json_is_unknown_not_no_fix(self):
        row = CveEnrichment(cve_id="CVE-2024-0002", osv_found=True, fixed_versions="{not json")
        assert fixability_for_enrichment(row) == UNKNOWN

    def test_unknown_and_no_known_fix_are_never_equal(self):
        assert UNKNOWN != NO_KNOWN_FIX


class TestFixedVersionSummary:
    def test_picks_the_lowest_fix_the_smallest_upgrade(self):
        row = enrichment(fixed=[
            {"package": "starlette", "fixed": "0.41.0"},
            {"package": "starlette", "fixed": "0.40.0"},
        ])
        assert fixed_version_summary(row).startswith("0.40.0")

    def test_sorts_numerically_not_lexically(self):
        """0.9.0 is below 0.10.0; string ordering gets this backwards."""
        row = enrichment(fixed=[{"fixed": "0.10.0"}, {"fixed": "0.9.0"}])
        assert fixed_version_summary(row) == "0.9.0"

    def test_names_the_package_when_known(self):
        row = enrichment(fixed=[{"package": "starlette", "fixed": "0.40.0"}])
        assert fixed_version_summary(row) == "0.40.0 (starlette)"

    def test_none_when_there_is_nothing_to_suggest(self):
        assert fixed_version_summary(enrichment(fixed=[])) is None
        assert fixed_version_summary(None) is None

    def test_non_numeric_versions_do_not_crash(self):
        row = enrichment(fixed=[{"fixed": "2024-01-15"}, {"fixed": "1.0"}])
        assert fixed_version_summary(row) is not None


class TestFindingsApi:
    def test_findings_carry_a_verdict(self, client, engine):
        _login(client, engine)
        res = client.get("/api/findings")
        assert res.status_code == 200
        for item in res.json()["items"]:
            assert item["fixability"] in {FIXABLE, NO_KNOWN_FIX, UNKNOWN}

    def test_invalid_filter_value_is_rejected(self, client, engine):
        _login(client, engine)
        res = client.get("/api/findings?fixability=probably")
        assert res.status_code == 422

    @pytest.mark.parametrize("value", [FIXABLE, NO_KNOWN_FIX, UNKNOWN])
    def test_each_filter_value_is_accepted(self, client, engine, value):
        _login(client, engine)
        assert client.get(f"/api/findings?fixability={value}").status_code == 200

    def test_a_sast_finding_with_no_cve_is_unknown_not_no_fix(self, client, engine):
        """Most SAST and secrets findings carry no CVE. "No known fix" would
        be actively wrong for a hardcoded secret, whose fix is obvious."""
        from app.core.fixability import fixability_for_finding

        with Session(engine) as session:
            f = Finding(target_id=1, tool="gitleaks", rule_id="x", title="secret",
                        file_path="a.py", severity="High", cve_id=None)
            assert fixability_for_finding(session, f) == UNKNOWN
