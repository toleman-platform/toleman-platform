"""Tests for GET /api/findings/{id}/enrichment (issue #71) and the
core.cve_enrichment caching layer -- CVE/CWE/fix-version data sourced from
NVD + OSV.dev, explicitly without any AI provider involved.

Follows the same in-memory SQLite + dependency_override pattern used in
tests/test_findings.py.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core.cve_enrichment import get_cve_enrichment
from app.core.security import create_session_token, hash_password
from app.main import app
from app.models.models import CveEnrichment, Finding, FindingState, Organization, Severity, Target, User, Workspace


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
        org = Organization(name="Org")
        session.add(org)
        session.commit()
        session.refresh(org)
        workspace = Workspace(organization_id=org.id, name="WS", api_key=f"key-{name}")
        session.add(workspace)
        session.commit()
        session.refresh(workspace)
        target = Target(workspace_id=workspace.id, name=name, repo_url="https://example.com/repo.git")
        session.add(target)
        session.commit()
        session.refresh(target)
        return target.id


def _make_finding(engine, target_id, **overrides) -> int:
    defaults = dict(
        target_id=target_id,
        dedup_hash=f"hash-{overrides.get('rule_id', 'r')}",
        tool="trivy",
        rule_id="CVE-2020-28483",
        title="gin: HTTP response splitting",
        file_path="go.mod",
        severity=Severity.HIGH,
        priority_score=50,
        state=FindingState.OPEN,
        cve_id="CVE-2020-28483",
    )
    defaults.update(overrides)
    with Session(engine) as session:
        finding = Finding(**defaults)
        session.add(finding)
        session.commit()
        session.refresh(finding)
        return finding.id


# ---------------------------------------------------------------------------
# core.cve_enrichment.get_cve_enrichment -- caching behavior
# ---------------------------------------------------------------------------


def test_first_lookup_calls_both_apis_and_persists_a_row(engine, mocker):
    fake_nvd = mocker.patch(
        "app.core.cve_enrichment.fetch_nvd_cve",
        return_value={
            "description": "desc", "cvss_score": 7.1, "cvss_vector": "CVSS:3.1/AV:N",
            "cwe_ids": ["CWE-444"], "references": ["https://example.com/a"],
        },
    )
    fake_osv = mocker.patch(
        "app.core.cve_enrichment.fetch_osv_vuln",
        return_value={"osv_id": "GHSA-1", "fixed_versions": [{"package": "gin", "ecosystem": "Go", "fixed": "1.7.0"}], "references": ["https://example.com/b"]},
    )

    with Session(engine) as session:
        row = get_cve_enrichment(session, "CVE-2020-28483")
        assert row.cve_id == "CVE-2020-28483"
        assert row.nvd_found is True
        assert row.osv_found is True
        assert row.cvss_score == 7.1
        assert row.cwe_ids == '["CWE-444"]'

    fake_nvd.assert_called_once_with("CVE-2020-28483")
    fake_osv.assert_called_once_with("CVE-2020-28483")

    with Session(engine) as session:
        rows = session.exec(select(CveEnrichment)).all()
        assert len(rows) == 1


def test_second_lookup_is_served_from_cache_no_second_network_call(engine, mocker):
    fake_nvd = mocker.patch(
        "app.core.cve_enrichment.fetch_nvd_cve",
        return_value={"description": "d", "cvss_score": 5.0, "cvss_vector": "v", "cwe_ids": [], "references": []},
    )
    fake_osv = mocker.patch("app.core.cve_enrichment.fetch_osv_vuln", return_value=None)

    with Session(engine) as session:
        get_cve_enrichment(session, "CVE-2020-28483")
    with Session(engine) as session:
        get_cve_enrichment(session, "CVE-2020-28483")

    fake_nvd.assert_called_once()
    fake_osv.assert_called_once()


def test_both_sources_failing_still_caches_a_negative_row(engine, mocker):
    mocker.patch("app.core.cve_enrichment.fetch_nvd_cve", return_value=None)
    mocker.patch("app.core.cve_enrichment.fetch_osv_vuln", return_value=None)

    with Session(engine) as session:
        row = get_cve_enrichment(session, "CVE-0000-00000")
        assert row.nvd_found is False
        assert row.osv_found is False
        assert row.nvd_description is None


# ---------------------------------------------------------------------------
# GET /api/findings/{id}/enrichment
# ---------------------------------------------------------------------------


def test_enrichment_endpoint_returns_null_fields_for_finding_without_cve(client, engine, mocker):
    fake_nvd = mocker.patch("app.core.cve_enrichment.fetch_nvd_cve")
    _login(client, engine)
    target_id = _make_target(engine)
    finding_id = _make_finding(engine, target_id, cve_id=None, tool="semgrep", rule_id="use-of-md5")

    resp = client.get(f"/api/findings/{finding_id}/enrichment")

    assert resp.status_code == 200
    body = resp.json()
    assert body["finding_id"] == finding_id
    assert body["cve_id"] is None
    assert body["cve_description"] is None
    assert body["cvss_score"] is None
    assert body["cwe_ids"] is None
    assert body["fix_versions"] is None
    fake_nvd.assert_not_called()  # no CVE -> never touches NVD/OSV at all


def test_enrichment_endpoint_returns_real_shaped_data_for_cve_finding(client, engine, mocker):
    mocker.patch(
        "app.core.cve_enrichment.fetch_nvd_cve",
        return_value={
            "description": "This affects all versions of package github.com/gin-gonic/gin.",
            "cvss_score": 7.1, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",
            "cwe_ids": ["CWE-444"], "references": ["https://github.com/gin-gonic/gin/pull/2474"],
        },
    )
    mocker.patch(
        "app.core.cve_enrichment.fetch_osv_vuln",
        return_value={
            "osv_id": "CVE-2020-28483",
            "fixed_versions": [{"package": "github.com/gin-gonic/gin", "ecosystem": "Go", "fixed": "1.7.0"}],
            "references": ["https://github.com/gin-gonic/gin/pull/2474", "https://snyk.io/vuln/SNYK-1"],
        },
    )
    _login(client, engine)
    target_id = _make_target(engine)
    finding_id = _make_finding(engine, target_id)

    resp = client.get(f"/api/findings/{finding_id}/enrichment")

    assert resp.status_code == 200
    body = resp.json()
    assert body["cve_id"] == "CVE-2020-28483"
    assert body["cvss_score"] == 7.1
    assert body["cwe_ids"] == ["CWE-444"]
    assert body["fix_versions"] == [{"package": "github.com/gin-gonic/gin", "ecosystem": "Go", "fixed": "1.7.0"}]
    # References from both sources, de-duplicated.
    assert body["references"] == ["https://github.com/gin-gonic/gin/pull/2474", "https://snyk.io/vuln/SNYK-1"]


def test_enrichment_endpoint_404s_for_finding_in_inaccessible_workspace(client, engine, mocker):
    mocker.patch("app.core.cve_enrichment.fetch_nvd_cve", return_value=None)
    mocker.patch("app.core.cve_enrichment.fetch_osv_vuln", return_value=None)
    _login(client, engine)
    target_id = _make_target(engine)
    finding_id = _make_finding(engine, target_id)

    resp = client.get(f"/api/findings/{finding_id + 999}/enrichment")
    assert resp.status_code == 404


def test_enrichment_endpoint_requires_login(client, engine):
    target_id = _make_target(engine)
    finding_id = _make_finding(engine, target_id)

    resp = client.get(f"/api/findings/{finding_id}/enrichment")
    assert resp.status_code in (401, 403)
