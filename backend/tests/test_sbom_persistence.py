import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

from app.api.sbom import upsert_components
from app.models.models import SbomComponent
from app.scanners.parsers import parse_trivy_sbom


@pytest.fixture()
def session():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(eng)
    with Session(eng) as s:
        yield s


def _comp(name="anthropic", version="0.121.0", package_type="pip", purl=None):
    return {
        "name": name,
        "version": version,
        "package_type": package_type,
        "purl": purl or f"pkg:pypi/{name}@{version}",
    }


def test_first_run_all_components_are_new(session):
    new = upsert_components(session, target_id=1, branch="main", discovered=[_comp(), _comp(name="celery", version="5.4.0")])
    assert len(new) == 2

    all_rows = session.exec(select(SbomComponent)).all()
    assert len(all_rows) == 2


def test_second_run_same_components_are_not_new(session):
    upsert_components(session, target_id=1, branch="main", discovered=[_comp()])
    new = upsert_components(session, target_id=1, branch="main", discovered=[_comp()])
    assert new == []

    all_rows = session.exec(select(SbomComponent)).all()
    assert len(all_rows) == 1  # updated in place, not duplicated


def test_second_run_with_an_added_component_only_reports_the_addition(session):
    upsert_components(session, target_id=1, branch="main", discovered=[_comp()])
    new = upsert_components(session, target_id=1, branch="main", discovered=[_comp(), _comp(name="requests", version="2.31.0")])

    assert len(new) == 1
    assert new[0].name == "requests"


def test_last_seen_updates_on_rescan(session):
    upsert_components(session, target_id=1, branch="main", discovered=[_comp()])
    row = session.exec(select(SbomComponent)).one()
    first_seen = row.first_seen
    last_seen_1 = row.last_seen

    upsert_components(session, target_id=1, branch="main", discovered=[_comp()])
    session.refresh(row)
    assert row.first_seen == first_seen  # unchanged
    assert row.last_seen >= last_seen_1


def test_different_branches_are_independent(session):
    upsert_components(session, target_id=1, branch="main", discovered=[_comp()])
    new_on_feature_branch = upsert_components(session, target_id=1, branch="feature-x", discovered=[_comp()])

    assert len(new_on_feature_branch) == 1  # same component, different branch -> still new


def test_version_bump_is_treated_as_a_new_component(session):
    """Upgrading a package version is a real supply-chain event worth
    surfacing as new -- not silently folded into the old row, since name+
    version+purl is the identity key (purl encodes the version too)."""
    upsert_components(session, target_id=1, branch="main", discovered=[_comp(version="0.121.0")])
    new = upsert_components(session, target_id=1, branch="main", discovered=[_comp(version="0.122.0")])

    assert len(new) == 1
    assert new[0].version == "0.122.0"

    all_rows = session.exec(select(SbomComponent)).all()
    assert len(all_rows) == 2  # old version row still present, not overwritten


def test_parse_trivy_sbom_filters_to_library_components_only():
    raw = {
        "components": [
            {
                "type": "application",
                "name": "requirements.txt",
                "properties": [{"name": "aquasecurity:trivy:Type", "value": "pip"}],
            },
            {
                "type": "library",
                "name": "anthropic",
                "version": "0.121.0",
                "purl": "pkg:pypi/anthropic@0.121.0",
                "properties": [{"name": "aquasecurity:trivy:PkgType", "value": "pip"}],
            },
        ]
    }
    parsed = parse_trivy_sbom(raw)
    assert len(parsed) == 1
    assert parsed[0] == {
        "name": "anthropic",
        "version": "0.121.0",
        "package_type": "pip",
        "purl": "pkg:pypi/anthropic@0.121.0",
    }
