import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

from app.api.sbom import _aggregate_org_components, upsert_components
from app.models.models import SbomComponent, Target


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
    new = upsert_components(session, target_id=1, branch="main", discovered=[_comp(), _comp(name="celery", version="5.4.0")], source="github")
    assert len(new) == 2

    all_rows = session.exec(select(SbomComponent)).all()
    assert len(all_rows) == 2


def test_second_run_same_components_are_not_new(session):
    upsert_components(session, target_id=1, branch="main", discovered=[_comp()], source="github")
    new = upsert_components(session, target_id=1, branch="main", discovered=[_comp()], source="github")
    assert new == []

    all_rows = session.exec(select(SbomComponent)).all()
    assert len(all_rows) == 1  # updated in place, not duplicated


def test_second_run_with_an_added_component_only_reports_the_addition(session):
    upsert_components(session, target_id=1, branch="main", discovered=[_comp()], source="github")
    new = upsert_components(session, target_id=1, branch="main", discovered=[_comp(), _comp(name="requests", version="2.31.0")], source="github")

    assert len(new) == 1
    assert new[0].name == "requests"


def test_last_seen_updates_on_rescan(session):
    upsert_components(session, target_id=1, branch="main", discovered=[_comp()], source="github")
    row = session.exec(select(SbomComponent)).one()
    first_seen = row.first_seen
    last_seen_1 = row.last_seen

    upsert_components(session, target_id=1, branch="main", discovered=[_comp()], source="github")
    session.refresh(row)
    assert row.first_seen == first_seen  # unchanged
    assert row.last_seen >= last_seen_1


def test_different_branches_are_independent(session):
    upsert_components(session, target_id=1, branch="main", discovered=[_comp()], source="github")
    new_on_feature_branch = upsert_components(session, target_id=1, branch="feature-x", discovered=[_comp()], source="github")

    assert len(new_on_feature_branch) == 1  # same component, different branch -> still new


def test_version_bump_is_treated_as_a_new_component(session):
    """Upgrading a package version is a real supply-chain event worth
    surfacing as new -- not silently folded into the old row, since name+
    version+purl is the identity key (purl encodes the version too)."""
    upsert_components(session, target_id=1, branch="main", discovered=[_comp(version="0.121.0")], source="github")
    new = upsert_components(session, target_id=1, branch="main", discovered=[_comp(version="0.122.0")], source="github")

    assert len(new) == 1
    assert new[0].version == "0.122.0"

    all_rows = session.exec(select(SbomComponent)).all()
    assert len(all_rows) == 2  # old version row still present, not overwritten


def _target(session, name="repo-a", branch="main"):
    t = Target(workspace_id=1, name=name, repo_url=f"https://github.com/acme/{name}", default_branch=branch)
    session.add(t)
    session.commit()
    session.refresh(t)
    return t


def test_org_aggregation_groups_same_component_version_across_targets(session):
    """Same package+version scanned into two different targets should
    collapse into a single group row listing both target ids -- this is the
    whole point of the org-wide view (e.g. 'is log4j 2.14 anywhere')."""
    t1 = _target(session, name="repo-a")
    t2 = _target(session, name="repo-b")
    upsert_components(session, target_id=t1.id, branch="main", discovered=[_comp(name="log4j-core", version="2.14.1")], source="github")
    upsert_components(session, target_id=t2.id, branch="main", discovered=[_comp(name="log4j-core", version="2.14.1")], source="github")

    ordered, summary, targets, targets_by_id = _aggregate_org_components(session)

    assert len(ordered) == 1
    group = ordered[0]
    assert group["name"] == "log4j-core"
    assert group["version"] == "2.14.1"
    assert sorted(group["target_ids"]) == sorted([t1.id, t2.id])
    assert summary["unique_component_count"] == 1
    assert summary["targets_with_sbom_count"] == 2
    assert summary["total_targets_count"] == 2
    assert len(targets) == 2
    assert targets_by_id[t1.id].name == "repo-a"


def test_org_aggregation_keeps_different_versions_as_separate_rows(session):
    """Different versions of the same package are a distinct supply-chain
    fact (one repo patched, one didn't) and must not be merged."""
    t1 = _target(session, name="repo-a")
    t2 = _target(session, name="repo-b")
    upsert_components(session, target_id=t1.id, branch="main", discovered=[_comp(name="log4j-core", version="2.14.1")], source="github")
    upsert_components(session, target_id=t2.id, branch="main", discovered=[_comp(name="log4j-core", version="2.17.1")], source="github")

    ordered, summary, _targets, _targets_by_id = _aggregate_org_components(session)

    assert len(ordered) == 2
    versions = {g["version"]: g["target_ids"] for g in ordered}
    assert versions["2.14.1"] == [t1.id]
    assert versions["2.17.1"] == [t2.id]
    assert summary["unique_component_count"] == 2


def test_org_aggregation_counts_targets_without_any_sbom(session):
    """A target that has never been scanned still counts toward
    total_targets_count but not targets_with_sbom_count."""
    t1 = _target(session, name="repo-a")
    _target(session, name="repo-b")  # never scanned
    upsert_components(session, target_id=t1.id, branch="main", discovered=[_comp()], source="github")

    _ordered, summary, _targets, _targets_by_id = _aggregate_org_components(session)

    assert summary["total_targets_count"] == 2
    assert summary["targets_with_sbom_count"] == 1


def test_org_aggregation_only_uses_each_targets_default_branch(session):
    """A component upserted on a non-default branch must not appear in the
    org-wide aggregation -- same 'default branch only' rule as the per-target
    GET/export endpoints."""
    t1 = _target(session, name="repo-a", branch="main")
    upsert_components(session, target_id=t1.id, branch="feature-x", discovered=[_comp()], source="github")

    ordered, summary, _targets, _targets_by_id = _aggregate_org_components(session)

    assert ordered == []
    assert summary["targets_with_sbom_count"] == 0
