import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

from app.api.discovery import upsert_endpoints
from app.models.models import ApiEndpoint


@pytest.fixture()
def session():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(eng)
    with Session(eng) as s:
        yield s


def _ep(method="GET", route="/health", file="app.py", line=10, framework="fastapi"):
    return {"framework": framework, "method": method, "route": route, "file": file, "line": line}


def test_first_run_all_endpoints_are_new(session):
    new = upsert_endpoints(session, target_id=1, branch="main", discovered=[_ep(), _ep(route="/users")])
    assert len(new) == 2

    all_rows = session.exec(select(ApiEndpoint)).all()
    assert len(all_rows) == 2


def test_second_run_same_endpoints_are_not_new(session):
    upsert_endpoints(session, target_id=1, branch="main", discovered=[_ep()])
    new = upsert_endpoints(session, target_id=1, branch="main", discovered=[_ep()])
    assert new == []

    all_rows = session.exec(select(ApiEndpoint)).all()
    assert len(all_rows) == 1  # updated in place, not duplicated


def test_second_run_with_an_added_endpoint_only_reports_the_addition(session):
    upsert_endpoints(session, target_id=1, branch="main", discovered=[_ep()])
    new = upsert_endpoints(session, target_id=1, branch="main", discovered=[_ep(), _ep(route="/new-thing")])

    assert len(new) == 1
    assert new[0].route == "/new-thing"


def test_last_seen_updates_on_rescan(session):
    upsert_endpoints(session, target_id=1, branch="main", discovered=[_ep()])
    row = session.exec(select(ApiEndpoint)).one()
    first_seen = row.first_seen
    last_seen_1 = row.last_seen

    upsert_endpoints(session, target_id=1, branch="main", discovered=[_ep()])
    session.refresh(row)
    assert row.first_seen == first_seen  # unchanged
    assert row.last_seen >= last_seen_1


def test_different_branches_are_independent(session):
    upsert_endpoints(session, target_id=1, branch="main", discovered=[_ep()])
    new_on_feature_branch = upsert_endpoints(session, target_id=1, branch="feature-x", discovered=[_ep()])

    assert len(new_on_feature_branch) == 1  # same route, different branch -> still new
