"""Test for the one line of real duplication extracted in #222; see
app.core.async_jobs's module docstring for why the rest of the
create-row-then-dispatch pattern was deliberately left alone.
"""
import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

from app.core.async_jobs import create_running_row
from app.models.models import Organization, Target, ToolInstallRun, Workspace


@pytest.fixture()
def engine():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(eng)
    return eng


def test_persists_and_assigns_an_id(engine):
    with Session(engine) as session:
        run = ToolInstallRun(tool="semgrep", package="semgrep", status="running")
        result = create_running_row(session, run)

        assert result is run
        assert result.id is not None
        assert session.get(ToolInstallRun, result.id) is not None


def test_the_returned_row_is_refreshed_from_the_database(engine):
    # Refresh matters when the model has server-side defaults (started_at
    # via default_factory here); the caller must see the persisted values,
    # not just the pre-insert Python object.
    with Session(engine) as session:
        run = ToolInstallRun(tool="semgrep", package="semgrep", status="running")
        result = create_running_row(session, run)
        assert result.started_at is not None


def test_works_with_a_foreign_key_relationship(engine):
    # Scan/DiscoveryRun/SbomRun all carry a target_id; confirm the helper
    # is not accidentally Scan-specific despite being introduced alongside
    # it.
    with Session(engine) as session:
        org = Organization(name="org")
        session.add(org)
        session.commit()
        session.refresh(org)
        ws = Workspace(organization_id=org.id, name="ws", api_key="key")
        session.add(ws)
        session.commit()
        session.refresh(ws)
        target = Target(workspace_id=ws.id, name="t", repo_url="https://github.com/acme/t")
        create_running_row(session, target)
        assert target.id is not None
