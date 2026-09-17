"""Tests for the PATCH /api/targets/{id} auto_raise_fix_prs field (#247
follow-up): the per-target opt-in the Fix Plan auto-raise sweep reads.

`auto_raise_fix_prs` is a plain NOT NULL boolean column (see Target's own
comment), same shape as the pre-existing diff_scoped_pr_scans, so an
explicit `null` in the request body must 422 (UpdateTargetRequest's
_check_auto_raise_fix_prs validator) rather than reach the ORM and 500 --
that's the one thing this field's own validator exists to catch, and it's
easy to accidentally skip when adding a boolean field's validator by hand.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core.security import create_session_token, hash_password
from app.main import app as fastapi_app
from app.models.models import Organization, Target, User, UserRole, Workspace, WorkspaceMembership, WorkspaceRole


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


def _dev_client_with_target(client, engine) -> int:
    with Session(engine) as session:
        org = Organization(name="org")
        session.add(org)
        session.commit()
        session.refresh(org)
        ws = Workspace(organization_id=org.id, name="ws", api_key="key")
        session.add(ws)
        session.commit()
        session.refresh(ws)
        t = Target(workspace_id=ws.id, name="t", repo_url="https://github.com/a/t")
        session.add(t)
        session.commit()
        session.refresh(t)
        target_id = t.id
        workspace_id = ws.id

        user = User(email="dev@e.com", name="D", password_hash=hash_password("whatever123"), role=UserRole.USER)
        session.add(user)
        session.commit()
        session.refresh(user)
        session.add(WorkspaceMembership(user_id=user.id, workspace_id=workspace_id, role=WorkspaceRole.DEVELOPER))
        session.commit()
        token = create_session_token(user.id, user.token_version)
    client.cookies.set("toleman_session", token)
    return target_id


def test_defaults_to_false(engine):
    assert Target.model_fields["auto_raise_fix_prs"].default is False


def test_can_be_turned_on_and_off(client, engine):
    target_id = _dev_client_with_target(client, engine)

    on = client.patch(f"/api/targets/{target_id}", json={"auto_raise_fix_prs": True})
    assert on.status_code == 200, on.text
    assert on.json()["auto_raise_fix_prs"] is True

    off = client.patch(f"/api/targets/{target_id}", json={"auto_raise_fix_prs": False})
    assert off.status_code == 200, off.text
    assert off.json()["auto_raise_fix_prs"] is False


def test_rejects_explicit_null_with_422_not_500(client, engine):
    target_id = _dev_client_with_target(client, engine)
    res = client.patch(f"/api/targets/{target_id}", json={"auto_raise_fix_prs": None})
    assert res.status_code == 422


def test_omitting_the_field_leaves_it_unchanged(client, engine):
    target_id = _dev_client_with_target(client, engine)
    client.patch(f"/api/targets/{target_id}", json={"auto_raise_fix_prs": True})

    res = client.patch(f"/api/targets/{target_id}", json={"name": "renamed"})
    assert res.status_code == 200, res.text
    assert res.json()["auto_raise_fix_prs"] is True
