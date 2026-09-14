"""Scope control for active API scanning (#469).

Active scanning sends real traffic at a real deployed host. Before this,
the only narrowing available was `endpoint_ids` on a single request --
an opt-in selection, not a standing rule -- so a scheduled scan, or any
caller that omitted it, went back to hitting every endpoint discovery had
ever found, including destructive ones.

Two rules are pinned here, and the interaction between them matters more
than either alone:

  - `excluded` is absolute. It outranks an explicit selection, because it
    represents an operator saying "never touch this route", and a UI that
    lets someone re-tick a checkbox must not be able to undo that.
  - a destructive verb is skipped by default but scannable when the
    endpoint is named explicitly, because naming one endpoint by id is
    already the deliberate act. If these were the same rule, either you
    could never scan a DELETE at all, or a whole-target scan would fire
    one nobody asked for.

Follows the in-memory SQLite + TestClient pattern from
tests/test_api_scan.py.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core.api_scan_targets import build_scan_urls
from app.core.discovery_ingestion import upsert_endpoints
from app.core.security import create_session_token, hash_password
from app.main import app
from app.models.models import (
    ApiEndpoint,
    Organization,
    Target,
    User,
    UserRole,
    Workspace,
    WorkspaceMembership,
    WorkspaceRole,
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
    original_engine = deps_module.engine
    deps_module.engine = engine
    c = TestClient(app)
    yield c
    app.dependency_overrides.clear()
    deps_module.engine = original_engine


def _make_target(engine, api_base_url="https://api.example.com"):
    with Session(engine) as session:
        org = Organization(name="Acme")
        session.add(org)
        session.commit()
        session.refresh(org)
        ws = Workspace(organization_id=org.id, name="ws", api_key="k")
        session.add(ws)
        session.commit()
        session.refresh(ws)
        t = Target(
            workspace_id=ws.id,
            name="t",
            repo_url="https://github.com/acme/app",
            api_base_url=api_base_url,
        )
        session.add(t)
        session.commit()
        session.refresh(t)
        return t.id, ws.id


def _add_endpoint(engine, target_id, route, method="GET", excluded=False, reason=None):
    with Session(engine) as session:
        target = session.get(Target, target_id)
        e = ApiEndpoint(
            target_id=target_id,
            branch=target.default_branch,
            framework="fastapi",
            method=method,
            route=route,
            file_path="main.py",
            line=1,
            excluded=excluded,
            exclusion_reason=reason,
        )
        session.add(e)
        session.commit()
        session.refresh(e)
        return e.id


def _login_developer(client, engine, workspace_id):
    with Session(engine) as session:
        user = User(
            email=f"dev-{id(object())}@example.com",
            name="Dev",
            password_hash=hash_password("whatever123"),
            role=UserRole.DEVELOPER,
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        session.add(
            WorkspaceMembership(
                user_id=user.id, workspace_id=workspace_id, role=WorkspaceRole.DEVELOPER
            )
        )
        session.commit()
        token = create_session_token(user.id, user.token_version)
    client.cookies.set("toleman_session", token)
    return client


def _scope(engine, target_id, endpoint_ids=None):
    with Session(engine) as session:
        return build_scan_urls(session, session.get(Target, target_id), endpoint_ids)


def test_excluded_endpoint_is_not_scanned(engine):
    target_id, _ = _make_target(engine)
    _add_endpoint(engine, target_id, "/safe")
    _add_endpoint(engine, target_id, "/wipe", excluded=True, reason="resets the staging tenant")

    scope = _scope(engine, target_id)

    assert scope.urls == ["https://api.example.com/safe"]
    assert [s.endpoint.route for s in scope.skipped] == ["/wipe"]
    assert "resets the staging tenant" in scope.skipped[0].reason


def test_exclusion_beats_an_explicit_selection(engine):
    """The one interaction worth being loud about: selecting an excluded
    endpoint by id must not scan it. Otherwise any UI that lets a user
    re-tick a row silently defeats the standing decision."""
    target_id, _ = _make_target(engine)
    excluded_id = _add_endpoint(engine, target_id, "/wipe", excluded=True, reason="destroys data")

    scope = _scope(engine, target_id, endpoint_ids=[excluded_id])

    assert scope.urls == []
    assert len(scope.skipped) == 1


def test_destructive_verb_is_skipped_on_a_whole_target_scan(engine):
    target_id, _ = _make_target(engine)
    _add_endpoint(engine, target_id, "/users/{id}", method="GET")
    _add_endpoint(engine, target_id, "/users/{id}", method="DELETE")

    scope = _scope(engine, target_id)

    assert scope.urls == ["https://api.example.com/users/{id}"]
    assert [s.endpoint.method for s in scope.skipped] == ["DELETE"]
    assert "selected explicitly" in scope.skipped[0].reason


def test_destructive_verb_is_scanned_when_named_explicitly(engine):
    target_id, _ = _make_target(engine)
    delete_id = _add_endpoint(engine, target_id, "/users/{id}", method="DELETE")

    scope = _scope(engine, target_id, endpoint_ids=[delete_id])

    assert scope.urls == ["https://api.example.com/users/{id}"]
    assert scope.skipped == []


def test_a_flask_multi_method_route_containing_delete_is_treated_as_destructive(engine):
    """discovery.py stores flask's `methods=[...]` as one comma-joined
    string, so a naive equality check against "DELETE" would never fire."""
    target_id, _ = _make_target(engine)
    _add_endpoint(engine, target_id, "/thing", method="GET, DELETE")

    scope = _scope(engine, target_id)

    assert scope.urls == []
    assert len(scope.skipped) == 1


def test_non_destructive_verbs_are_still_scanned_by_default(engine):
    """PUT/PATCH/POST modify rather than destroy, and POST is how most APIs
    express logins and searches. Defaulting them off would switch active
    scanning off for most real targets."""
    target_id, _ = _make_target(engine)
    for method in ("GET", "POST", "PUT", "PATCH", "HEAD", "OPTIONS", "-"):
        _add_endpoint(engine, target_id, f"/r-{method}", method=method)

    scope = _scope(engine, target_id)

    assert len(scope.urls) == 7
    assert scope.skipped == []


def test_rediscovery_does_not_reset_an_exclusion(engine):
    """The decision has to outlive the next discovery run, or it is not a
    scope rule -- it is a setting that quietly expires."""
    target_id, _ = _make_target(engine)
    endpoint_id = _add_endpoint(engine, target_id, "/wipe", method="POST", excluded=True, reason="destructive")

    with Session(engine) as session:
        target = session.get(Target, target_id)
        upsert_endpoints(
            session,
            target_id,
            target.default_branch,
            [{"framework": "fastapi", "method": "POST", "route": "/wipe", "file": "main.py", "line": 2}],
        )

    with Session(engine) as session:
        refreshed = session.get(ApiEndpoint, endpoint_id)
        assert refreshed.excluded is True
        assert refreshed.exclusion_reason == "destructive"
        assert refreshed.line == 2, "the upsert should still have refreshed the ordinary fields"


def test_scope_can_be_set_through_the_api(client, engine):
    target_id, workspace_id = _make_target(engine)
    endpoint_id = _add_endpoint(engine, target_id, "/wipe")
    client = _login_developer(client, engine, workspace_id)

    res = client.patch(
        f"/api/discovery/{target_id}/endpoints/{endpoint_id}",
        json={"excluded": True, "reason": "bills per call"},
    )

    assert res.status_code == 200
    assert res.json()["excluded"] is True
    assert _scope(engine, target_id).urls == []


def test_bringing_an_endpoint_back_into_scope_clears_the_stale_reason(client, engine):
    target_id, workspace_id = _make_target(engine)
    endpoint_id = _add_endpoint(engine, target_id, "/wipe", excluded=True, reason="was destructive")
    client = _login_developer(client, engine, workspace_id)

    res = client.patch(
        f"/api/discovery/{target_id}/endpoints/{endpoint_id}", json={"excluded": False}
    )

    assert res.status_code == 200
    assert res.json()["exclusion_reason"] is None
    assert _scope(engine, target_id).urls == ["https://api.example.com/wipe"]


def test_an_endpoint_from_another_target_cannot_be_rescoped(client, engine):
    target_id, workspace_id = _make_target(engine)
    other_target_id, _ = _make_target(engine)
    foreign_id = _add_endpoint(engine, other_target_id, "/other-teams-route")
    client = _login_developer(client, engine, workspace_id)

    res = client.patch(
        f"/api/discovery/{target_id}/endpoints/{foreign_id}", json={"excluded": True}
    )

    assert res.status_code == 404


def test_setting_scope_requires_more_than_being_logged_in(client, engine):
    """Same bar as triggering the scan: this decides whether real traffic
    reaches a real route, so it is not a display preference."""
    target_id, _workspace_id = _make_target(engine)
    endpoint_id = _add_endpoint(engine, target_id, "/wipe")
    other_workspace_target, other_workspace_id = _make_target(engine)
    client = _login_developer(client, engine, other_workspace_id)

    res = client.patch(
        f"/api/discovery/{target_id}/endpoints/{endpoint_id}", json={"excluded": True}
    )

    assert res.status_code == 403
