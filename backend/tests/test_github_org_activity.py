"""Tests for GET /api/github/org-activity (issue #123: repo filter + real
pagination on GitHub Org Logs). The GitHub API boundary is mocked the same
way tests/test_enforcement_mode.py mocks it -- monkeypatch the github_get
symbol imported into app.api.github, no real network calls.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

import app.api.deps as deps_module
import app.api.github as github_module
from app.api.deps import get_session
from app.core.security import create_session_token, hash_password
from app.main import app
from app.models.models import Organization, Target, User, Workspace


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


def _login(client, engine, email="user@example.com", password="whatever123"):
    with Session(engine) as session:
        user = User(email=email, name="Test User", password_hash=hash_password(password))
        session.add(user)
        session.commit()
        session.refresh(user)
        token = create_session_token(user.id)
    client.cookies.set("rikugan_session", token)
    return client


def _make_target(engine, name="repo-a") -> int:
    with Session(engine) as session:
        org = Organization(name="Org")
        session.add(org)
        session.commit()
        session.refresh(org)

        workspace = Workspace(organization_id=org.id, name="WS", api_key=f"key-{name}")
        session.add(workspace)
        session.commit()
        session.refresh(workspace)

        target = Target(workspace_id=workspace.id, name=name, repo_url=f"https://github.com/acme/{name}.git")
        session.add(target)
        session.commit()
        session.refresh(target)
        return target.id


class _FakeResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload

    @property
    def text(self):
        return str(self._payload)


def _commit(sha, message, author="Dev One", date="2026-08-10T00:00:00Z"):
    return {
        "sha": sha,
        "commit": {"message": message, "author": {"name": author, "date": date}},
        "html_url": f"https://github.com/acme/repo/commit/{sha}",
    }


def test_org_activity_filters_by_repo(client, engine, monkeypatch):
    _login(client, engine)
    target_a = _make_target(engine, "repo-a")
    target_b = _make_target(engine, "repo-b")

    def fake_github_get(path, params=None, **kwargs):
        if "repo-a" in path:
            return _FakeResponse(200, [_commit("aaa1111", "fix in repo a")])
        return _FakeResponse(200, [_commit("bbb2222", "fix in repo b")])

    monkeypatch.setattr(github_module, "github_get", fake_github_get)

    resp = client.get("/api/github/org-activity", params={"target_id": target_a})
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["message"] == "fix in repo a"
    assert body["items"][0]["target_id"] == target_a


def test_org_activity_paginates_combined_results(client, engine, monkeypatch):
    _login(client, engine)
    target_id = _make_target(engine, "repo-a")

    commits = [_commit(f"sha{i:03d}", f"commit {i}", date=f"2026-08-{10 + i:02d}T00:00:00Z") for i in range(15)]

    def fake_github_get(path, params=None, **kwargs):
        return _FakeResponse(200, commits)

    monkeypatch.setattr(github_module, "github_get", fake_github_get)

    resp = client.get("/api/github/org-activity", params={"target_id": target_id, "page": 1, "page_size": 10})
    body = resp.json()
    assert body["total"] == 15
    assert len(body["items"]) == 10

    resp2 = client.get("/api/github/org-activity", params={"target_id": target_id, "page": 2, "page_size": 10})
    body2 = resp2.json()
    assert len(body2["items"]) == 5


def test_org_activity_passes_date_range_to_github(client, engine, monkeypatch):
    _login(client, engine)
    target_id = _make_target(engine, "repo-a")
    captured = {}

    def fake_github_get(path, params=None, **kwargs):
        captured["params"] = params
        return _FakeResponse(200, [])

    monkeypatch.setattr(github_module, "github_get", fake_github_get)

    client.get(
        "/api/github/org-activity",
        params={"target_id": target_id, "date_from": "2026-08-01", "date_to": "2026-08-10"},
    )
    assert captured["params"]["since"] == "2026-08-01T00:00:00Z"
    assert captured["params"]["until"] == "2026-08-10T23:59:59Z"


def test_org_activity_skips_repos_github_errors_on(client, engine, monkeypatch):
    _login(client, engine)
    target_a = _make_target(engine, "repo-a")
    _make_target(engine, "repo-b")

    def fake_github_get(path, params=None, **kwargs):
        if "repo-a" in path:
            return _FakeResponse(200, [_commit("aaa1111", "fix in repo a")])
        return _FakeResponse(404, {"message": "not found"})

    monkeypatch.setattr(github_module, "github_get", fake_github_get)

    resp = client.get("/api/github/org-activity")
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["target_id"] == target_a
