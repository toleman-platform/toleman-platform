"""Tests for issue #227's two SBOM import paths, which sit alongside
Generate SBOM rather than replacing it:

  - POST /api/sbom/{id}/github-sync -- pull the target's dependency inventory
    from GitHub's Dependency Graph SBOM API without a trivy scan.
  - POST /api/sbom/{id}/upload -- import an uploaded CycloneDX/SPDX JSON
    document as multipart form data.

Both merge into the persisted SbomComponent inventory via upsert_components
and report count/new_count. Follows the same in-memory SQLite + TestClient +
session-token-login pattern as tests/test_celery_offload.py, which is also the
source of the WorkspaceMembership setup the DEVELOPER-role routes need.
"""
import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

import app.api.deps as deps_module
import app.api.sbom as sbom_module
from app.api.deps import get_session
from app.core.github_dependency_graph import DependencyGraphUnavailable
from app.core.security import create_session_token, hash_password
from app.main import app
from app.models.models import (
    Organization,
    SbomComponent,
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


def _dev_client_with_target(client, engine) -> tuple[TestClient, int]:
    with Session(engine) as session:
        org = Organization(name="org-sbom-import")
        session.add(org)
        session.commit()
        session.refresh(org)
        ws = Workspace(organization_id=org.id, name="ws-sbom-import", api_key="key-sbom-import")
        session.add(ws)
        session.commit()
        session.refresh(ws)
        target = Target(
            workspace_id=ws.id,
            name="repo-a",
            repo_url="https://github.com/acme/repo-a",
            default_branch="main",
        )
        session.add(target)
        session.commit()
        session.refresh(target)
        target_id = target.id

        user = User(
            email=f"dev-{id(object())}@example.com",
            name="Test",
            password_hash=hash_password("whatever123"),
            role=UserRole.DEVELOPER,
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        session.add(WorkspaceMembership(user_id=user.id, workspace_id=ws.id, role=WorkspaceRole.DEVELOPER))
        session.commit()
        token = create_session_token(user.id, user.token_version)

    client.cookies.set("rikugan_session", token)
    return client, target_id


def _seed_component(engine, target_id: int, name: str, version: str, package_type: str, purl: str):
    with Session(engine) as session:
        session.add(
            SbomComponent(
                target_id=target_id, branch="main", name=name, version=version,
                package_type=package_type, purl=purl,
            )
        )
        session.commit()


# --- github-sync -----------------------------------------------------------


def test_github_sync_merges_components_and_reports_new_count(client, engine, monkeypatch):
    client, target_id = _dev_client_with_target(client, engine)
    _seed_component(engine, target_id, "requests", "2.31.0", "pip", "pkg:pypi/requests@2.31.0")

    monkeypatch.setattr(sbom_module, "resolve_github_token", lambda session, workspace_id, slug: "tok")
    monkeypatch.setattr(
        sbom_module,
        "fetch_dependency_graph",
        lambda repo_url, token: [
            {"name": "requests", "version": "2.31.0", "package_type": "pip", "purl": "pkg:pypi/requests@2.31.0"},
            {"name": "anthropic", "version": "0.121.0", "package_type": "pip", "purl": "pkg:pypi/anthropic@0.121.0"},
        ],
    )

    res = client.post(f"/api/sbom/{target_id}/github-sync")
    assert res.status_code == 200
    body = res.json()
    assert body["target_id"] == target_id
    assert body["count"] == 2
    assert body["new_count"] == 1

    names = {c["name"] for c in client.get(f"/api/sbom/{target_id}").json()["components"]}
    assert names == {"requests", "anthropic"}


def test_github_sync_returns_502_when_dependency_graph_unavailable(client, engine, monkeypatch):
    client, target_id = _dev_client_with_target(client, engine)
    monkeypatch.setattr(sbom_module, "resolve_github_token", lambda session, workspace_id, slug: None)

    def _raise(repo_url, token):
        raise DependencyGraphUnavailable("dependency graph disabled")

    monkeypatch.setattr(sbom_module, "fetch_dependency_graph", _raise)

    res = client.post(f"/api/sbom/{target_id}/github-sync")
    assert res.status_code == 502


def test_github_sync_unknown_target_is_404(client, engine):
    client, _target_id = _dev_client_with_target(client, engine)
    res = client.post("/api/sbom/999999/github-sync")
    assert res.status_code == 404


# --- upload ----------------------------------------------------------------


def test_upload_cyclonedx_merges_components(client, engine):
    client, target_id = _dev_client_with_target(client, engine)
    doc = {
        "bomFormat": "CycloneDX",
        "components": [
            {"type": "library", "name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"},
            {"type": "library", "name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"},
        ],
    }

    res = client.post(
        f"/api/sbom/{target_id}/upload",
        files={"file": ("sbom.json", json.dumps(doc).encode(), "application/json")},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["count"] == 2
    assert body["new_count"] == 2

    names = {c["name"] for c in client.get(f"/api/sbom/{target_id}").json()["components"]}
    assert names == {"requests", "lodash"}


def test_upload_spdx_json_merges_components(client, engine):
    client, target_id = _dev_client_with_target(client, engine)
    doc = {
        "spdxVersion": "SPDX-2.3",
        "packages": [
            {
                "SPDXID": "SPDXRef-Package-1",
                "name": "anthropic",
                "versionInfo": "0.121.0",
                "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:pypi/anthropic@0.121.0"}],
            },
        ],
    }

    res = client.post(
        f"/api/sbom/{target_id}/upload",
        files={"file": ("sbom.spdx.json", json.dumps(doc).encode(), "application/json")},
    )
    assert res.status_code == 200
    assert res.json()["new_count"] == 1


def test_upload_invalid_json_returns_400(client, engine):
    client, target_id = _dev_client_with_target(client, engine)

    res = client.post(
        f"/api/sbom/{target_id}/upload",
        files={"file": ("sbom.json", b"not json", "application/json")},
    )
    assert res.status_code == 400


def test_upload_document_with_no_components_returns_400(client, engine):
    client, target_id = _dev_client_with_target(client, engine)

    res = client.post(
        f"/api/sbom/{target_id}/upload",
        files={"file": ("sbom.json", json.dumps({"some": "thing"}).encode(), "application/json")},
    )
    assert res.status_code == 400


def test_upload_unknown_target_is_404(client, engine):
    client, _target_id = _dev_client_with_target(client, engine)

    res = client.post(
        "/api/sbom/999999/upload",
        files={"file": ("sbom.json", json.dumps({"components": []}).encode(), "application/json")},
    )
    assert res.status_code == 404
