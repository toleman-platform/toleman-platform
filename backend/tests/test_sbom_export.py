"""Tests for issue #121's SBOM export-format parity: SBOM used to only ever
produce CycloneDX JSON while Reports offered CSV+PDF. GET /api/sbom/{id}/export
now accepts format=cyclonedx-json|spdx-json|csv|pdf, all built from the same
real persisted SbomComponent rows (no mocked content, matching every other
export in the app; see reports.py/render_csv/render_pdf for the identical
pattern this mirrors).

Follows the same in-memory SQLite + TestClient + session-token-login pattern
used in tests/test_pr_guardrail_ignore.py / tests/test_workspace_roles.py.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core.security import create_session_token, hash_password
from app.main import app
from app.models.models import SbomComponent, Target, User, UserRole


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


def _login(client, engine, role=UserRole.USER, email=None):
    email = email or f"{role.value}@example.com"
    with Session(engine) as session:
        user = User(email=email, name="Test", password_hash=hash_password("whatever123"), role=role)
        session.add(user)
        session.commit()
        session.refresh(user)
        token = create_session_token(user.id, user.token_version)
    client.cookies.set("toleman_session", token)
    return client


def _target_with_components(engine) -> int:
    with Session(engine) as session:
        target = Target(workspace_id=1, name="repo-a", repo_url="https://github.com/acme/repo-a", default_branch="main")
        session.add(target)
        session.commit()
        session.refresh(target)

        session.add(
            SbomComponent(
                target_id=target.id, branch="main", name="requests", version="2.31.0",
                package_type="pip", purl="pkg:pypi/requests@2.31.0",
            )
        )
        session.add(
            SbomComponent(
                target_id=target.id, branch="main", name="lodash", version="4.17.21",
                package_type="npm", purl="pkg:npm/lodash@4.17.21",
            )
        )
        session.commit()
        return target.id


def test_export_default_is_cyclonedx_json(client, engine):
    _login(client, engine)
    target_id = _target_with_components(engine)

    res = client.get(f"/api/sbom/{target_id}/export")
    assert res.status_code == 200
    body = res.json()
    assert body["bomFormat"] == "CycloneDX"
    assert body["specVersion"] == "1.5"
    assert {c["name"] for c in body["components"]} == {"requests", "lodash"}
    assert res.headers["content-disposition"].endswith('.json"')


def test_export_cyclonedx_json_explicit(client, engine):
    _login(client, engine)
    target_id = _target_with_components(engine)

    res = client.get(f"/api/sbom/{target_id}/export", params={"format": "cyclonedx-json"})
    assert res.status_code == 200
    assert res.json()["bomFormat"] == "CycloneDX"


def test_export_spdx_json_is_valid_spdx_shape(client, engine):
    _login(client, engine)
    target_id = _target_with_components(engine)

    res = client.get(f"/api/sbom/{target_id}/export", params={"format": "spdx-json"})
    assert res.status_code == 200
    body = res.json()
    assert body["spdxVersion"] == "SPDX-2.3"
    assert body["SPDXID"] == "SPDXRef-DOCUMENT"
    assert len(body["packages"]) == 2
    names = {p["name"] for p in body["packages"]}
    assert names == {"requests", "lodash"}
    # every package SPDXID must be a real SPDX reference id (letters/digits/./- only)
    for pkg in body["packages"]:
        assert pkg["SPDXID"].startswith("SPDXRef-Package-")
        assert all(ch.isalnum() or ch in ".-" for ch in pkg["SPDXID"].removeprefix("SPDXRef-"))
    # relationships tie every package back to the document root
    assert len(body["relationships"]) == 2
    for rel in body["relationships"]:
        assert rel["spdxElementId"] == "SPDXRef-DOCUMENT"
        assert rel["relationshipType"] == "DESCRIBES"
    assert res.headers["content-disposition"].endswith('.spdx.json"')


def test_export_csv_contains_component_rows(client, engine):
    _login(client, engine)
    target_id = _target_with_components(engine)

    res = client.get(f"/api/sbom/{target_id}/export", params={"format": "csv"})
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("text/csv")
    text = res.text
    assert "requests" in text
    assert "2.31.0" in text
    assert "lodash" in text
    assert res.headers["content-disposition"].endswith('.csv"')


def test_export_pdf_returns_pdf_bytes(client, engine):
    _login(client, engine)
    target_id = _target_with_components(engine)

    res = client.get(f"/api/sbom/{target_id}/export", params={"format": "pdf"})
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/pdf"
    assert res.content.startswith(b"%PDF")
    assert res.headers["content-disposition"].endswith('.pdf"')


def test_export_pdf_with_no_components_does_not_error(client, engine):
    _login(client, engine)
    with Session(engine) as session:
        target = Target(workspace_id=1, name="empty-repo", repo_url="https://github.com/acme/empty-repo", default_branch="main")
        session.add(target)
        session.commit()
        session.refresh(target)
        target_id = target.id

    res = client.get(f"/api/sbom/{target_id}/export", params={"format": "pdf"})
    assert res.status_code == 200
    assert res.content.startswith(b"%PDF")


def test_export_invalid_format_is_422(client, engine):
    _login(client, engine)
    target_id = _target_with_components(engine)

    res = client.get(f"/api/sbom/{target_id}/export", params={"format": "yaml"})
    assert res.status_code == 422


def test_export_unknown_target_is_404(client, engine):
    _login(client, engine)
    res = client.get("/api/sbom/999999/export", params={"format": "csv"})
    assert res.status_code == 404
