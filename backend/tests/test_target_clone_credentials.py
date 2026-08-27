"""Target clone credentials for VPN/client-cert-gated hosts (#298).

Covers the API surface: repo_url host validation honoring EXTRA_CLONE_HOSTS,
the clone-credentials endpoint's encrypt-at-rest / never-echo-back behavior,
and that GET/PATCH responses never leak the raw ciphertext columns.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core import crypto
from app.core.config import settings
from app.core.security import create_session_token, hash_password
from app.main import app as fastapi_app
from app.models.models import Organization, Target, User, UserRole, Workspace


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


@pytest.fixture(autouse=True)
def _reset_extra_clone_hosts():
    original = settings.extra_clone_hosts
    crypto._get_fernet.cache_clear()
    yield
    settings.extra_clone_hosts = original
    crypto._get_fernet.cache_clear()


def _admin(client, engine):
    with Session(engine) as session:
        user = User(email="a@example.com", name="A", password_hash=hash_password("whatever123"),
                    role=UserRole.ADMIN)
        session.add(user)
        session.commit()
        session.refresh(user)
        token = create_session_token(user.id, user.token_version)
    client.cookies.set("toleman_session", token)
    return client


def _target(engine, **kw):
    with Session(engine) as session:
        org = Organization(name="o")
        session.add(org)
        session.commit()
        session.refresh(org)
        ws = Workspace(organization_id=org.id, name="w", api_key="k")
        session.add(ws)
        session.commit()
        session.refresh(ws)
        t = Target(name="t", repo_url="https://github.com/a/b", workspace_id=ws.id, **kw)
        session.add(t)
        session.commit()
        session.refresh(t)
        return t.id


class TestRepoUrlHostValidation:
    def test_non_allowed_host_rejected_on_create(self, client, engine):
        _admin(client, engine)
        with Session(engine) as session:
            org = Organization(name="o")
            session.add(org)
            session.commit()
            session.refresh(org)
            ws = Workspace(organization_id=org.id, name="w", api_key="k")
            session.add(ws)
            session.commit()
            session.refresh(ws)
            wid = ws.id
        res = client.post(
            "/api/targets",
            json={"workspace_id": wid, "name": "t", "repo_url": "https://gitlab.internal.corp/a/b"},
        )
        assert res.status_code == 400

    def test_extra_clone_hosts_allows_creation_against_that_host(self, client, engine):
        settings.extra_clone_hosts = "gitlab.internal.corp"
        _admin(client, engine)
        with Session(engine) as session:
            org = Organization(name="o")
            session.add(org)
            session.commit()
            session.refresh(org)
            ws = Workspace(organization_id=org.id, name="w", api_key="k")
            session.add(ws)
            session.commit()
            session.refresh(ws)
            wid = ws.id
        res = client.post(
            "/api/targets",
            json={"workspace_id": wid, "name": "t", "repo_url": "https://gitlab.internal.corp/a/b"},
        )
        assert res.status_code == 200, res.text
        assert res.json()["repo_url"] == "https://gitlab.internal.corp/a/b"


class TestCloneCredentialsEndpoint:
    def test_setting_a_cert_encrypts_at_rest(self, client, engine):
        _admin(client, engine)
        tid = _target(engine)
        res = client.put(f"/api/targets/{tid}/clone-credentials", json={"client_cert_pem": "fake-cert-pem"})
        assert res.status_code == 200, res.text
        assert res.json() == {"client_cert_set": True, "client_key_set": False}

        with Session(engine) as session:
            t = session.get(Target, tid)
            assert t.client_cert_ciphertext != "fake-cert-pem"
            assert t.client_cert_ciphertext != ""
            assert crypto.decrypt_secret(t.client_cert_ciphertext) == "fake-cert-pem"

    def test_cert_never_echoed_back_by_get_or_patch(self, client, engine):
        _admin(client, engine)
        tid = _target(engine)
        client.put(f"/api/targets/{tid}/clone-credentials", json={"client_cert_pem": "fake-cert-pem"})

        get_res = client.get(f"/api/targets/{tid}")
        assert get_res.status_code == 200
        body = get_res.json()
        assert "client_cert_ciphertext" not in body
        assert "client_key_ciphertext" not in body
        assert "fake-cert-pem" not in get_res.text
        assert body["client_cert_set"] is True
        assert body["client_key_set"] is False

        patch_res = client.patch(f"/api/targets/{tid}", json={"name": "renamed"})
        assert patch_res.status_code == 200
        assert "fake-cert-pem" not in patch_res.text
        assert patch_res.json()["client_cert_set"] is True

    def test_empty_string_clears_a_previously_set_cert(self, client, engine):
        _admin(client, engine)
        tid = _target(engine)
        client.put(f"/api/targets/{tid}/clone-credentials", json={"client_cert_pem": "fake-cert-pem"})
        res = client.put(f"/api/targets/{tid}/clone-credentials", json={"client_cert_pem": ""})
        assert res.status_code == 200
        assert res.json() == {"client_cert_set": False, "client_key_set": False}

    def test_omitting_a_field_leaves_it_untouched(self, client, engine):
        _admin(client, engine)
        tid = _target(engine)
        client.put(f"/api/targets/{tid}/clone-credentials", json={"client_cert_pem": "cert", "client_key_pem": "key"})
        res = client.put(f"/api/targets/{tid}/clone-credentials", json={"client_cert_pem": "new-cert"})
        assert res.status_code == 200
        assert res.json() == {"client_cert_set": True, "client_key_set": True}
        with Session(engine) as session:
            t = session.get(Target, tid)
            assert crypto.decrypt_secret(t.client_cert_ciphertext) == "new-cert"
            assert crypto.decrypt_secret(t.client_key_ciphertext) == "key"


class TestCloneProxyUrl:
    def test_settable_via_patch(self, client, engine):
        _admin(client, engine)
        tid = _target(engine)
        res = client.patch(
            f"/api/targets/{tid}", json={"clone_proxy_url": "http://vpn-gateway.internal.corp:3128"}
        )
        assert res.status_code == 200, res.text
        assert res.json()["clone_proxy_url"] == "http://vpn-gateway.internal.corp:3128"

    def test_null_clears_it(self, client, engine):
        _admin(client, engine)
        tid = _target(engine, clone_proxy_url="http://vpn-gateway.internal.corp:3128")
        res = client.patch(f"/api/targets/{tid}", json={"clone_proxy_url": None})
        assert res.status_code == 200
        assert res.json()["clone_proxy_url"] == ""
