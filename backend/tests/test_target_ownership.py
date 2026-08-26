"""Target ownership metadata (#251): owner, environment, lifecycle.

`criticality_weight` already multiplies every finding's priority_score, but
nothing recorded *why* a target is critical; so the number was an assertion
nobody could audit or argue with. These three fields make it explainable, and
give the findings list the facets people actually filter by.

Two properties worth pinning, both about not inventing data:

* NULL means "not recorded" and stays distinct from any value an operator
  sets. No backfill guesses "production" for existing targets.
* The facet endpoints drop nulls rather than offering an "unrecorded" bucket,
  and are workspace-scoped like every other list endpoint (#57); an owner
  name is org-structure information and must not leak across tenants.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

import app.api.deps as deps_module
from app.api.deps import get_session
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


class TestDefaults:
    def test_unrecorded_is_null_not_a_guess(self, engine):
        """No backfill invents "production" for a target nobody labelled."""
        tid = _target(engine)
        with Session(engine) as session:
            t = session.get(Target, tid)
            assert t.owner is None
            assert t.environment is None
            assert t.lifecycle is None


class TestUpdate:
    def test_fields_are_settable(self, client, engine):
        _admin(client, engine)
        tid = _target(engine)
        res = client.patch(
            f"/api/targets/{tid}",
            json={"owner": "platform-team", "environment": "production", "lifecycle": "active"},
        )
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["owner"] == "platform-team"
        assert body["environment"] == "production"
        assert body["lifecycle"] == "active"

    def test_null_clears_a_field(self, client, engine):
        """"Not recorded" is a real state an operator can return to."""
        _admin(client, engine)
        tid = _target(engine, environment="production")
        res = client.patch(f"/api/targets/{tid}", json={"environment": None})
        assert res.status_code == 200
        assert res.json()["environment"] is None

    def test_omitting_a_field_leaves_it_untouched(self, client, engine):
        _admin(client, engine)
        tid = _target(engine, owner="platform-team", environment="production")
        res = client.patch(f"/api/targets/{tid}", json={"name": "renamed"})
        assert res.status_code == 200
        assert res.json()["owner"] == "platform-team"
        assert res.json()["environment"] == "production"

    def test_free_text_is_accepted(self, client, engine):
        """No enum: orgs name environments differently, and rejecting "live"
        because we guessed "production" would be us imposing a vocabulary."""
        _admin(client, engine)
        tid = _target(engine)
        res = client.patch(f"/api/targets/{tid}", json={"environment": "live-eu-west"})
        assert res.status_code == 200
        assert res.json()["environment"] == "live-eu-west"


class TestFacets:
    def test_environments_facet_lists_distinct_values(self, client, engine):
        _admin(client, engine)
        _target(engine, environment="production")
        _target(engine, environment="staging")
        _target(engine, environment="production")
        res = client.get("/api/findings/facets/environments")
        assert res.status_code == 200
        assert res.json() == ["production", "staging"]

    def test_unrecorded_targets_are_not_offered_as_a_bucket(self, client, engine):
        _admin(client, engine)
        _target(engine, environment="production")
        _target(engine)  # no environment
        assert res_json(client, "/api/findings/facets/environments") == ["production"]

    def test_empty_strings_are_not_offered(self, client, engine):
        _admin(client, engine)
        _target(engine, environment="")
        _target(engine, environment="production")
        assert res_json(client, "/api/findings/facets/environments") == ["production"]

    def test_owners_facet(self, client, engine):
        _admin(client, engine)
        _target(engine, owner="platform-team")
        _target(engine, owner="data-team")
        assert res_json(client, "/api/findings/facets/owners") == ["data-team", "platform-team"]


class TestFindingsFilter:
    def test_filtering_by_environment_is_accepted(self, client, engine):
        _admin(client, engine)
        _target(engine, environment="production")
        assert client.get("/api/findings?environment=production").status_code == 200

    def test_filtering_by_owner_is_accepted(self, client, engine):
        _admin(client, engine)
        _target(engine, owner="platform-team")
        assert client.get("/api/findings?owner=platform-team").status_code == 200

    def test_both_filters_compose(self, client, engine):
        _admin(client, engine)
        _target(engine, owner="platform-team", environment="production")
        res = client.get("/api/findings?owner=platform-team&environment=production")
        assert res.status_code == 200

    def test_composes_with_the_existing_search_join(self, client, engine):
        """Both paths join Target. Joining twice raises, so this asserts the
        target_joined guard actually holds."""
        _admin(client, engine)
        _target(engine, environment="production")
        res = client.get("/api/findings?environment=production&search=anything")
        assert res.status_code == 200


def res_json(client, url):
    r = client.get(url)
    assert r.status_code == 200, r.text
    return r.json()
