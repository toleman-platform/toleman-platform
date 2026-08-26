"""Tests for finding BLD-01: an instance must be able to say which instance
it is.

An external evaluator built a fresh stack with `--no-cache --pull` while a
previously-running host-native instance still held :3000/:8000. The browser
resolved localhost to the old process, so the "fresh" install showed 1,434
findings and 35 targets while the new container database held zero. Nothing
in the product flagged it; it was only caught by querying Postgres directly.

GET /health now carries build identity and the database it is talking to, so
that mismatch is visible before an hour goes into reviewing the wrong stack.
"""

from fastapi.testclient import TestClient

import app.main as main_module
from app.core.config import Settings
from app.main import _database_identity, app


def _client() -> TestClient:
    # No startup event: this endpoint must answer without a database, since
    # container healthchecks call it while the stack is still coming up.
    return TestClient(app)


def test_health_reports_build_identity():
    res = _client().get("/health")
    assert res.status_code == 200
    body = res.json()

    assert body["status"] == "ok"
    for field in ("version", "commit", "database"):
        assert field in body, f"/health must carry {field}; see BLD-01"


def test_health_needs_no_session():
    """Container healthchecks curl this with no cookie, and an evaluator has
    to be able to check which instance answers *before* logging in; which
    is exactly the moment the wrong-instance confusion happens."""
    assert _client().get("/health").status_code == 200


def test_database_identity_never_leaks_credentials(monkeypatch):
    """/health is unauthenticated by design, so anything it echoes is public.
    The DSN carries a password."""
    monkeypatch.setattr(
        main_module.settings,
        "database_url",
        "postgresql+psycopg://toleman_user:sup3r-s3cret@db.internal:5432/toleman",
    )

    identity = _database_identity()

    assert identity == "db.internal:5432/toleman"
    assert "sup3r-s3cret" not in identity
    assert "toleman_user" not in identity


def test_database_identity_distinguishes_two_instances(monkeypatch):
    """The whole point: two stacks on the same port must not look alike."""
    monkeypatch.setattr(main_module.settings, "database_url", "postgresql+psycopg://u:p@localhost:5432/osp")
    host_native = _database_identity()

    monkeypatch.setattr(main_module.settings, "database_url", "postgresql+psycopg://u:p@postgres:5432/osp")
    containerised = _database_identity()

    assert host_native != containerised


def test_database_identity_survives_an_unparseable_url(monkeypatch):
    # A healthcheck endpoint must not 500 because a DSN is malformed; that
    # turns a config typo into an unhealthy container with no explanation.
    monkeypatch.setattr(main_module.settings, "database_url", "not a url at all::::")
    assert isinstance(_database_identity(), str)

    monkeypatch.setattr(main_module.settings, "database_url", "")
    assert isinstance(_database_identity(), str)


def test_build_version_defaults_to_dev_not_a_fabricated_number():
    # "dev" is the honest answer for a working tree. A default like "1.0.0"
    # would assert something untrue about an unbuilt checkout.
    s = Settings(_env_file=None)
    assert s.build_version == "dev"
    assert s.build_commit == ""


def test_build_identity_is_configurable_from_the_environment():
    s = Settings(_env_file=None, build_version="2026.08.21", build_commit="deadbee")
    assert s.build_version == "2026.08.21"
    assert s.build_commit == "deadbee"
