"""What a scan actually covered has to reach the UI, not just the database.

#244 persists `blast_radius_files` (how many of `files_scanned` the import
graph pulled in rather than the PR changing them) and `scope_reason` (why a
target that opted into diff scoping got a full scan anyway), but neither was
serialized. The PR Guardrail log therefore described every diff-scoped scan
as "N changed file(s) only" even when it had deliberately scanned past the
diff, and showed an escalated full scan as indistinguishable from a
deliberate one. Both are exactly the "do not claim assurance you do not
have, and do not hide the assurance you do" property the rest of this
module is built around, so they are pinned here.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core.security import create_session_token, hash_password
from app.main import app
from app.models.models import (
    Organization,
    PRGuardrailScan,
    PRGuardrailStatus,
    Target,
    User,
    UserRole,
    Workspace,
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
    with Session(engine) as session:
        user = User(
            email="admin@example.com",
            name="Admin",
            password_hash=hash_password("whatever123"),
            role=UserRole.ADMIN,
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        c.cookies.set("toleman_session", create_session_token(user.id, user.token_version))
    yield c
    app.dependency_overrides.clear()
    deps_module.engine = original_engine


def _scan(engine, **scan_fields) -> tuple[int, int]:
    with Session(engine) as session:
        org = Organization(name="org")
        session.add(org)
        session.commit()
        session.refresh(org)
        ws = Workspace(organization_id=org.id, name="ws", api_key="key")
        session.add(ws)
        session.commit()
        session.refresh(ws)
        target = Target(workspace_id=ws.id, name="target", repo_url="https://github.com/acme/repo")
        session.add(target)
        session.commit()
        session.refresh(target)
        scan = PRGuardrailScan(
            target_id=target.id,
            pr_number=7,
            pr_title="a pr",
            branch="feature",
            status=PRGuardrailStatus.PASSED,
            **scan_fields,
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)
        return target.id, scan.id


def test_log_reports_how_much_of_the_scan_was_blast_radius(client, engine):
    target_id, _ = _scan(
        engine, scan_scope="diff", files_scanned=12, blast_radius_files=10, scope_reason="10 importers",
    )

    rows = client.get(f"/api/pr-guardrail/log?target_id={target_id}").json()

    assert rows[0]["files_scanned"] == 12
    assert rows[0]["blast_radius_files"] == 10
    assert rows[0]["scope_reason"] == "10 importers"


def test_log_reports_why_a_diff_scoped_target_got_a_full_scan(client, engine):
    """The escalation is the honest outcome, but a row that only says "full"
    cannot be told apart from a target that never opted in at all."""
    target_id, _ = _scan(
        engine, scan_scope="full", scope_reason="the PR's changed-file list could not be retrieved",
    )

    rows = client.get(f"/api/pr-guardrail/log?target_id={target_id}").json()

    assert rows[0]["scan_scope"] == "full"
    assert "could not be retrieved" in rows[0]["scope_reason"]


def test_the_override_response_carries_the_same_two_fields(client, engine):
    """POST /override returns a whole scan row of its own, which the UI swaps
    in without refetching the log. The two payloads disagreeing about scope is
    how a surface ends up quietly rendering the old wording again."""
    _, scan_id = _scan(engine, scan_scope="diff", files_scanned=3, blast_radius_files=1, scope_reason="1 importer")

    body = client.post(
        f"/api/pr-guardrail/{scan_id}/override", json={"reason": "accepted for this PR"}
    ).json()

    assert body["blast_radius_files"] == 1
    assert body["scope_reason"] == "1 importer"


def test_a_plain_diff_scan_reports_no_blast_radius(client, engine):
    """0 is meaningful, not missing: it is what lets the UI keep the original
    "changed files only" wording for a scan whose radius really was the diff."""
    target_id, _ = _scan(engine, scan_scope="diff", files_scanned=4)

    rows = client.get(f"/api/pr-guardrail/log?target_id={target_id}").json()

    assert rows[0]["blast_radius_files"] == 0
    assert rows[0]["scope_reason"] == ""
