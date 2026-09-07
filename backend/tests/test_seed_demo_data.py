import random

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

from app.core.config import settings
from app.core.dedup import compute_dedup_hash
from app.core.scoring import compute_priority_score
from app.core.security import verify_password
from app.models.models import (
    CveEnrichment,
    Finding,
    FindingState,
    FindingStateLog,
    Organization,
    PRGuardrailScan,
    Scan,
    Target,
    User,
    Workspace,
)
from scripts.seed_demo_data import seed_random_data


@pytest.fixture(autouse=True)
def local_environment(monkeypatch):
    monkeypatch.setattr(settings, "environment", "local")


@pytest.fixture()
def session():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


def test_seed_rejects_non_local_environment_before_writing(monkeypatch, session):
    monkeypatch.setattr(settings, "environment", "production")

    with pytest.raises(RuntimeError, match="local environments"):
        seed_random_data(session, count=0)

    assert session.exec(select(Organization)).first() is None


def test_seeded_data_follows_production_invariants(session):
    random.seed(19)
    seed_random_data(session, count=40, clean=True)

    findings = session.exec(select(Finding)).all()
    scans = {scan.id: scan for scan in session.exec(select(Scan)).all()}
    targets = {target.id: target for target in session.exec(select(Target)).all()}
    enrichments = session.exec(select(CveEnrichment)).all()
    state_logs = session.exec(select(FindingStateLog)).all()
    pr_scans = session.exec(select(PRGuardrailScan)).all()

    assert findings
    assert enrichments
    assert state_logs
    assert pr_scans

    for scan in scans.values():
        assert scan.findings_count == len([f for f in findings if f.scan_id == scan.id])

    for finding in findings:
        scan = scans[finding.scan_id]
        assert (scan.target_id, scan.tool) == (finding.target_id, finding.tool)
        assert finding.dedup_hash == compute_dedup_hash(
            finding.rule_id,
            finding.file_path,
            finding.tool,
            line_start=finding.line_start,
        )
        assert finding.priority_score == compute_priority_score(
            finding.severity,
            targets[finding.target_id].criticality_weight,
            epss_score=finding.epss_score,
            kev_listed=finding.kev_listed,
        )
        if finding.state == FindingState.MITIGATED:
            assert finding.first_seen <= finding.mitigated_at <= finding.last_seen

    findings_by_id = {finding.id: finding for finding in findings}
    for state_log in state_logs:
        finding = findings_by_id[state_log.finding_id]
        assert finding.first_seen <= state_log.created_at <= finding.last_seen

    assert {row.cve_id for row in enrichments} == {
        finding.cve_id for finding in findings if finding.cve_id
    }
    assert all(row.cvss_score and row.cvss_vector and row.osv_found and row.fixed_versions for row in enrichments)
    assert all(scan.created_at <= scan.completed_at for scan in pr_scans)


def test_seed_uses_fresh_demo_credentials(session):
    seed_random_data(session, count=0, clean=True)
    first_keys = {workspace.api_key for workspace in session.exec(select(Workspace)).all()}
    users = session.exec(select(User)).all()

    assert all(not verify_password("changeme123", user.password_hash) for user in users)

    seed_random_data(session, count=0, clean=True)
    second_keys = {workspace.api_key for workspace in session.exec(select(Workspace)).all()}

    assert first_keys.isdisjoint(second_keys)


def test_seed_accepts_custom_password_and_preserves_on_reseed(session):
    custom_pw = "CustomSecret2026!"
    seed_random_data(session, count=0, clean=True, demo_password=custom_pw)
    users = session.exec(select(User)).all()
    assert all(verify_password(custom_pw, user.password_hash) for user in users)

    # Reseed without clean and without password -> user password preserved
    seed_random_data(session, count=0, clean=False)
    users_after = session.exec(select(User)).all()
    assert all(verify_password(custom_pw, user.password_hash) for user in users_after)

