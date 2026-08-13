"""Tests for GET /api/reports/posture (CSV + PDF compliance/audit exports).

Follows the same in-memory SQLite + dependency_override pattern used in
tests/test_findings.py -- no shared conftest exists for this yet either.
"""
import csv
import io
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core.security import create_session_token, hash_password
from app.main import app
from app.models.models import (
    Finding,
    FindingState,
    Organization,
    SbomComponent,
    Scan,
    Severity,
    Target,
    User,
    Workspace,
)


@pytest.fixture()
def engine():
    eng = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(eng)
    return eng


@pytest.fixture()
def client(engine):
    def override_get_session():
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session

    original_deps_engine = deps_module.engine
    deps_module.engine = engine

    c = TestClient(app)
    yield c
    app.dependency_overrides.clear()
    deps_module.engine = original_deps_engine


def _login(client, engine, email="user@example.com", password="whatever123"):
    with Session(engine) as session:
        user = User(email=email, name="Test User", password_hash=hash_password(password))
        session.add(user)
        session.commit()
        session.refresh(user)
        token = create_session_token(user.id)
    client.cookies.set("osp_session", token)
    return client


def _make_target(engine, name="Target A", default_branch="main") -> int:
    with Session(engine) as session:
        org = Organization(name="Org")
        session.add(org)
        session.commit()
        session.refresh(org)

        workspace = Workspace(organization_id=org.id, name="WS", api_key=f"key-{name}")
        session.add(workspace)
        session.commit()
        session.refresh(workspace)

        target = Target(
            workspace_id=workspace.id,
            name=name,
            repo_url=f"https://example.com/{name}.git",
            default_branch=default_branch,
        )
        session.add(target)
        session.commit()
        session.refresh(target)
        return target.id


def _make_finding(engine, target_id, **overrides) -> int:
    defaults = dict(
        target_id=target_id,
        dedup_hash=f"hash-{overrides.get('title', 'x')}-{overrides.get('rule_id', 'r')}-{overrides.get('branch', 'main')}",
        tool="semgrep",
        rule_id="rule-1",
        title="SQL Injection",
        file_path="app/main.py",
        severity=Severity.HIGH,
        priority_score=50,
        state=FindingState.OPEN,
        branch="main",
    )
    defaults.update(overrides)
    with Session(engine) as session:
        finding = Finding(**defaults)
        session.add(finding)
        session.commit()
        session.refresh(finding)
        return finding.id


def _make_scan(engine, target_id, **overrides) -> int:
    defaults = dict(
        target_id=target_id,
        tool="semgrep",
        branch="main",
        status="completed",
        findings_count=2,
    )
    defaults.update(overrides)
    with Session(engine) as session:
        scan = Scan(**defaults)
        session.add(scan)
        session.commit()
        session.refresh(scan)
        return scan.id


def _make_sbom_component(engine, target_id, **overrides) -> int:
    defaults = dict(
        target_id=target_id,
        branch="main",
        name="requests",
        version="2.31.0",
        package_type="pip",
        purl="pkg:pypi/requests@2.31.0",
    )
    defaults.update(overrides)
    with Session(engine) as session:
        c = SbomComponent(**defaults)
        session.add(c)
        session.commit()
        session.refresh(c)
        return c.id


def test_posture_csv_requires_auth(client):
    res = client.get("/api/reports/posture?format=csv")
    assert res.status_code in (401, 403)


def test_posture_csv_for_single_target_reflects_real_findings(client, engine):
    _login(client, engine)
    target_id = _make_target(engine, name="govwa")
    _make_finding(engine, target_id, title="SQL Injection", severity=Severity.CRITICAL, state=FindingState.OPEN)
    _make_finding(engine, target_id, title="XSS", rule_id="rule-2", severity=Severity.HIGH, state=FindingState.OPEN)
    _make_finding(engine, target_id, title="Old secret", rule_id="rule-3", severity=Severity.HIGH, state=FindingState.MITIGATED)
    _make_scan(engine, target_id, tool="semgrep", status="completed", findings_count=3)
    _make_sbom_component(engine, target_id)

    res = client.get(f"/api/reports/posture?target_id={target_id}&format=csv")
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("text/csv")
    assert "attachment" in res.headers["content-disposition"]
    assert "govwa" in res.headers["content-disposition"]

    text = res.text
    rows = list(csv.reader(io.StringIO(text)))

    # Real severity/state counts must appear verbatim -- not fabricated.
    assert any(r[:3] == ["govwa", "Critical", "Open"] and r[3] == "1" for r in rows)
    assert any(r[:3] == ["govwa", "High", "Open"] and r[3] == "1" for r in rows)
    assert any(r[:3] == ["govwa", "High", "Mitigated"] and r[3] == "1" for r in rows)

    # Scan coverage row for the seeded semgrep scan.
    assert any(r[:2] == ["govwa", "semgrep"] and r[6] == "3" for r in rows if len(r) > 6)

    # SBOM summary row.
    assert any(r[:2] == ["govwa", "1"] for r in rows)


def test_posture_csv_open_finding_age_matches_seeded_first_seen(client, engine):
    _login(client, engine)
    target_id = _make_target(engine, name="gotest")
    old_time = datetime.utcnow() - timedelta(days=45)
    with Session(engine) as session:
        f = Finding(
            target_id=target_id,
            dedup_hash="h1",
            tool="trivy",
            rule_id="CVE-2021-1234",
            title="Vulnerable dependency",
            file_path="go.mod",
            severity=Severity.MEDIUM,
            state=FindingState.OPEN,
            branch="main",
            first_seen=old_time,
            last_seen=old_time,
        )
        session.add(f)
        session.commit()

    res = client.get(f"/api/reports/posture?target_id={target_id}&format=csv")
    assert res.status_code == 200
    rows = list(csv.reader(io.StringIO(res.text)))

    age_row = next(r for r in rows if r[:2] == ["gotest", "Medium"] and len(r) == 9)
    open_count, avg_age, oldest_age = age_row[2], float(age_row[3]), int(age_row[4])
    assert open_count == "1"
    assert 44 <= avg_age <= 46
    assert 44 <= oldest_age <= 46
    assert age_row[7] == "1"  # falls in the 31-90d bucket


def test_posture_csv_org_wide_omits_target_id_and_covers_all_targets(client, engine):
    _login(client, engine)
    t1 = _make_target(engine, name="vulpy")
    t2 = _make_target(engine, name="gotest")
    _make_finding(engine, t1, title="Hardcoded secret", severity=Severity.CRITICAL)
    _make_finding(engine, t2, title="CVE-2020-0001", severity=Severity.LOW)

    res = client.get("/api/reports/posture?format=csv")
    assert res.status_code == 200
    assert "org-wide" in res.headers["content-disposition"]

    rows = list(csv.reader(io.StringIO(res.text)))
    names = {r[1] for r in rows if len(r) >= 5 and r[0].isdigit()}
    assert "vulpy" in names
    assert "gotest" in names


def test_posture_csv_404s_for_unknown_target(client, engine):
    _login(client, engine)
    res = client.get("/api/reports/posture?target_id=99999&format=csv")
    assert res.status_code == 404


def test_posture_pdf_is_a_real_parseable_pdf_with_correct_content_type(client, engine):
    _login(client, engine)
    target_id = _make_target(engine, name="gotest")
    _make_finding(engine, target_id, title="SQL Injection", severity=Severity.CRITICAL)
    _make_scan(engine, target_id, tool="gosec", findings_count=1)

    res = client.get(f"/api/reports/posture?target_id={target_id}&format=pdf")
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/pdf"
    assert "attachment" in res.headers["content-disposition"]

    body = res.content
    assert len(body) > 500
    assert body[:4] == b"%PDF"
    assert body.rstrip().endswith(b"%%EOF")

    # Parse it back for real with pypdf to prove it's not a mislabeled text
    # file -- extracted text should contain the real seeded finding data.
    from pypdf import PdfReader

    reader = PdfReader(io.BytesIO(body))
    assert len(reader.pages) >= 1
    full_text = "\n".join(page.extract_text() for page in reader.pages)
    assert "gotest" in full_text
    assert "Critical" in full_text
