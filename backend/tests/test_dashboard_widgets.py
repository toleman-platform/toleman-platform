"""Tests for issue #69 (configurable dashboard): the widget catalog, real
per-widget data resolvers in app.core.widgets, and DashboardLayout
save/load (GET/PUT /api/dashboard/layout) + the batched
GET /api/dashboard/widget-data endpoint.

Follows the same in-memory SQLite + TestClient + session-token-login
pattern used across tests/test_sla_rules.py and tests/test_workspace_roles.py.
"""
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core.security import create_session_token, hash_password
from app.core.widgets import (
    WIDGET_CATALOG,
    build_default_layout,
    resolve_cve_timeline,
    resolve_findings_trend,
    resolve_kpi_cards,
    resolve_recent_findings,
    resolve_sla_compliance,
    resolve_top_risky_repos,
)
from app.main import app
from app.models.models import (
    DashboardLayout,
    Finding,
    FindingState,
    Organization,
    Severity,
    SlaRule,
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
    yield c
    app.dependency_overrides.clear()
    deps_module.engine = original_engine


def _login(client, engine, role=UserRole.ADMIN, email=None):
    email = email or f"{role.value}-{id(object())}@example.com"
    with Session(engine) as session:
        user = User(email=email, name="Test", password_hash=hash_password("whatever123"), role=role)
        session.add(user)
        session.commit()
        session.refresh(user)
        uid = user.id
        token = create_session_token(user.id, user.token_version)
    client.cookies.set("osp_session", token)
    return client, uid


def _seed(engine):
    with Session(engine) as session:
        org = Organization(name="acme")
        session.add(org)
        session.commit()
        session.refresh(org)

        ws = Workspace(organization_id=org.id, name="ws", api_key="key-ws")
        session.add(ws)
        session.commit()
        session.refresh(ws)

        t1 = Target(workspace_id=ws.id, name="repo-a", repo_url="https://github.com/acme/repo-a")
        t2 = Target(workspace_id=ws.id, name="repo-b", repo_url="https://github.com/acme/repo-b")
        session.add(t1)
        session.add(t2)
        session.commit()
        session.refresh(t1)
        session.refresh(t2)

        now = datetime.utcnow()
        findings = [
            Finding(
                target_id=t1.id, dedup_hash="h1", tool="trivy", rule_id="CVE-1", title="Critical CVE",
                file_path="go.mod", severity=Severity.CRITICAL, priority_score=200, state=FindingState.OPEN,
                cve_id="CVE-2024-0001", first_seen=now - timedelta(days=5),
            ),
            Finding(
                target_id=t1.id, dedup_hash="h2", tool="trivy", rule_id="CVE-2", title="High CVE",
                file_path="go.mod", severity=Severity.HIGH, priority_score=150, state=FindingState.OPEN,
                cve_id="CVE-2024-0002", first_seen=now - timedelta(days=3),
            ),
            Finding(
                target_id=t2.id, dedup_hash="h3", tool="semgrep", rule_id="sast-1", title="SAST issue",
                file_path="app.py", severity=Severity.MEDIUM, priority_score=90, state=FindingState.MITIGATED,
                first_seen=now - timedelta(days=10), mitigated_at=now - timedelta(days=1),
            ),
            Finding(
                target_id=t2.id, dedup_hash="h4", tool="gitleaks", rule_id="secret-1", title="Leaked key",
                file_path=".env", severity=Severity.CRITICAL, priority_score=250, state=FindingState.OPEN,
                first_seen=now - timedelta(days=1),
            ),
        ]
        for f in findings:
            session.add(f)

        rule = SlaRule(workspace_id=ws.id, group_id=None, severity=Severity.CRITICAL, days_to_fix=3)
        session.add(rule)
        session.commit()
        return t1.id, t2.id, ws.id


# ---------------------------------------------------------------------------
# Widget resolver unit tests (real query assertions against seeded data)
# ---------------------------------------------------------------------------


def test_kpi_cards_counts_real_findings(engine):
    _seed(engine)
    with Session(engine) as session:
        data = resolve_kpi_cards(session, None, {})
    assert data["open"] == 3  # 2 open on t1, 1 open on t2 (mitigated excluded)
    assert data["critical"] == 2
    assert data["high"] == 1
    assert data["mitigated"] == 1
    assert data["targets"] == 2


def test_findings_trend_daily_snapshot(engine):
    _seed(engine)
    with Session(engine) as session:
        data = resolve_findings_trend(session, None, {"days": 7})
    assert len(data["points"]) == 7
    today_point = data["points"][-1]
    # 3 open findings today (mitigated one was mitigated yesterday, excluded)
    assert today_point["open"] == 3
    # points are ordered oldest -> newest
    dates = [p["date"] for p in data["points"]]
    assert dates == sorted(dates)


def test_findings_trend_clamps_days(engine):
    _seed(engine)
    with Session(engine) as session:
        data = resolve_findings_trend(session, None, {"days": 500})
    assert len(data["points"]) == 90


def test_cve_timeline_only_cve_findings_most_recent_first(engine):
    _seed(engine)
    with Session(engine) as session:
        data = resolve_cve_timeline(session, None, {"limit": 10})
    cve_ids = [item["cve_id"] for item in data["items"]]
    assert cve_ids == ["CVE-2024-0002", "CVE-2024-0001"]  # newer first_seen first
    assert all(item["cve_id"] for item in data["items"])


def test_sla_compliance_widget_matches_dashboard_endpoint(engine):
    _seed(engine)
    with Session(engine) as session:
        data = resolve_sla_compliance(session, None, {})
    # only the two CRITICAL open findings have an SLA rule (3 days); one is
    # 5 days old (violated), one is 1 day old (within window)
    assert data["with_sla"] == 2
    assert data["in_violation"] == 1
    assert data["compliant"] == 1


def test_top_risky_repos_ranks_by_open_critical_high(engine):
    t1, t2, _ = _seed(engine)
    with Session(engine) as session:
        data = resolve_top_risky_repos(session, None, {"limit": 5})
    assert data["items"][0]["target_id"] == t1  # 1 critical + 1 high open
    assert data["items"][0]["critical"] == 1
    assert data["items"][0]["high"] == 1


def test_recent_findings_ordered_and_limited(engine):
    _seed(engine)
    with Session(engine) as session:
        data = resolve_recent_findings(session, None, {"limit": 2})
    assert len(data["items"]) == 2
    assert data["items"][0]["title"] == "Leaked key"  # most recent first_seen


def test_widget_catalog_has_six_concrete_widgets():
    assert set(WIDGET_CATALOG.keys()) == {
        "kpi_cards",
        "findings_trend",
        "cve_timeline",
        "sla_compliance",
        "top_risky_repos",
        "recent_findings",
    }


def test_build_default_layout_all_valid_widget_ids():
    layout = build_default_layout()
    assert len(layout) == 6
    ids = {w["id"] for w in layout}
    assert len(ids) == 6  # each instance gets a unique id
    for w in layout:
        assert w["widget_id"] in WIDGET_CATALOG


# ---------------------------------------------------------------------------
# HTTP endpoint tests: catalog, layout save/load round-trip, widget-data
# ---------------------------------------------------------------------------


def test_get_widgets_catalog_endpoint(client, engine):
    client, _ = _login(client, engine)
    res = client.get("/api/dashboard/widgets")
    assert res.status_code == 200
    body = res.json()
    assert len(body) == 6
    assert {w["widget_id"] for w in body} == set(WIDGET_CATALOG.keys())


def test_get_layout_returns_default_when_unsaved(client, engine):
    client, _ = _login(client, engine)
    res = client.get("/api/dashboard/layout")
    assert res.status_code == 200
    body = res.json()
    assert len(body["widgets"]) == 6


def test_layout_save_and_load_round_trip(client, engine):
    client, uid = _login(client, engine)
    custom = {
        "widgets": [
            {"id": "a", "widget_id": "cve_timeline", "config": {"limit": 20}},
            {"id": "b", "widget_id": "kpi_cards", "config": {}},
        ]
    }
    put_res = client.put("/api/dashboard/layout", json=custom)
    assert put_res.status_code == 200
    assert put_res.json()["widgets"] == custom["widgets"]

    get_res = client.get("/api/dashboard/layout")
    assert get_res.status_code == 200
    assert get_res.json()["widgets"] == custom["widgets"]

    with Session(engine) as session:
        row = session.exec(select(DashboardLayout).where(DashboardLayout.user_id == uid)).first()
        assert row is not None
        assert len(row.widgets) == 2


def test_layout_rejects_unknown_widget_id(client, engine):
    client, _ = _login(client, engine)
    res = client.put(
        "/api/dashboard/layout",
        json={"widgets": [{"id": "a", "widget_id": "not_a_real_widget", "config": {}}]},
    )
    assert res.status_code == 400


def test_layout_save_overwrites_previous_layout(client, engine):
    client, uid = _login(client, engine)
    client.put("/api/dashboard/layout", json={"widgets": [{"id": "a", "widget_id": "kpi_cards", "config": {}}]})
    client.put("/api/dashboard/layout", json={"widgets": [{"id": "b", "widget_id": "sla_compliance", "config": {}}]})
    with Session(engine) as session:
        rows = session.exec(select(DashboardLayout).where(DashboardLayout.user_id == uid)).all()
        assert len(rows) == 1  # upsert, not a second row
        assert rows[0].widgets[0]["widget_id"] == "sla_compliance"


def test_widget_data_batches_real_data_for_custom_layout(client, engine):
    _seed(engine)
    client, _ = _login(client, engine)
    client.put(
        "/api/dashboard/layout",
        json={
            "widgets": [
                {"id": "kpi-1", "widget_id": "kpi_cards", "config": {}},
                {"id": "cve-1", "widget_id": "cve_timeline", "config": {"limit": 5}},
            ]
        },
    )
    res = client.get("/api/dashboard/widget-data")
    assert res.status_code == 200
    body = res.json()["widgets"]
    assert set(body.keys()) == {"kpi-1", "cve-1"}
    assert body["kpi-1"]["widget_id"] == "kpi_cards"
    assert body["kpi-1"]["data"]["open"] == 3
    assert body["cve-1"]["widget_id"] == "cve_timeline"
    assert len(body["cve-1"]["data"]["items"]) == 2


def test_widget_data_uses_default_layout_when_unsaved(client, engine):
    _seed(engine)
    client, _ = _login(client, engine)
    res = client.get("/api/dashboard/widget-data")
    assert res.status_code == 200
    assert len(res.json()["widgets"]) == 6
