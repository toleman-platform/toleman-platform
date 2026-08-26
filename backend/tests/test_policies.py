"""Tests for policy-as-code (ROADMAP Sprint 4).

Covers:
  - Policy rule CRUD via the /api/policies routes (create, list active-only,
    soft-delete).
  - Pure `apply_policies` suppression actually removing a matching net-new
    finding (SUPPRESS_RULE and SUPPRESS_LICENSE).
  - Pure `apply_policies` severity threshold actually changing should_block's
    outcome (via the effective blocking-severities set it returns).
  - No policy configured for a workspace falls back to default
    BLOCKING_SEVERITIES behavior, unchanged.

Follows the same in-memory SQLite + dependency_override pattern used in
tests/test_findings.py; no shared conftest exists yet either.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

import app.api.deps as deps_module
from app.api.deps import get_session
from app.core.policy import apply_policies
from app.core.pr_guardrail import BLOCKING_SEVERITIES, should_block
from app.core.security import create_session_token, hash_password
from app.main import app
from app.models.models import Organization, PolicyRule, PolicyRuleType, User, Workspace


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
    client.cookies.set("toleman_session", token)
    return client


def _make_workspace(engine, name="WS") -> int:
    with Session(engine) as session:
        org = Organization(name="Org")
        session.add(org)
        session.commit()
        session.refresh(org)

        workspace = Workspace(organization_id=org.id, name=name, api_key=f"key-{name}")
        session.add(workspace)
        session.commit()
        session.refresh(workspace)
        return workspace.id


def _finding(rule_id="rule-1", severity="Medium", title=None, file_path="a.py"):
    return {
        "dedup_hash": f"hash-{rule_id}",
        "rule_id": rule_id,
        "title": title or rule_id,
        "file_path": file_path,
        "line_start": 1,
        "severity": severity,
    }


# ---------------------------------------------------------------------------
# Rule CRUD (API)
# ---------------------------------------------------------------------------

def test_create_and_list_policy(client, engine):
    client = _login(client, engine)
    ws_id = _make_workspace(engine)

    res = client.post("/api/policies", json={
        "workspace_id": ws_id,
        "rule_type": "block_severity",
        "value": "Medium",
        "reason": "tighten posture",
    })
    assert res.status_code == 200
    body = res.json()
    assert body["workspace_id"] == ws_id
    assert body["rule_type"] == "block_severity"
    assert body["value"] == "Medium"
    assert body["active"] is True

    res = client.get(f"/api/policies?workspace_id={ws_id}")
    assert res.status_code == 200
    rules = res.json()
    assert len(rules) == 1
    assert rules[0]["value"] == "Medium"


def test_create_policy_rejects_invalid_rule_type(client, engine):
    client = _login(client, engine)
    ws_id = _make_workspace(engine)

    res = client.post("/api/policies", json={
        "workspace_id": ws_id,
        "rule_type": "not_a_real_type",
        "value": "Medium",
    })
    assert res.status_code == 400


def test_delete_policy_soft_deletes_and_excludes_from_list(client, engine):
    client = _login(client, engine)
    ws_id = _make_workspace(engine)

    created = client.post("/api/policies", json={
        "workspace_id": ws_id,
        "rule_type": "suppress_rule",
        "value": "noisy-rule",
        "reason": "known false positive",
    }).json()

    res = client.delete(f"/api/policies/{created['id']}")
    assert res.status_code == 200
    assert res.json()["active"] is False

    # Soft-deleted: excluded from the active list...
    rules = client.get(f"/api/policies?workspace_id={ws_id}").json()
    assert rules == []

    # ...but the row itself still exists (audit-relevant, not hard-deleted).
    with Session(engine) as session:
        row = session.get(PolicyRule, created["id"])
        assert row is not None
        assert row.active is False


def test_list_policies_scoped_to_workspace(client, engine):
    client = _login(client, engine)
    ws_a = _make_workspace(engine, "WS-A")
    ws_b = _make_workspace(engine, "WS-B")

    client.post("/api/policies", json={"workspace_id": ws_a, "rule_type": "block_severity", "value": "Medium"})
    client.post("/api/policies", json={"workspace_id": ws_b, "rule_type": "block_severity", "value": "Low"})

    rules_a = client.get(f"/api/policies?workspace_id={ws_a}").json()
    assert len(rules_a) == 1
    assert rules_a[0]["value"] == "Medium"


# ---------------------------------------------------------------------------
# apply_policies: suppression
# ---------------------------------------------------------------------------

def test_suppress_rule_removes_matching_finding_from_net_new():
    net_new = [_finding(rule_id="sql-injection", severity="Critical"), _finding(rule_id="xss", severity="High")]
    policies = [PolicyRule(workspace_id=1, rule_type=PolicyRuleType.SUPPRESS_RULE, value="sql-injection")]

    filtered, _ = apply_policies(net_new, policies)

    assert [f["rule_id"] for f in filtered] == ["xss"]


def test_suppress_license_removes_matching_license_finding():
    net_new = [
        {"dedup_hash": "h1", "rule_id": "license:GPL-3.0", "title": "GPL-3.0 license detected in libfoo", "severity": "High", "file_path": "go.mod"},
        {"dedup_hash": "h2", "rule_id": "license:MIT", "title": "MIT license detected in libbar", "severity": "Medium", "file_path": "go.mod"},
    ]
    policies = [PolicyRule(workspace_id=1, rule_type=PolicyRuleType.SUPPRESS_LICENSE, value="MIT")]

    filtered, _ = apply_policies(net_new, policies)

    assert [f["rule_id"] for f in filtered] == ["license:GPL-3.0"]


def test_inactive_suppress_rule_does_not_apply():
    net_new = [_finding(rule_id="sql-injection", severity="Critical")]
    policies = [PolicyRule(workspace_id=1, rule_type=PolicyRuleType.SUPPRESS_RULE, value="sql-injection", active=False)]

    filtered, _ = apply_policies(net_new, policies)

    assert len(filtered) == 1


# ---------------------------------------------------------------------------
# apply_policies: severity threshold actually changes should_block's outcome
# ---------------------------------------------------------------------------

def test_block_severity_policy_widens_blocking_set_and_flips_outcome():
    net_new = [_finding(rule_id="minor-issue", severity="Medium")]

    # Default behavior: Medium alone does not block.
    assert should_block(net_new) is False

    policies = [PolicyRule(workspace_id=1, rule_type=PolicyRuleType.BLOCK_SEVERITY, value="Medium")]
    filtered, blocking_severities = apply_policies(net_new, policies)

    assert blocking_severities == {"Medium", "High", "Critical"}
    assert should_block(filtered, blocking_severities) is True


def test_block_severity_policy_can_only_widen_not_narrow_by_itself():
    # A High threshold policy still blocks Critical too (severities at or
    # above the threshold).
    net_new = [_finding(rule_id="crit-issue", severity="Critical")]
    policies = [PolicyRule(workspace_id=1, rule_type=PolicyRuleType.BLOCK_SEVERITY, value="High")]

    filtered, blocking_severities = apply_policies(net_new, policies)

    assert blocking_severities == {"High", "Critical"}
    assert should_block(filtered, blocking_severities) is True


# ---------------------------------------------------------------------------
# No policy configured -> default behavior preserved
# ---------------------------------------------------------------------------

def test_no_policies_falls_back_to_default_blocking_severities():
    net_new = [_finding(rule_id="sql-injection", severity="Critical"), _finding(rule_id="minor", severity="Low")]

    filtered, blocking_severities = apply_policies(net_new, policies=[])

    assert blocking_severities == BLOCKING_SEVERITIES
    assert filtered == net_new
    assert should_block(filtered, blocking_severities) is True


def test_no_policies_medium_alone_does_not_block_by_default():
    net_new = [_finding(rule_id="minor-issue", severity="Medium")]

    filtered, blocking_severities = apply_policies(net_new, policies=[])

    assert should_block(filtered, blocking_severities) is False
