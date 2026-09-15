"""Issue #506 part 3: workspace-isolation coverage for the gaps the audit
found -- sbom.py's org/export/run/components GET routes, search.py,
github.py's _get_target-backed routes, and audit.py's /log + /actors, none
of which filtered by workspace before this issue. Plus one reports.py
lock-in case, already correctly scoped but not previously covered here.

Uses the shared engine/client fixtures and _login/_make_workspace/
_make_target/_make_finding/_assign helpers from conftest.py (see
test_workspace_scoped_reads.py for the original #57 suite these extend).
"""
import app.api.github as github_module
from sqlmodel import Session

from app.models.models import (
    FindingStateLog,
    McpAuditLog,
    Scan,
    SbomComponent,
    UserRole,
)

from .conftest import _assign, _login, _make_finding, _make_target, _make_workspace


def _two_workspace_setup(engine):
    ws_a = _make_workspace(engine, "p2-ws-a")
    ws_b = _make_workspace(engine, "p2-ws-b")
    target_a = _make_target(engine, ws_a, "p2-target-a")
    target_b = _make_target(engine, ws_b, "p2-target-b")
    finding_a = _make_finding(engine, target_a, rule_id="p2-r-a")
    finding_b = _make_finding(engine, target_b, rule_id="p2-r-b")
    return ws_a, ws_b, target_a, target_b, finding_a, finding_b


def _add_sbom_component(engine, target_id: int, name: str):
    with Session(engine) as session:
        session.add(
            SbomComponent(
                target_id=target_id, branch="main", name=name, version="1.0.0",
                package_type="pip", purl=f"pkg:pypi/{name}@1.0.0",
            )
        )
        session.commit()


# ---------------------------------------------------------------------------
# sbom.py
# ---------------------------------------------------------------------------


def test_org_sbom_only_aggregates_callers_workspace(client, engine):
    ws_a, ws_b, target_a, target_b, _fa, _fb = _two_workspace_setup(engine)
    _add_sbom_component(engine, target_a, "package-a")
    _add_sbom_component(engine, target_b, "package-b")
    client, uid = _login(client, engine, role=UserRole.VIEWER)
    _assign(engine, uid, ws_a)

    res = client.get("/api/sbom/org")
    assert res.status_code == 200
    body = res.json()
    names = {c["name"] for c in body["components"]}
    assert names == {"package-a"}
    assert body["total_targets_count"] == 1


def test_org_sbom_export_only_aggregates_callers_workspace(client, engine):
    ws_a, ws_b, target_a, target_b, _fa, _fb = _two_workspace_setup(engine)
    _add_sbom_component(engine, target_a, "package-a")
    _add_sbom_component(engine, target_b, "package-b")
    client, uid = _login(client, engine, role=UserRole.VIEWER)
    _assign(engine, uid, ws_a)

    res = client.get("/api/sbom/org/export")
    assert res.status_code == 200
    body = res.json()
    assert [t["id"] for t in body["targets"]] == [target_a]


def test_sbom_components_in_other_workspace_returns_404(client, engine):
    ws_a, ws_b, target_a, target_b, _fa, _fb = _two_workspace_setup(engine)
    _add_sbom_component(engine, target_b, "package-b")
    client, uid = _login(client, engine, role=UserRole.VIEWER)
    _assign(engine, uid, ws_a)

    res = client.get(f"/api/sbom/{target_b}")
    assert res.status_code == 404


def test_sbom_run_in_other_workspace_returns_404(client, engine):
    ws_a, ws_b, target_a, target_b, _fa, _fb = _two_workspace_setup(engine)
    client, uid = _login(client, engine, role=UserRole.VIEWER)
    _assign(engine, uid, ws_a)

    res = client.get(f"/api/sbom/{target_b}/runs/1")
    assert res.status_code == 404


# ---------------------------------------------------------------------------
# search.py
# ---------------------------------------------------------------------------


def test_search_only_returns_callers_workspace_results(client, engine):
    ws_a, ws_b, target_a, target_b, finding_a, finding_b = _two_workspace_setup(engine)
    client, uid = _login(client, engine, role=UserRole.VIEWER)
    _assign(engine, uid, ws_a)

    res = client.get("/api/search", params={"q": "p2-target"})
    assert res.status_code == 200
    body = res.json()
    assert {t["id"] for t in body["targets"]} == {target_a}


def test_search_finds_own_workspace_finding_by_rule_id(client, engine):
    ws_a, ws_b, target_a, target_b, finding_a, finding_b = _two_workspace_setup(engine)
    client, uid = _login(client, engine, role=UserRole.VIEWER)
    _assign(engine, uid, ws_a)

    res = client.get("/api/search", params={"q": "p2-r-"})
    assert res.status_code == 200
    body = res.json()
    assert {f["id"] for f in body["findings"]} == {finding_a}


# ---------------------------------------------------------------------------
# github.py
# ---------------------------------------------------------------------------


class _FakeGithubResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or []

    def json(self):
        return self._payload

    @property
    def text(self):
        return str(self._payload)


def test_repo_activity_in_other_workspace_returns_404(client, engine, monkeypatch):
    ws_a, ws_b, target_a, target_b, _fa, _fb = _two_workspace_setup(engine)
    client, uid = _login(client, engine, role=UserRole.VIEWER)
    _assign(engine, uid, ws_a)
    monkeypatch.setattr(github_module, "github_get", lambda *a, **kw: _FakeGithubResponse())

    res = client.get(f"/api/github/activity/{target_b}")
    assert res.status_code == 404


def test_repo_prs_in_other_workspace_returns_404(client, engine, monkeypatch):
    ws_a, ws_b, target_a, target_b, _fa, _fb = _two_workspace_setup(engine)
    client, uid = _login(client, engine, role=UserRole.VIEWER)
    _assign(engine, uid, ws_a)
    monkeypatch.setattr(github_module, "github_get", lambda *a, **kw: _FakeGithubResponse())

    res = client.get(f"/api/github/prs/{target_b}")
    assert res.status_code == 404


def test_org_activity_excludes_other_workspace_targets(client, engine, monkeypatch):
    ws_a, ws_b, target_a, target_b, _fa, _fb = _two_workspace_setup(engine)
    client, uid = _login(client, engine, role=UserRole.VIEWER)
    _assign(engine, uid, ws_a)

    def fake_github_get(path, params=None, **kwargs):
        return _FakeGithubResponse(200, [
            {
                "sha": "aaa1111",
                "commit": {"message": "msg", "author": {"name": "dev", "date": "2026-08-10T00:00:00Z"}},
                "html_url": "https://github.com/acme/repo/commit/aaa1111",
            }
        ])

    monkeypatch.setattr(github_module, "github_get", fake_github_get)

    res = client.get("/api/github/org-activity")
    assert res.status_code == 200
    body = res.json()
    assert {e["target_id"] for e in body["items"]} == {target_a}


# ---------------------------------------------------------------------------
# audit.py
# ---------------------------------------------------------------------------


def _add_triage_log(engine, finding_id: int, actor: str):
    with Session(engine) as session:
        session.add(FindingStateLog(finding_id=finding_id, from_state="open", to_state="triaged", actor=actor))
        session.commit()


def _add_scan(engine, target_id: int, tool: str):
    with Session(engine) as session:
        session.add(Scan(target_id=target_id, tool=tool, branch="main", status="completed"))
        session.commit()


def _add_mcp_log(engine, user_id: int, tool: str, target_id: int | None = None, finding_id: int | None = None):
    with Session(engine) as session:
        session.add(
            McpAuditLog(user_id=user_id, tool=tool, target_id=target_id, finding_id=finding_id, summary=tool)
        )
        session.commit()


def test_audit_log_excludes_other_workspace_triage_and_scan_events(client, engine):
    ws_a, ws_b, target_a, target_b, finding_a, finding_b = _two_workspace_setup(engine)
    _add_triage_log(engine, finding_a, actor="alice@example.com")
    _add_triage_log(engine, finding_b, actor="bob@example.com")
    _add_scan(engine, target_a, tool="semgrep")
    _add_scan(engine, target_b, tool="trivy")
    client, uid = _login(client, engine, role=UserRole.VIEWER)
    _assign(engine, uid, ws_a)

    res = client.get("/api/audit/log")
    assert res.status_code == 200
    actors = {e["actor"] for e in res.json()["items"]}
    assert "bob@example.com" not in actors
    assert "alice@example.com" in actors
    summaries = " ".join(e["summary"] for e in res.json()["items"])
    assert "trivy" not in summaries


def test_audit_log_mcp_event_scoped_by_target(client, engine):
    ws_a, ws_b, target_a, target_b, _fa, _fb = _two_workspace_setup(engine)
    # Some other user's MCP calls, attributed to a target in each workspace.
    # _login mutates the shared client's cookie, so create+log-in this actor
    # first and log in as the viewer under test last, right before the
    # request that exercises their view.
    client, other_uid = _login(client, engine, role=UserRole.VIEWER, email="p2-mcp-actor@example.com")
    _assign(engine, other_uid, ws_a)
    _assign(engine, other_uid, ws_b)
    _add_mcp_log(engine, other_uid, "get_target", target_id=target_a)
    _add_mcp_log(engine, other_uid, "get_target_b", target_id=target_b)

    client, uid = _login(client, engine, role=UserRole.VIEWER, email="p2-mcp-viewer@example.com")
    _assign(engine, uid, ws_a)

    res = client.get("/api/audit/log")
    assert res.status_code == 200
    tools = {e["summary"] for e in res.json()["items"] if e["type"] == "mcp"}
    assert any("get_target]" in t for t in tools)
    assert not any("get_target_b]" in t for t in tools)


def test_audit_log_unattributed_mcp_event_visible_only_to_its_own_actor(client, engine):
    ws_a, _ws_b, _ta, _tb, _fa, _fb = _two_workspace_setup(engine)
    # An MCP call with neither target_id nor finding_id (e.g. list_targets)
    # can't be workspace-attributed; a non-admin should only see their own.
    # _login mutates the shared client's cookie -- log in as the viewer
    # under test last, right before the request.
    client, other_uid = _login(client, engine, role=UserRole.VIEWER, email="p2-mcp-other@example.com")
    _assign(engine, other_uid, ws_a)
    _add_mcp_log(engine, other_uid, "list_targets")

    client, uid = _login(client, engine, role=UserRole.VIEWER, email="p2-mcp-viewer@example.com")
    _assign(engine, uid, ws_a)

    res = client.get("/api/audit/log")
    assert res.status_code == 200
    mcp_summaries = [e["summary"] for e in res.json()["items"] if e["type"] == "mcp"]
    assert not any("list_targets" in s for s in mcp_summaries)

    _add_mcp_log(engine, uid, "list_targets")
    res2 = client.get("/api/audit/log")
    mcp_summaries2 = [e["summary"] for e in res2.json()["items"] if e["type"] == "mcp"]
    assert any("list_targets" in s for s in mcp_summaries2)


def test_audit_actors_excludes_other_workspace_actor(client, engine):
    ws_a, ws_b, target_a, target_b, finding_a, finding_b = _two_workspace_setup(engine)
    _add_triage_log(engine, finding_a, actor="p2-alice@example.com")
    _add_triage_log(engine, finding_b, actor="p2-bob@example.com")
    client, uid = _login(client, engine, role=UserRole.VIEWER)
    _assign(engine, uid, ws_a)

    res = client.get("/api/audit/actors")
    assert res.status_code == 200
    actors = res.json()
    assert "p2-alice@example.com" in actors
    assert "p2-bob@example.com" not in actors


def test_admin_sees_every_workspace_in_audit_log_and_actors(client, engine):
    ws_a, ws_b, target_a, target_b, finding_a, finding_b = _two_workspace_setup(engine)
    _add_triage_log(engine, finding_a, actor="p2-admin-a@example.com")
    _add_triage_log(engine, finding_b, actor="p2-admin-b@example.com")
    client, _uid = _login(client, engine, role=UserRole.ADMIN)

    log_res = client.get("/api/audit/log")
    actors_from_log = {e["actor"] for e in log_res.json()["items"]}
    assert {"p2-admin-a@example.com", "p2-admin-b@example.com"} <= actors_from_log

    actors_res = client.get("/api/audit/actors")
    assert {"p2-admin-a@example.com", "p2-admin-b@example.com"} <= set(actors_res.json())


# ---------------------------------------------------------------------------
# reports.py (already scoped -- lock-in coverage)
# ---------------------------------------------------------------------------


def test_posture_report_for_other_workspace_target_returns_404(client, engine):
    ws_a, ws_b, target_a, target_b, _fa, _fb = _two_workspace_setup(engine)
    client, uid = _login(client, engine, role=UserRole.VIEWER)
    _assign(engine, uid, ws_a)

    res = client.get("/api/reports/posture", params={"target_id": target_b, "format": "csv"})
    assert res.status_code == 404
