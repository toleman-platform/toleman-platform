"""Regression coverage for the cross-tenant findings from the full-repo
security review: discovery.py's two GET routes, scans.py's get_scan/
run_native_scan, api_scan.py's get_api_scan_credential, github_app.py's
sync_now, pr_guardrail.py's ignore-action endpoints (request/approve/reject/
revoke), the org-wide log's target_id branch, the approval-queue's pending/
history lists, and webhooks.py's cross-tenant signature/target binding.

Uses the shared engine/client fixtures and _login/_make_workspace/
_make_target/_make_finding/_make_pr_scan/_assign helpers from conftest.py
(see test_workspace_scoped_reads.py and _part2.py for the original #57/#506
suites these extend).
"""
import hashlib
import hmac

from sqlmodel import Session

from app.core.crypto import encrypt_secret
from app.models.models import (
    ApiEndpoint,
    DiscoveryRun,
    GitHubAppConfig,
    GitHubInstallation,
    PRGuardrailFinding,
    Scan,
    UserRole,
    WorkspaceRole,
)

from .conftest import _assign, _login, _make_pr_scan, _make_target, _make_workspace


def _two_workspace_targets(engine):
    ws_a = _make_workspace(engine, "p3-ws-a")
    ws_b = _make_workspace(engine, "p3-ws-b")
    target_a = _make_target(engine, ws_a, "p3-target-a")
    target_b = _make_target(engine, ws_b, "p3-target-b")
    return ws_a, ws_b, target_a, target_b


# ---------------------------------------------------------------------------
# discovery.py
# ---------------------------------------------------------------------------


def test_discovery_run_in_other_workspace_returns_404(client, engine):
    ws_a, ws_b, target_a, target_b = _two_workspace_targets(engine)
    with Session(engine) as session:
        run = DiscoveryRun(target_id=target_b, branch="main", status="completed")
        session.add(run)
        session.commit()
        session.refresh(run)
        run_id = run.id
    client, uid = _login(client, engine, role=UserRole.VIEWER)
    _assign(engine, uid, ws_a)

    res = client.get(f"/api/discovery/{target_b}/runs/{run_id}")
    assert res.status_code == 404


def test_discovered_endpoints_in_other_workspace_returns_404(client, engine):
    ws_a, ws_b, target_a, target_b = _two_workspace_targets(engine)
    with Session(engine) as session:
        session.add(
            ApiEndpoint(target_id=target_b, branch="main", framework="fastapi", method="GET", route="/admin", file_path="a.py")
        )
        session.commit()
    client, uid = _login(client, engine, role=UserRole.VIEWER)
    _assign(engine, uid, ws_a)

    res = client.get(f"/api/discovery/{target_b}")
    assert res.status_code == 404


# ---------------------------------------------------------------------------
# scans.py
# ---------------------------------------------------------------------------


def test_get_scan_in_other_workspace_reports_not_found(client, engine):
    ws_a, ws_b, target_a, target_b = _two_workspace_targets(engine)
    with Session(engine) as session:
        scan = Scan(target_id=target_b, tool="semgrep", branch="main", status="completed")
        session.add(scan)
        session.commit()
        session.refresh(scan)
        scan_id = scan.id
    client, uid = _login(client, engine, role=UserRole.VIEWER)
    _assign(engine, uid, ws_a)

    res = client.get(f"/api/scans/{scan_id}")
    assert res.status_code == 200  # this endpoint's own 200-with-{"error"} convention
    assert res.json()["error"] == "scan not found"


def test_run_native_scan_refuses_a_target_outside_callers_workspace(client, engine):
    ws_a, ws_b, target_a, target_b = _two_workspace_targets(engine)
    client, uid = _login(client, engine, role=UserRole.DEVELOPER)
    _assign(engine, uid, ws_a, role=WorkspaceRole.DEVELOPER)

    res = client.post("/api/scans/run", params={"target_id": target_b, "tool": "semgrep"})
    assert res.status_code == 200
    assert res.json()["error"] == "target not found"


def test_run_native_scan_works_for_a_target_in_callers_own_workspace(client, engine, monkeypatch):
    from app.tasks import scan_tasks

    monkeypatch.setattr(scan_tasks.run_scan, "delay", lambda *a, **k: None)
    ws_a, ws_b, target_a, target_b = _two_workspace_targets(engine)
    client, uid = _login(client, engine, role=UserRole.DEVELOPER)
    _assign(engine, uid, ws_a, role=WorkspaceRole.DEVELOPER)

    res = client.post("/api/scans/run", params={"target_id": target_a, "tool": "semgrep"})
    assert res.status_code == 202


# ---------------------------------------------------------------------------
# api_scan.py
# ---------------------------------------------------------------------------


def test_get_api_scan_credential_in_other_workspace_returns_404(client, engine):
    ws_a, ws_b, target_a, target_b = _two_workspace_targets(engine)
    client, uid = _login(client, engine, role=UserRole.VIEWER)
    _assign(engine, uid, ws_a)

    res = client.get(f"/api/api-scan/{target_b}/credential")
    assert res.status_code == 404


# ---------------------------------------------------------------------------
# github_app.py
# ---------------------------------------------------------------------------


def test_sync_now_requires_global_admin(client, engine):
    client, uid = _login(client, engine, role=UserRole.SECURITY_ENGINEER)

    res = client.post("/api/github-app/sync")
    assert res.status_code == 403


def test_sync_now_allows_admin(client, engine, monkeypatch):
    import app.api.github_app as github_app_api

    monkeypatch.setattr(github_app_api, "_sync_repos", lambda session: [])
    client, uid = _login(client, engine, role=UserRole.ADMIN)

    res = client.post("/api/github-app/sync")
    assert res.status_code == 200


# ---------------------------------------------------------------------------
# pr_guardrail.py: ignore-action endpoints
# ---------------------------------------------------------------------------


def _make_pr_finding(engine, target_id: int) -> int:
    pr_scan_id = _make_pr_scan(engine, target_id)
    with Session(engine) as session:
        finding = PRGuardrailFinding(
            pr_scan_id=pr_scan_id, tool="semgrep", rule_id="r1", title="t", file_path="a.py", severity="High",
        )
        session.add(finding)
        session.commit()
        session.refresh(finding)
        return finding.id


def test_request_ignore_on_other_workspace_finding_returns_404(client, engine):
    ws_a, ws_b, target_a, target_b = _two_workspace_targets(engine)
    finding_id = _make_pr_finding(engine, target_b)
    client, uid = _login(client, engine, role=UserRole.DEVELOPER)
    _assign(engine, uid, ws_a, role=WorkspaceRole.DEVELOPER)

    res = client.post(f"/api/pr-guardrail/findings/{finding_id}/request-ignore", json={"reason": "fp"})
    assert res.status_code == 404


def test_global_security_engineer_cannot_approve_ignore_outside_own_workspace(client, engine):
    """The core cross-tenant escalation: a global security_engineer role
    granted for Workspace A must not be usable to approve/reject/revoke an
    ignore on a finding that belongs to Workspace B, just because
    require_security_reviewer only ever checked the caller's *global* role."""
    ws_a, ws_b, target_a, target_b = _two_workspace_targets(engine)
    finding_id = _make_pr_finding(engine, target_b)
    client, uid = _login(client, engine, role=UserRole.SECURITY_ENGINEER)
    _assign(engine, uid, ws_a, role=WorkspaceRole.SECURITY_ENGINEER)

    res = client.post(f"/api/pr-guardrail/findings/{finding_id}/approve-ignore")
    assert res.status_code == 404


def test_global_security_engineer_cannot_reject_ignore_outside_own_workspace(client, engine):
    ws_a, ws_b, target_a, target_b = _two_workspace_targets(engine)
    finding_id = _make_pr_finding(engine, target_b)
    client, uid = _login(client, engine, role=UserRole.SECURITY_ENGINEER)
    _assign(engine, uid, ws_a, role=WorkspaceRole.SECURITY_ENGINEER)

    res = client.post(f"/api/pr-guardrail/findings/{finding_id}/reject-ignore", json={"reason": "no"})
    assert res.status_code == 404


def test_global_security_engineer_cannot_revoke_ignore_outside_own_workspace(client, engine):
    ws_a, ws_b, target_a, target_b = _two_workspace_targets(engine)
    finding_id = _make_pr_finding(engine, target_b)
    with Session(engine) as session:
        finding = session.get(PRGuardrailFinding, finding_id)
        from app.models.models import IgnoreStatus

        finding.ignore_status = IgnoreStatus.APPROVED
        session.add(finding)
        session.commit()
    client, uid = _login(client, engine, role=UserRole.SECURITY_ENGINEER)
    _assign(engine, uid, ws_a, role=WorkspaceRole.SECURITY_ENGINEER)

    res = client.post(f"/api/pr-guardrail/findings/{finding_id}/revoke-ignore")
    assert res.status_code == 404


def test_security_engineer_can_approve_ignore_in_own_workspace(client, engine, monkeypatch):
    import app.core.pr_guardrail_executor as pr_guardrail_executor

    monkeypatch.setattr(
        pr_guardrail_executor, "github_get",
        lambda *a, **k: type("R", (), {"raise_for_status": lambda self: None, "json": lambda self: {"head": {"sha": "abc"}}})(),
    )
    monkeypatch.setattr(pr_guardrail_executor, "set_commit_status", lambda *a, **k: None)

    ws_a, ws_b, target_a, target_b = _two_workspace_targets(engine)
    finding_id = _make_pr_finding(engine, target_a)
    client, uid = _login(client, engine, role=UserRole.SECURITY_ENGINEER)
    _assign(engine, uid, ws_a, role=WorkspaceRole.SECURITY_ENGINEER)

    res = client.post(f"/api/pr-guardrail/findings/{finding_id}/approve-ignore")
    assert res.status_code == 200


# ---------------------------------------------------------------------------
# pr_guardrail.py: /log?target_id= and the approval-queue lists
# ---------------------------------------------------------------------------


def test_pr_guardrail_log_for_other_workspace_target_returns_404(client, engine):
    ws_a, ws_b, target_a, target_b = _two_workspace_targets(engine)
    client, uid = _login(client, engine, role=UserRole.VIEWER)
    _assign(engine, uid, ws_a)

    res = client.get(f"/api/pr-guardrail/log?target_id={target_b}")
    assert res.status_code == 404


def test_pending_ignore_queue_only_shows_callers_own_workspace(client, engine):
    ws_a, ws_b, target_a, target_b = _two_workspace_targets(engine)
    finding_a = _make_pr_finding(engine, target_a)
    finding_b = _make_pr_finding(engine, target_b)
    with Session(engine) as session:
        from app.models.models import IgnoreStatus

        for fid in (finding_a, finding_b):
            f = session.get(PRGuardrailFinding, fid)
            f.ignore_status = IgnoreStatus.REQUESTED
            session.add(f)
        session.commit()

    client, uid = _login(client, engine, role=UserRole.SECURITY_ENGINEER)
    _assign(engine, uid, ws_a, role=WorkspaceRole.SECURITY_ENGINEER)

    res = client.get("/api/pr-guardrail/ignore-requests/pending")
    assert res.status_code == 200
    ids = [f["id"] for f in res.json()["items"]]
    assert finding_a in ids
    assert finding_b not in ids
    assert res.json()["total"] == 1


# ---------------------------------------------------------------------------
# webhooks.py: signature verification must not authorize acting on a
# different tenant's target than the one the firing installation belongs to.
# ---------------------------------------------------------------------------


def _sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def test_webhook_cannot_forge_an_event_against_another_workspaces_target(client, engine, monkeypatch):
    """The core cross-tenant webhook forgery: Workspace A legitimately owns
    a real App/installation and therefore knows its own real webhook
    secret. A payload signed with that real secret but naming Workspace B's
    registered repo in `repository.clone_url` must NOT be treated as
    authorized to act on Workspace B's Target -- a valid signature only
    proves *someone* has a real secret, not that they're entitled to touch
    the repo the same (attacker-controlled) body happens to name."""
    import app.api.webhooks as webhooks_module

    monkeypatch.setattr(webhooks_module, "engine", engine)

    ws_a = _make_workspace(engine, "p3-webhook-ws-a")
    ws_b = _make_workspace(engine, "p3-webhook-ws-b")
    target_b = _make_target(engine, ws_b, "victim-repo")
    with Session(engine) as session:
        from app.models.models import Target as TargetModel

        t = session.get(TargetModel, target_b)
        t.repo_url = "https://github.com/victim-org/victim-repo"
        session.add(t)
        session.commit()

        cfg_a = GitHubAppConfig(
            app_id="1", slug="app-a", client_id="c", client_secret="s", private_key_pem="pem",
            webhook_secret=encrypt_secret("workspace-a-real-secret"), html_url="https://github.com/apps/app-a",
            workspace_id=ws_a,
        )
        session.add(cfg_a)
        session.commit()
        session.refresh(cfg_a)

        inst_a = GitHubInstallation(
            installation_id=555, account_login="attacker-org", account_type="Organization",
            workspace_id=ws_a, github_app_config_id=cfg_a.id,
        )
        session.add(inst_a)
        session.commit()

    body = (
        b'{"installation": {"id": 555}, "ref": "refs/heads/main", '
        b'"repository": {"clone_url": "https://github.com/victim-org/victim-repo"}}'
    )
    sig = _sign("workspace-a-real-secret", body)

    res = client.post(
        "/api/webhooks/github",
        content=body,
        headers={"X-Hub-Signature-256": sig, "X-GitHub-Event": "push", "Content-Type": "application/json"},
    )
    assert res.status_code == 200
    assert res.json() == {"ok": True, "skipped": "no matching target"}


def test_webhook_from_the_targets_own_installation_is_accepted(client, engine, monkeypatch):
    """Same shape as above, but the signature comes from the installation
    that actually owns the named target's workspace -- must still work."""
    from app.tasks import scan_tasks
    import app.api.webhooks as webhooks_module

    monkeypatch.setattr(webhooks_module, "engine", engine)
    monkeypatch.setattr(scan_tasks.queue_full_scan_for_target_task, "delay", lambda *a, **k: None)

    ws = _make_workspace(engine, "p3-webhook-ws-legit")
    target_id = _make_target(engine, ws, "own-repo")
    with Session(engine) as session:
        from app.models.models import Target as TargetModel

        t = session.get(TargetModel, target_id)
        t.repo_url = "https://github.com/own-org/own-repo"
        session.add(t)
        session.commit()

        cfg = GitHubAppConfig(
            app_id="2", slug="app-legit", client_id="c", client_secret="s", private_key_pem="pem",
            webhook_secret=encrypt_secret("legit-secret"), html_url="https://github.com/apps/app-legit",
            workspace_id=ws,
        )
        session.add(cfg)
        session.commit()
        session.refresh(cfg)

        inst = GitHubInstallation(
            installation_id=777, account_login="own-org", account_type="Organization",
            workspace_id=ws, github_app_config_id=cfg.id,
        )
        session.add(inst)
        session.commit()

    body = (
        b'{"installation": {"id": 777}, "ref": "refs/heads/main", '
        b'"repository": {"clone_url": "https://github.com/own-org/own-repo"}}'
    )
    sig = _sign("legit-secret", body)

    res = client.post(
        "/api/webhooks/github",
        content=body,
        headers={"X-Hub-Signature-256": sig, "X-GitHub-Event": "push", "Content-Type": "application/json"},
    )
    assert res.status_code == 200
    assert res.json()["queued"] is True


def test_webhook_resolves_the_right_workspaces_target_when_repo_url_is_duplicated(client, engine, monkeypatch):
    """CodeRabbit review on #540: the pre-fix query picked the first Target
    matching repo_url across ALL workspaces, then compared workspace ids
    after the fact. If two workspaces ever register the same clone_url, an
    unscoped `.first()` could return the OTHER workspace's row and reject a
    perfectly legitimate delivery. Filtering the query itself by
    installation_workspace_id must resolve to the correct target instead."""
    import app.api.webhooks as webhooks_module
    from app.tasks import scan_tasks

    monkeypatch.setattr(webhooks_module, "engine", engine)
    monkeypatch.setattr(scan_tasks.queue_full_scan_for_target_task, "delay", lambda *a, **k: None)

    shared_url = "https://github.com/shared-name/repo"
    ws_a = _make_workspace(engine, "p3-dup-ws-a")
    ws_b = _make_workspace(engine, "p3-dup-ws-b")
    with Session(engine) as session:
        from app.models.models import Target as TargetModel

        # Both workspaces happen to have registered a target with the same
        # clone_url (a plausible real scenario: someone re-registers, or a
        # fork, under a different tenant). target_a is created first, so an
        # unscoped `.first()` would return it even for a webhook that
        # actually belongs to workspace B.
        target_a = TargetModel(workspace_id=ws_a, name="a", repo_url=shared_url, default_branch="main")
        session.add(target_a)
        session.commit()
        session.refresh(target_a)
        target_b = TargetModel(workspace_id=ws_b, name="b", repo_url=shared_url, default_branch="main")
        session.add(target_b)
        session.commit()
        session.refresh(target_b)
        target_b_id = target_b.id

        cfg_b = GitHubAppConfig(
            app_id="3", slug="app-b", client_id="c", client_secret="s", private_key_pem="pem",
            webhook_secret=encrypt_secret("secret-b"), html_url="https://github.com/apps/app-b",
            workspace_id=ws_b,
        )
        session.add(cfg_b)
        session.commit()
        session.refresh(cfg_b)

        inst_b = GitHubInstallation(
            installation_id=888, account_login="org-b", account_type="Organization",
            workspace_id=ws_b, github_app_config_id=cfg_b.id,
        )
        session.add(inst_b)
        session.commit()

    body = (
        b'{"installation": {"id": 888}, "ref": "refs/heads/main", '
        b'"repository": {"clone_url": "' + shared_url.encode() + b'"}}'
    )
    sig = _sign("secret-b", body)

    res = client.post(
        "/api/webhooks/github",
        content=body,
        headers={"X-Hub-Signature-256": sig, "X-GitHub-Event": "push", "Content-Type": "application/json"},
    )
    assert res.status_code == 200
    body_json = res.json()
    assert body_json["queued"] is True
    assert body_json["target_id"] == target_b_id


def test_installation_repositories_webhook_syncs_only_the_firing_installation(client, engine, monkeypatch):
    """CodeRabbit + human review on #540: the installation_repositories
    handler used to call the no-arg sync_repos_task, resyncing every
    workspace's installations platform-wide off of any one valid webhook
    signature -- the exact reach POST /api/github-app/sync is admin-gated
    for. Must be scoped to the firing installation only."""
    import app.api.webhooks as webhooks_module

    monkeypatch.setattr(webhooks_module, "engine", engine)

    ws = _make_workspace(engine, "p3-instrepos-ws")
    with Session(engine) as session:
        cfg = GitHubAppConfig(
            app_id="4", slug="app-instrepos", client_id="c", client_secret="s", private_key_pem="pem",
            webhook_secret=encrypt_secret("instrepos-secret"), html_url="https://github.com/apps/app-instrepos",
            workspace_id=ws,
        )
        session.add(cfg)
        session.commit()
        session.refresh(cfg)

        inst = GitHubInstallation(
            installation_id=999, account_login="org-instrepos", account_type="Organization",
            workspace_id=ws, github_app_config_id=cfg.id,
        )
        session.add(inst)
        session.commit()

    calls = []
    from app.tasks import github_sync_tasks

    monkeypatch.setattr(github_sync_tasks.sync_repos_task, "delay", lambda *a, **k: calls.append(k))

    body = b'{"action": "added", "installation": {"id": 999}}'
    sig = _sign("instrepos-secret", body)

    res = client.post(
        "/api/webhooks/github",
        content=body,
        headers={
            "X-Hub-Signature-256": sig,
            "X-GitHub-Event": "installation_repositories",
            "Content-Type": "application/json",
        },
    )
    assert res.status_code == 200
    assert res.json()["queued"] is True
    assert calls == [{"installation_id": 999}]


def test_a_fallback_verified_signature_cannot_bind_to_the_claimed_installations_workspace(engine):
    """Human review on #540: a signature that only verifies via the
    try-every-config fallback (_candidate_configs' `narrowed=False` path)
    proves someone knows *some* real secret, never that they own the
    installation the payload names. `_verify_signature` must surface that
    distinction so callers never resolve a workspace from an unnarrowed
    match's claimed installation id."""
    import app.api.webhooks as webhooks_module

    ws_a = _make_workspace(engine, "p3-fallback-ws-a")
    with Session(engine) as session:
        cfg_a = GitHubAppConfig(
            app_id="5", slug="app-fallback-a", client_id="c", client_secret="s", private_key_pem="pem",
            webhook_secret=encrypt_secret("fallback-secret-a"), html_url="https://github.com/apps/app-fallback-a",
            workspace_id=ws_a,
        )
        session.add(cfg_a)
        session.commit()
        session.refresh(cfg_a)

        inst_a = GitHubInstallation(
            installation_id=1010, account_login="org-fallback-a", account_type="Organization",
            workspace_id=ws_a, github_app_config_id=cfg_a.id,
        )
        session.add(inst_a)
        session.commit()

    body = b'{"action": "opened"}'
    sig = _sign("fallback-secret-a", body)

    with Session(engine) as session:
        # payload_installation_id=None (no id claimed at all, or one that
        # doesn't resolve): _candidate_configs falls back to trying every
        # configured App's secret, matches cfg_a's, but that is NOT the
        # same thing as proving ownership of a specific installation.
        verified, narrowed = webhooks_module._verify_signature(body, sig, session, payload_installation_id=None)
        assert verified is True
        assert narrowed is False
