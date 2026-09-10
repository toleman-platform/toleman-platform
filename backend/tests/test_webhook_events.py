"""Tests for the three webhook event handlers added alongside pull_request
(app/api/webhooks.py): push (re-scan a target's default branch), and
issue_comment (`@toleman ignore finding=<id> <reason>`). Plumbing for
installation_repositories tested where it dispatches; the actual
resync logic itself is app.api.github_app._sync_repos's own coverage.
"""
import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

from app.api import webhooks
from app.models.models import (
    IgnoreStatus,
    Organization,
    PRGuardrailFinding,
    PRGuardrailScan,
    Target,
    Workspace,
)


@pytest.fixture()
def engine():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(eng)
    return eng


@pytest.fixture()
def target_id(engine):
    with Session(engine) as session:
        org = Organization(name="org")
        session.add(org)
        session.commit()
        session.refresh(org)
        ws = Workspace(organization_id=org.id, name="ws", api_key="k")
        session.add(ws)
        session.commit()
        session.refresh(ws)
        t = Target(workspace_id=ws.id, name="repo", repo_url="https://github.com/acme/repo", default_branch="main")
        session.add(t)
        session.commit()
        session.refresh(t)
        return t.id


class TestPushHandler:
    def test_push_to_default_branch_queues_a_scan(self, engine, target_id, monkeypatch):
        from app.tasks import scan_tasks

        calls = []
        monkeypatch.setattr(scan_tasks.queue_full_scan_for_target_task, "delay", lambda *a, **k: calls.append(a))

        with Session(engine) as session:
            result = webhooks._handle_push(
                session,
                {"ref": "refs/heads/main", "repository": {"clone_url": "https://github.com/acme/repo"}},
            )

        assert result["queued"] is True
        assert calls == [(target_id,)]

    def test_push_to_a_feature_branch_is_skipped(self, engine, target_id, monkeypatch):
        from app.tasks import scan_tasks

        calls = []
        monkeypatch.setattr(scan_tasks.queue_full_scan_for_target_task, "delay", lambda *a, **k: calls.append(a))

        with Session(engine) as session:
            result = webhooks._handle_push(
                session,
                {"ref": "refs/heads/feature-x", "repository": {"clone_url": "https://github.com/acme/repo"}},
            )

        assert "skipped" in result
        assert calls == []

    def test_deleted_branch_push_is_skipped(self, engine, target_id, monkeypatch):
        from app.tasks import scan_tasks

        calls = []
        monkeypatch.setattr(scan_tasks.queue_full_scan_for_target_task, "delay", lambda *a, **k: calls.append(a))

        with Session(engine) as session:
            result = webhooks._handle_push(
                session,
                {
                    "ref": "refs/heads/main",
                    "deleted": True,
                    "repository": {"clone_url": "https://github.com/acme/repo"},
                },
            )

        assert "skipped" in result
        assert calls == []

    def test_push_with_no_matching_target_is_skipped(self, engine, target_id):
        with Session(engine) as session:
            result = webhooks._handle_push(
                session,
                {"ref": "refs/heads/main", "repository": {"clone_url": "https://github.com/no-such/repo"}},
            )
        assert result == {"ok": True, "skipped": "no matching target"}


class TestInstallationRepositoriesHandler:
    def test_added_queues_a_resync(self, monkeypatch):
        from app.tasks import github_sync_tasks

        calls = []
        monkeypatch.setattr(github_sync_tasks.sync_repos_task, "delay", lambda *a, **k: calls.append(a))

        result = webhooks._handle_installation_repositories({"action": "added"})

        assert result["queued"] is True
        assert calls == [()]

    def test_removed_does_not_delete_anything(self, monkeypatch):
        from app.tasks import github_sync_tasks

        calls = []
        monkeypatch.setattr(github_sync_tasks.sync_repos_task, "delay", lambda *a, **k: calls.append(a))

        result = webhooks._handle_installation_repositories({"action": "removed"})

        assert "skipped" in result
        assert calls == []


class TestIssueCommentHandler:
    def _finding(self, session, target_id, pr_number=7):
        scan = PRGuardrailScan(target_id=target_id, pr_number=pr_number, branch="feature")
        session.add(scan)
        session.commit()
        session.refresh(scan)
        finding = PRGuardrailFinding(
            pr_scan_id=scan.id, tool="semgrep", rule_id="r1", title="t", file_path="f.py", severity="High"
        )
        session.add(finding)
        session.commit()
        session.refresh(finding)
        return finding

    def _payload(self, finding_id, pr_number=7, association="COLLABORATOR", body_extra=""):
        return {
            "action": "created",
            "issue": {"number": pr_number, "pull_request": {}},
            "comment": {
                "body": f"@toleman ignore finding={finding_id} false positive, see line 12{body_extra}",
                "author_association": association,
                "user": {"login": "alice"},
            },
            "repository": {"clone_url": "https://github.com/acme/repo"},
        }

    def test_trusted_comment_requests_an_ignore(self, engine, target_id, monkeypatch):
        replies = []
        monkeypatch.setattr(webhooks, "reply_to_pr", lambda *a, **k: replies.append(a))

        with Session(engine) as session:
            finding = self._finding(session, target_id)
            result = webhooks._handle_issue_comment(session, self._payload(finding.id))

            assert result["ignore_requested"] is True
            refreshed = session.get(PRGuardrailFinding, finding.id)
            assert refreshed.ignore_status == IgnoreStatus.REQUESTED
            assert refreshed.ignore_requested_by == "github:alice"
            assert "false positive" in refreshed.ignore_requested_reason

        assert len(replies) == 1

    def test_untrusted_commenter_is_ignored(self, engine, target_id):
        with Session(engine) as session:
            finding = self._finding(session, target_id)
            payload = self._payload(finding.id, association="NONE")
            result = webhooks._handle_issue_comment(session, payload)

            assert "skipped" in result
            refreshed = session.get(PRGuardrailFinding, finding.id)
            assert refreshed.ignore_status == IgnoreStatus.NONE

    def test_finding_from_a_different_pr_is_rejected(self, engine, target_id):
        """The finding id in a comment is attacker-controlled: a trusted
        commenter on PR #7 must not be able to touch a finding that actually
        belongs to a different PR."""
        with Session(engine) as session:
            finding = self._finding(session, target_id, pr_number=7)
            payload = self._payload(finding.id, pr_number=999)
            result = webhooks._handle_issue_comment(session, payload)

            assert result == {"ok": True, "skipped": "finding does not belong to this PR"}
            refreshed = session.get(PRGuardrailFinding, finding.id)
            assert refreshed.ignore_status == IgnoreStatus.NONE

    def test_comment_on_a_plain_issue_is_ignored(self, engine, target_id):
        with Session(engine) as session:
            finding = self._finding(session, target_id)
            payload = self._payload(finding.id)
            del payload["issue"]["pull_request"]
            result = webhooks._handle_issue_comment(session, payload)
            assert result == {"ok": True, "skipped": "not a PR comment"}

    def test_comment_without_the_command_is_ignored(self, engine, target_id):
        with Session(engine) as session:
            finding = self._finding(session, target_id)
            payload = self._payload(finding.id)
            payload["comment"]["body"] = "looks good to me!"
            result = webhooks._handle_issue_comment(session, payload)
            assert result == {"ok": True, "skipped": "no ignore command"}

    def test_nonexistent_finding_id_is_ignored(self, engine, target_id):
        with Session(engine) as session:
            payload = self._payload(finding_id=999999)
            result = webhooks._handle_issue_comment(session, payload)
            assert result == {"ok": True, "skipped": "finding not found"}
