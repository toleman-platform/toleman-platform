"""Tests for the three webhook event handlers added alongside pull_request
(app/api/webhooks.py): push (re-scan a target's default branch), and
issue_comment (`@toleman ignore finding=<id>[,<id>...] <reason>`). Plumbing
for installation_repositories tested where it dispatches; the actual
resync logic itself is app.api.github_app._sync_repos's own coverage.

Also covers _handle_pr_merged: `push` turned out not to reliably deliver in
practice even when correctly subscribed+saved (confirmed live via GitHub's
own Recent Deliveries page -- zero push deliveries across dozens of real
pushes/merges in the same window pull_request deliveries for those same
commits arrived fine for), so pull_request.closed(merged=true) is now a
second, more reliable trigger for the same "reflect a merged fix" goal.

And TestPullRequestHandler (#401): the ordinary opened/reopened/synchronize
trigger now creates the PRGuardrailScan row itself, synchronously, before
dispatching the scan task, so the dashboard has something to show as
"running" from the moment the webhook lands rather than only once the task
gets around to its own GitHub-API PR fetch.
"""
import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

from app.api import webhooks
from app.models.models import (
    IgnoreStatus,
    Organization,
    PRGuardrailFinding,
    PRGuardrailScan,
    PRGuardrailStatus,
    Target,
    Workspace,
)


@pytest.fixture()
def engine():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(eng)
    return eng


@pytest.fixture()
def workspace_id(engine):
    with Session(engine) as session:
        org = Organization(name="org")
        session.add(org)
        session.commit()
        session.refresh(org)
        ws = Workspace(organization_id=org.id, name="ws", api_key="k")
        session.add(ws)
        session.commit()
        session.refresh(ws)
        return ws.id


@pytest.fixture()
def target_id(engine, workspace_id):
    with Session(engine) as session:
        t = Target(
            workspace_id=workspace_id, name="repo", repo_url="https://github.com/acme/repo", default_branch="main"
        )
        session.add(t)
        session.commit()
        session.refresh(t)
        return t.id


class TestPushHandler:
    def test_push_to_default_branch_queues_a_scan(self, engine, target_id, workspace_id, monkeypatch):
        from app.tasks import scan_tasks

        calls = []
        monkeypatch.setattr(scan_tasks.queue_full_scan_for_target_task, "delay", lambda *a, **k: calls.append(a))

        with Session(engine) as session:
            result = webhooks._handle_push(
                session,
                {"ref": "refs/heads/main", "repository": {"clone_url": "https://github.com/acme/repo"}},
            workspace_id,
            )

        assert result["queued"] is True
        assert calls == [(target_id,)]

    def test_push_to_a_feature_branch_is_skipped(self, engine, target_id, workspace_id, monkeypatch):
        from app.tasks import scan_tasks

        calls = []
        monkeypatch.setattr(scan_tasks.queue_full_scan_for_target_task, "delay", lambda *a, **k: calls.append(a))

        with Session(engine) as session:
            result = webhooks._handle_push(
                session,
                {"ref": "refs/heads/feature-x", "repository": {"clone_url": "https://github.com/acme/repo"}},
            workspace_id,
            )

        assert "skipped" in result
        assert calls == []

    def test_deleted_branch_push_is_skipped(self, engine, target_id, workspace_id, monkeypatch):
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
            workspace_id,
            )

        assert "skipped" in result
        assert calls == []

    def test_push_with_no_matching_target_is_skipped(self, engine, target_id, workspace_id):
        with Session(engine) as session:
            result = webhooks._handle_push(
                session,
                {"ref": "refs/heads/main", "repository": {"clone_url": "https://github.com/no-such/repo"}},
            workspace_id,
            )
        assert result == {"ok": True, "skipped": "no matching target"}


class TestPullRequestHandler:
    """#401: the ordinary opened/reopened/synchronize trigger must create
    the PRGuardrailScan row itself, synchronously, before dispatching the
    scan task -- not leave the dashboard with nothing to show as "running"
    until the task gets around to its own GitHub-API PR fetch."""

    def _payload(self, action="opened", pr_number=7, title="Add feature", head_ref="feature-x", head_sha="deadbeef"):
        return {
            "action": action,
            "number": pr_number,
            "pull_request": {"title": title, "head": {"ref": head_ref, "sha": head_sha}},
            "repository": {"clone_url": "https://github.com/acme/repo"},
        }

    def test_opened_creates_a_running_placeholder_before_dispatch(self, engine, target_id, workspace_id, monkeypatch):
        from app.tasks import pr_guardrail_tasks

        calls = []
        monkeypatch.setattr(pr_guardrail_tasks.run_pr_guardrail_scan_task, "delay", lambda *a, **k: calls.append(a))

        with Session(engine) as session:
            result = webhooks._handle_pull_request(session, self._payload(), workspace_id)

        assert result["queued"] is True
        pr_scan_id = result["pr_scan_id"]
        assert calls == [(target_id, 7, pr_scan_id)]

        with Session(engine) as session:
            pr_scan = session.get(PRGuardrailScan, pr_scan_id)
            assert pr_scan is not None
            assert pr_scan.target_id == target_id
            assert pr_scan.pr_number == 7
            assert pr_scan.status == PRGuardrailStatus.RUNNING
            # Straight from the webhook payload, no extra GitHub API call
            # needed to have something real to show immediately.
            assert pr_scan.pr_title == "Add feature"
            assert pr_scan.branch == "feature-x"

    def test_synchronize_also_creates_a_placeholder(self, engine, target_id, workspace_id, monkeypatch):
        from app.tasks import pr_guardrail_tasks

        monkeypatch.setattr(pr_guardrail_tasks.run_pr_guardrail_scan_task, "delay", lambda *a, **k: None)

        with Session(engine) as session:
            result = webhooks._handle_pull_request(session, self._payload(action="synchronize"), workspace_id)

        with Session(engine) as session:
            assert session.get(PRGuardrailScan, result["pr_scan_id"]).status == PRGuardrailStatus.RUNNING

    def test_no_matching_target_creates_no_placeholder(self, engine, target_id, workspace_id, monkeypatch):
        from app.tasks import pr_guardrail_tasks

        calls = []
        monkeypatch.setattr(pr_guardrail_tasks.run_pr_guardrail_scan_task, "delay", lambda *a, **k: calls.append(a))
        payload = self._payload()
        payload["repository"]["clone_url"] = "https://github.com/no-such/repo"

        with Session(engine) as session:
            result = webhooks._handle_pull_request(session, payload, workspace_id)
            assert result == {"ok": True, "skipped": "no matching target"}
            assert session.exec(select(PRGuardrailScan)).all() == []
        assert calls == []

    def test_closed_without_merging_creates_no_placeholder(self, engine, target_id, workspace_id, monkeypatch):
        from app.tasks import pr_guardrail_tasks

        calls = []
        monkeypatch.setattr(pr_guardrail_tasks.run_pr_guardrail_scan_task, "delay", lambda *a, **k: calls.append(a))
        payload = self._payload(action="closed")
        payload["pull_request"]["merged"] = False

        with Session(engine) as session:
            webhooks._handle_pull_request(session, payload, workspace_id)
            assert session.exec(select(PRGuardrailScan)).all() == []
        assert calls == []

    def test_opened_posts_a_pending_commit_status_immediately(self, engine, target_id, workspace_id, monkeypatch):
        """GitHub's own PR checks list had the identical gap #401 fixed for
        Toleman's dashboard: set_commit_status was only ever called once the
        scan finished, so "toleman/pr-guardrail" never appeared in that list
        at all until it was already done -- indistinguishable from the check
        not existing."""
        from app.tasks import pr_guardrail_tasks

        monkeypatch.setattr(pr_guardrail_tasks.run_pr_guardrail_scan_task, "delay", lambda *a, **k: None)
        status_calls = []
        monkeypatch.setattr(webhooks, "set_commit_status", lambda *a, **k: status_calls.append(a))

        with Session(engine) as session:
            target = session.get(Target, target_id)
            webhooks._handle_pull_request(session, self._payload(head_sha="cafef00d"), workspace_id)
            assert status_calls == [(session, target, "cafef00d", "pending", "Scanning...")]

    def test_disabled_enforcement_mode_skips_placeholder_and_pending_status(self, engine, target_id, workspace_id, monkeypatch):
        """"disabled" means no clone, no PRGuardrailScan row, no PR comment,
        no commit status at all -- a disabled target must not get a
        placeholder row or a "pending" status that nothing will ever
        resolve."""
        from app.tasks import pr_guardrail_tasks

        with Session(engine) as session:
            target = session.get(Target, target_id)
            target.enforcement_mode = "disabled"
            session.add(target)
            session.commit()

        dispatch_calls = []
        status_calls = []
        monkeypatch.setattr(pr_guardrail_tasks.run_pr_guardrail_scan_task, "delay", lambda *a, **k: dispatch_calls.append(a))
        monkeypatch.setattr(webhooks, "set_commit_status", lambda *a, **k: status_calls.append(a))

        with Session(engine) as session:
            result = webhooks._handle_pull_request(session, self._payload(), workspace_id)
            assert result == {"ok": True, "skipped": "enforcement_mode=disabled"}
            assert session.exec(select(PRGuardrailScan)).all() == []
        assert dispatch_calls == []
        assert status_calls == []


class TestPullRequestMergedHandler:
    def _payload(self, merged=True, action="closed", base_ref="main"):
        return {
            "action": action,
            "number": 7,
            "pull_request": {"merged": merged, "base": {"ref": base_ref}},
            "repository": {"clone_url": "https://github.com/acme/repo"},
        }

    def test_merged_pr_into_default_branch_queues_a_full_scan(self, engine, target_id, workspace_id, monkeypatch):
        from app.tasks import scan_tasks

        calls = []
        monkeypatch.setattr(scan_tasks.queue_full_scan_for_target_task, "delay", lambda *a, **k: calls.append(a))

        with Session(engine) as session:
            result = webhooks._handle_pull_request(session, self._payload(), workspace_id)

        assert result["queued"] is True
        assert calls == [(target_id,)]

    def test_closed_without_merging_does_not_queue_a_scan(self, engine, target_id, workspace_id, monkeypatch):
        """A closed-but-not-merged PR (abandoned) changed nothing on the
        default branch; nothing to re-scan for."""
        from app.tasks import pr_guardrail_tasks, scan_tasks

        calls = []
        monkeypatch.setattr(scan_tasks.queue_full_scan_for_target_task, "delay", lambda *a, **k: calls.append(a))
        monkeypatch.setattr(pr_guardrail_tasks.run_pr_guardrail_scan_task, "delay", lambda *a, **k: calls.append(a))

        with Session(engine) as session:
            result = webhooks._handle_pull_request(session, self._payload(merged=False), workspace_id)

        assert "skipped" in result
        assert calls == []

    def test_merged_into_non_default_branch_is_skipped(self, engine, target_id, workspace_id, monkeypatch):
        from app.tasks import scan_tasks

        calls = []
        monkeypatch.setattr(scan_tasks.queue_full_scan_for_target_task, "delay", lambda *a, **k: calls.append(a))

        with Session(engine) as session:
            result = webhooks._handle_pull_request(session, self._payload(base_ref="release-branch"), workspace_id)

        assert "skipped" in result
        assert calls == []

    def test_merged_pr_with_no_matching_target_is_skipped(self, engine, target_id, workspace_id, monkeypatch):
        from app.tasks import scan_tasks

        calls = []
        monkeypatch.setattr(scan_tasks.queue_full_scan_for_target_task, "delay", lambda *a, **k: calls.append(a))

        payload = self._payload()
        payload["repository"]["clone_url"] = "https://github.com/no-such/repo"

        with Session(engine) as session:
            result = webhooks._handle_pull_request(session, payload, workspace_id)

        assert result == {"ok": True, "skipped": "no matching target"}
        assert calls == []

    def test_opened_action_still_triggers_the_ordinary_pr_scan_not_a_full_scan(self, engine, target_id, workspace_id, monkeypatch):
        """A merged-PR full scan and the ordinary PR-diff guardrail scan are
        separate paths; opening a PR must still hit the latter, not get
        mistakenly routed into the former."""
        from app.tasks import pr_guardrail_tasks, scan_tasks

        pr_calls = []
        full_scan_calls = []
        monkeypatch.setattr(pr_guardrail_tasks.run_pr_guardrail_scan_task, "delay", lambda *a, **k: pr_calls.append(a))
        monkeypatch.setattr(
            scan_tasks.queue_full_scan_for_target_task, "delay", lambda *a, **k: full_scan_calls.append(a)
        )

        with Session(engine) as session:
            result = webhooks._handle_pull_request(session, self._payload(action="opened", merged=False), workspace_id)

        assert result["queued"] is True
        assert pr_calls == [(target_id, 7, result["pr_scan_id"])]
        assert full_scan_calls == []


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

    def test_trusted_comment_requests_an_ignore(self, engine, target_id, workspace_id, monkeypatch):
        replies = []
        monkeypatch.setattr(webhooks, "reply_to_pr", lambda *a, **k: replies.append(a))

        with Session(engine) as session:
            finding = self._finding(session, target_id)
            result = webhooks._handle_issue_comment(session, self._payload(finding.id), workspace_id)

            assert result["ignore_requested"] is True
            refreshed = session.get(PRGuardrailFinding, finding.id)
            assert refreshed.ignore_status == IgnoreStatus.REQUESTED
            assert refreshed.ignore_requested_by == "github:alice"
            assert "false positive" in refreshed.ignore_requested_reason

        assert len(replies) == 1

    def test_untrusted_commenter_is_ignored(self, engine, target_id, workspace_id):
        with Session(engine) as session:
            finding = self._finding(session, target_id)
            payload = self._payload(finding.id, association="NONE")
            result = webhooks._handle_issue_comment(session, payload, workspace_id)

            assert "skipped" in result
            refreshed = session.get(PRGuardrailFinding, finding.id)
            assert refreshed.ignore_status == IgnoreStatus.NONE

    def test_finding_from_a_different_pr_is_rejected(self, engine, target_id, workspace_id):
        """The finding id in a comment is attacker-controlled: a trusted
        commenter on PR #7 must not be able to touch a finding that actually
        belongs to a different PR."""
        with Session(engine) as session:
            finding = self._finding(session, target_id, pr_number=7)
            payload = self._payload(finding.id, pr_number=999)
            result = webhooks._handle_issue_comment(session, payload, workspace_id)

            assert result == {"ok": True, "skipped": "finding does not belong to this PR"}
            refreshed = session.get(PRGuardrailFinding, finding.id)
            assert refreshed.ignore_status == IgnoreStatus.NONE

    def test_comment_on_a_plain_issue_is_ignored(self, engine, target_id, workspace_id):
        with Session(engine) as session:
            finding = self._finding(session, target_id)
            payload = self._payload(finding.id)
            del payload["issue"]["pull_request"]
            result = webhooks._handle_issue_comment(session, payload, workspace_id)
            assert result == {"ok": True, "skipped": "not a PR comment"}

    def test_comment_without_the_command_is_ignored(self, engine, target_id, workspace_id):
        with Session(engine) as session:
            finding = self._finding(session, target_id)
            payload = self._payload(finding.id)
            payload["comment"]["body"] = "looks good to me!"
            result = webhooks._handle_issue_comment(session, payload, workspace_id)
            assert result == {"ok": True, "skipped": "no ignore command"}

    def test_nonexistent_finding_id_is_ignored(self, engine, target_id, workspace_id):
        with Session(engine) as session:
            payload = self._payload(finding_id=999999)
            result = webhooks._handle_issue_comment(session, payload, workspace_id)
            assert result == {"ok": True, "skipped": "finding not found"}

    def test_comma_separated_finding_ids_all_requested_in_one_command(self, engine, target_id, workspace_id, monkeypatch):
        replies = []
        monkeypatch.setattr(webhooks, "reply_to_pr", lambda *a, **k: replies.append(a))

        with Session(engine) as session:
            f1 = self._finding(session, target_id)
            f2 = self._finding(session, target_id)
            payload = self._payload(f1.id, body_extra="")
            payload["comment"]["body"] = f"@toleman ignore finding={f1.id},{f2.id} false positive, see line 12"
            result = webhooks._handle_issue_comment(session, payload, workspace_id)

            assert result["ignore_requested"] is True
            assert result["finding_ids"] == [f1.id, f2.id]
            assert "finding_id" not in result

            for f in (f1, f2):
                refreshed = session.get(PRGuardrailFinding, f.id)
                assert refreshed.ignore_status == IgnoreStatus.REQUESTED
                assert refreshed.ignore_requested_by == "github:alice"
                assert "false positive" in refreshed.ignore_requested_reason

        # One combined reply, not one per finding.
        assert len(replies) == 1

    def test_duplicate_ids_in_one_command_are_deduped(self, engine, target_id, workspace_id, monkeypatch):
        monkeypatch.setattr(webhooks, "reply_to_pr", lambda *a, **k: None)

        with Session(engine) as session:
            finding = self._finding(session, target_id)
            payload = self._payload(finding.id)
            payload["comment"]["body"] = f"@toleman ignore finding={finding.id},{finding.id} dup id typo"
            result = webhooks._handle_issue_comment(session, payload, workspace_id)

            assert result["finding_ids"] == [finding.id]
            assert result["finding_id"] == finding.id

    def test_bulk_command_with_one_bad_id_still_requests_the_good_ones(self, engine, target_id, workspace_id, monkeypatch):
        replies = []
        monkeypatch.setattr(webhooks, "reply_to_pr", lambda *a, **k: replies.append(a))

        with Session(engine) as session:
            f1 = self._finding(session, target_id)
            other_pr_finding = self._finding(session, target_id, pr_number=999)
            payload = self._payload(f1.id)
            payload["comment"]["body"] = (
                f"@toleman ignore finding={f1.id},{other_pr_finding.id},999999 false positive"
            )
            result = webhooks._handle_issue_comment(session, payload, workspace_id)

            assert result["ignore_requested"] is True
            assert result["finding_ids"] == [f1.id]
            assert result["skipped_finding_ids"] == {
                other_pr_finding.id: "finding does not belong to this PR",
                999999: "finding not found",
            }

            assert session.get(PRGuardrailFinding, f1.id).ignore_status == IgnoreStatus.REQUESTED
            assert session.get(PRGuardrailFinding, other_pr_finding.id).ignore_status == IgnoreStatus.NONE

        assert len(replies) == 1
        # The PUBLIC reply (unlike the handler's own result dict above) must
        # never distinguish "not found" from "belongs to a different PR" --
        # that would let anyone reading this PR's thread, not just the
        # trusted commenter, probe whether a guessed finding id exists
        # elsewhere.
        reply_body = replies[0][-1]
        assert f"#{other_pr_finding.id}" in reply_body
        assert "#999999" in reply_body
        assert "finding not found" not in reply_body
        assert "does not belong to this PR" not in reply_body

    def test_bulk_command_where_every_id_is_bad_is_skipped_with_no_reply(self, engine, target_id, workspace_id, monkeypatch):
        replies = []
        monkeypatch.setattr(webhooks, "reply_to_pr", lambda *a, **k: replies.append(a))

        with Session(engine) as session:
            other_pr_finding = self._finding(session, target_id, pr_number=999)
            payload = self._payload(other_pr_finding.id)
            payload["comment"]["body"] = f"@toleman ignore finding={other_pr_finding.id},999999 false positive"
            result = webhooks._handle_issue_comment(session, payload, workspace_id)

            assert result == {
                "ok": True,
                "skipped": "no listed finding id could be ignore-requested",
                "errors": {
                    other_pr_finding.id: "finding does not belong to this PR",
                    999999: "finding not found",
                },
            }

        assert replies == []
