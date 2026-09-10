"""GitHub webhook receiver: real-time triggers (as opposed to the on-demand
"Scan This PR" button in app/api/pr_guardrail.py and the manual "Sync now"
button in app/api/github_app.py).

Unauthenticated by necessity (GitHub calls this directly, no session cookie
available); trust is established via HMAC signature verification against
the App's webhook secret instead, same as any GitHub webhook integration.

GitHub's webhook delivery expects a fast response (~10s timeout), so any
real work (a scan, a repo sync) is dispatched to Celery rather than run
inline here.

Four event types handled, each independent of the others:
  - pull_request: the original PR Guardrail trigger (GH-03).
  - push: re-scan a target's default branch so the dashboard reflects a
    merged fix without depending on that target's own generated
    toleman-scan.yml having TOLEMAN_API_URL/TOLEMAN_API_KEY configured.
  - installation_repositories: auto-create/remove Targets when repo access
    changes on an existing installation, instead of only at initial install
    or a manually-clicked "Sync now".
  - issue_comment: `@toleman ignore finding=<id> <reason>` on a PR, the
    comment-driven equivalent of the "Request ignore" UI button.

None of these needed a new App permission scope (see github_app.py's
default_permissions comment), only a new entry in default_events -- but
that only affects an App created from here on; an already-installed App's
webhook event subscriptions are edited on its own GitHub settings page, not
retroactively by this file changing.
"""
import hashlib
import hmac
import logging
import re

from fastapi import APIRouter, Header, HTTPException, Request
from sqlmodel import Session, select

from app.core.crypto import decrypt_secret
from app.core.db import engine
from app.core.github_app import resolve_config_for_installation
from app.core.pr_guardrail_executor import reply_to_pr, submit_ignore_request
from app.models.models import GitHubAppConfig, GitHubInstallation, PRGuardrailFinding, PRGuardrailScan, Target

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/webhooks", tags=["webhooks"])

PR_TRIGGERING_ACTIONS = {"opened", "reopened", "synchronize"}

# `@toleman ignore finding=123 reason text...` anywhere in a comment, case-
# insensitive. Requires an explicit finding id rather than trying to infer
# "the" finding: PR Guardrail posts one summary comment per PR, not one per
# finding, so there is no comment thread naturally tied to a single finding
# the way an inline review comment would be -- a bare "@toleman ignore
# <reason>" would be ambiguous the moment a PR has more than one net-new
# finding.
IGNORE_COMMAND_RE = re.compile(
    r"@toleman\s+ignore\s+finding=(?P<finding_id>\d+)\s+(?P<reason>.+)", re.IGNORECASE
)

# Only these can create an ignore *request* from a comment (still goes to
# the security team for approval either way, see submit_ignore_request's
# docstring -- this isn't a trust boundary for suppressing findings, it's
# noise control so a random external commenter on a public repo can't spam
# the approval queue).
TRUSTED_COMMENT_ASSOCIATIONS = {"OWNER", "MEMBER", "COLLABORATOR"}


def _candidate_configs(session: Session, payload_installation_id: int | None) -> list[GitHubAppConfig]:
    """Which GitHubAppConfig(s) could plausibly have delivered this webhook
    (#34). Every GitHub App webhook delivery includes the firing
    installation's id in the payload, resolve straight to that
    installation's own App config when present (correct even with multiple
    Apps/installations). Falls back to trying every configured App's secret
    when the id is missing/unresolvable, so a delivery isn't rejected just
    because we can't pin down which App it came from up front."""
    if payload_installation_id is not None:
        installation = session.exec(
            select(GitHubInstallation).where(GitHubInstallation.installation_id == payload_installation_id)
        ).first()
        if installation:
            config = resolve_config_for_installation(session, installation)
            if config:
                return [config]
    return session.exec(select(GitHubAppConfig)).all()


def _verify_signature(
    raw_body: bytes, signature_header: str | None, session: Session, payload_installation_id: int | None = None
) -> bool:
    if not signature_header or not signature_header.startswith("sha256="):
        return False

    configs = _candidate_configs(session, payload_installation_id)
    if not configs:
        logger.warning("webhook: no GitHub App configured, rejecting delivery")
        return False

    for config in configs:
        if not config.webhook_secret:
            continue
        secret = decrypt_secret(config.webhook_secret)
        expected = "sha256=" + hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()
        if hmac.compare_digest(expected, signature_header):
            return True
    return False


def _handle_pull_request(session: Session, payload: dict) -> dict:
    action = payload.get("action")
    if action not in PR_TRIGGERING_ACTIONS:
        return {"ok": True, "skipped": f"action={action}"}

    repo_clone_url = payload.get("repository", {}).get("clone_url")
    pr_number = payload.get("number")
    target = session.exec(select(Target).where(Target.repo_url == repo_clone_url)).first()
    if not target:
        logger.info("webhook: no target registered for %s, ignoring", repo_clone_url)
        return {"ok": True, "skipped": "no matching target"}

    from app.tasks.pr_guardrail_tasks import run_pr_guardrail_scan_task

    run_pr_guardrail_scan_task.delay(target.id, pr_number)
    return {"ok": True, "queued": True, "target_id": target.id, "pr_number": pr_number}


def _handle_push(session: Session, payload: dict) -> dict:
    if payload.get("deleted"):
        # A branch delete is also delivered as a `push` with deleted=true
        # and a ref that no longer points anywhere; nothing to scan.
        return {"ok": True, "skipped": "branch deleted"}

    ref = payload.get("ref", "")
    repo_clone_url = payload.get("repository", {}).get("clone_url")
    target = session.exec(select(Target).where(Target.repo_url == repo_clone_url)).first()
    if not target:
        return {"ok": True, "skipped": "no matching target"}

    if ref != f"refs/heads/{target.default_branch}":
        # Pushes to any other branch already get scanned (if at all) via the
        # pull_request event above; scanning every feature-branch push here
        # too would duplicate that and burn Celery/scan budget for no gain.
        return {"ok": True, "skipped": f"not default branch (ref={ref})"}

    from app.tasks.scan_tasks import queue_full_scan_for_target_task

    queue_full_scan_for_target_task.delay(target.id)
    return {"ok": True, "queued": True, "target_id": target.id, "reason": "push to default branch"}


def _handle_installation_repositories(payload: dict) -> dict:
    action = payload.get("action")
    if action != "added":
        # "removed" is deliberately a no-op: deleting a Target on access
        # removal would also delete its finding history (or leave orphaned
        # rows if it doesn't), and "someone unchecked a repo in GitHub's
        # Configure screen" isn't consent to discard that. Left for a human
        # to do deliberately via existing target-management UI, same as
        # today.
        return {"ok": True, "skipped": f"installation_repositories action={action}"}

    from app.tasks.github_sync_tasks import sync_repos_task

    sync_repos_task.delay()
    return {"ok": True, "queued": True, "reason": "installation_repositories added"}


def _handle_issue_comment(session: Session, payload: dict) -> dict:
    if payload.get("action") != "created":
        return {"ok": True, "skipped": f"issue_comment action={payload.get('action')}"}

    issue = payload.get("issue") or {}
    if "pull_request" not in issue:
        # issue_comment fires for plain issues too, not just PRs; the
        # ignore-request command only makes sense on a PR (findings are
        # scoped to a PRGuardrailScan, which is scoped to a PR).
        return {"ok": True, "skipped": "not a PR comment"}

    comment = payload.get("comment") or {}
    match = IGNORE_COMMAND_RE.search(comment.get("body") or "")
    if not match:
        return {"ok": True, "skipped": "no ignore command"}

    association = comment.get("author_association", "NONE")
    if association not in TRUSTED_COMMENT_ASSOCIATIONS:
        return {"ok": True, "skipped": f"author_association={association} not trusted"}

    reason = match.group("reason").strip()
    if not reason:
        return {"ok": True, "skipped": "empty reason"}

    finding_id = int(match.group("finding_id"))
    finding = session.get(PRGuardrailFinding, finding_id)
    if not finding:
        return {"ok": True, "skipped": "finding not found"}

    # The finding id in a comment is attacker-controlled input from anyone
    # who can comment on this PR (even a trusted associate could typo or
    # guess a neighboring id): confirm it actually belongs to a scan of
    # *this* repo and *this* PR before touching it, not just that some
    # finding with that id exists somewhere in the whole platform.
    pr_scan = session.get(PRGuardrailScan, finding.pr_scan_id)
    repo_clone_url = payload.get("repository", {}).get("clone_url")
    target = session.exec(select(Target).where(Target.repo_url == repo_clone_url)).first()
    if not pr_scan or not target or pr_scan.target_id != target.id or pr_scan.pr_number != issue.get("number"):
        return {"ok": True, "skipped": "finding does not belong to this PR"}

    commenter = (comment.get("user") or {}).get("login") or "unknown"
    submit_ignore_request(session, finding, requested_by=f"github:{commenter}", reason=reason)

    reply_to_pr(
        session,
        target,
        issue.get("number"),
        f"Ignore requested for finding #{finding_id} by @{commenter}: {reason}\n\n"
        "This still needs approval from the security team in Toleman before it takes effect.",
    )
    return {"ok": True, "ignore_requested": True, "finding_id": finding_id}


EVENT_HANDLERS = {
    "pull_request": _handle_pull_request,
    "push": _handle_push,
    "issue_comment": _handle_issue_comment,
}


@router.post("/github")
async def github_webhook(
    request: Request,
    x_github_event: str | None = Header(default=None),
    x_hub_signature_256: str | None = Header(default=None),
):
    raw_body = await request.body()
    # Parsing untrusted JSON is safe before signature verification (no
    # side effects, just structure); doing so lets us pull the firing
    # installation's id out of the payload (every App webhook delivery
    # carries one) so multi-App/multi-install signature verification (#34)
    # can go straight to the right App's secret instead of trying them all.
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    payload_installation_id = (payload.get("installation") or {}).get("id")

    with Session(engine) as session:
        if not _verify_signature(raw_body, x_hub_signature_256, session, payload_installation_id):
            raise HTTPException(status_code=401, detail="invalid webhook signature")

        if x_github_event == "installation_repositories":
            # No repo-scoped `target` lookup for this one (it's about
            # installation-level access changes, not a single repo), so it
            # doesn't fit EVENT_HANDLERS' (session, payload) -> dict shape.
            return _handle_installation_repositories(payload)

        handler = EVENT_HANDLERS.get(x_github_event)
        if handler is None:
            return {"ok": True, "skipped": f"event={x_github_event}"}
        return handler(session, payload)
