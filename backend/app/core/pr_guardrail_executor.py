"""PR Guardrail execution: clone the PR head branch, scan, diff against the
default branch, persist a PRGuardrailScan, and best-effort post a PR comment
+ commit status. Extracted from app/api/pr_guardrail.py so both the on-demand
API route and the webhook-driven (real-time, PR opened/synchronize) path call
the exact same logic instead of two copies drifting apart.
"""
import logging
from datetime import datetime

import httpx
from sqlmodel import Session, select

from app.core.dedup import compute_dedup_hash
from app.core.github import get_github_token, github_get, repo_slug_from_url
from app.core.github_app import get_installation_token
from app.core.policy import apply_policies
from app.core.pr_guardrail import compute_net_new, highest_severity, should_block
from app.models.models import (
    Finding,
    FindingState,
    GitHubAppConfig,
    GitHubInstallation,
    PolicyRule,
    PRGuardrailScan,
    PRGuardrailStatus,
    Target,
)
from app.scanners import parsers, runner

logger = logging.getLogger(__name__)

GUARDRAIL_TOOL = "semgrep"
GUARDRAIL_PARSER = parsers.parse_semgrep
MAX_NEW_FINDINGS_IN_RESPONSE = 20


def finding_summary(f: dict) -> dict:
    return {
        "tool": GUARDRAIL_TOOL,
        "rule_id": f.get("rule_id"),
        "title": f.get("title"),
        "file_path": f.get("file_path"),
        "line_start": f.get("line_start"),
        "severity": f.get("severity"),
    }


def render_comment(net_new: list[dict], status: PRGuardrailStatus) -> str:
    if not net_new:
        return "**OSP PR Guardrail**: no net-new findings vs the default branch. ✅"
    lines = [f"**OSP PR Guardrail**: {len(net_new)} net-new finding(s) vs the default branch.", ""]
    for f in net_new[:MAX_NEW_FINDINGS_IN_RESPONSE]:
        loc = f.get("file_path", "")
        if f.get("line_start"):
            loc += f":{f['line_start']}"
        lines.append(f"- **{f.get('severity')}** `{f.get('rule_id')}` — {f.get('title')} ({loc})")
    if status == PRGuardrailStatus.BLOCKED:
        lines.append("")
        lines.append("This PR is **blocked** pending fix or AppSec override.")
    return "\n".join(lines)


def _get_installation_token_or_none(session: Session) -> str | None:
    config = session.exec(select(GitHubAppConfig)).first()
    installation = session.exec(select(GitHubInstallation)).first()
    if not config or not installation:
        return None
    return get_installation_token(config, installation.installation_id)


def post_pr_comment(session: Session, slug: str, pr_number: int, net_new: list[dict], status: PRGuardrailStatus) -> None:
    """Best-effort: never raises -- a scan result that fails to post a comment is still useful."""
    try:
        token = _get_installation_token_or_none(session)
        if not token:
            logger.warning("PR guardrail: no GitHub App installed, skipping PR comment")
            return
        body = render_comment(net_new, status)
        res = httpx.post(
            f"https://api.github.com/repos/{slug}/issues/{pr_number}/comments",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
            json={"body": body},
            timeout=15,
        )
        if res.status_code >= 300:
            logger.warning("PR guardrail: failed to post PR comment: %s %s", res.status_code, res.text[:300])
    except Exception:
        logger.warning("PR guardrail: exception posting PR comment", exc_info=True)


def set_commit_status(session: Session, slug: str, sha: str, state: str, description: str) -> None:
    """Best-effort: never raises."""
    try:
        token = _get_installation_token_or_none(session)
        if not token:
            logger.warning("PR guardrail: no GitHub App installed, skipping commit status")
            return
        res = httpx.post(
            f"https://api.github.com/repos/{slug}/statuses/{sha}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
            json={
                "state": state,
                "context": "osp/pr-guardrail",
                "description": description[:140],
                "target_url": "http://localhost:3000/pr-history",
            },
            timeout=15,
        )
        if res.status_code >= 300:
            logger.warning("PR guardrail: failed to set commit status: %s %s", res.status_code, res.text[:300])
    except Exception:
        logger.warning("PR guardrail: exception setting commit status", exc_info=True)


def execute_pr_guardrail_scan(target: Target, pr_number: int, session: Session) -> dict:
    """Diff-only scan: scan the PR's head branch, diff against the target's
    default-branch Open findings, persist a PRGuardrailScan, best-effort post
    a PR comment + commit status. Returns the same response shape regardless
    of caller (on-demand API route, webhook handler, or Celery task)."""
    slug = repo_slug_from_url(target.repo_url)

    pr_res = github_get(f"/repos/{slug}/pulls/{pr_number}")
    pr_res.raise_for_status()
    pr = pr_res.json()
    head_branch = pr["head"]["ref"]
    head_sha = pr["head"]["sha"]
    pr_title = pr.get("title", "")

    pr_scan = PRGuardrailScan(
        target_id=target.id,
        pr_number=pr_number,
        pr_title=pr_title,
        branch=head_branch,
        status=PRGuardrailStatus.RUNNING,
    )
    session.add(pr_scan)
    session.commit()
    session.refresh(pr_scan)

    try:
        repo_path = runner.clone_repo(
            target.repo_url, head_branch, get_github_token(), scan_id=f"pr-{pr_scan.id}"
        )
        raw = runner.run_tool(GUARDRAIL_TOOL, repo_path)
        parsed = GUARDRAIL_PARSER(raw)

        for item in parsed:
            # Must match the same normalization ingest_findings applies, or
            # dedup_hash never lines up with the persisted default-branch
            # findings and every PR finding looks "net-new" even when it
            # already exists on the base branch.
            item["file_path"] = runner.normalize_file_path(item.get("file_path", ""), repo_path)
            item["dedup_hash"] = compute_dedup_hash(
                rule_id=item["rule_id"],
                file_path=item["file_path"],
                tool=GUARDRAIL_TOOL,
                snippet=item.get("snippet", ""),
                line_start=item.get("line_start"),
            )

        existing_hashes = set(
            session.exec(
                select(Finding.dedup_hash).where(
                    Finding.target_id == target.id,
                    Finding.branch == target.default_branch,
                    Finding.state == FindingState.OPEN,
                )
            ).all()
        )

        net_new = compute_net_new(parsed, existing_hashes)

        # Policy-as-code (ROADMAP Sprint 4): apply the target's workspace
        # active policy rules -- org-level suppression + severity threshold
        # override -- before deciding whether to block. No policies configured
        # for the workspace means today's default behavior is unchanged.
        policies = session.exec(
            select(PolicyRule).where(
                PolicyRule.workspace_id == target.workspace_id,
                PolicyRule.active == True,  # noqa: E712
            )
        ).all()
        net_new, blocking_severities = apply_policies(net_new, policies)

        status = PRGuardrailStatus.BLOCKED if should_block(net_new, blocking_severities) else PRGuardrailStatus.PASSED

        pr_scan.status = status
        pr_scan.new_findings_count = len(net_new)
        pr_scan.highest_new_severity = highest_severity(net_new)
        pr_scan.completed_at = datetime.utcnow()
        session.add(pr_scan)
        session.commit()
        session.refresh(pr_scan)

        post_pr_comment(session, slug, pr_number, net_new, status)
        set_commit_status(
            session,
            slug,
            head_sha,
            "success" if status == PRGuardrailStatus.PASSED else "failure",
            f"{len(net_new)} net-new finding(s), highest: {pr_scan.highest_new_severity or 'none'}",
        )

        return {
            "pr_scan_id": pr_scan.id,
            "status": pr_scan.status,
            "new_findings_count": pr_scan.new_findings_count,
            "highest_new_severity": pr_scan.highest_new_severity,
            "new_findings": [finding_summary(f) for f in net_new[:MAX_NEW_FINDINGS_IN_RESPONSE]],
        }
    except Exception as exc:
        pr_scan.status = PRGuardrailStatus.ERROR
        pr_scan.completed_at = datetime.utcnow()
        session.add(pr_scan)
        session.commit()
        return {
            "pr_scan_id": pr_scan.id,
            "status": pr_scan.status,
            "new_findings_count": 0,
            "highest_new_severity": None,
            "new_findings": [],
            "error": str(exc),
        }
