"""PR Guardrail (architecture doc Flow C, ROADMAP Sprint 2): diff-only scan on
a PR's head branch vs the target's default branch, surfacing only net-new
findings, with a best-effort PR comment + commit status via the GitHub App.

Replaces the hardcoded scan_status: "not scanned" placeholder previously
returned by GET /api/github/prs/{target_id}.
"""
import logging
from datetime import datetime

import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select

from app.api.deps import get_session
from app.core.dedup import compute_dedup_hash
from app.core.github import get_github_token, github_get, repo_slug_from_url
from app.core.github_app import get_installation_token
from app.core.pr_guardrail import compute_net_new, highest_severity, should_block
from app.models.models import (
    Finding,
    FindingState,
    GitHubAppConfig,
    GitHubInstallation,
    PRGuardrailScan,
    PRGuardrailStatus,
    Target,
)
from app.scanners import parsers, runner

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/pr-guardrail", tags=["pr-guardrail"])

# For MVP, only semgrep runs synchronously in the guardrail path -- fast and
# broadly applicable across languages. Running all 4 configured tools (also
# gitleaks/trivy/gosec) synchronously in one HTTP request would make a PR
# check take minutes; multi-tool PR scanning (likely via an async job +
# webhook-driven status update) is a follow-up, not MVP scope.
GUARDRAIL_TOOL = "semgrep"
GUARDRAIL_PARSER = parsers.parse_semgrep

MAX_NEW_FINDINGS_IN_RESPONSE = 20


def _get_target(target_id: int, session: Session) -> Target:
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="target not found")
    return target


def _finding_summary(f: dict) -> dict:
    return {
        "tool": GUARDRAIL_TOOL,
        "rule_id": f.get("rule_id"),
        "title": f.get("title"),
        "file_path": f.get("file_path"),
        "line_start": f.get("line_start"),
        "severity": f.get("severity"),
    }


def _render_comment(net_new: list[dict], status: PRGuardrailStatus) -> str:
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


def _post_pr_comment(session: Session, slug: str, pr_number: int, net_new: list[dict], status: PRGuardrailStatus) -> None:
    """Best-effort: post a PR comment summarizing net-new findings. Never
    raises -- a scan result that fails to post a comment is still useful."""
    try:
        token = _get_installation_token_or_none(session)
        if not token:
            logger.warning("PR guardrail: no GitHub App installed, skipping PR comment")
            return
        body = _render_comment(net_new, status)
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


def _set_commit_status(session: Session, slug: str, sha: str, state: str, description: str) -> None:
    """Best-effort: set the osp/pr-guardrail commit status. Never raises."""
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


@router.post("/scan")
def run_pr_guardrail_scan(
    target_id: int,
    pr_number: int,
    session: Session = Depends(get_session),
):
    """Diff-only scan: scan the PR's head branch, diff findings against the
    target's default-branch Open findings, surface only net-new ones. Runs
    synchronously for MVP simplicity (same pattern as POST /api/scans/run)."""
    target = _get_target(target_id, session)
    slug = repo_slug_from_url(target.repo_url)

    pr_res = github_get(f"/repos/{slug}/pulls/{pr_number}")
    if pr_res.status_code != 200:
        raise HTTPException(status_code=pr_res.status_code, detail=pr_res.text[:300])
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
        status = PRGuardrailStatus.BLOCKED if should_block(net_new) else PRGuardrailStatus.PASSED

        pr_scan.status = status
        pr_scan.new_findings_count = len(net_new)
        pr_scan.highest_new_severity = highest_severity(net_new)
        pr_scan.completed_at = datetime.utcnow()
        session.add(pr_scan)
        session.commit()
        session.refresh(pr_scan)

        # Best-effort: PR comment + commit status posting via the GitHub App.
        # Wrapped so a posting failure never fails the scan-result response.
        _post_pr_comment(session, slug, pr_number, net_new, status)
        _set_commit_status(
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
            "new_findings": [_finding_summary(f) for f in net_new[:MAX_NEW_FINDINGS_IN_RESPONSE]],
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


@router.get("/log")
def pr_guardrail_log(target_id: int, session: Session = Depends(get_session)):
    """PR Audit & Discovery Log (architecture doc §6): most-recent-first list
    of PR Guardrail scans for a target."""
    _get_target(target_id, session)
    scans = session.exec(
        select(PRGuardrailScan)
        .where(PRGuardrailScan.target_id == target_id)
        .order_by(PRGuardrailScan.created_at.desc())
    ).all()
    return [
        {
            "id": s.id,
            "pr_number": s.pr_number,
            "pr_title": s.pr_title,
            "branch": s.branch,
            "status": s.status,
            "new_findings_count": s.new_findings_count,
            "highest_new_severity": s.highest_new_severity,
            "override_reason": s.override_reason,
            "created_at": s.created_at,
            "completed_at": s.completed_at,
        }
        for s in scans
    ]


@router.post("/{pr_scan_id}/override")
def override_pr_guardrail_scan(pr_scan_id: int, body: dict, session: Session = Depends(get_session)):
    """AppSec accept-risk override for a blocked PR (architecture doc §6)."""
    pr_scan = session.get(PRGuardrailScan, pr_scan_id)
    if not pr_scan:
        raise HTTPException(status_code=404, detail="pr guardrail scan not found")

    reason = (body or {}).get("reason", "")
    if not reason:
        raise HTTPException(status_code=400, detail="reason is required")

    pr_scan.status = PRGuardrailStatus.OVERRIDDEN
    pr_scan.override_reason = reason
    session.add(pr_scan)
    session.commit()
    session.refresh(pr_scan)

    # Best-effort: re-set the commit status to success so the override
    # actually unblocks merge in GitHub's UI, not just in our own DB.
    try:
        target = session.get(Target, pr_scan.target_id)
        if target:
            slug = repo_slug_from_url(target.repo_url)
            pr_res = github_get(f"/repos/{slug}/pulls/{pr_scan.pr_number}")
            if pr_res.status_code == 200:
                head_sha = pr_res.json()["head"]["sha"]
                _set_commit_status(session, slug, head_sha, "success", f"Overridden: {reason[:100]}")
    except Exception:
        logger.warning("PR guardrail: exception re-setting commit status on override", exc_info=True)

    return {
        "id": pr_scan.id,
        "pr_number": pr_scan.pr_number,
        "pr_title": pr_scan.pr_title,
        "branch": pr_scan.branch,
        "status": pr_scan.status,
        "new_findings_count": pr_scan.new_findings_count,
        "highest_new_severity": pr_scan.highest_new_severity,
        "override_reason": pr_scan.override_reason,
        "created_at": pr_scan.created_at,
        "completed_at": pr_scan.completed_at,
    }
