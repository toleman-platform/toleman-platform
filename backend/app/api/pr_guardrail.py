"""PR Guardrail (architecture doc Flow C, ROADMAP Sprint 2/4): diff-only scan
on a PR's head branch vs the target's default branch, surfacing only net-new
findings and new API endpoints, with a best-effort PR comment + commit status
via the GitHub App. Each net-new finding is persisted (PRGuardrailFinding) so
it can be deep-linked from the PR comment and carry its own ignore-request /
security-review lifecycle.

Execution logic lives in app.core.pr_guardrail_executor so the on-demand
route here and the webhook-driven real-time path (app/api/webhooks.py) run
the exact same code, not two copies.
"""
import logging
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select

from app.api.auth import current_user, require_security_reviewer
from app.api.deps import get_session
from app.core.github import github_get, repo_slug_from_url
from app.core.pr_guardrail_executor import execute_pr_guardrail_scan, set_commit_status
from app.models.models import IgnoreStatus, PRGuardrailFinding, PRGuardrailScan, PRGuardrailStatus, Target, User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/pr-guardrail", tags=["pr-guardrail"])


def _get_target(target_id: int, session: Session) -> Target:
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="target not found")
    return target


def _finding_out(f: PRGuardrailFinding) -> dict:
    return {
        "id": f.id,
        "pr_scan_id": f.pr_scan_id,
        "tool": f.tool,
        "rule_id": f.rule_id,
        "title": f.title,
        "file_path": f.file_path,
        "line_start": f.line_start,
        "severity": f.severity,
        "ignore_status": f.ignore_status,
        "ignore_requested_by": f.ignore_requested_by,
        "ignore_requested_reason": f.ignore_requested_reason,
        "ignore_reviewed_by": f.ignore_reviewed_by,
        "ignore_reviewed_at": f.ignore_reviewed_at,
    }


@router.post("/scan")
def run_pr_guardrail_scan(target_id: int, pr_number: int, session: Session = Depends(get_session)):
    """Diff-only scan, triggered on-demand. Runs synchronously (same pattern
    as POST /api/scans/run) for MVP simplicity."""
    target = _get_target(target_id, session)
    try:
        return execute_pr_guardrail_scan(target, pr_number, session)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"failed to fetch PR from GitHub: {exc}")


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
            "new_endpoints_count": s.new_endpoints_count,
            "override_reason": s.override_reason,
            "created_at": s.created_at,
            "completed_at": s.completed_at,
        }
        for s in scans
    ]


@router.get("/{pr_scan_id}/findings")
def list_pr_guardrail_findings(pr_scan_id: int, session: Session = Depends(get_session)):
    """Persisted net-new findings for one PR scan, with ignore-request state."""
    pr_scan = session.get(PRGuardrailScan, pr_scan_id)
    if not pr_scan:
        raise HTTPException(status_code=404, detail="pr guardrail scan not found")
    findings = session.exec(
        select(PRGuardrailFinding).where(PRGuardrailFinding.pr_scan_id == pr_scan_id)
    ).all()
    return [_finding_out(f) for f in findings]


@router.post("/findings/{finding_id}/request-ignore")
def request_ignore(
    finding_id: int,
    body: dict,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    """A developer requests that a specific PR Guardrail finding be ignored
    (e.g. false positive, accepted risk for this PR) - goes to the security
    team for approval, does NOT suppress it unilaterally."""
    finding = session.get(PRGuardrailFinding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="finding not found")
    reason = (body or {}).get("reason", "")
    if not reason:
        raise HTTPException(status_code=400, detail="reason is required")

    finding.ignore_status = IgnoreStatus.REQUESTED
    finding.ignore_requested_by = user.email
    finding.ignore_requested_reason = reason
    finding.ignore_reviewed_by = ""
    finding.ignore_reviewed_at = None
    session.add(finding)
    session.commit()
    session.refresh(finding)
    return _finding_out(finding)


@router.get("/ignore-requests/pending")
def list_pending_ignore_requests(
    session: Session = Depends(get_session),
    user: User = Depends(require_security_reviewer),
):
    """The security team's approval queue."""
    findings = session.exec(
        select(PRGuardrailFinding).where(PRGuardrailFinding.ignore_status == IgnoreStatus.REQUESTED)
    ).all()
    return [_finding_out(f) for f in findings]


@router.post("/findings/{finding_id}/approve-ignore")
def approve_ignore(
    finding_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(require_security_reviewer),
):
    finding = session.get(PRGuardrailFinding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="finding not found")
    finding.ignore_status = IgnoreStatus.APPROVED
    finding.ignore_reviewed_by = user.email
    finding.ignore_reviewed_at = datetime.utcnow()
    session.add(finding)
    session.commit()
    session.refresh(finding)
    return _finding_out(finding)


@router.post("/findings/{finding_id}/reject-ignore")
def reject_ignore(
    finding_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(require_security_reviewer),
):
    finding = session.get(PRGuardrailFinding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="finding not found")
    finding.ignore_status = IgnoreStatus.REJECTED
    finding.ignore_reviewed_by = user.email
    finding.ignore_reviewed_at = datetime.utcnow()
    session.add(finding)
    session.commit()
    session.refresh(finding)
    return _finding_out(finding)


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
                set_commit_status(session, slug, head_sha, "success", f"Overridden: {reason[:100]}")
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
        "new_endpoints_count": pr_scan.new_endpoints_count,
        "override_reason": pr_scan.override_reason,
        "created_at": pr_scan.created_at,
        "completed_at": pr_scan.completed_at,
    }
