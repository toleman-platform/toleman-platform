"""PR Guardrail execution: clone the PR head branch, scan, diff against the
default branch, persist a PRGuardrailScan (+ one PRGuardrailFinding per
net-new finding, so each can be deep-linked and carry its own ignore/approval
state), and best-effort post a PR comment + commit status. Extracted from
app/api/pr_guardrail.py so both the on-demand API route and the
webhook-driven (real-time, PR opened/synchronize) path call the exact same
logic instead of two copies drifting apart.
"""
import logging
from datetime import datetime

import httpx
from sqlmodel import Session, select

from app.core.dedup import compute_dedup_hash
from app.core.enforcement import resolve_enforcement_mode
from app.core.github import get_github_token, github_get, repo_slug_from_url
from app.core.github_app import get_installation_token, resolve_config_for_installation, resolve_installation_for_repo
from app.core.policy import apply_policies
from app.core.pr_guardrail import compute_net_new, highest_severity, should_block
from app.models.models import (
    ApiEndpoint,
    Finding,
    FindingState,
    PolicyRule,
    PRGuardrailFinding,
    PRGuardrailScan,
    PRGuardrailStatus,
    Target,
)
from app.scanners import parsers, runner
from app.scanners.discovery import discover_endpoints

logger = logging.getLogger(__name__)

FRONTEND_URL = "http://localhost:3000"

GUARDRAIL_TOOL = "semgrep"
GUARDRAIL_PARSER = parsers.parse_semgrep
MAX_NEW_FINDINGS_IN_RESPONSE = 20
MAX_NEW_ENDPOINTS_IN_RESPONSE = 10


def _severity_str(severity) -> str:
    """Findings carry a Severity enum member up to this point; f-string-ing
    an enum directly renders "Severity.MEDIUM" (its default __repr__-ish
    __str__), not "Medium" -- a real bug found via a screenshot of an actual
    posted PR comment. Persisted PRGuardrailFinding.severity is already a
    plain str, so this also passes those through unchanged."""
    return severity.value if hasattr(severity, "value") else str(severity)


def finding_summary(f: dict) -> dict:
    return {
        "tool": GUARDRAIL_TOOL,
        "rule_id": f.get("rule_id"),
        "title": f.get("title"),
        "file_path": f.get("file_path"),
        "line_start": f.get("line_start"),
        "severity": _severity_str(f.get("severity")),
    }


def _persist_findings(session: Session, pr_scan_id: int, net_new: list[dict]) -> list[PRGuardrailFinding]:
    rows = []
    for f in net_new[:MAX_NEW_FINDINGS_IN_RESPONSE]:
        row = PRGuardrailFinding(
            pr_scan_id=pr_scan_id,
            tool=GUARDRAIL_TOOL,
            rule_id=f.get("rule_id", ""),
            title=f.get("title", "") or f.get("rule_id", ""),
            file_path=f.get("file_path", ""),
            line_start=f.get("line_start"),
            severity=_severity_str(f.get("severity")),
        )
        session.add(row)
        rows.append(row)
    session.commit()
    for row in rows:
        session.refresh(row)
    return rows


def _diff_new_endpoints(session: Session, target: Target, repo_path) -> list[dict]:
    """Real static-analysis route discovery on the PR branch, diffed against
    what's already persisted for the target's default branch -- same
    net-new pattern as findings, but informational only (no ignore workflow;
    unlike vulnerabilities, a new API endpoint isn't inherently something to
    approve/reject, just something to be aware of in review)."""
    try:
        discovered = discover_endpoints(repo_path)
    except Exception:
        logger.warning("PR guardrail: endpoint discovery failed, skipping", exc_info=True)
        return []

    existing = {
        (e.method, e.route, e.file_path)
        for e in session.exec(
            select(ApiEndpoint).where(ApiEndpoint.target_id == target.id, ApiEndpoint.branch == target.default_branch)
        ).all()
    }
    return [d for d in discovered if (d["method"], d["route"], d["file"]) not in existing]


def render_comment(
    findings: list[PRGuardrailFinding],
    new_endpoints: list[dict],
    status: PRGuardrailStatus,
    target_id: int,
    pr_scan_id: int,
) -> str:
    if not findings and not new_endpoints:
        return "**OSP PR Guardrail**: no net-new findings or API changes vs the default branch. ✅"

    lines = ["**OSP PR Guardrail**", ""]

    if findings:
        lines.append(f"**{len(findings)} net-new vulnerability finding(s)** vs the default branch:")
        lines.append("")
        for f in findings:
            loc = f.file_path
            if f.line_start:
                loc += f":{f.line_start}"
            ref_link = f"{FRONTEND_URL}/pr-history?target_id={target_id}&pr_scan_id={pr_scan_id}#finding-{f.id}"
            ignore_link = f"{FRONTEND_URL}/pr-history?target_id={target_id}&ignore_finding={f.id}"
            lines.append(
                f"- **{f.severity}** `{f.rule_id}` — {f.title} (`{loc}`) "
                f"[[view]]({ref_link}) · [[request ignore]]({ignore_link})"
            )
        lines.append("")

    if new_endpoints:
        lines.append(f"**{len(new_endpoints)} new API endpoint(s)** detected in this PR:")
        lines.append("")
        for e in new_endpoints[:MAX_NEW_ENDPOINTS_IN_RESPONSE]:
            lines.append(f"- `{e['method']}` `{e['route']}` (`{e['file']}:{e.get('line', '?')}`)")
        if len(new_endpoints) > MAX_NEW_ENDPOINTS_IN_RESPONSE:
            lines.append(f"- _...and {len(new_endpoints) - MAX_NEW_ENDPOINTS_IN_RESPONSE} more_")
        lines.append("")

    if status == PRGuardrailStatus.BLOCKED:
        lines.append("This PR is **blocked** pending fix or AppSec override — [review in OSP]"
                      f"({FRONTEND_URL}/pr-history?target_id={target_id}&pr_scan_id={pr_scan_id}).")

    return "\n".join(lines)


def _get_installation_token_or_none(session: Session, target: Target) -> str | None:
    """Resolve the installation token for THIS target's repo specifically
    (#34) -- previously this always grabbed installation row #1 and App
    config row #1 regardless of which repo/target the caller actually
    needed a token for, so PR Guardrail would silently use the wrong App's
    installation token (or fail) for any repo not owned by the first
    installation once a second real installation existed."""
    slug = repo_slug_from_url(target.repo_url)
    installation = resolve_installation_for_repo(session, target.workspace_id, slug)
    if not installation:
        return None
    config = resolve_config_for_installation(session, installation)
    if not config:
        return None
    return get_installation_token(config, installation.installation_id)


def post_pr_comment(session: Session, target: Target, pr_number: int, body: str) -> None:
    """Best-effort: never raises -- a scan result that fails to post a comment is still useful."""
    slug = repo_slug_from_url(target.repo_url)
    try:
        token = _get_installation_token_or_none(session, target)
        if not token:
            logger.warning("PR guardrail: no GitHub App installed, skipping PR comment")
            return
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


def set_commit_status(session: Session, target: Target, sha: str, state: str, description: str) -> None:
    """Best-effort: never raises."""
    slug = repo_slug_from_url(target.repo_url)
    try:
        token = _get_installation_token_or_none(session, target)
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
    """Diff-only scan: scan the PR's head branch, diff findings against the
    target's default-branch Open findings and API endpoints against the
    persisted default-branch discovery set, persist a PRGuardrailScan +
    PRGuardrailFinding rows, best-effort post a PR comment + commit status.
    Returns the same response shape regardless of caller (on-demand API
    route, webhook handler, or Celery task).

    Enforcement mode (issue #62, app.core.enforcement.resolve_enforcement_mode)
    gates this at the very top: "disabled" means PR Guardrail doesn't run for
    this target/PR at all -- no clone, no PRGuardrailScan row, no PR comment,
    no commit status. "block"/"alert" both run the full scan below; the
    difference between them only affects the commit status sent to GitHub
    at the end (see the set_commit_status call)."""
    enforcement_mode = resolve_enforcement_mode(session, target)
    if enforcement_mode == "disabled":
        logger.info(
            "PR guardrail: enforcement_mode=disabled for target %s, skipping scan for PR #%s",
            target.id, pr_number,
        )
        return {
            "pr_scan_id": None,
            "status": "disabled",
            "new_findings_count": 0,
            "highest_new_severity": None,
            "new_endpoints_count": 0,
            "new_findings": [],
            "new_endpoints": [],
            "enforcement_mode": enforcement_mode,
        }

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

        new_endpoints = _diff_new_endpoints(session, target, repo_path)

        pr_scan.status = status
        pr_scan.new_findings_count = len(net_new)
        pr_scan.highest_new_severity = highest_severity(net_new)
        pr_scan.new_endpoints_count = len(new_endpoints)
        pr_scan.completed_at = datetime.utcnow()
        session.add(pr_scan)
        session.commit()
        session.refresh(pr_scan)

        persisted_findings = _persist_findings(session, pr_scan.id, net_new)

        comment_body = render_comment(persisted_findings, new_endpoints, status, target.id, pr_scan.id)
        post_pr_comment(session, target, pr_number, comment_body)

        summary_desc = f"{len(net_new)} net-new finding(s), {len(new_endpoints)} new endpoint(s)"
        if status == PRGuardrailStatus.PASSED:
            commit_state, commit_desc = "success", summary_desc
        elif enforcement_mode == "alert":
            # Alert mode: real blocking findings exist, but this
            # target/group/workspace is configured to warn rather than fail
            # the build. GitHub commit statuses only support
            # success/failure/pending/error -- there's no dedicated "neutral"
            # state -- so we use "success" (non-blocking) with a description
            # that makes clear this is alert-mode, not a clean scan.
            commit_state, commit_desc = "success", f"[alert mode, non-blocking] {summary_desc}"
        else:
            commit_state, commit_desc = "failure", summary_desc

        set_commit_status(session, target, head_sha, commit_state, commit_desc)

        return {
            "pr_scan_id": pr_scan.id,
            "status": pr_scan.status,
            "new_findings_count": pr_scan.new_findings_count,
            "highest_new_severity": pr_scan.highest_new_severity,
            "new_endpoints_count": pr_scan.new_endpoints_count,
            "new_findings": [finding_summary(f) for f in net_new[:MAX_NEW_FINDINGS_IN_RESPONSE]],
            "new_endpoints": new_endpoints[:MAX_NEW_ENDPOINTS_IN_RESPONSE],
            "enforcement_mode": enforcement_mode,
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
            "new_endpoints_count": 0,
            "new_findings": [],
            "new_endpoints": [],
            # runner.clone_error_message avoids echoing raw subprocess argv/paths
            # (and, historically, an embedded GitHub token) back in the response.
            "error": runner.clone_error_message(exc),
        }
