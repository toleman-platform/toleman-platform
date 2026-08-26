"""PR Guardrail execution: clone the PR head branch, scan, diff against the
default branch, persist a PRGuardrailScan (+ one PRGuardrailFinding per
net-new finding, so each can be deep-linked and carry its own ignore/approval
state), and best-effort post a PR comment + commit status. Extracted from
app/api/pr_guardrail.py so both the on-demand API route and the
webhook-driven (real-time, PR opened/synchronize) path call the exact same
logic instead of two copies drifting apart.
"""
import logging
from datetime import UTC, datetime

import httpx
from sqlmodel import Session, select

from app.core.config import settings
from app.core.dedup import compute_dedup_hash
from app.core.enforcement import resolve_enforcement_mode
from app.core.github import github_get, repo_slug_from_url
from app.core.github_app import get_installation_token, resolve_config_for_installation, resolve_installation_for_repo
from app.core.github_token import resolve_github_token
from app.core.policy import apply_policies, effective_blocking_severities
from app.core.pr_guardrail import SEVERITY_ORDER, compute_net_new, highest_severity, should_block
from app.models.models import (
    ApiEndpoint,
    Finding,
    FindingState,
    IgnoreStatus,
    PolicyRule,
    PRGuardrailFinding,
    PRGuardrailScan,
    PRGuardrailStatus,
    Target,
)
from app.core.tool_usage import tools_for_surface
from app.core.time import utcnow
from app.scanners import parsers, runner
from app.scanners.discovery import discover_endpoints

logger = logging.getLogger(__name__)

# GH-02: every link this module posts to GitHub (PR comment "review in
# Rikugan", "request ignore", and the commit status target_url below) used
# to be a hardcoded localhost:3000, unfollowable by anyone but the author.
FRONTEND_URL = settings.public_base_url.rstrip("/")

# Fallback when a workspace has no usable pr_guardrail assignment resolved
# (see _resolve_guardrail_tools). Kept because semgrep is bundled in the
# backend image and was the historical hardcoded behavior -- but it is now a
# floor, not the whole story: whatever else the workspace assigns runs too.
GUARDRAIL_FALLBACK_TOOL = "semgrep"
MAX_NEW_FINDINGS_IN_RESPONSE = 20
MAX_NEW_ENDPOINTS_IN_RESPONSE = 10


def _resolve_guardrail_tools(session: Session, target: Target) -> list[str]:
    """Tools to run for this target's PR guardrail scan.

    Reads the workspace's real pr_guardrail usage assignments (GH-01 --
    before this, those checkboxes were decorative and only semgrep ever
    ran). Falls back to semgrep alone if the workspace has somehow resolved
    to nothing runnable, so a guardrail scan never silently degrades into
    scanning with no tools at all and reporting a clean pass.
    """
    tools = tools_for_surface(session, target.workspace_id, "pr_guardrail")
    if not tools:
        logger.warning(
            "target %s workspace %s has no runnable pr_guardrail tools assigned; "
            "falling back to %s",
            target.id, target.workspace_id, GUARDRAIL_FALLBACK_TOOL,
        )
        return [GUARDRAIL_FALLBACK_TOOL]
    return tools


def _run_guardrail_tools(
    tools: list[str], repo_path, paths: list[str] | None = None
) -> tuple[list[dict], list[str], dict[str, str]]:
    """Run every assigned tool over the PR checkout.

    ``paths`` (repo-relative changed files, #243) scopes each tool per
    ``runner.TOOL_SCOPING``. ``None`` scans the whole checkout.

    Returns ``(findings, failed_tools, skipped_tools)``. Each finding carries
    its own ``tool`` key so downstream dedup, persistence and rendering can
    attribute it correctly.

    Three outcomes, kept separate on purpose:

    * **ran** -- findings (possibly none), a real result
    * **failed** -- the tool raised; recorded rather than aborting the scan,
      since one broken scanner shouldn't discard what the others found
    * **skipped** -- diff scoping left it nothing to examine (``trivy`` with
      no manifest change, ``tfsec`` with no Terraform). Mapped to its reason.

    The caller must not treat a run with non-empty ``failed`` or ``skipped``
    as a clean pass. That is the "a check that did not really run must never
    look like a check that passed" rule this codebase already applies in
    osv_malware.py.
    """
    findings: list[dict] = []
    failed: list[str] = []
    skipped: dict[str, str] = {}
    for tool in tools:
        try:
            raw = runner.run_tool(tool, repo_path, paths=paths)
            parsed = parsers.PARSER_MAP[tool](raw)
        except runner.ToolNotApplicable as exc:
            # Not a failure and not a pass. Nothing was examined, so say so.
            logger.info("pr guardrail tool %s skipped: %s", tool, exc)
            skipped[tool] = str(exc)
            continue
        except Exception:
            logger.exception("pr guardrail tool %s failed", tool)
            failed.append(tool)
            continue
        for item in parsed:
            item["tool"] = tool
        findings.extend(parsed)
    return findings, failed, skipped


# Above this many changed files a PR is not meaningfully a "diff" any more:
# the per-file process cost of the PER_FILE tools stops paying for itself,
# and the odds that the change is a rename/vendor/lockfile sweep (where
# whole-repo context matters) go up sharply. Falls back to a full scan.
MAX_DIFF_SCOPED_FILES = 300


def _changed_files(slug: str, pr_number: int) -> list[str] | None:
    """Repo-relative paths the PR adds or modifies.

    Returns None when the list can't be established, which the caller must
    treat as "fall back to a full scan" -- never as "nothing changed".

    Deleted files are excluded: there is no file left to scan, and their
    findings disappear from the head branch anyway. Renames report only the
    new path, which is what exists in the checkout.
    """
    paths: list[str] = []
    page = 1
    while True:
        try:
            res = github_get(f"/repos/{slug}/pulls/{pr_number}/files?per_page=100&page={page}")
            res.raise_for_status()
            batch = res.json()
        except Exception:
            logger.warning(
                "pr guardrail: could not list changed files for %s#%s; falling back to a full scan",
                slug, pr_number, exc_info=True,
            )
            return None
        if not batch:
            break
        for entry in batch:
            if entry.get("status") == "removed":
                continue
            filename = entry.get("filename")
            if filename:
                paths.append(filename)
        if len(batch) < 100:
            break
        page += 1
        if page > 30:  # 3000 files; far past MAX_DIFF_SCOPED_FILES anyway
            logger.warning("pr guardrail: %s#%s has more files than we will page", slug, pr_number)
            return None
    return paths


def _severity_str(severity) -> str:
    """Findings carry a Severity enum member up to this point; f-string-ing
    an enum directly renders "Severity.MEDIUM" (its default __repr__-ish
    __str__), not "Medium" -- a real bug found via a screenshot of an actual
    posted PR comment. Persisted PRGuardrailFinding.severity is already a
    plain str, so this also passes those through unchanged."""
    return severity.value if hasattr(severity, "value") else str(severity)


def finding_summary(f: dict) -> dict:
    return {
        # Per-finding now that the guardrail is multi-tool (GH-01). Was a
        # module constant, which mislabelled every finding as semgrep's the
        # moment a second tool could contribute one.
        "tool": f.get("tool") or GUARDRAIL_FALLBACK_TOOL,
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
            tool=f.get("tool") or GUARDRAIL_FALLBACK_TOOL,
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

    if not existing:
        # (GH-06) No baseline has ever been discovered for the default
        # branch, so there is nothing to diff against -- and diffing against
        # an empty set makes the *entire repository* look new.
        #
        # An external evaluation hit exactly this: a PR touching one file got
        # a comment announcing four new endpoints across bad/vulpy.py,
        # good/vulpy.py and their SSL variants. First-run noise, in the most
        # visible artefact this tool produces, at the moment a team is
        # deciding whether to trust it.
        #
        # "No baseline" is not "everything is new" -- same distinction this
        # codebase draws between a check that found nothing and a check that
        # never ran. Report nothing rather than something false.
        logger.info(
            "PR guardrail: no persisted endpoint baseline for target %s branch %s -- "
            "skipping the new-endpoint diff for this scan rather than reporting the "
            "whole repo as new",
            target.id, target.default_branch,
        )
        return []

    return [d for d in discovered if (d["method"], d["route"], d["file"]) not in existing]


# Hidden HTML marker embedded in every comment `render_comment()` produces,
# used by `post_pr_comment()` to find a prior Rikugan comment on the PR and
# PATCH it in place instead of posting a new one on every rescan (#127).
# GitHub strips HTML comments from the rendered view, so this is invisible
# to a human reading the PR but trivially greppable via the Issue Comments API.
COMMENT_MARKER = "<!-- rikugan-pr-guardrail -->"

# Severities whose per-finding <details> block is expanded by default -- the
# ones a reviewer needs to see without an extra click. Medium/Low collapse
# since they're rarely PR-blocking on their own (see BLOCKING_SEVERITIES in
# app/core/pr_guardrail.py).
OPEN_BY_DEFAULT_SEVERITIES = {"Critical", "High"}


def _severity_badge(status: PRGuardrailStatus) -> str:
    """shields.io-style top-line pass/fail badge -- same visual pattern as
    the SafeDep bot's badge comments already seen on this repo's PRs (e.g.
    PR #11), rebuilt via img.shields.io instead of a static PNG so the label
    changes with the real scan outcome."""
    if status == PRGuardrailStatus.BLOCKED:
        return "![Blocked](https://img.shields.io/badge/status-blocked-red)"
    return "![Passed](https://img.shields.io/badge/status-passed-brightgreen)"


def _severity_counts(findings: list[PRGuardrailFinding]) -> dict[str, int]:
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def _severity_count_table(findings: list[PRGuardrailFinding]) -> str:
    """One-line (single header + single data row) GFM table summarizing
    net-new finding counts by severity, meant to be the first thing a
    reviewer sees -- before any per-finding detail."""
    counts = _severity_counts(findings)
    header = "| " + " | ".join(SEVERITY_ORDER) + " |"
    divider = "|" + "|".join(["---"] * len(SEVERITY_ORDER)) + "|"
    row = "| " + " | ".join(str(counts[sev]) for sev in SEVERITY_ORDER) + " |"
    return "\n".join([header, divider, row])


def _findings_table(findings: list[PRGuardrailFinding], target_id: int, pr_scan_id: int) -> str:
    """GFM table (Severity | Rule | Title | Location | Links) for one
    severity group's findings -- replaces the old flat prose-bullet list."""
    lines = [
        "| Severity | Rule | Title | Location | Links |",
        "|---|---|---|---|---|",
    ]
    for f in findings:
        loc = f.file_path
        if f.line_start:
            loc += f":{f.line_start}"
        ref_link = f"{FRONTEND_URL}/pr-history?target_id={target_id}&pr_scan_id={pr_scan_id}#finding-{f.id}"
        ignore_link = f"{FRONTEND_URL}/pr-history?target_id={target_id}&ignore_finding={f.id}"
        lines.append(
            f"| {f.severity} | `{f.rule_id}` | {f.title} | `{loc}` | "
            f"[view]({ref_link}) &middot; [request ignore]({ignore_link}) |"
        )
    return "\n".join(lines)


# (#271) A PR comment is a snapshot that gets read days later. Every severity
# here is derived from priority_score (app/core/scoring.py), which folds in
# EPSS and CISA KEV -- both of which move. A finding rendered Medium when the
# comment was posted can genuinely be Critical by the time someone reviews
# it, because CISA added its CVE to KEV in between.
#
# Snyk's own fix PRs carry this line, and it was the one thing the
# competitive teardown said to steal outright:
#
#   "Max score is 1000. Note that the real score may have changed since the
#    PR was raised."
#
# It is the same instinct as tools_failed/tools_skipped (#243, #253) -- a
# result is only true as of when it ran -- applied to score freshness rather
# than scan completeness. Deliberately rendered on every comment, not only
# when something scored high: a reader cannot know whether a score moved
# without being told the number has an as-of date at all.
def _staleness_footer(scanned_at: datetime | None) -> str | None:
    if scanned_at is None:
        return None
    stamp = scanned_at.strftime("%Y-%m-%d %H:%M UTC")
    return (
        f"<sub>Severity reflects EPSS/KEV data as of {stamp} and may have changed since. "
        "Open the finding in Rikugan for the current score.</sub>"
    )


def render_comment(
    findings: list[PRGuardrailFinding],
    new_endpoints: list[dict],
    status: PRGuardrailStatus,
    target_id: int,
    pr_scan_id: int,
    tools_run: list[str] | None = None,
    tools_failed: list[str] | None = None,
    tools_skipped: dict[str, str] | None = None,
    scan_scope: str = "full",
    files_scanned: int = 0,
    scanned_at: datetime | None = None,
) -> str:
    """`tools_run`/`tools_failed` default to None for callers (and tests)
    predating the multi-tool guardrail (GH-01); None means "don't render a
    coverage line", which reproduces the old output exactly.

    `scan_scope`/`files_scanned`/`tools_skipped` (#243) default to the
    whole-repo case for the same reason, so a caller that doesn't know about
    diff scoping renders exactly what it used to.

    `scanned_at` (#271) is when this scan ran. None omits the staleness
    footer entirely, same backwards-compatible default as everything above."""
    lines = [COMMENT_MARKER, "**Rikugan PR Guardrail**", "", _severity_badge(status), ""]

    if scan_scope == "diff":
        # Stated up front, above the result. A reader who takes "no findings"
        # as whole-repo assurance when only 7 files were examined has been
        # misled by us, not by the scanner -- so the limit is part of the
        # headline, not a footnote.
        lines.append(
            f"🔍 **Diff-scoped scan** — only the {files_scanned} file(s) changed in this PR were "
            "examined, not the whole repository. Pre-existing issues elsewhere in the codebase "
            "would not appear here."
        )
        lines.append("")

    if tools_skipped:
        lines.append(
            "ℹ️ **Not run for this PR:** "
            + "; ".join(f"`{tool}` ({reason})" for tool, reason in sorted(tools_skipped.items()))
        )
        lines.append("")

    if tools_failed:
        # Rendered before anything else, and never alongside a clean-pass
        # tick: a PR scanned with a broken scanner is inconclusive, not
        # clean. Naming the tool is what makes it actionable -- "scan
        # failed" alone sends people to the container logs.
        lines.append(
            f"⚠️ **{', '.join(tools_failed)} failed to run — this PR was not fully scanned.** "
            "Findings below (if any) are from the tools that did run, and may be incomplete."
        )
        lines.append("")

    if not findings and not new_endpoints:
        if tools_failed:
            lines.append(
                "No net-new findings from the tools that completed. "
                "This is **not** an all-clear — see the warning above."
            )
        elif scan_scope == "diff":
            # No tick here. A green check next to a partial scan is the exact
            # thing that turns a narrowed check into a false all-clear.
            lines.append(
                "No net-new findings or API changes in the changed files. "
                "This covers the diff only — see the scope note above."
            )
        else:
            lines.append("No net-new findings or API changes vs the default branch. ✅")
        if tools_run:
            lines.append("")
            lines.append(f"<sub>Scanned with: {', '.join(tools_run)}</sub>")
        staleness = _staleness_footer(scanned_at)
        if staleness:
            lines.append(staleness)
        return "\n".join(lines)

    if findings:
        lines.append(f"**{len(findings)} net-new vulnerability finding(s)** vs the default branch:")
        lines.append("")
        lines.append(_severity_count_table(findings))
        lines.append("")

        by_severity: dict[str, list[PRGuardrailFinding]] = {}
        for f in findings:
            by_severity.setdefault(f.severity, []).append(f)

        # Most-severe-first, matching SEVERITY_ORDER's ranking (reversed
        # since SEVERITY_ORDER is least-to-most severe).
        for sev in reversed(SEVERITY_ORDER):
            sev_findings = by_severity.get(sev)
            if not sev_findings:
                continue
            open_attr = " open" if sev in OPEN_BY_DEFAULT_SEVERITIES else ""
            lines.append(f"<details{open_attr}>")
            lines.append(f"<summary><strong>{sev}</strong> ({len(sev_findings)})</summary>")
            lines.append("")
            lines.append(_findings_table(sev_findings, target_id, pr_scan_id))
            lines.append("")
            lines.append("</details>")
            lines.append("")

    if new_endpoints:
        lines.append("<details>")
        lines.append(f"<summary><strong>{len(new_endpoints)} new API endpoint(s)</strong> detected in this PR (informational, not blocking)</summary>")
        lines.append("")
        lines.append("| Method | Route | Location |")
        lines.append("|---|---|---|")
        for e in new_endpoints[:MAX_NEW_ENDPOINTS_IN_RESPONSE]:
            lines.append(f"| `{e['method']}` | `{e['route']}` | `{e['file']}:{e.get('line', '?')}` |")
        if len(new_endpoints) > MAX_NEW_ENDPOINTS_IN_RESPONSE:
            lines.append("")
            lines.append(f"_...and {len(new_endpoints) - MAX_NEW_ENDPOINTS_IN_RESPONSE} more_")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    if status == PRGuardrailStatus.BLOCKED:
        lines.append("This PR is **blocked** pending fix or AppSec override — [review in Rikugan]"
                      f"({FRONTEND_URL}/pr-history?target_id={target_id}&pr_scan_id={pr_scan_id}).")

    if tools_run:
        lines.append("")
        lines.append(f"<sub>Scanned with: {', '.join(tools_run)}</sub>")

    staleness = _staleness_footer(scanned_at)
    if staleness:
        lines.append(staleness)

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


def _find_existing_comment_id(slug: str, pr_number: int, token: str) -> int | None:
    """List issue comments on the PR and return the id of the first one
    carrying COMMENT_MARKER, or None if this is the first Rikugan comment on
    this PR. GitHub's issue-comments API is paginated (100/page default);
    walk pages since a long-lived PR can accumulate comments from humans and
    other bots ahead of Rikugan's own."""
    page = 1
    while True:
        res = httpx.get(
            f"https://api.github.com/repos/{slug}/issues/{pr_number}/comments",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
            params={"per_page": 100, "page": page},
            timeout=15,
        )
        if res.status_code >= 300:
            logger.warning("PR guardrail: failed to list PR comments: %s %s", res.status_code, res.text[:300])
            return None
        comments = res.json()
        for comment in comments:
            if COMMENT_MARKER in (comment.get("body") or ""):
                return comment["id"]
        if len(comments) < 100:
            return None
        page += 1


def post_pr_comment(session: Session, target: Target, pr_number: int, body: str) -> None:
    """Best-effort: never raises -- a scan result that fails to post a comment
    is still useful.

    Update-in-place (#127): look for a prior Rikugan comment on this PR via
    COMMENT_MARKER (embedded by render_comment) and PATCH it instead of
    always POSTing a new one, so an actively-iterated PR gets one comment
    that stays current across rescans rather than a growing stack of
    near-duplicates."""
    slug = repo_slug_from_url(target.repo_url)
    try:
        token = _get_installation_token_or_none(session, target)
        if not token:
            logger.warning("PR guardrail: no GitHub App installed, skipping PR comment")
            return

        headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
        existing_comment_id = _find_existing_comment_id(slug, pr_number, token)

        if existing_comment_id is not None:
            res = httpx.patch(
                f"https://api.github.com/repos/{slug}/issues/comments/{existing_comment_id}",
                headers=headers,
                json={"body": body},
                timeout=15,
            )
            action = "update"
        else:
            res = httpx.post(
                f"https://api.github.com/repos/{slug}/issues/{pr_number}/comments",
                headers=headers,
                json={"body": body},
                timeout=15,
            )
            action = "create"

        if res.status_code >= 300:
            logger.warning("PR guardrail: failed to %s PR comment: %s %s", action, res.status_code, res.text[:300])
    except Exception:
        logger.warning("PR guardrail: exception posting PR comment", exc_info=True)


def set_commit_status(session: Session, target: Target, sha: str, state: str, description: str) -> str:
    """Post the commit status. Never raises; returns "" on success or a short
    human-readable reason on failure.

    (GH-04) Still fail-open at the transport layer -- a GitHub outage must not
    abort a scan that already produced real findings -- but no longer *silent*.
    Enforcement resolution is carefully fail-closed (conflicting groups resolve
    to the most restrictive), while the channel carrying that decision to
    GitHub failed open into a container log nobody reads. If an installation
    token breaks, PRs quietly stop being marked and no one is told.

    The returned reason is persisted on the scan row and rendered in PR
    History, so "the decision never reached GitHub" is visible in the same
    place as the decision itself.
    """
    slug = repo_slug_from_url(target.repo_url)
    try:
        token = _get_installation_token_or_none(session, target)
        if not token:
            logger.warning("PR guardrail: no GitHub App installed, skipping commit status")
            return "No GitHub App installed for this repository, so no commit status was posted."
        res = httpx.post(
            f"https://api.github.com/repos/{slug}/statuses/{sha}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
            json={
                "state": state,
                "context": "rikugan/pr-guardrail",
                "description": description[:140],
                "target_url": f"{FRONTEND_URL}/pr-history",
            },
            timeout=15,
        )
        if res.status_code >= 300:
            logger.warning("PR guardrail: failed to set commit status: %s %s", res.status_code, res.text[:300])
            return f"GitHub rejected the commit status ({res.status_code}). The PR was scanned but is not marked on GitHub."
    except Exception as exc:
        logger.warning("PR guardrail: exception setting commit status", exc_info=True)
        # Type name only, never str(exc): an httpx error can carry the
        # request URL, and that URL is built with an installation token.
        return (
            f"Could not reach GitHub to post the commit status ({type(exc).__name__}). "
            "The PR was scanned but is not marked on GitHub."
        )
    return ""


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

    pr_res = github_get(f"/repos/{slug}/pulls/{pr_number}", token=resolve_github_token(session, target.workspace_id, slug) or "")
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
            target.repo_url, head_branch, resolve_github_token(session, target.workspace_id, slug) or "", scan_id=f"pr-{pr_scan.id}"
        )
        guardrail_tools = _resolve_guardrail_tools(session, target)

        # (#243) Scope the scan to the PR's changed files when the target
        # opts in. Every path back to a full scan is explicit, and the scope
        # actually used is persisted -- a diff scan and a full scan report
        # very different amounts of assurance and must never be confused for
        # each other in the PR comment or the audit trail.
        scan_paths: list[str] | None = None
        if target.diff_scoped_pr_scans:
            changed = _changed_files(slug, pr_number)
            if changed is None:
                logger.info("pr guardrail: full scan for %s#%s (changed files unavailable)", slug, pr_number)
            elif len(changed) > MAX_DIFF_SCOPED_FILES:
                logger.info(
                    "pr guardrail: full scan for %s#%s (%s changed files exceeds %s)",
                    slug, pr_number, len(changed), MAX_DIFF_SCOPED_FILES,
                )
            elif not changed:
                logger.info("pr guardrail: full scan for %s#%s (no scannable changed files)", slug, pr_number)
            else:
                scan_paths = changed

        parsed, failed_tools, skipped_tools = _run_guardrail_tools(
            guardrail_tools, repo_path, paths=scan_paths
        )
        pr_scan.scan_scope = "diff" if scan_paths is not None else "full"
        pr_scan.files_scanned = len(scan_paths) if scan_paths is not None else 0
        pr_scan.tools_skipped = ",".join(sorted(skipped_tools))

        for item in parsed:
            # Must match the same normalization ingest_findings applies, or
            # dedup_hash never lines up with the persisted default-branch
            # findings and every PR finding looks "net-new" even when it
            # already exists on the base branch.
            item["file_path"] = runner.normalize_file_path(item.get("file_path", ""), repo_path)
            item["dedup_hash"] = compute_dedup_hash(
                rule_id=item["rule_id"],
                file_path=item["file_path"],
                # Per-finding: hashing every tool's findings under a single
                # constant would collide unrelated rules across tools and
                # make a gitleaks finding "match" a semgrep one on the same
                # line, silently suppressing it as not-net-new.
                tool=item["tool"],
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
        # Skipped tools are excluded as firmly as failed ones. tools_run is
        # the record of what actually examined this PR; a tool that never ran
        # must not appear in it (#243).
        pr_scan.tools_run = ",".join(
            t for t in guardrail_tools if t not in failed_tools and t not in skipped_tools
        )
        pr_scan.tools_failed = ",".join(failed_tools)
        pr_scan.completed_at = utcnow()
        session.add(pr_scan)
        session.commit()
        session.refresh(pr_scan)

        persisted_findings = _persist_findings(session, pr_scan.id, net_new)

        comment_body = render_comment(
            persisted_findings,
            new_endpoints,
            status,
            target.id,
            pr_scan.id,
            tools_run=[t for t in guardrail_tools if t not in failed_tools and t not in skipped_tools],
            tools_failed=failed_tools,
            tools_skipped=skipped_tools,
            scan_scope=pr_scan.scan_scope,
            files_scanned=pr_scan.files_scanned,
            # (#271) completed_at is set just above this call; falling back
            # to now() keeps the footer honest rather than omitting it if
            # that ordering ever changes.
            scanned_at=pr_scan.completed_at or utcnow(),
        )
        post_pr_comment(session, target, pr_number, comment_body)

        summary_desc = f"{len(net_new)} net-new finding(s), {len(new_endpoints)} new endpoint(s)"
        if failed_tools:
            # An assigned tool did not run. Whatever the other tools found,
            # this PR was NOT fully checked -- reporting "success" here would
            # be the exact false all-clear this project treats as a bug
            # (see issue #229, and osv_malware.py's None-vs-{} handling).
            # GitHub's "error" state is visually distinct from both success
            # and failure, which is precisely the signal wanted: inconclusive.
            commit_state = "error"
            commit_desc = f"{', '.join(failed_tools)} failed to run - PR not fully scanned. {summary_desc}"
        elif status == PRGuardrailStatus.PASSED:
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

        status_delivery_error = set_commit_status(session, target, head_sha, commit_state, commit_desc)
        if status_delivery_error:
            pr_scan.status_delivery_error = status_delivery_error
            session.add(pr_scan)
            session.commit()
            session.refresh(pr_scan)

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
        pr_scan.completed_at = utcnow()
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


def recompute_pr_scan_status(session: Session, pr_scan: PRGuardrailScan) -> None:
    """Re-evaluate a BLOCKED PRGuardrailScan after an individual finding's
    ignore-request is approved (#112). Before this, the only way to unblock
    a PR was the blunt whole-scan `override` -- approving every one of a
    PR's blocking findings individually still left the scan (and GitHub
    commit status) stuck on BLOCKED forever, since approve_ignore only
    touched the finding row, never the scan.

    No-op for scans not currently BLOCKED: a PASSED scan has nothing to
    recompute, and OVERRIDDEN is a deliberate accept-everything escape hatch
    that a later per-finding approval shouldn't silently reverse.
    """
    if pr_scan.status != PRGuardrailStatus.BLOCKED:
        return

    target = session.get(Target, pr_scan.target_id)
    if not target:
        return

    findings = session.exec(
        select(PRGuardrailFinding).where(PRGuardrailFinding.pr_scan_id == pr_scan.id)
    ).all()
    still_open = [f for f in findings if f.ignore_status != IgnoreStatus.APPROVED]

    policies = session.exec(
        select(PolicyRule).where(
            PolicyRule.workspace_id == target.workspace_id,
            PolicyRule.active == True,  # noqa: E712
        )
    ).all()
    blocking_severities = effective_blocking_severities(policies)

    if any(f.severity in blocking_severities for f in still_open):
        return  # a still-open (non-approved) finding legitimately keeps this blocked

    pr_scan.status = PRGuardrailStatus.PASSED
    session.add(pr_scan)
    session.commit()
    session.refresh(pr_scan)

    enforcement_mode = resolve_enforcement_mode(session, target)
    if enforcement_mode == "disabled":
        return
    try:
        slug = repo_slug_from_url(target.repo_url)
        pr_res = github_get(f"/repos/{slug}/pulls/{pr_scan.pr_number}", token=resolve_github_token(session, target.workspace_id, slug) or "")
        pr_res.raise_for_status()
        head_sha = pr_res.json()["head"]["sha"]
        set_commit_status(
            session,
            target,
            head_sha,
            "success",
            "All blocking findings individually approved for ignore",
        )
    except Exception:
        # Best-effort, same philosophy as the rest of this module's GitHub
        # calls -- the scan row itself is already correctly updated above;
        # a failure here just means GitHub's commit status lags until the
        # next real scan or a retry, not a failed approval.
        logger.exception(
            "PR guardrail: failed to update commit status after per-finding "
            "ignore approval for scan %s",
            pr_scan.id,
        )
