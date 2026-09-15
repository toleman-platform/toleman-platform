"""PR Guardrail execution: clone the PR head branch, scan, diff against the
default branch, persist a PRGuardrailScan (+ one PRGuardrailFinding per
net-new finding, so each can be deep-linked and carry its own ignore/approval
state), and best-effort post a PR comment + commit status. Extracted from
app/api/pr_guardrail.py so both the on-demand API route and the
webhook-driven (real-time, PR opened/synchronize) path call the exact same
logic instead of two copies drifting apart.
"""
import logging
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

import httpx
from sqlmodel import Session, select

from app.core.config import settings
from app.core.dedup import compute_dedup_hash
from app.core import code_graph
from app.core.enforcement import resolve_enforcement_mode
from app.core.github import github_get, repo_slug_from_url
from app.core.github_app import get_installation_token, resolve_config_for_installation, resolve_installation_for_repo
from app.core.github_token import resolve_github_token
from app.core.policy import apply_policies, effective_blocking_severities
from app.core.pr_guardrail import (
    SEVERITY_ORDER,
    WHOLE_FILE,
    attributable_to_diff,
    compute_net_new,
    highest_severity,
    should_block,
)
from app.models.models import (
    ApiEndpoint,
    Finding,
    FindingState,
    IgnoreStatus,
    PolicyRule,
    PRGuardrailFinding,
    PRGuardrailScan,
    PRGuardrailStatus,
    Scan,
    Target,
)
from app.core import target_lifecycle
from app.core.tool_usage import tools_for_surface
from app.core.time import utcnow
from app.scanners import parsers, runner
from app.scanners.discovery import discover_endpoints

logger = logging.getLogger(__name__)

# GH-02: every link this module posts to GitHub (PR comment "review in
# Toleman", "request ignore", and the commit status target_url below) used
# to be a hardcoded localhost:3000, unfollowable by anyone but the author.
FRONTEND_URL = settings.public_base_url.rstrip("/")

# Fallback when a workspace has no usable pr_guardrail assignment resolved
# (see _resolve_guardrail_tools). Kept because semgrep is bundled in the
# backend image and was the historical hardcoded behavior; but it is now a
# floor, not the whole story: whatever else the workspace assigns runs too.
GUARDRAIL_FALLBACK_TOOL = "semgrep"
MAX_NEW_FINDINGS_IN_RESPONSE = 20
MAX_NEW_ENDPOINTS_IN_RESPONSE = 10


def _resolve_guardrail_tools(session: Session, target: Target) -> list[str]:
    """Tools to run for this target's PR guardrail scan.

    Reads the workspace's real pr_guardrail usage assignments (GH-01:
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

    * **ran**: findings (possibly none), a real result
    * **failed**: the tool raised; recorded rather than aborting the scan,
      since one broken scanner shouldn't discard what the others found
    * **skipped**: diff scoping left it nothing to examine (``trivy`` with
      no manifest change, ``tfsec`` with no Terraform). Mapped to its reason.

    The caller must not treat a run with non-empty ``failed`` or ``skipped``
    as a clean pass. That is the "a check that did not really run must never
    look like a check that passed" rule this codebase already applies in
    osv_malware.py.
    """
    findings: list[dict] = []
    failed: list[str] = []
    skipped: dict[str, str] = {}
    if any(tool in ("trivy", "trivy-license") for tool in tools) and (
        paths is None or runner.manifest_changed(paths)
    ):
        # (#229) Guardrail scans hardlink from the same warm vulnerability
        # DB the scheduled scans use. Warming here too means a PR check on a
        # deployment whose beat has not run yet pays the download once,
        # under the shared lock, instead of once per concurrent PR.
        #
        # The gate mirrors run_tool's own scoping decision exactly, so we
        # only pay for the download when trivy is actually going to run:
        #
        #   paths is None      unscoped scan; _run_tool_inner runs trivy
        #                      over the whole checkout, so warm it. (Passing
        #                      None to manifest_changed, which iterates its
        #                      argument, raised TypeError and aborted the
        #                      whole guardrail scan before any tool ran.)
        #   paths given        diff-scoped; _run_tool_scoped raises
        #                      ToolNotApplicable for a MANIFEST tool when no
        #                      manifest changed. Warming on assignment alone
        #                      would make the typical PR -- one that changes
        #                      application code only -- wait on a
        #                      multi-hundred-megabyte download for a scanner
        #                      that is then skipped.
        runner.ensure_warm_trivy_db()
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


def _pr_files(slug: str, pr_number: int, token: str = "") -> list[dict] | None:
    """Raw `GET /pulls/{n}/files` entries for the PR, all pages.

    Returns None when the list can't be established, which every caller must
    treat as "we do not know what this PR changed"; never as "nothing
    changed". Both things derived from it -- the diff-scoped scan path list
    (#243) and the changed-line map used for authorship attribution -- have
    a defined, non-suppressing behavior for None, and neither may invent an
    empty diff out of an API failure.

    ``token`` should be the caller's already-resolved
    ``resolve_github_token(...)`` credential; without it this call runs
    unauthenticated and 404s on any private repo, which the except-branch
    below would silently read as a missing diff rather than the auth failure
    it actually is.
    """
    entries: list[dict] = []
    page = 1
    while True:
        try:
            res = github_get(f"/repos/{slug}/pulls/{pr_number}/files?per_page=100&page={page}", token=token)
            res.raise_for_status()
            batch = res.json()
        except Exception:
            logger.warning(
                "pr guardrail: could not list changed files for %s#%s",
                slug, pr_number, exc_info=True,
            )
            return None
        if not isinstance(batch, list):
            # Not a file list. An error object served with a 200, a proxy's
            # HTML, anything: it tells us nothing about what changed, so it
            # takes the same path as an outright failure rather than being
            # iterated into nonsense.
            logger.warning(
                "pr guardrail: unexpected files payload for %s#%s (%s)",
                slug, pr_number, type(batch).__name__,
            )
            return None
        if not batch:
            break
        entries.extend(batch)
        if len(batch) < 100:
            break
        page += 1
        if page > 30:  # 3000 files; far past MAX_DIFF_SCOPED_FILES anyway
            logger.warning("pr guardrail: %s#%s has more files than we will page", slug, pr_number)
            return None
    return entries


def _changed_paths(entries: list[dict]) -> list[str]:
    """Repo-relative paths the PR adds or modifies, out of `_pr_files` entries.

    Deleted files are excluded: there is no file left to scan, and their
    findings disappear from the head branch anyway. Renames report only the
    new path, which is what exists in the checkout.
    """
    paths: list[str] = []
    for entry in entries:
        if entry.get("status") == "removed":
            continue
        filename = entry.get("filename")
        if filename:
            paths.append(filename)
    return paths


# `@@ -old,count +new,count @@`; only the head-side start matters here,
# since attribution is about lines that exist in the PR's checkout.
_HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def _added_lines_from_patch(patch: str) -> set[int]:
    """Head-side line numbers a unified-diff patch adds or rewrites.

    Only `+` lines count. A `-` line is code the author deleted -- there is
    nothing left in the checkout for a scanner to flag -- and a context line
    is code they left alone, which is the whole point of this filter.
    """
    added: set[int] = set()
    line_no = 0
    in_hunk = False
    for raw in patch.splitlines():
        header = _HUNK_HEADER.match(raw)
        if header:
            line_no = int(header.group(1))
            in_hunk = True
            continue
        if not in_hunk:
            # Anything before the first `@@` has no head-side line number to
            # attribute it to. Counting it would number lines from zero.
            continue
        if not raw:
            # An empty line in a patch body is an unchanged blank line (the
            # leading space is often stripped in transit). Advance, count
            # nothing.
            line_no += 1
            continue
        marker = raw[0]
        if marker == "+":
            added.add(line_no)
            line_no += 1
        elif marker == "-":
            continue
        elif marker == "\\":
            # "\ No newline at end of file"; metadata, not a line.
            continue
        else:
            line_no += 1
    return added


def _changed_line_map(entries: list[dict]) -> dict[str, set[int] | None]:
    """Map each non-deleted path in the PR to the head-side lines it changed,
    or to ``WHOLE_FILE`` when GitHub gives no patch to read them from.

    GitHub omits `patch` for binary files and for diffs past its inline size
    limit, and a pure rename carries no hunks. In all three the file is
    genuinely part of this PR, so it maps to ``WHOLE_FILE`` (attribute
    everything in it) rather than to an empty set (attribute nothing) --
    this filter exists to stop blaming authors for code they did not touch,
    not to become a new way for a real finding to disappear.
    """
    out: dict[str, set[int] | None] = {}
    for entry in entries:
        if entry.get("status") == "removed":
            continue
        filename = entry.get("filename")
        if not filename:
            continue
        patch = entry.get("patch")
        out[filename] = _added_lines_from_patch(patch) if patch else WHOLE_FILE
    return out


def _severity_str(severity) -> str:
    """Findings carry a Severity enum member up to this point; f-string-ing
    an enum directly renders "Severity.MEDIUM" (its default __repr__-ish
    __str__), not "Medium"; a real bug found via a screenshot of an actual
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


def _carry_forward_approved_ignore(
    session: Session, target_id: int, pr_number: int, tool: str, rule_id: str, file_path: str, line_start: int | None
) -> PRGuardrailFinding | None:
    """A security reviewer approving an ignore on one scan of a PR is a
    decision about that PR, not just that one scan snapshot. Without this,
    the next scan of the same PR (e.g. after an unrelated commit) re-surfaces
    the identical finding as a fresh row with ignore_status="none" -- net-new
    vs the default branch is still technically correct, but it looks exactly
    like an unaddressed issue a reviewer never saw, when they already
    approved it. Matched the same way _sync_approved_ignore_to_main_findings
    (app/api/pr_guardrail.py) matches a main Finding: tool/rule_id/file_path
    /line_start, since PRGuardrailFinding has no snippet to build a real
    dedup_hash from. Most-recently-approved instance wins if there happen to
    be more than one (there normally won't be)."""
    query = select(PRGuardrailFinding).where(
        PRGuardrailFinding.pr_scan_id.in_(
            select(PRGuardrailScan.id).where(
                PRGuardrailScan.target_id == target_id, PRGuardrailScan.pr_number == pr_number
            )
        ),
        PRGuardrailFinding.tool == tool,
        PRGuardrailFinding.rule_id == rule_id,
        PRGuardrailFinding.file_path == file_path,
        PRGuardrailFinding.ignore_status == IgnoreStatus.APPROVED,
    )
    query = query.where(
        PRGuardrailFinding.line_start.is_(None) if line_start is None else PRGuardrailFinding.line_start == line_start
    )
    query = query.order_by(PRGuardrailFinding.ignore_reviewed_at.desc())
    return session.exec(query).first()


def _carry_forward_approvals(session: Session, target_id: int, pr_number: int, net_new: list[dict]) -> list[PRGuardrailFinding | None]:
    """One prior-approval lookup per net_new item, computed once and reused
    by both the blocking-severity filter (a carried-forward finding must not
    keep re-blocking the PR on every subsequent scan) and _persist_findings
    (which stamps the carried-forward status onto the new row) -- rather
    than each querying independently and disagreeing if the DB changed
    between the two calls within the same scan."""
    return [
        _carry_forward_approved_ignore(
            session, target_id, pr_number,
            f.get("tool") or GUARDRAIL_FALLBACK_TOOL, f.get("rule_id", ""), f.get("file_path", ""), f.get("line_start"),
        )
        for f in net_new
    ]


def _persist_findings(
    session: Session, pr_scan_id: int, net_new: list[dict], prior_approvals: list[PRGuardrailFinding | None]
) -> list[PRGuardrailFinding]:
    rows = []
    for f, prior_approval in list(zip(net_new, prior_approvals))[:MAX_NEW_FINDINGS_IN_RESPONSE]:
        row = PRGuardrailFinding(
            pr_scan_id=pr_scan_id,
            tool=f.get("tool") or GUARDRAIL_FALLBACK_TOOL,
            rule_id=f.get("rule_id", ""),
            title=f.get("title", "") or f.get("rule_id", ""),
            file_path=f.get("file_path", ""),
            line_start=f.get("line_start"),
            severity=_severity_str(f.get("severity")),
        )
        if prior_approval:
            row.ignore_status = IgnoreStatus.APPROVED
            row.ignore_requested_by = prior_approval.ignore_requested_by
            row.ignore_requested_reason = prior_approval.ignore_requested_reason
            row.ignore_reviewed_by = prior_approval.ignore_reviewed_by
            row.ignore_reviewed_at = prior_approval.ignore_reviewed_at
        session.add(row)
        rows.append(row)
    session.commit()
    for row in rows:
        session.refresh(row)
    return rows


def _has_baseline_scan(session: Session, target: Target) -> bool:
    """Whether the target's default branch has ever had a completed Scan
    persisted (GH-07).

    ``existing_hashes`` in ``execute_pr_guardrail_scan`` is drawn from
    Finding rows on ``target.default_branch``; on a target whose default
    branch has never actually been scanned, that set is empty for the same
    reason it would be empty on a branch that was scanned and found clean.
    Those two must not be treated the same -- one means "nothing to diff
    against", the other means "diffed and matched". This is checked against
    Scan (what actually ran), not against Finding directly, so a default
    branch scan that legitimately found nothing still counts as a baseline.
    """
    return (
        session.exec(
            select(Scan.id).where(
                Scan.target_id == target.id,
                Scan.branch == target.default_branch,
                Scan.status == "completed",
            )
        ).first()
        is not None
    )


def _diff_new_endpoints(session: Session, target: Target, repo_path) -> list[dict]:
    """Real static-analysis route discovery on the PR branch, diffed against
    what's already persisted for the target's default branch; same
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
        # branch, so there is nothing to diff against; and diffing against
        # an empty set makes the *entire repository* look new.
        #
        # An external evaluation hit exactly this: a PR touching one file got
        # a comment announcing four new endpoints across bad/vulpy.py,
        # good/vulpy.py and their SSL variants. First-run noise, in the most
        # visible artefact this tool produces, at the moment a team is
        # deciding whether to trust it.
        #
        # "No baseline" is not "everything is new", same distinction this
        # codebase draws between a check that found nothing and a check that
        # never ran. Report nothing rather than something false.
        logger.info(
            "PR guardrail: no persisted endpoint baseline for target %s branch %s, "
            "skipping the new-endpoint diff for this scan rather than reporting the "
            "whole repo as new",
            target.id, target.default_branch,
        )
        return []

    return [d for d in discovered if (d["method"], d["route"], d["file"]) not in existing]


def _attributable_endpoints(endpoints: list[dict], changed_lines: dict[str, set[int] | None] | None) -> list[dict]:
    """The endpoint list has the same false-attribution failure the finding
    list does, and for the same reason: "absent from the persisted baseline"
    is not "added by this PR". A baseline that predates a route, or a
    discovery pass that has improved since it was written, announces
    endpoints in files the author never opened -- the reported case had 15
    of them on a PR that changed one workflow file.

    Informational or not, that is still the comment telling a reviewer this
    PR did something it did not do. Filtered through the same diff.

    ``None`` (diff unavailable) returns the list untouched, matching the
    findings path: unknown authorship is never resolved by hiding things.
    """
    if changed_lines is None:
        return endpoints
    shaped = [
        {"file_path": e.get("file", ""), "line_start": e.get("line"), "_endpoint": e}
        for e in endpoints
    ]
    return [item["_endpoint"] for item in attributable_to_diff(shaped, changed_lines)]


# Hidden HTML marker embedded in every comment `render_comment()` produces,
# used by `post_pr_comment()` to find a prior Toleman comment on the PR and
# PATCH it in place instead of posting a new one on every rescan (#127).
# GitHub strips HTML comments from the rendered view, so this is invisible
# to a human reading the PR but trivially greppable via the Issue Comments API.
COMMENT_MARKER = "<!-- toleman-pr-guardrail -->"

# Pre-rename marker. Comments posted before the Rikugan -> Toleman rename
# carry this one, so the lookup below has to match either; otherwise the
# first rescan after upgrading would fail to find its own prior comment and
# post a second one alongside it on every PR the guardrail has ever touched.
# Only ever matched, never emitted: new comments always carry COMMENT_MARKER,
# so a PR migrates to the new marker the first time it is rescanned.
LEGACY_COMMENT_MARKERS = ("<!-- rikugan-pr-guardrail -->",)

# Severities whose per-finding <details> block is expanded by default; the
# ones a reviewer needs to see without an extra click. Medium/Low collapse
# since they're rarely PR-blocking on their own (see BLOCKING_SEVERITIES in
# app/core/pr_guardrail.py).
OPEN_BY_DEFAULT_SEVERITIES = {"Critical", "High"}


# --- Same-location grouping (#383) -------------------------------------------
#
# One hardcoded test secret on one line is routinely flagged by two tools at
# once -- semgrep's generic.secrets.security.detected-aws-access-key-id-value
# and gitleaks' aws-access-token both fire on the same AWS key. Both
# detections are correct and both are persisted (see below), but rendering
# them as two top-level rows and counting them as two net-new findings tells
# a reviewer there are two problems to fix when there is one line and one fix.
#
# This is a *presentation* layer only, and deliberately so:
#
# * `compute_dedup_hash` still includes each finding's own `tool`, and must
#   keep doing so (tests/test_pr_guardrail_multi_tool.py::
#   test_same_rule_from_two_tools_is_not_deduped_away). Collapsing across
#   tools by content alone would let an unrelated semgrep hit "match" a real
#   gitleaks hit on the same file/line and silently vanish as not-net-new.
#   Nothing here changes what is scanned, hashed, diffed or persisted.
# * Every member of a group keeps its own PRGuardrailFinding row, its own
#   rule/title, its own deep link and its own ignore-request lifecycle. A
#   group is a row, never an entity: there is nothing to approve, ignore or
#   deep-link at group level, which is why LocationGroup has no id.
#
# Grouping is therefore safe in a way cross-tool dedup is not: nothing is
# dropped, so a group that turns out to hold two genuinely different problems
# on one line still shows both, one click away.


def _severity_rank(severity: str) -> int:
    """Position in SEVERITY_ORDER, or -1 for a severity string this platform
    doesn't rank (a parser emitting something unexpected). -1 sorts below
    everything known, so an unrankable severity can never win a group's
    reported severity away from a real one."""
    return SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else -1


@dataclass
class LocationGroup:
    """The findings rendered as one row: everything flagged at one file and
    line by two or more different tools (see group_findings_by_location for
    why single-tool locations are never grouped)."""

    file_path: str
    line_start: int | None
    findings: list[PRGuardrailFinding] = field(default_factory=list)

    @property
    def key(self) -> str:
        """Identifier for this group, used by the API to tell the frontend
        which rows belong together without it re-deriving the grouping rule.

        Deliberately NOT the location alone. A location is not unique across
        groups: group_findings_by_location emits *one group per finding* in
        exactly the two cases it must not merge -- one tool's own findings on
        one line, and file-level findings carrying no line number -- and all
        of those groups share a file/line. Keying on the location would let a
        consumer re-merge precisely what the grouping rule just kept apart
        (three trivy CVEs on requirements.txt collapsing into one row, two of
        them hidden behind a toggle). The first member's id disambiguates:
        every finding belongs to exactly one group, so no two groups can
        share one. The location is kept in the string for legibility only.

        Never empty, whatever the finding carries -- parse_sarif emits
        file_path "" for a result with no locations, and an empty key would
        slip past a consumer's nullish check and bucket every such finding
        together.
        """
        return f"{self.findings[0].id}@{_location_label(self.file_path, self.line_start)}"

    @property
    def tools(self) -> list[str]:
        """Distinct contributing tools, in the order they were scanned, so
        the "found by" line reads the same way twice for the same scan."""
        seen: list[str] = []
        for f in self.findings:
            if f.tool not in seen:
                seen.append(f.tool)
        return seen

    @property
    def is_grouped(self) -> bool:
        return len(self.findings) > 1

    @property
    def primary(self) -> PRGuardrailFinding:
        """The member whose severity and title represent the group: the
        most severe one, earliest-scanned on a tie (max() is stable). Its
        title is the group's headline precisely because it is the member a
        reviewer would act on first."""
        return max(self.findings, key=lambda f: _severity_rank(f.severity))

    @property
    def severity(self) -> str:
        """Highest severity among the members.

        Tools disagree about the same line all the time -- semgrep's generic
        secret rule is High where gitleaks' provider-specific one is
        Critical, and vice versa. Reporting the highest is the only choice
        that can't hide a problem: a group rendered at its *lowest* member's
        severity would let a Critical finding sit inside a row labelled
        Medium, collapsed by default (OPEN_BY_DEFAULT_SEVERITIES) and counted
        in the wrong column of the severity table. Blocking is unaffected
        either way -- should_block still runs over individual findings, not
        groups -- so this only governs how the row reads."""
        return self.primary.severity


def group_findings_by_location(findings: list[PRGuardrailFinding]) -> list[LocationGroup]:
    """Collapse findings that several tools reported at the same file/line
    into one group each; everything else stays a group of one, so callers can
    render a uniform list of groups without special-casing.

    Two deliberate non-groupings:

    * **Same tool, same line.** A tool that reports two rules on one line has
      already deduplicated its own output and is saying these are two
      findings; we are in no position to overrule it. The confusing case this
      addresses is specifically one line reported by *different* tools, each
      unaware of the others.
    * **No line number.** A file-level finding (a vulnerable dependency in a
      manifest, say) is not a location in the sense this grouping means: two
      tools flagging "somewhere in requirements.txt" are very often flagging
      different packages, and merging them into a row that names one of them
      would be actively misleading. They stay separate rows. A falsy check,
      not `is not None`: parse_trivy's CauseMetadata.StartLine and parse_iac's
      file_line_range[0] both report 0 for a file-level check, which means
      the same "no line" as None and must not slip past into a location.
    * **No file path.** parse_sarif reports file_path "" for a result that
      carries no locations at all. "Line 12 of nowhere in particular" is not
      somewhere two tools can agree on, and bucketing on it would merge
      findings whose only established connection is that neither could say
      where it was.

    Findings keep their original order, and a merged group sits where its
    first member was, so when nothing merges (the common case) the rendered
    order is exactly the order the findings arrived in -- rather than later
    members of a bucket being hoisted up next to the first.
    """
    buckets: dict[tuple[str, int], list[int]] = {}
    for index, f in enumerate(findings):
        if not f.line_start or not f.file_path:
            continue
        buckets.setdefault((f.file_path, f.line_start), []).append(index)

    # Which buckets actually merge, recorded by the index of their first
    # member so the merged row lands in that member's original position.
    merged: dict[int, list[PRGuardrailFinding]] = {}
    absorbed: set[int] = set()
    for indices in buckets.values():
        members = [findings[i] for i in indices]
        if len({f.tool for f in members}) < 2:
            # One tool's own multiple findings at one line: separate rows,
            # see the docstring. Also the overwhelmingly common case of a
            # single finding at a location.
            continue
        merged[indices[0]] = members
        absorbed.update(indices)

    groups: list[LocationGroup] = []
    for index, f in enumerate(findings):
        if index in merged:
            groups.append(LocationGroup(f.file_path, f.line_start, merged[index]))
        elif index not in absorbed:
            groups.append(LocationGroup(f.file_path, f.line_start, [f]))
    return groups


def _severity_badge(status: PRGuardrailStatus) -> str:
    """shields.io-style top-line pass/fail badge, same visual pattern as
    the SafeDep bot's badge comments already seen on this repo's PRs (e.g.
    PR #11), rebuilt via img.shields.io instead of a static PNG so the label
    changes with the real scan outcome."""
    if status == PRGuardrailStatus.BLOCKED:
        return "![Blocked](https://img.shields.io/badge/status-blocked-red)"
    return "![Passed](https://img.shields.io/badge/status-passed-brightgreen)"


def _severity_counts(groups: list[LocationGroup]) -> dict[str, int]:
    # (#383) Counts rows, not raw detections: two tools flagging one line
    # contribute 1 here, at the higher of the two severities (see
    # LocationGroup.severity), because that is one thing for a reviewer to
    # look at. The raw detection count is still disclosed in render_comment's
    # headline whenever the two numbers differ.
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for g in groups:
        counts[g.severity] = counts.get(g.severity, 0) + 1
    return counts


def _severity_count_table(groups: list[LocationGroup]) -> str:
    """One-line (single header + single data row) GFM table summarizing
    net-new finding counts by severity, meant to be the first thing a
    reviewer sees; before any per-finding detail."""
    counts = _severity_counts(groups)
    header = "| " + " | ".join(SEVERITY_ORDER) + " |"
    divider = "|" + "|".join(["---"] * len(SEVERITY_ORDER)) + "|"
    row = "| " + " | ".join(str(counts[sev]) for sev in SEVERITY_ORDER) + " |"
    return "\n".join([header, divider, row])


def _finding_ref_link(target_id: int, pr_scan_id: int, finding_id: int) -> str:
    return f"{FRONTEND_URL}/pr-history?target_id={target_id}&pr_scan_id={pr_scan_id}#finding-{finding_id}"


def _finding_ignore_link(pr_scan_id: int, finding_id: int) -> str:
    # A dedicated, minimal page (frontend/src/app/ignore-request/...), not
    # /pr-history: that page carries the full dashboard layout (sidebar, a
    # live GitHub-PRs fetch, the whole PR Audit log for the target), all of
    # it irrelevant to this one action and slow to clear before the user
    # sees anything. This route does the one API call it needs and shows the
    # result -- "Requested" or whatever the finding's state already is --
    # with nothing else in the way.
    return f"{FRONTEND_URL}/ignore-request/{pr_scan_id}/{finding_id}"


def _scanned_commit(repo_path: Path | str, reported_head_sha: str) -> str:
    """The commit the clone actually landed on.

    runner.clone_repo clones the PR's head *branch* (`--depth 1 --branch ...`),
    not the SHA the GitHub API reported a moment earlier, and a PR being
    actively pushed to can advance in between. The scan then examines one
    commit while the PR comment's source links point at another, where the
    same line number is a different line. The commit status is deliberately
    left on the API-reported SHA -- that is the ref GitHub keys a check to, and
    a status posted against a commit GitHub did not ask about is not shown at
    all -- so only the links move.

    Falls back to the reported SHA on any failure: a link to a slightly older
    commit is worth far more than no link.
    """
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_path), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=15, check=True,
        )
        return result.stdout.strip() or reported_head_sha
    except Exception:
        logger.warning(
            "pr guardrail: could not resolve the cloned HEAD; linking findings to the "
            "PR's reported head sha instead", exc_info=True,
        )
        return reported_head_sha


def _code_span(text: str) -> str:
    """`text` as a Markdown code span in a GFM table cell, proof against
    whatever the text happens to contain.

    Every caller of this passes a filename, and filenames on a PR branch are
    written by whoever opened the PR. Three things in one would otherwise
    escape the span and become markup in a comment posted under this app's own
    identity:

    * A backtick ends a single-backtick span early, so a name like
      ``x`](https://evil.example.com)`` leaves a real link behind. CommonMark
      closes a span on a backtick run of exactly the opening length, so the
      fence is one longer than the longest run inside the text; a leading or
      trailing backtick additionally needs the padding space CommonMark strips
      back off.
    * A newline ends the table row, putting the rest of the filename outside
      the table entirely. Rendered as a visible \\n rather than dropped, so the
      label still says what the file is actually called.
    * A pipe splits the row into an extra column, shifting every cell after it
      one place left. GFM honours a backslash escape here even inside a code
      span, which is the only reason a pipe can be shown at all.
    """
    flat = text.replace("\r", "\\r").replace("\n", "\\n").replace("|", "\\|")
    longest_run = max((len(run) for run in re.findall(r"`+", flat)), default=0)
    fence = "`" * (longest_run + 1)
    pad = " " if flat.startswith("`") or flat.endswith("`") else ""
    return f"{fence}{pad}{flat}{pad}{fence}"


def _source_link(repo_slug: str | None, head_sha: str | None, file_path: str, line_start: int | None) -> str:
    """The `path:line` location cell, as a link straight to that line of that
    file on GitHub when we know which commit was scanned.

    A reviewer reading a finding's location has to get to the code before they
    can judge it, and a bare `app/api/github.py:58` made them go find it by
    hand in the Files tab. Pinned to the scanned commit's SHA rather than the
    branch name: the comment is a record of what a specific commit contained,
    and a branch link would silently re-point at later commits where the line
    numbers no longer mean anything.

    repo_slug/head_sha are optional for the same reason every other addition
    to this comment is (see render_comment's docstring): a caller that doesn't
    have them renders exactly the plain code span this used to.

    Anyone who can open a PR controls the filenames in it, so the path is
    treated as hostile in both places it lands: percent-encoded in the link
    target ("/" left alone so the URL keeps its path structure), and rendered
    through _code_span in the label. See each for what they are defending
    against.
    """
    loc = file_path
    if line_start:
        loc += f":{line_start}"
    label = _code_span(loc)
    if not repo_slug or not head_sha or not file_path:
        return label
    quoted_path = quote(file_path.lstrip("/"), safe="/")
    url = f"https://github.com/{repo_slug}/blob/{head_sha}/{quoted_path}"
    if line_start:
        url += f"#L{line_start}"
    return f"[{label}]({url})"


def _approved_action_cell(ref_link: str) -> str:
    return f"[view]({ref_link}) &middot; ✅ approved to ignore"


def _pending_action_cell(ref_link: str, ignore_link: str) -> str:
    return f"[view]({ref_link}) &middot; [request ignore]({ignore_link})"


def _location_label(file_path: str, line_start: int | None) -> str:
    return f"{file_path}:{line_start}" if line_start else file_path


def _action_cell(f: PRGuardrailFinding, target_id: int, pr_scan_id: int) -> str:
    ref_link = _finding_ref_link(target_id, pr_scan_id, f.id)
    if f.ignore_status == IgnoreStatus.APPROVED:
        # #401: this row's ignore_status can arrive already "approved"
        # at render time -- carried forward from an earlier scan of the
        # same PR (_carry_forward_approved_ignore) -- and must not offer
        # "request ignore" again as if nobody had acted on it yet.
        return _approved_action_cell(ref_link)
    return _pending_action_cell(ref_link, _finding_ignore_link(pr_scan_id, f.id))


def _findings_table(
    groups: list[LocationGroup],
    target_id: int,
    pr_scan_id: int,
    repo_slug: str | None = None,
    head_sha: str | None = None,
) -> str:
    """GFM table (Severity | Rule | Title | Location | Links) for one
    severity group's findings, replaces the old flat prose-bullet list.

    (#383) One row per LocationGroup. A group of one renders exactly as it
    always did. A multi-tool group renders a single collapsed row naming the
    tools, with each member's own rule, title and links in the expandable
    block `_group_detail_blocks` emits just below this table.
    """
    lines = [
        "| Severity | Rule | Title | Location | Links |",
        "|---|---|---|---|---|",
    ]
    for g in groups:
        # (#455) The location is a link to that line of that file at the
        # scanned commit, and its label is _code_span'd against hostile
        # filenames. A group's members share one location by construction, so
        # the grouped row links exactly where each of its members would.
        loc = _source_link(repo_slug, head_sha, g.file_path, g.line_start)
        if not g.is_grouped:
            f = g.findings[0]
            lines.append(
                f"| {f.severity} | `{f.rule_id}` | {f.title} | {loc} | "
                f"{_action_cell(f, target_id, pr_scan_id)} |"
            )
            continue
        # The Rule cell carries the tool list rather than a rule id: the
        # whole point of the row is that there is no single rule here, and
        # "found by: semgrep, gitleaks" is the fact that turns two scary
        # rows into one line to go and look at. Per-tool rule ids are one
        # click away, below.
        #
        # The Links cell deliberately offers only "view" -- no group-level
        # "request ignore". Ignores are per-finding (there is no group row
        # in the database to approve), and a group-level ignore link would
        # also collide with the exact-substring patching
        # update_finding_status_in_pr_comment/revoke_finding_status_in_pr_comment
        # do on an individual row's cell.
        lines.append(
            f"| {g.severity} | found by: {', '.join(g.tools)} | {g.primary.title} | {loc} | "
            f"{_group_action_cell(g, target_id, pr_scan_id)} |"
        )
    return "\n".join(lines)


def _group_action_cell(
    group: LocationGroup, target_id: int, pr_scan_id: int, approved: int | None = None
) -> str:
    """The collapsed row's Links cell, which has to say whether the findings
    behind it have already been dealt with.

    A group whose members are *all* approved-to-ignore would otherwise render
    a header indistinguishable from an untouched one, with the approvals
    visible only after expanding -- the same "looks like an unaddressed issue
    a reviewer never saw" failure #401 fixed for individual rows.

    The tick goes *before* the view link, and never as `_approved_action_cell`
    itself. That cell's exact text is what
    `revoke_finding_status_in_pr_comment` searches for (built from a
    finding's own ref link, replaced once); emitting it here for the primary
    member would put a copy earlier in the body than the member's own row and
    silently send that single replacement to the header instead of the row it
    belongs to. Arranged this way the header cannot contain either patch
    path's search string -- `[view](ref) &middot; ✅ approved to ignore` or
    `&middot; [request ignore](link)` -- as a substring.

    `approved` overrides the count taken from the members' current state, and
    exists so `_patch_group_header_in_comment` can reconstruct the exact cell
    a past render produced for a past approval count. The cells for different
    counts are mutually exclusive strings, which is what makes finding the
    stale one in a posted comment an exact match rather than a guess.
    """
    ref_link = _finding_ref_link(target_id, pr_scan_id, group.primary.id)
    if approved is None:
        approved = sum(1 for f in group.findings if f.ignore_status == IgnoreStatus.APPROVED)
    if approved == len(group.findings):
        return f"✅ all {approved} approved to ignore &middot; [view]({ref_link})"
    if approved:
        return (
            f"[view]({ref_link}) &middot; {len(group.findings)} findings "
            f"({approved} approved), expand below"
        )
    return f"[view]({ref_link}) &middot; {len(group.findings)} findings, expand below"


def _patch_group_header_in_comment(
    session: Session, target_id: int, finding: PRGuardrailFinding, body: str
) -> str:
    """Bring the collapsed group header above `finding`'s row back in line
    with what its members now say, returning the patched body (unchanged if
    there is nothing to do).

    The individual cells `update_finding_status_in_pr_comment` and
    `revoke_finding_status_in_pr_comment` patch are per-finding, so before
    #383 every claim in a comment was owned by exactly one row and those two
    patches kept the whole comment current. A collapsed group header is the
    first thing in this comment that makes an *aggregate* claim ("all 2
    approved to ignore"), and an aggregate goes stale when any one member
    changes: after a revoke the header would keep saying all 2 are approved
    while the row below it offers a live "request ignore" link again.

    That direction is the one this module never tolerates. A stale header
    that *understates* (the approve direction: "2 findings" when one is now
    approved) is merely out of date; one that overstates is a false
    all-clear, the same thing the tools_failed and baseline-missing branches
    of render_comment exist to prevent. It would self-heal on the next
    rescan, but "wrong until someone pushes a commit" is exactly the gap #401
    closed for individual rows, so the header is patched from both paths and
    stays exactly current in both directions.

    Finding the stale text is an exact match, not a guess: a group renders
    exactly one of len(members)+1 possible header cells, all mutually
    exclusive and all reconstructible here, and each carries its group's own
    primary ref link so it cannot collide with another group's header. Any
    miss (the comment predates this, the group is a single row, the header
    was already patched) leaves the body untouched -- best-effort, like every
    other GitHub-facing step in this module.

    **Never raises**, and that is a requirement rather than tidiness. Both
    callers run this between their own per-finding replace and the single
    httpx.patch that ships it, inside one try/except. This step is also the
    only part of that sequence that touches the database once the comment
    body has been fetched -- a detached instance, a closed session, a dead
    connection -- so letting an exception out would abort the PATCH entirely
    and silently discard the per-finding cell update, which is the whole
    guarantee #401 makes ("a reviewer clicking Approve sees it on GitHub
    now"). A decoration must never be able to take down the thing it
    decorates: on any failure the caller's own patched body is returned
    unchanged and still gets posted, with the header left to self-heal on
    the next rescan.
    """
    try:
        siblings = session.exec(
            select(PRGuardrailFinding)
            .where(PRGuardrailFinding.pr_scan_id == finding.pr_scan_id)
            .order_by(PRGuardrailFinding.id)
        ).all()
        group = next(
            (
                g
                for g in group_findings_by_location(list(siblings))
                if any(f.id == finding.id for f in g.findings)
            ),
            None,
        )
        if group is None or not group.is_grouped:
            return body

        current = _group_action_cell(group, target_id, finding.pr_scan_id)
        for count in range(len(group.findings) + 1):
            stale = _group_action_cell(group, target_id, finding.pr_scan_id, approved=count)
            if stale != current and stale in body:
                return body.replace(stale, current, 1)
        return body
    except Exception:
        logger.warning(
            "PR guardrail: could not refresh the group header for finding %s; "
            "posting the per-finding update without it",
            finding.id, exc_info=True,
        )
        return body


def _group_detail_blocks(groups: list[LocationGroup], target_id: int, pr_scan_id: int) -> list[str]:
    """(#383) The expandable per-tool breakdown for every multi-tool group in
    one severity section, rendered under that section's table.

    A nested <details> rather than markup inside a table cell: block-level
    HTML in a GFM table cell renders inconsistently on GitHub, and this
    breakdown has to stay a real table so each tool's own rule, title,
    severity and -- crucially -- its own live "request ignore" link survive
    the collapse. Those per-member action cells are byte-identical to the
    ones an ungrouped row would carry, which is what keeps the approve and
    revoke comment-patching paths working unchanged for grouped findings.
    """
    lines: list[str] = []
    for g in groups:
        if not g.is_grouped:
            continue
        loc = _location_label(g.file_path, g.line_start)
        lines.append("<details>")
        lines.append(
            f"<summary><code>{loc}</code> &middot; {len(g.findings)} findings from "
            f"{', '.join(g.tools)}</summary>"
        )
        lines.append("")
        lines.append("| Tool | Severity | Rule | Title | Links |")
        lines.append("|---|---|---|---|---|")
        for f in g.findings:
            lines.append(
                f"| `{f.tool}` | {f.severity} | `{f.rule_id}` | {f.title} | "
                f"{_action_cell(f, target_id, pr_scan_id)} |"
            )
        lines.append("")
        lines.append("</details>")
        lines.append("")
    return lines


# (#271) A PR comment is a snapshot that gets read days later. Every severity
# here is derived from priority_score (app/core/scoring.py), which folds in
# EPSS and CISA KEV; both of which move. A finding rendered Medium when the
# comment was posted can genuinely be Critical by the time someone reviews
# it, because CISA added its CVE to KEV in between.
#
# Snyk's own fix PRs carry this line, and it was the one thing the
# competitive teardown said to steal outright:
#
#   "Max score is 1000. Note that the real score may have changed since the
#    PR was raised."
#
# It is the same instinct as tools_failed/tools_skipped (#243, #253) (a
# result is only true as of when it ran) applied to score freshness rather
# than scan completeness. Deliberately rendered on every comment, not only
# when something scored high: a reader cannot know whether a score moved
# without being told the number has an as-of date at all.
def _staleness_footer(scanned_at: datetime | None) -> str | None:
    if scanned_at is None:
        return None
    stamp = scanned_at.strftime("%Y-%m-%d %H:%M UTC")
    return (
        f"<sub>Severity reflects EPSS/KEV data as of {stamp} and may have changed since. "
        "Open the finding in Toleman for the current score.</sub>"
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
    baseline_missing: bool = False,
    scanned_at: datetime | None = None,
    blast_radius_files: int = 0,
    diff_attributed: bool | None = None,
    repo_slug: str | None = None,
    head_sha: str | None = None,
    total_findings: int | None = None,
) -> str:
    """`tools_run`/`tools_failed` default to None for callers (and tests)
    predating the multi-tool guardrail (GH-01); None means "don't render a
    coverage line", which reproduces the old output exactly.

    `scan_scope`/`files_scanned`/`tools_skipped` (#243) default to the
    whole-repo case for the same reason, so a caller that doesn't know about
    diff scoping renders exactly what it used to.

    `tools_skipped` (a tool ToolNotApplicable'd out, e.g. gosec on a repo
    with no Go files) is still recorded on the PRGuardrailScan row and still
    excluded from the "Scanned with" line below, but is no longer rendered
    as its own note in the comment body (previously "Not run for this PR:
    ..."): on a platform whose targets are mostly non-Go/non-Terraform, that
    note was a near-permanent, low-information fixture on every PR rather
    than something that changes a reader's judgment of the result -- unlike
    `tools_failed` below, which stays rendered because it means something
    that should have run didn't.

    `baseline_missing` (GH-07) defaults to False so callers/tests predating
    the baseline check render exactly what they used to; True means the
    finding diff was skipped because the target's default branch has never
    had a completed scan, so "no net-new findings" here is not yet a real
    diff against anything.

    `scanned_at` (#271) is when this scan ran. None omits the staleness
    footer entirely, same backwards-compatible default as everything above.

    `blast_radius_files` (#244) is how many of `files_scanned` were pulled
    in by the import graph rather than literally changed. 0 keeps the
    original #243 wording, which is the honest rendering for a scan whose
    radius really was just the diff.

    `diff_attributed` is three-valued, following the same
    None-means-render-what-you-used-to convention as everything above.
    True: findings were filtered down to the lines this PR changed, so the
    headline may claim this PR introduced them. False: the PR's diff could
    not be read, so they are net-new-against-the-baseline only and that gap
    is called out. None (default): a caller predating this filter, rendered
    exactly as before.

    `repo_slug`/`head_sha` are what turn each finding's `path:line` location
    into a link to that exact line on GitHub (see _source_link). Both None
    (the default) renders the plain code span this comment used to carry, so
    a caller that does not know which commit was scanned still produces a
    valid comment rather than a link pointing at the wrong revision.

    `total_findings` is how many net-new findings the scan actually produced,
    where `findings` is only the first MAX_NEW_FINDINGS_IN_RESPONSE of them.
    None (the default, and every pre-existing caller) means "what you were
    given is all there was", which is how this always behaved -- silently,
    since nothing ever disclosed the truncation."""
    lines = [COMMENT_MARKER, "**Toleman PR Guardrail**", "", _severity_badge(status), ""]

    if baseline_missing:
        # Rendered ahead of the scope note and any findings: a reader must
        # not walk away thinking a clean-looking result here means this PR
        # (or the repo behind it) was actually compared to anything. Once
        # the target's default branch has a completed scan, later PRs get a
        # real diff and this note stops appearing.
        lines.append(
            "ℹ️ **No baseline scan yet.** This target's default branch has never been "
            "scanned, so there is nothing to diff this PR against; pre-existing findings "
            "are not shown here. Run a scan of the default branch in Toleman to enable "
            "real diffs on future PRs."
        )
        lines.append("")

    if scan_scope == "diff":
        # Stated up front, above the result. A reader who takes "no findings"
        # as whole-repo assurance when only 7 files were examined has been
        # misled by us, not by the scanner; so the limit is part of the
        # headline, not a footnote.
        if blast_radius_files:
            # The expansion is disclosed rather than folded silently into
            # files_scanned: "12 files" and "2 changed plus 10 that import
            # them" describe the same scan, but only the second lets a
            # reader judge whether the radius covered what they care about.
            changed_count = files_scanned - blast_radius_files
            lines.append(
                f"🔍 **Diff-scoped scan (blast radius expanded)**, {files_scanned} file(s) "
                f"examined: the {changed_count} changed in this PR, plus {blast_radius_files} "
                "that import them. The whole repository was not scanned, so pre-existing issues "
                "outside that set would not appear here."
            )
        else:
            lines.append(
                f"🔍 **Diff-scoped scan**, only the {files_scanned} file(s) changed in this PR were "
                "examined, not the whole repository. Pre-existing issues elsewhere in the codebase "
                "would not appear here."
            )
        lines.append("")

    if diff_attributed is False:
        # Rendered with the other caveats, above the result: the difference
        # between "this PR introduced these" and "these are absent from the
        # last baseline scan, cause unknown" is the whole question a reader
        # is asking when a finding points at a file they never opened.
        lines.append(
            "⚠️ **This PR's diff could not be read**, so findings below could not be "
            "attributed to the lines it changed. They are net-new against the default "
            "branch's last scan, which can include pre-existing code whose finding moved "
            "(a renamed scanner rule, a stale baseline) rather than anything this PR wrote."
        )
        lines.append("")

    if tools_failed:
        # Rendered before anything else, and never alongside a clean-pass
        # tick: a PR scanned with a broken scanner is inconclusive, not
        # clean. Naming the tool is what makes it actionable, "scan
        # failed" alone sends people to the container logs.
        lines.append(
            f"⚠️ **{', '.join(tools_failed)} failed to run; this PR was not fully scanned.** "
            "Findings below (if any) are from the tools that did run, and may be incomplete."
        )
        lines.append("")

    if not findings and not new_endpoints:
        if baseline_missing:
            # Not "✅" and not "vs the default branch": there was no default
            # branch scan to diff against, see the note above. Contradicting
            # that note with a clean-looking checkmark here is exactly the
            # false all-clear this codebase's own tools_failed/scan_scope
            # branches already avoid.
            lines.append("No findings to report; see the baseline note above.")
        elif tools_failed:
            lines.append(
                "No net-new findings from the tools that completed. "
                "This is **not** an all-clear; see the warning above."
            )
        elif scan_scope == "diff":
            # No tick here. A green check next to a partial scan is the exact
            # thing that turns a narrowed check into a false all-clear.
            lines.append(
                "No net-new findings or API changes in the changed files. "
                "This covers the diff only; see the scope note above."
            )
        elif diff_attributed:
            lines.append("No net-new findings or API changes introduced by this PR. ✅")
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
        # (#383) Everything below counts and renders *groups*: same-line
        # findings from two or more tools are one row, because they are one
        # thing to go and fix. When nothing groups (the common case) there is
        # one group per finding and this renders exactly as it always did.
        groups = group_findings_by_location(findings)

        # `findings` is only ever the first MAX_NEW_FINDINGS_IN_RESPONSE of a
        # scan's net-new set (_persist_findings truncates), and until now
        # nothing said so: the headline simply counted the page and called it
        # the result. Pre-existing, but this change makes it matter -- the
        # commit status beside this comment reports the full count when the
        # set was truncated (see execute_pr_guardrail_scan), so without this
        # note the two numbers disagree for no visible reason.
        total = total_findings if total_findings is not None else len(findings)
        truncated = total > len(findings)

        headline = "introduced by this PR's changes" if diff_attributed else "vs the default branch"
        # When truncated the headline is the real total, which is also what
        # the commit status says; the note below explains that only some of
        # them are rendered. Untruncated, it is the number of rows below.
        lines.append(f"**{total if truncated else len(groups)} net-new vulnerability finding(s)** {headline}:")
        lines.append("")
        # Never silently report a smaller number than the scanners produced.
        # A reviewer comparing this against the dashboard, the API, or the
        # Approval Queue (all of which are per-finding, and stay that way)
        # has to be able to see where any difference comes from -- same
        # reason tools_failed and the diff-scope note are rendered rather
        # than folded away.
        multi = sum(1 for g in groups if g.is_grouped)
        grouped_note = (
            f"grouped into {len(groups)} row(s) by location ({multi} line(s) flagged by more "
            "than one tool)"
            if len(groups) != len(findings)
            else ""
        )
        if truncated:
            lines.append(
                f"<sub>Showing the first {len(findings)} of {total} net-new findings"
                + (f", {grouped_note}" if grouped_note else "")
                + ". Open the scan in Toleman for the full list.</sub>"
            )
            lines.append("")
        elif grouped_note:
            lines.append(
                f"<sub>{len(findings)} detections, grouped into {len(groups)} by location: "
                f"{multi} line(s) flagged by more than one tool. Every tool's finding is still "
                "recorded and can be ignored on its own; expand a grouped row to see them.</sub>"
            )
            lines.append("")
        lines.append(_severity_count_table(groups))
        lines.append("")

        by_severity: dict[str, list[LocationGroup]] = {}
        for g in groups:
            by_severity.setdefault(g.severity, []).append(g)

        # Most-severe-first, matching SEVERITY_ORDER's ranking (reversed
        # since SEVERITY_ORDER is least-to-most severe).
        for sev in reversed(SEVERITY_ORDER):
            sev_groups = by_severity.get(sev)
            if not sev_groups:
                continue
            open_attr = " open" if sev in OPEN_BY_DEFAULT_SEVERITIES else ""
            lines.append(f"<details{open_attr}>")
            lines.append(f"<summary><strong>{sev}</strong> ({len(sev_groups)})</summary>")
            lines.append("")
            lines.append(_findings_table(sev_groups, target_id, pr_scan_id, repo_slug, head_sha))
            lines.append("")
            lines.extend(_group_detail_blocks(sev_groups, target_id, pr_scan_id))
            lines.append("</details>")
            lines.append("")

    if new_endpoints:
        lines.append("<details>")
        lines.append(f"<summary><strong>{len(new_endpoints)} new API endpoint(s)</strong> detected in this PR (informational, not blocking)</summary>")
        lines.append("")
        lines.append("| Method | Route | Location |")
        lines.append("|---|---|---|")
        for e in new_endpoints[:MAX_NEW_ENDPOINTS_IN_RESPONSE]:
            endpoint_loc = _source_link(repo_slug, head_sha, e.get("file", ""), e.get("line"))
            lines.append(f"| `{e['method']}` | `{e['route']}` | {endpoint_loc} |")
        if len(new_endpoints) > MAX_NEW_ENDPOINTS_IN_RESPONSE:
            lines.append("")
            lines.append(f"_...and {len(new_endpoints) - MAX_NEW_ENDPOINTS_IN_RESPONSE} more_")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    if status == PRGuardrailStatus.BLOCKED:
        lines.append("This PR is **blocked** pending fix or AppSec override, [review in Toleman]"
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
    (#34), previously this always grabbed installation row #1 and App
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


def _find_existing_comment(slug: str, pr_number: int, token: str) -> tuple[int, str] | None:
    """List issue comments on the PR and return (id, body) of the first one
    carrying COMMENT_MARKER, or None if there is no Toleman comment on this
    PR yet. GitHub's issue-comments API is paginated (100/page default);
    walk pages since a long-lived PR can accumulate comments from humans and
    other bots ahead of Toleman's own."""
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
            body = comment.get("body") or ""
            if COMMENT_MARKER in body or any(m in body for m in LEGACY_COMMENT_MARKERS):
                return comment["id"], body
        if len(comments) < 100:
            return None
        page += 1


def _find_existing_comment_id(slug: str, pr_number: int, token: str) -> int | None:
    found = _find_existing_comment(slug, pr_number, token)
    return found[0] if found else None


def post_pr_comment(session: Session, target: Target, pr_number: int, body: str) -> None:
    """Best-effort: never raises; a scan result that fails to post a comment
    is still useful.

    Update-in-place (#127): look for a prior Toleman comment on this PR via
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


def update_finding_status_in_pr_comment(session: Session, target: Target, pr_number: int, finding: PRGuardrailFinding) -> None:
    """#401: a rescan is not the only way an ignore approval should show up
    on GitHub -- a security reviewer clicking Approve wants the PR comment
    to say so immediately, not "next time someone pushes a commit". Rather
    than regenerating the whole comment from render_comment (which needs
    scan-level context, e.g. the new-API-endpoints list, that isn't fully
    persisted and would otherwise mean re-cloning the repo just to answer an
    approval click), this patches only the one table cell that changed:
    finding.id makes the "request ignore" link for this row unique within
    the comment (see _findings_table's ignore_link), so a plain substring
    swap is exact and leaves every other row -- and the endpoints section,
    tool-coverage line, everything else -- byte-identical to what the scan
    itself produced. Best-effort and silent on any miss (no Toleman comment
    yet, the row's already been patched, the comment structure changed):
    this is a nice-to-have on top of an already-correct approval, not a
    step the approval itself depends on."""
    slug = repo_slug_from_url(target.repo_url)
    try:
        token = _get_installation_token_or_none(session, target)
        if not token:
            return
        found = _find_existing_comment(slug, pr_number, token)
        if not found:
            return
        comment_id, body = found

        old = f"&middot; [request ignore]({_finding_ignore_link(finding.pr_scan_id, finding.id)})"
        new = "&middot; ✅ approved to ignore"
        if old not in body:
            return
        patched = body.replace(old, new, 1)
        # (#383) And the collapsed header above it, if this row is inside a
        # group: its "N findings" count of what is still outstanding is an
        # aggregate claim no single row's cell owns. Searches for strings
        # only a group header can produce, so it cannot disturb the
        # per-finding cell just patched above.
        patched = _patch_group_header_in_comment(session, target.id, finding, patched)

        res = httpx.patch(
            f"https://api.github.com/repos/{slug}/issues/comments/{comment_id}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
            json={"body": patched},
            timeout=15,
        )
        if res.status_code >= 300:
            logger.warning(
                "PR guardrail: failed to patch approved-ignore status into PR comment: %s %s",
                res.status_code, res.text[:300],
            )
    except Exception:
        logger.warning("PR guardrail: exception patching approved-ignore status into PR comment", exc_info=True)


def _pr_is_merged(session: Session, target: Target, pr_number: int) -> bool:
    """Best-effort merge-state check, used to gate revoke_finding_status_in_pr_comment
    below: a merged PR's Toleman comment is a historical record, not something
    a reviewer can still act on, so there is nothing to gain by editing it
    back and one more avoidable GitHub call to fail on a PR that has been
    quiet for entirely unrelated reasons. Fails closed to "merged" (i.e. skip
    the edit) on any error -- an unnecessary skip costs nothing here, unlike
    the fail-open posture set_commit_status uses for a scan result that must
    reach GitHub regardless."""
    try:
        slug = repo_slug_from_url(target.repo_url)
        pr_res = github_get(f"/repos/{slug}/pulls/{pr_number}", token=resolve_github_token(session, target.workspace_id, slug) or "")
        pr_res.raise_for_status()
        return bool(pr_res.json().get("merged"))
    except Exception:
        logger.warning("PR guardrail: could not determine merge state for %s#%s", target.repo_url, pr_number, exc_info=True)
        return True


def revoke_finding_status_in_pr_comment(session: Session, target: Target, pr_number: int, finding: PRGuardrailFinding) -> None:
    """Undoes what update_finding_status_in_pr_comment did: a security
    reviewer revoking a previously-approved ignore wants the PR comment to
    stop claiming this finding is approved, immediately, the same way
    approving it updated the comment immediately rather than waiting for a
    rescan.

    The "approved to ignore" cell (_approved_action_cell) doesn't embed
    finding.id on its own -- unlike the pending cell's ignore link, its text
    is identical for every approved row in the comment -- so the search
    string here has to include the row's ref_link (_finding_ref_link, which
    does embed the id via "#finding-{id}") to land on the right row and
    reconstruct exactly the pending-cell text render_comment would have
    produced for this finding had it never been approved.

    Skipped once the PR is merged (see _pr_is_merged): there is no reviewer
    left to show a live "request ignore" link to. Best-effort and silent on
    any other miss, same as the approve path."""
    if _pr_is_merged(session, target, pr_number):
        return
    slug = repo_slug_from_url(target.repo_url)
    try:
        token = _get_installation_token_or_none(session, target)
        if not token:
            return
        found = _find_existing_comment(slug, pr_number, token)
        if not found:
            return
        comment_id, body = found

        ref_link = _finding_ref_link(target.id, finding.pr_scan_id, finding.id)
        old = _approved_action_cell(ref_link)
        if old not in body:
            return
        new = _pending_action_cell(ref_link, _finding_ignore_link(finding.pr_scan_id, finding.id))
        patched = body.replace(old, new, 1)
        # (#383) This is the direction that matters: without it a collapsed
        # header goes on claiming "✅ all N approved to ignore" above a row
        # that now offers a live "request ignore" link again -- a false
        # all-clear, and the only stale state in this comment that reassures
        # rather than merely lags. See _patch_group_header_in_comment.
        patched = _patch_group_header_in_comment(session, target.id, finding, patched)

        res = httpx.patch(
            f"https://api.github.com/repos/{slug}/issues/comments/{comment_id}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
            json={"body": patched},
            timeout=15,
        )
        if res.status_code >= 300:
            logger.warning(
                "PR guardrail: failed to patch revoked-ignore status into PR comment: %s %s",
                res.status_code, res.text[:300],
            )
    except Exception:
        logger.warning("PR guardrail: exception patching revoked-ignore status into PR comment", exc_info=True)


def reply_to_pr(session: Session, target: Target, pr_number: int, body: str) -> None:
    """Post a plain new comment on a PR. Best-effort: never raises, same as
    post_pr_comment.

    Deliberately NOT post_pr_comment: that function finds-and-updates the
    one comment carrying COMMENT_MARKER (the main scan-result comment) via
    PATCH, so calling it here would overwrite the actual scan summary with
    whatever unrelated reply this is -- e.g. an ignore-request confirmation.
    This always POSTs a fresh comment instead."""
    slug = repo_slug_from_url(target.repo_url)
    try:
        token = _get_installation_token_or_none(session, target)
        if not token:
            logger.warning("PR guardrail: no GitHub App installed, skipping PR reply")
            return
        res = httpx.post(
            f"https://api.github.com/repos/{slug}/issues/{pr_number}/comments",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
            json={"body": body},
            timeout=15,
        )
        if res.status_code >= 300:
            logger.warning("PR guardrail: failed to post PR reply: %s %s", res.status_code, res.text[:300])
    except Exception:
        logger.warning("PR guardrail: exception posting PR reply", exc_info=True)


def submit_ignore_request(session: Session, finding: PRGuardrailFinding, requested_by: str, reason: str) -> None:
    """Record a request to ignore `finding`; shared by the "Request ignore"
    UI button (app/api/pr_guardrail.py's request_ignore) and the
    `@toleman ignore finding=<id> <reason>` PR-comment command (#385's
    webhook UX work) so the two entry points can't drift.

    This only ever creates a REQUESTED row -- approve_ignore/reject_ignore
    still require an authenticated Toleman user with require_security_reviewer,
    same as before either entry point existed. A comment can ask, same as
    clicking the UI button asks; neither can approve.

    `requested_by` is a free-text identifier, not necessarily a Toleman
    user's email (see PRGuardrailFinding.ignore_requested_by: a plain str
    column, nothing downstream parses it as an email) -- the webhook path
    passes "github:<login>" for exactly this reason, so it's visibly
    distinct from a Toleman-authenticated request without needing a new
    column or a Toleman account for every GitHub commenter."""
    finding.ignore_status = IgnoreStatus.REQUESTED
    finding.ignore_requested_by = requested_by
    finding.ignore_requested_reason = reason
    finding.ignore_reviewed_by = ""
    finding.ignore_reviewed_at = None
    # A finding can be rejected and then asked about again. The reviewer's
    # rejection reason belongs to that closed decision, not to the new
    # pending request, and leaving it set makes the History tab show a
    # pending request already carrying a reason someone was turned down for.
    finding.reject_reason = None
    session.add(finding)
    session.commit()
    session.refresh(finding)


def set_commit_status(session: Session, target: Target, sha: str, state: str, description: str) -> str:
    """Post the commit status. Never raises; returns "" on success or a short
    human-readable reason on failure.

    (GH-04) Still fail-open at the transport layer (a GitHub outage must not
    abort a scan that already produced real findings) but no longer *silent*.
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
                "context": "toleman/pr-guardrail",
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


def _discard_placeholder_pr_scan(session: Session, pr_scan_id: int | None) -> None:
    """Drop the webhook path's pre-created "running" PRGuardrailScan row when
    the scan turns out not to run at all.

    Extracted (#273) because there are now two such early exits -- policy
    (enforcement_mode="disabled") and lifecycle (deactivated/deleted) -- and
    forgetting it in either one leaves the dashboard showing a PR scan stuck
    RUNNING forever, which reads as a hung platform rather than as a skip."""
    if pr_scan_id is None:
        return
    placeholder = session.get(PRGuardrailScan, pr_scan_id)
    if placeholder:
        session.delete(placeholder)
        session.commit()


def execute_pr_guardrail_scan(target: Target, pr_number: int, session: Session, pr_scan_id: int | None = None) -> dict:
    """Diff-only scan: scan the PR's head branch, diff findings against the
    target's default-branch Open findings and API endpoints against the
    persisted default-branch discovery set, persist a PRGuardrailScan +
    PRGuardrailFinding rows, best-effort post a PR comment + commit status.
    Returns the same response shape regardless of caller (on-demand API
    route, webhook handler, or Celery task).

    Two gates run before any work, both returning early with no clone, no
    PRGuardrailScan row, no PR comment and no commit status. First target
    lifecycle (#273): a deactivated or soft-deleted target isn't scanned at
    all, returned as status="skipped" with a reason. Then:

    Enforcement mode (issue #62, app.core.enforcement.resolve_enforcement_mode)
    gates this at the very top: "disabled" means PR Guardrail doesn't run for
    this target/PR at all, no clone, no PRGuardrailScan row, no PR comment,
    no commit status. "block"/"alert" both run the full scan below; the
    difference between them only affects the commit status sent to GitHub
    at the end (see the set_commit_status call).

    pr_scan_id (#401): the webhook path pre-creates the PRGuardrailScan row
    synchronously at webhook-receipt time (see app/api/webhooks.py) so the
    dashboard has something to show as "running" immediately, rather than
    only once this function's own GitHub-API PR fetch below completes. When
    given, that row is reused (updated in place) instead of a second one
    being created; None (the on-demand route's case, which already runs
    synchronously on the request thread with no such gap to close) keeps
    the original create-fresh behavior."""
    # (#273) Target lifecycle is checked before enforcement mode, and before
    # anything else: a deactivated or soft-deleted target gets no clone, no
    # PRGuardrailScan row, no PR comment and no commit status, exactly like
    # enforcement_mode="disabled" below. Checked here in the shared executor
    # rather than only in the two entry points (the webhook handler and the
    # on-demand route) so neither can be reached by a path that skipped it --
    # the Celery task in particular re-loads the target by id, minutes after
    # the webhook decided it was fine.
    #
    # Note the deliberate asymmetry with enforcement_mode="disabled": that
    # one is a *policy* decision about PR gating, so it is reported as a
    # distinct "disabled" status. This is the repo being switched off
    # wholesale, and is reported as "skipped" with the reason, so a reader
    # of the returned payload can tell "we chose not to gate PRs here" from
    # "this repo is not being scanned at all".
    lifecycle_refusal = target_lifecycle.scan_refusal_reason(target)
    if lifecycle_refusal:
        logger.info(
            "PR guardrail: %s (target %s), skipping scan for PR #%s",
            lifecycle_refusal, target.id, pr_number,
        )
        _discard_placeholder_pr_scan(session, pr_scan_id)
        return {
            "pr_scan_id": None,
            "status": "skipped",
            "skipped": lifecycle_refusal,
            "new_findings_count": 0,
            "highest_new_severity": None,
            "new_endpoints_count": 0,
            "new_findings": [],
            "new_endpoints": [],
            "enforcement_mode": None,
        }

    enforcement_mode = resolve_enforcement_mode(session, target)
    if enforcement_mode == "disabled":
        logger.info(
            "PR guardrail: enforcement_mode=disabled for target %s, skipping scan for PR #%s",
            target.id, pr_number,
        )
        # "disabled" means no PRGuardrailScan row at all (see docstring
        # above) -- must not leave the webhook path's placeholder
        # stuck RUNNING forever.
        _discard_placeholder_pr_scan(session, pr_scan_id)
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

    pr_scan = session.get(PRGuardrailScan, pr_scan_id) if pr_scan_id is not None else None
    if pr_scan is not None:
        pr_scan.pr_title = pr_title
        pr_scan.branch = head_branch
        pr_scan.status = PRGuardrailStatus.RUNNING
    else:
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
            target.repo_url, head_branch, resolve_github_token(session, target.workspace_id, slug) or "",
            scan_id=f"pr-{pr_scan.id}", **runner.clone_kwargs_for_target(target),
        )
        guardrail_tools = _resolve_guardrail_tools(session, target)

        # One fetch, two consumers: the changed-line map every scan needs to
        # decide which net-new findings this PR's author actually introduced,
        # and the optional diff-scoped scan path list below.
        pr_file_entries = _pr_files(slug, pr_number, resolve_github_token(session, target.workspace_id, slug) or "")
        changed_lines = _changed_line_map(pr_file_entries) if pr_file_entries is not None else None

        # (#243) Scope the scan to the PR's changed files when the target
        # opts in. Every path back to a full scan is explicit, and the scope
        # actually used is persisted; a diff scan and a full scan report
        # very different amounts of assurance and must never be confused for
        # each other in the PR comment or the audit trail.
        scan_paths: list[str] | None = None
        radius_added = 0
        radius_note = ""
        if target.diff_scoped_pr_scans:
            changed = _changed_paths(pr_file_entries) if pr_file_entries is not None else None
            if changed is None:
                logger.info("pr guardrail: full scan for %s#%s (changed files unavailable)", slug, pr_number)
                radius_note = "the PR's changed-file list could not be retrieved"
            elif len(changed) > MAX_DIFF_SCOPED_FILES:
                logger.info(
                    "pr guardrail: full scan for %s#%s (%s changed files exceeds %s)",
                    slug, pr_number, len(changed), MAX_DIFF_SCOPED_FILES,
                )
                radius_note = (
                    f"this PR changes {len(changed)} files, over the {MAX_DIFF_SCOPED_FILES}-file "
                    "limit for a diff-scoped scan"
                )
            elif not changed:
                logger.info("pr guardrail: full scan for %s#%s (no scannable changed files)", slug, pr_number)
                radius_note = "no scannable changed files"
            else:
                # (#244) Scanning literally-changed files misses the case
                # where editing A.py makes existing code in B.py vulnerable.
                # Expand to the changed files' direct importers so the
                # narrowed scan covers what the change can actually reach.
                # A None result means the radius could not be established --
                # or is so wide that a narrowed scan would be one in name
                # only -- and the scan escalates to full rather than
                # quietly covering less than it claims.
                expanded, radius_added, radius_note = code_graph.resolve_blast_radius(
                    session, target, repo_path, changed, commit_sha=head_sha,
                )
                if expanded is None:
                    logger.info(
                        "pr guardrail: full scan for %s#%s (blast radius unavailable: %s)",
                        slug, pr_number, radius_note,
                    )
                else:
                    scan_paths = expanded

        # (#244 meets the diff-attribution filter below) A blast-radius file
        # is in this scan precisely because the PR's change can reach it:
        # the expansion exists to catch "editing A.py made existing code in
        # B.py vulnerable", and B.py is by definition not in the diff.
        # Attributing by changed lines alone would therefore discard exactly
        # the findings the expansion was added to surface. Every expanded
        # path is attributed as WHOLE_FILE instead -- the same
        # "we could not narrow it, so do not suppress" value
        # _changed_line_map already uses for a file GitHub sends no patch
        # for. setdefault, so a literally-changed file keeps its real line
        # set and stays filtered to the lines the author wrote.
        if scan_paths is not None and changed_lines is not None:
            for path in scan_paths:
                changed_lines.setdefault(path, WHOLE_FILE)

        parsed, failed_tools, skipped_tools = _run_guardrail_tools(
            guardrail_tools, repo_path, paths=scan_paths
        )
        pr_scan.scan_scope = "diff" if scan_paths is not None else "full"
        pr_scan.files_scanned = len(scan_paths) if scan_paths is not None else 0
        pr_scan.blast_radius_files = radius_added if scan_paths is not None else 0
        pr_scan.scope_reason = radius_note
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

        baseline_missing = not _has_baseline_scan(session, target)
        if baseline_missing:
            # (GH-07, mirrors _diff_new_endpoints' GH-06 fix) No completed
            # scan of the default branch exists to diff against; treating an
            # empty existing_hashes as "diffed clean" here would report this
            # PR as introducing the repository's entire pre-existing finding
            # set, on whichever PR happens to be scanned first.
            logger.info(
                "PR guardrail: no completed baseline scan for target %s branch %s, "
                "skipping the finding diff for this scan rather than reporting the "
                "whole repo as net-new",
                target.id, target.default_branch,
            )
            net_new = []
        else:
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

        # Net-new is necessary but not sufficient. A finding's dedup hash can
        # stop matching the baseline for reasons that have nothing to do with
        # this PR -- an upstream semgrep rule renamed under --config=auto, a
        # scanner upgrade, a tool enabled for the PR surface but not for the
        # default-branch scan, a baseline that simply hasn't been refreshed --
        # and the result was this guardrail reporting a repo's pre-existing
        # findings against whichever PR happened to be scanned next, in files
        # its author never opened. Authorship is decided by the diff.
        attribution_unavailable = changed_lines is None
        if attribution_unavailable:
            # Same rule the rest of this module follows: something that could
            # not be established is never quietly resolved in the direction
            # that hides findings. Report the unfiltered set and say so.
            logger.warning(
                "pr guardrail: no diff available for %s#%s; reporting net-new findings "
                "without attributing them to changed lines",
                slug, pr_number,
            )
        else:
            net_new = attributable_to_diff(net_new, changed_lines)

        # Policy-as-code (ROADMAP Sprint 4): apply the target's workspace
        # active policy rules (org-level suppression + severity threshold
        # override) before deciding whether to block. No policies configured
        # for the workspace means today's default behavior is unchanged.
        policies = session.exec(
            select(PolicyRule).where(
                PolicyRule.workspace_id == target.workspace_id,
                PolicyRule.active == True,  # noqa: E712
            )
        ).all()
        net_new, blocking_severities = apply_policies(net_new, policies)

        # #401: excluded from the blocking calculation up front, not just
        # cosmetically labeled after the fact -- a finding a reviewer
        # already approved-to-ignore on an earlier scan of this same PR
        # must not keep the PR BLOCKED again on every subsequent scan just
        # because an unrelated commit re-triggered the same diff.
        prior_approvals = _carry_forward_approvals(session, target.id, pr_number, net_new)
        blocking_net_new = [item for item, prior in zip(net_new, prior_approvals) if prior is None]

        status = PRGuardrailStatus.BLOCKED if should_block(blocking_net_new, blocking_severities) else PRGuardrailStatus.PASSED

        new_endpoints = _attributable_endpoints(
            _diff_new_endpoints(session, target, repo_path), changed_lines
        )

        pr_scan.status = status
        pr_scan.new_findings_count = len(net_new)
        pr_scan.highest_new_severity = highest_severity(net_new)
        pr_scan.new_endpoints_count = len(new_endpoints)
        pr_scan.baseline_missing = baseline_missing
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

        persisted_findings = _persist_findings(session, pr_scan.id, net_new, prior_approvals)

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
            baseline_missing=baseline_missing,
            blast_radius_files=pr_scan.blast_radius_files,
            diff_attributed=not attribution_unavailable,
            # Every finding's location links to that line of that file at the
            # commit this scan actually read, which is not necessarily the SHA
            # the PR API reported (see _scanned_commit and _source_link).
            repo_slug=slug,
            head_sha=_scanned_commit(repo_path, head_sha),
            # persisted_findings is capped at MAX_NEW_FINDINGS_IN_RESPONSE;
            # this is what the cap is hiding, so the comment can say so
            # instead of presenting a page as the whole result.
            total_findings=len(net_new),
            # (#271) completed_at is set just above this call; falling back
            # to now() keeps the footer honest rather than omitting it if
            # that ordering ever changes.
            scanned_at=pr_scan.completed_at or utcnow(),
        )
        post_pr_comment(session, target, pr_number, comment_body)

        # (#383) The commit status sits beside that comment on the same PR,
        # so reporting "2 net-new finding(s)" next to a comment headlining 1
        # is the same two-numbers-for-one-thing confusion this grouping set
        # out to remove. Counted over the rows the comment actually rendered
        # -- except when there were more net-new findings than we persist and
        # render (MAX_NEW_FINDINGS_IN_RESPONSE), where those rows are only a
        # page of the result and the full count is the honest one to put on
        # the merge gate. That is the same branch render_comment takes for
        # its headline, so the two numbers agree in both cases.
        if len(persisted_findings) == len(net_new):
            reported_findings = len(group_findings_by_location(persisted_findings))
        else:
            reported_findings = len(net_new)
        summary_desc = f"{reported_findings} net-new finding(s), {len(new_endpoints)} new endpoint(s)"
        if status == PRGuardrailStatus.BLOCKED:
            # A real net-new blocking finding exists among the tools that
            # did run. That is a known problem regardless of what else
            # failed to run, and must not be downgraded to "error"
            # (inconclusive) just because coverage was also partial --
            # a known-blocking finding and incomplete coverage are different
            # facts, and the more serious one always wins.
            if enforcement_mode == "alert":
                # Alert mode: real blocking findings exist, but this
                # target/group/workspace is configured to warn rather than
                # fail the build. GitHub commit statuses only support
                # success/failure/pending/error (there's no dedicated
                # "neutral" state) so we use "success" (non-blocking) with a
                # description that makes clear this is alert-mode, not a
                # clean scan.
                commit_state, commit_desc = "success", f"[alert mode, non-blocking] {summary_desc}"
            else:
                commit_state, commit_desc = "failure", summary_desc
        elif failed_tools:
            # PASSED among the tools that ran, but not every assigned tool
            # did. Coverage was incomplete -- said plainly here and in the
            # PR comment (still rendered as "not an all-clear", never a
            # plain checkmark) -- but incomplete coverage with zero findings
            # in what *did* run is not itself grounds to block merge.
            # Without this, a workspace whose pr_guardrail assignment
            # includes a single tool this deployment can never run (not
            # installed, e.g. a GitHub-release-only binary) would fail
            # every PR forever regardless of content, which defeats using
            # this as a required check at all. This never masks a real
            # finding: that path is handled by the BLOCKED branch above,
            # which always wins over this one.
            commit_state = "success"
            commit_desc = f"{summary_desc} ({', '.join(failed_tools)} failed to run)"
        else:
            commit_state, commit_desc = "success", summary_desc

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
    """Re-evaluate a PRGuardrailScan's blocked/passed status after an
    individual finding's ignore decision changes -- an approval (#112) or a
    revocation of one. Before #112, the only way to unblock a PR was the
    blunt whole-scan `override`; approving every one of a PR's blocking
    findings individually still left the scan (and GitHub commit status)
    stuck on BLOCKED forever, since approve_ignore only touched the finding
    row, never the scan. Revoking an approval has the same gap in the other
    direction: without this, un-approving the one finding that got a scan
    unblocked leaves it reading PASSED (and GitHub green) on a PR that is
    once again blocking, until whatever the next real scan happens to be.

    No-op for scans not currently BLOCKED or PASSED: RUNNING/ERROR have
    nothing to recompute, and OVERRIDDEN is a deliberate accept-everything
    escape hatch that a per-finding approval or revocation shouldn't
    silently reverse either way.
    """
    if pr_scan.status not in (PRGuardrailStatus.BLOCKED, PRGuardrailStatus.PASSED):
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

    now_blocked = any(f.severity in blocking_severities for f in still_open)
    if now_blocked == (pr_scan.status == PRGuardrailStatus.BLOCKED):
        return  # already correct: still-open findings legitimately explain the current status

    pr_scan.status = PRGuardrailStatus.BLOCKED if now_blocked else PRGuardrailStatus.PASSED
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
        if now_blocked:
            # Same alert-mode carve-out execute_pr_guardrail_scan's own
            # BLOCKED branch uses: alert-mode targets warn, never fail the
            # commit status, even once a revoked approval restores a real
            # blocking finding.
            if enforcement_mode == "alert":
                state, desc = "success", "[alert mode, non-blocking] A previously-approved ignore was revoked"
            else:
                state, desc = "failure", "A previously-approved ignore was revoked, restoring a blocking finding"
        else:
            state, desc = "success", "All blocking findings individually approved for ignore"
        set_commit_status(session, target, head_sha, state, desc)
    except Exception:
        # Best-effort, same philosophy as the rest of this module's GitHub
        # calls; the scan row itself is already correctly updated above;
        # a failure here just means GitHub's commit status lags until the
        # next real scan or a retry, not a failed approval/revocation.
        logger.exception(
            "PR guardrail: failed to update commit status after per-finding "
            "ignore decision for scan %s",
            pr_scan.id,
        )
