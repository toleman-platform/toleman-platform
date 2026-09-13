"""Compliance / audit-evidence posture reports (CSV + PDF export).

Reuses the same "default branch is the org's current state" convention as
GET /api/dashboard/posture and the persisted-state-only SBOM endpoints;
this pulls real rows out of Finding / Scan / SbomComponent, never
fabricated content, matching the pattern already established by
GET /api/sbom/{target_id}/export and GET /api/sbom/org/export.

Issue #302 added two things on top of that:

* **Filters.** The report can be scoped the same way the Findings page can
  be scoped (severity, state, tool, category, environment, owner, repo
  group, and a date range over the finding window), not just by target. The
  finding rows come from `app.api.findings._filtered_findings_query`, the
  *same* query builder the Findings page and its category facet use, rather
  than a second implementation -- so the report can never show a finding the
  caller could not see on the Findings page, and a filter can never come to
  mean two different things in two places.
* **Modularity.** The report's sections are selectable (REPORT_SECTIONS),
  and both renderers honour the selection. The default is still every
  section, so a caller that was happily hitting this endpoint before #302
  gets exactly the same sections it always did.

Both of those make an honesty requirement unavoidable: a filtered report
that *looks* like a full one is an audit-evidence problem, not a cosmetic
one. So every rendered report states, on the document itself, the filters
it was generated under and which sections were included -- and an excluded
section is printed with an explicit "excluded" marker rather than simply
being missing, because a reader cannot tell an omitted section from an
empty one.

The date range makes that requirement sharper still, because it makes the
document *look* like a point-in-time snapshot. It is only partly one.
Open-finding ages are measured to the window's end and scan coverage stops
there, but a finding's triage state and an SBOM's composition have no
queryable history in this schema, so those are unavoidably current-state.
A Q1 export run in September would otherwise silently mix 250-day ages and
September triage decisions into what reads as a Q1 snapshot; see
POINT_IN_TIME_NOTE, which is printed on every report for the same reason
the filter header is.
"""
import io
import re
from dataclasses import dataclass, field
from datetime import date, datetime, time
from typing import NamedTuple, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response, StreamingResponse
from sqlmodel import Session, func, select

from app.api.auth import accessible_workspace_ids, current_user
from app.api.deps import get_session
from app.api.findings import (
    _apply_category,
    _filtered_findings_query,
    _target_facet,
    list_tool_facets,
)
from app.core.csv_export import safe_csv_writer
from app.core.downloads import attachment_disposition
from app.core.time import utcnow
from app.core.tool_registry import all_categories, all_known_tools
from app.models.models import (
    Finding,
    FindingState,
    Group,
    Scan,
    SbomComponent,
    Severity,
    Target,
    TargetGroup,
    User,
)

router = APIRouter(prefix="/api/reports", tags=["reports"])


# ---------------------------------------------------------------------------
# Section catalog (#302)
# ---------------------------------------------------------------------------

class ReportSection(NamedTuple):
    """One selectable block of the posture report.

    `csv_heading` and `pdf_heading` are deliberately allowed to differ: both
    renderers already used slightly different wording before #302 (the CSV's
    "Targets" vs the PDF's "Targets in Scope"), and quietly "fixing" that
    would change the shape of a document existing audit evidence was
    exported into. `label` is the neutral name used by the section manifest,
    the /sections catalog and the UI.
    """

    key: str
    label: str
    description: str
    csv_heading: str
    pdf_heading: str


REPORT_SECTIONS: tuple[ReportSection, ...] = (
    ReportSection(
        key="targets",
        label="Targets in scope",
        description="The repositories this report covers, with their default branch.",
        csv_heading="Targets",
        pdf_heading="Targets in Scope",
    ),
    ReportSection(
        key="totals",
        label="Finding totals by severity and state",
        description="Finding counts by severity and triage state, totalled across every in-scope target.",
        csv_heading="Finding Totals By Severity And State (all in-scope targets)",
        pdf_heading="Finding Totals By Severity And State",
    ),
    ReportSection(
        key="severity_state",
        label="Finding counts by target, severity, state",
        description="The same severity/state counts, broken out per target.",
        csv_heading="Finding Counts By Target, Severity, State",
        pdf_heading="Finding Counts By Target, Severity, State",
    ),
    ReportSection(
        key="open_age",
        label="Open-finding age / SLA buckets",
        description="Open-finding age and SLA buckets (0-7d, 8-30d, 31-90d, 90d+) per target and severity.",
        csv_heading="Open Finding Age / SLA (default branch)",
        pdf_heading="Open Finding Age / SLA (default branch)",
    ),
    ReportSection(
        key="scan_coverage",
        label="Scan history / coverage",
        description="Latest scan run per tool, per target, including targets that have never been scanned.",
        csv_heading="Scan History / Coverage (latest run per tool)",
        pdf_heading="Scan History / Coverage (latest run per tool)",
    ),
    ReportSection(
        key="sbom",
        label="SBOM component summary",
        description="SBOM component count and last-updated date per target, when SBOM data has been generated.",
        csv_heading="SBOM Component Summary (default branch)",
        pdf_heading="SBOM Component Summary (default branch)",
    ),
)

SECTION_KEYS: tuple[str, ...] = tuple(s.key for s in REPORT_SECTIONS)
SECTION_BY_KEY: dict[str, ReportSection] = {s.key: s for s in REPORT_SECTIONS}

# Headings for the two honesty blocks every report carries, regardless of
# format or of whether anything was actually filtered out. Kept as module
# constants because the tests assert on them and the two renderers must not
# drift on the wording.
APPLIED_FILTERS_HEADING = "Applied Filters"
SECTION_MANIFEST_HEADING = "Report Sections"
EXCLUDED_MARKER = "Section excluded from this report."
NO_FILTER_VALUE = "(all)"
UNFILTERED_SUMMARY = "None - this report is unfiltered"

# Which filters bite where. Said out loud on the document because the split
# is not guessable: narrowing to Critical findings does not (and should not)
# change the statement "this repo's last Trivy scan ran on the 3rd", and a
# reader who assumed otherwise would draw the wrong conclusion from the
# coverage table.
FILTER_SCOPE_NOTE = (
    "Target-level filters (scope, repo group, environment, owner) narrow every section. "
    "Finding-level filters (severity, finding state, tool, category) narrow which findings are "
    "counted; scan coverage and the SBOM summary are not narrowed by them, because when a "
    "repository was last scanned does not change because the reader asked to see only critical "
    "findings. The finding window behaves differently again -- see the point-in-time note below."
)

# The asymmetry a dated report would otherwise hide. A finding window makes
# this document look like a snapshot of a past period, and for two of its
# figures it genuinely is (ages are measured to the window's end, scan
# coverage stops there). For two others it cannot be: this platform stores
# no queryable history of a finding's triage state or of an SBOM's
# composition, so those are unavoidably today's values. Saying which is
# which is the difference between a period report and a misleading one --
# without this, a Q1 export run in September silently mixes 250-day ages
# and September triage decisions into what reads as a Q1 snapshot.
POINT_IN_TIME_NOTE = (
    "Figures are stated as at the 'Figures As Of' timestamp above: open-finding ages are measured to "
    "that instant, and scan coverage is the latest run per tool on or before it. Two figures are "
    "NOT reconstructed as of that date and are current-state regardless: each finding's triage "
    "state, and the SBOM component summary. A report with a finding window is therefore a "
    "period-scoped view of today's triage decisions, not a snapshot of how the queue looked then."
)


# ---------------------------------------------------------------------------
# Filters (#302)
# ---------------------------------------------------------------------------

@dataclass
class ReportFilters:
    """The scope the operator asked for, as one object rather than ten
    parameters threaded through four functions.

    Split deliberately into *target-level* filters (which narrow the set of
    repositories the whole report is about) and *finding-level* filters
    (which narrow the rows inside the finding sections). See
    FILTER_SCOPE_NOTE; that distinction is printed on the document.
    """

    # Target-level.
    target_id: Optional[int] = None
    group_id: Optional[int] = None
    environment: Optional[str] = None
    owner: Optional[str] = None
    # Finding-level.
    severity: list[Severity] = field(default_factory=list)
    state: list[FindingState] = field(default_factory=list)
    tool: list[str] = field(default_factory=list)
    category: Optional[str] = None
    date_from: Optional[date] = None
    date_to: Optional[date] = None
    # Resolved Group.name for the report header, filled in by
    # build_posture_report once it has looked the group up. A raw
    # `group_id=4` on an audit document is not evidence of anything a human
    # reading the document can check.
    group_label: Optional[str] = None

    @property
    def window_from(self) -> Optional[datetime]:
        """Start of `date_from`'s day. The DB columns are naive UTC
        datetimes (app.core.time.utcnow), so the bounds must be too."""
        return datetime.combine(self.date_from, time.min) if self.date_from else None

    @property
    def window_to(self) -> Optional[datetime]:
        """End of `date_to`'s day: the range is inclusive of the day the
        operator typed, matching the audit log's own date-range filter. A
        bare midnight bound would exclude everything that happened on the
        last day of the range, which reads as data loss."""
        return datetime.combine(self.date_to, time.max) if self.date_to else None

    def describe(self) -> list[dict]:
        """Every filter dimension with its value, including the ones nobody
        set (as `(all)`).

        Listing the untouched dimensions too is the point: "Severity: (all)"
        is a positive statement that nothing was hidden, which is what an
        auditor reading the document needs. A block that listed only the
        active filters would be indistinguishable, on an unfiltered report,
        from a block that had simply failed to render.
        """
        def joined(values) -> str:
            return ", ".join(str(_enum_value(v)) for v in values) if values else NO_FILTER_VALUE

        if self.date_from or self.date_to:
            start = self.date_from.isoformat() if self.date_from else "(open)"
            end = self.date_to.isoformat() if self.date_to else "(open)"
            # Spelled out rather than left as a bare "from .. to ..": the
            # bounds test the finding's *window*, not a single timestamp, so
            # a finding first seen before the range but still present inside
            # it is included. See findings._apply_finding_window.
            window = f"{start} to {end} (findings present at any point in the range)"
        else:
            window = NO_FILTER_VALUE

        return [
            {"label": "Repo group", "value": self.group_label or NO_FILTER_VALUE},
            {"label": "Environment", "value": self.environment or NO_FILTER_VALUE},
            {"label": "Owner", "value": self.owner or NO_FILTER_VALUE},
            {"label": "Severity", "value": joined(self.severity)},
            {"label": "Finding state", "value": joined(self.state)},
            {"label": "Tool", "value": joined(self.tool)},
            {"label": "Category", "value": self.category or NO_FILTER_VALUE},
            {"label": "Finding window", "value": window},
        ]

    def target_level_narrowed(self) -> bool:
        """Whether anything beyond `target_id` narrows the set of repos.

        `target_id` is excluded because a single-target report already says
        so on its Scope line; this exists to stop an org-wide report
        describing itself as covering "all targets" when a group or
        environment filter means it plainly does not.
        """
        return any((self.group_id is not None, self.environment, self.owner))

    def target_level_summary(self) -> str:
        parts = []
        if self.group_id is not None:
            parts.append(f"group {self.group_label or self.group_id}")
        if self.environment:
            parts.append(f"environment {self.environment}")
        if self.owner:
            parts.append(f"owner {self.owner}")
        return ", ".join(parts)

    def active_count(self) -> int:
        """How many filter dimensions were actually narrowed. `target_id` is
        excluded: the scope picker has always existed and is reported on its
        own "Scope" line, so counting it would make every single-target
        report claim to be "filtered"."""
        dimensions = [
            self.group_id,
            self.environment,
            self.owner,
            self.category,
            self.severity or None,
            self.state or None,
            self.tool or None,
            self.date_from or self.date_to,
        ]
        return sum(1 for d in dimensions if d)

    def summary(self) -> str:
        count = self.active_count()
        if not count:
            return UNFILTERED_SUMMARY
        return f"{count} filter{'s' if count != 1 else ''} applied - see '{APPLIED_FILTERS_HEADING}' below"


def _enum_value(v) -> str:
    """Normalize a Severity/FindingState enum (or plain str) query result to
    its plain string value, str(Severity.CRITICAL) renders as
    'Severity.CRITICAL' via Enum's default __str__, which is not what
    belongs in an audit report."""
    return v.value if hasattr(v, "value") else v


def _age_bucket(age_days: int) -> str:
    if age_days <= 7:
        return "0-7d"
    if age_days <= 30:
        return "8-30d"
    if age_days <= 90:
        return "31-90d"
    return "90d+"


def _resolve_targets(
    session: Session, filters: ReportFilters, ws_ids: Optional[list[int]]
) -> tuple[list[Target], str, str]:
    """The in-scope targets, the human scope label, and the raw scope name
    the filename is built from.

    `ws_ids` is `accessible_workspace_ids()`'s result; None for admins
    (no filter), else the caller's workspace ids (issue #86, same
    unscoped-aggregate bug class #57 fixed on dashboard/findings/targets).
    A caller with no memberships (ws_ids == []) gets an empty report rather
    than every workspace's data.

    The target-level filters (#302: group / environment / owner) apply
    whether or not a single `target_id` was named. A named target that does
    not match them yields an empty report rather than silently ignoring the
    filters -- the document says which filters were applied, so an empty
    result is readable, whereas a full result under filters the header
    claims were active would not be.
    """
    # "org-wide" has always meant "every target you can see". Once target-
    # level filters exist it can no longer say "(all targets)" unqualified:
    # a report narrowed to one repo group is not org-wide, and a header that
    # claims it is contradicts the Applied Filters block three rows below.
    org_label = (
        "org-wide (all targets)"
        if not filters.target_level_narrowed()
        else f"org-wide, narrowed by {filters.target_level_summary()} (see '{APPLIED_FILTERS_HEADING}')"
    )

    if ws_ids is not None and not ws_ids and filters.target_id is None:
        # No memberships and no named target: an empty org-wide report. The
        # named-target case deliberately falls through to the lookup below
        # so it still 404s rather than degrading into a silent empty report,
        # which is what it did before #302.
        return [], org_label, "org-wide"

    query = select(Target)
    if ws_ids:
        query = query.where(Target.workspace_id.in_(ws_ids))
    if filters.group_id is not None:
        # Same membership lookup app/api/findings.py uses for group_id, as a
        # subquery rather than a join so it cannot duplicate target rows.
        query = query.where(
            Target.id.in_(select(TargetGroup.target_id).where(TargetGroup.group_id == filters.group_id))
        )
    if filters.environment is not None:
        query = query.where(Target.environment == filters.environment)
    if filters.owner is not None:
        query = query.where(Target.owner == filters.owner)

    if filters.target_id is None:
        return list(session.exec(query.order_by(Target.name)).all()), org_label, "org-wide"

    target = session.get(Target, filters.target_id)
    if not target or (ws_ids is not None and target.workspace_id not in ws_ids):
        # 404 rather than 403 to avoid confirming the target exists in a
        # workspace the caller can't see (matches findings.py's get_finding).
        raise HTTPException(status_code=404, detail="target not found")
    matching = list(session.exec(query.where(Target.id == target.id)).all())
    # The label/name describe what was *asked for*, so a report that came
    # back empty because the named repo fell outside the other filters is
    # still filed under that repo's name instead of a blank. The name is
    # returned raw; the Content-Disposition layer owns making it header-safe
    # (app.core.downloads), so no caller here can forget to.
    return matching, target.name, target.name


def _resolve_group_label(session: Session, filters: ReportFilters, ws_ids: Optional[list[int]]) -> None:
    """Resolve `group_id` to the group's name, or 404.

    Workspace-scoped, like every other Group lookup in this codebase (see
    app/api/groups.py, where each lookup is followed by
    enforce_workspace_role). An unscoped `session.get(Group, id)` here would
    print another tenant's group name straight into the Applied Filters
    block, turning the report's own honesty header into an enumeration
    oracle: walk `?group_id=1..N` and read the names back off the document.

    404 rather than 403, matching the target lookup below: the existence of
    another tenant's group is itself information.
    """
    if filters.group_id is None or filters.group_label is not None:
        return
    group = session.get(Group, filters.group_id)
    if not group or (ws_ids is not None and group.workspace_id not in ws_ids):
        raise HTTPException(status_code=404, detail="group not found")
    filters.group_label = group.name


def build_posture_report(
    session: Session,
    user: User,
    filters: Optional[ReportFilters] = None,
    sections: Optional[list[str]] = None,
) -> dict:
    """Assemble the real audit-evidence dataset: finding counts by
    severity/state, SLA/age of open findings, scan history/coverage, and an
    SBOM component summary; all scoped to each target's default branch,
    mirroring GET /api/dashboard/posture's convention.

    `filters` defaults to "no filters" and `sections` to "every section", so
    the no-argument call produces exactly the report this function produced
    before #302.

    The finding rows come from `findings._filtered_findings_query`, the same
    builder GET /api/findings and its category facet use. That is the whole
    point of #302's filter work: the report must never be able to show a
    finding the caller could not see on the Findings page, and reusing the
    query is a stronger guarantee of that than a second implementation that
    merely intends to agree. It calls `accessible_workspace_ids` itself,
    which is why this function's own call below is not threaded into it --
    two cheap membership lookups per export, rather than a parallel scoping
    path that could disagree with the Findings page's.
    """
    filters = filters or ReportFilters()
    included = list(sections) if sections is not None else list(SECTION_KEYS)
    included_set = {k for k in included if k in SECTION_BY_KEY}

    ws_ids = accessible_workspace_ids(session, user)
    _resolve_group_label(session, filters, ws_ids)
    targets, scope_label, scope_name = _resolve_targets(session, filters, ws_ids)
    now = utcnow()
    # The instant every figure in this report is stated as of. A report with
    # a finding window is evidence about a period, so its figures are
    # measured at the end of that period, not at whatever moment the export
    # happened to be run -- see POINT_IN_TIME_NOTE for what that does and
    # does not reach. `min` because a window ending in the future cannot
    # make us report on data we do not have.
    as_of = min(now, filters.window_to) if filters.window_to else now

    # One Findings-page query, then narrowed per target below. `target_id`,
    # `group_id`, `environment` and `owner` are passed here as well as to
    # _resolve_targets: redundant given the per-target narrowing, but it
    # keeps this the literal Findings-page query for the same scope rather
    # than a subset of it, so workspace scoping holds even if the target
    # resolution above is ever changed.
    base_query, _ = _filtered_findings_query(
        session,
        user,
        target_id=[filters.target_id] if filters.target_id is not None else None,
        group_id=filters.group_id,
        branch=None,
        state=filters.state or None,
        resolved=None,
        severity=filters.severity or None,
        tool=filters.tool or None,
        fixability=None,
        environment=filters.environment,
        owner=filters.owner,
        search=None,
        date_from=filters.window_from,
        date_to=filters.window_to,
    )
    if base_query is not None:
        base_query = _apply_category(base_query, filters.category)

    severity_state_rows: list[dict] = []
    open_age_rows: list[dict] = []
    scan_rows: list[dict] = []
    sbom_rows: list[dict] = []

    totals_by_severity_state: dict[tuple[str, str], int] = {}

    # An excluded section's queries are not run at all -- the section is
    # genuinely not in the report, not computed and then dropped.
    want_breakdown = bool({"totals", "severity_state"} & included_set)
    want_open_age = "open_age" in included_set
    want_scans = "scan_coverage" in included_set
    want_sbom = "sbom" in included_set

    for target in targets:
        # Default-branch-only, same convention as GET /api/dashboard/posture.
        target_query = (
            base_query.where(Finding.target_id == target.id, Finding.branch == target.default_branch)
            if base_query is not None
            else None
        )

        if want_breakdown and target_query is not None:
            # Aggregated over the filtered query as a subquery, the same
            # shape findings.list_category_facets uses to count over its own
            # filtered query, rather than re-deriving the WHERE clause here.
            subq = target_query.subquery()
            breakdown_rows = session.exec(
                select(subq.c.severity, subq.c.state, func.count()).group_by(subq.c.severity, subq.c.state)
            ).all()
            for severity, state, count in breakdown_rows:
                severity = _enum_value(severity)
                state = _enum_value(state)
                severity_state_rows.append(
                    {"target": target.name, "severity": severity, "state": state, "count": count}
                )
                key = (severity, state)
                totals_by_severity_state[key] = totals_by_severity_state.get(key, 0) + count

        if want_open_age and target_query is not None:
            # Still literally FindingState.OPEN, not OPEN_FINDING_STATES: this
            # section's numbers have always meant "Open", and widening it
            # would silently restate previously-published reports.
            open_findings = session.exec(target_query.where(Finding.state == FindingState.OPEN)).all()
            ages_by_severity: dict[str, list[int]] = {}
            for f in open_findings:
                # Measured to `as_of`, not to now: on a report scoped to a
                # finding window, "how long has this been open" means "as at
                # the end of the period this report covers". Without the
                # window the two are the same instant, so an undated report
                # is unchanged. Note the *set* of findings here is still
                # today's Open set -- that half cannot be reconstructed
                # without state history, and POINT_IN_TIME_NOTE says so
                # rather than letting the reader assume otherwise.
                age_days = max((as_of - f.first_seen).days, 0)
                ages_by_severity.setdefault(_enum_value(f.severity), []).append(age_days)
            for severity, ages in sorted(ages_by_severity.items()):
                buckets: dict[str, int] = {}
                for a in ages:
                    b = _age_bucket(a)
                    buckets[b] = buckets.get(b, 0) + 1
                open_age_rows.append(
                    {
                        "target": target.name,
                        "severity": severity,
                        "open_count": len(ages),
                        "avg_age_days": round(sum(ages) / len(ages), 1) if ages else 0,
                        "oldest_age_days": max(ages) if ages else 0,
                        "bucket_0_7d": buckets.get("0-7d", 0),
                        "bucket_8_30d": buckets.get("8-30d", 0),
                        "bucket_31_90d": buckets.get("31-90d", 0),
                        "bucket_90d_plus": buckets.get("90d+", 0),
                    }
                )

        if want_scans:
            # Latest scan per tool for this target; "coverage" is which
            # (target, tool) pairs have ever been scanned and when they last
            # ran, not a full run-by-run history. Deliberately NOT narrowed
            # by the finding-level filters: "this repo was last scanned by
            # Trivy on the 3rd" is a fact about the repository, and it does
            # not become less true because the reader asked to see only
            # critical findings. FILTER_SCOPE_NOTE says so on the document.
            #
            # It IS bounded by the window's end, though: a Q1 report that
            # lists a September scan is not describing Q1. Only the upper
            # bound is applied -- a lower bound would drop repos last
            # scanned before the window and read as a coverage gap that
            # doesn't exist, which is the more dangerous error for an audit
            # artifact. With no window, `as_of` is now and this is a no-op.
            scan_query = select(Scan).where(Scan.target_id == target.id)
            if filters.window_to is not None:
                scan_query = scan_query.where(Scan.started_at <= as_of)
            all_scans = session.exec(scan_query.order_by(Scan.started_at.desc())).all()
            seen_tools: set[str] = set()
            for s in all_scans:
                if s.tool in seen_tools:
                    continue
                seen_tools.add(s.tool)
                scan_rows.append(
                    {
                        "target": target.name,
                        "tool": s.tool,
                        "branch": s.branch,
                        "status": s.status,
                        "started_at": s.started_at.isoformat() + "Z",
                        "completed_at": (s.completed_at.isoformat() + "Z") if s.completed_at else "",
                        "findings_count": s.findings_count,
                    }
                )
            if not all_scans:
                scan_rows.append(
                    {
                        "target": target.name,
                        "tool": "",
                        "branch": target.default_branch,
                        "status": "never scanned",
                        "started_at": "",
                        "completed_at": "",
                        "findings_count": 0,
                    }
                )

        if want_sbom:
            components = session.exec(
                select(SbomComponent).where(
                    SbomComponent.target_id == target.id, SbomComponent.branch == target.default_branch
                )
            ).all()
            last_updated = max((c.last_seen for c in components), default=None)
            sbom_rows.append(
                {
                    "target": target.name,
                    "component_count": len(components),
                    "last_updated": (last_updated.isoformat() + "Z") if last_updated else "",
                }
            )

    totals_rows = [
        {"severity": severity, "state": state, "count": count}
        for (severity, state), count in sorted(totals_by_severity_state.items())
    ]

    section_manifest = [
        {"key": s.key, "label": s.label, "included": s.key in included_set} for s in REPORT_SECTIONS
    ]
    section_count = len(included_set)
    sections_summary = (
        f"{section_count} of {len(REPORT_SECTIONS)} (all sections)"
        if section_count == len(REPORT_SECTIONS)
        else f"{section_count} of {len(REPORT_SECTIONS)} - see '{SECTION_MANIFEST_HEADING}' below"
    )

    target_rows = [
        {"id": t.id, "name": t.name, "repo_url": t.repo_url, "label": t.label, "default_branch": t.default_branch}
        for t in targets
    ]

    # An empty report is the one outcome a reader is most likely to
    # misread -- "no targets" and "no problems" look identical once the
    # tables are blank. Say which it is, rather than leaving it to be
    # inferred from a Target Count of 0.
    if targets:
        result_note = ""
    elif filters.active_count():
        result_note = (
            "No targets matched the applied filters, so every section below is empty. "
            "This is an empty SCOPE, not a clean result: it says nothing about the security "
            f"posture of anything. See '{APPLIED_FILTERS_HEADING}' for what was applied."
        )
    else:
        result_note = (
            "No targets are visible to the account that generated this report, so every section "
            "below is empty. This says nothing about the security posture of anything."
        )

    return {
        "generated_at": now.isoformat() + "Z",
        "as_of": as_of.isoformat() + "Z",
        "scope": scope_label,
        "scope_name": scope_name,
        "target_count": len(targets),
        "result_note": result_note,
        "filters": filters.describe(),
        "filters_summary": filters.summary(),
        "filters_active_count": filters.active_count(),
        "filter_scope_note": FILTER_SCOPE_NOTE,
        "point_in_time_note": POINT_IN_TIME_NOTE,
        "sections": section_manifest,
        "sections_included": [k for k in SECTION_KEYS if k in included_set],
        "sections_summary": sections_summary,
        # All six gated the same way. The want_* flags above already skip
        # the work; this second gate is what the renderers read, and having
        # three of the six rely on the flags alone was an invitation for a
        # future edit to leave rows in a section the manifest calls excluded.
        "targets": target_rows if "targets" in included_set else [],
        "totals_by_severity_state": totals_rows if "totals" in included_set else [],
        "severity_state_rows": severity_state_rows if "severity_state" in included_set else [],
        "open_age_rows": open_age_rows if "open_age" in included_set else [],
        "scan_rows": scan_rows if "scan_coverage" in included_set else [],
        "sbom_rows": sbom_rows if "sbom" in included_set else [],
    }


def render_csv(data: dict) -> str:
    buf = io.StringIO()
    writer = safe_csv_writer(buf)
    included = set(data["sections_included"])

    writer.writerow(["Toleman Compliance Posture Report"])
    writer.writerow(["Generated At", data["generated_at"]])
    writer.writerow(["Figures As Of", data["as_of"]])
    writer.writerow(["Scope", data["scope"]])
    writer.writerow(["Target Count", data["target_count"]])
    writer.writerow(["Filters Applied", data["filters_summary"]])
    writer.writerow(["Sections Included", data["sections_summary"]])
    if data["result_note"]:
        writer.writerow(["Result", data["result_note"]])
    writer.writerow([])

    # Honesty block 1: what was filtered. Always rendered, unfiltered
    # reports included -- see ReportFilters.describe.
    writer.writerow([APPLIED_FILTERS_HEADING])
    writer.writerow(["Filter", "Value"])
    writer.writerow(["Scope", data["scope"]])
    for row in data["filters"]:
        writer.writerow([row["label"], row["value"]])
    writer.writerow(["Note", data["filter_scope_note"]])
    writer.writerow(["Point-in-time note", data["point_in_time_note"]])

    # Honesty block 2: what was included. An excluded section is named here
    # AND marked in place below, so neither a reader scanning the manifest
    # nor one scrolling the body can mistake "excluded" for "empty".
    writer.writerow([])
    writer.writerow([SECTION_MANIFEST_HEADING])
    writer.writerow(["Section", "Status"])
    for s in data["sections"]:
        writer.writerow([s["label"], "Included" if s["included"] else "Excluded"])

    def open_section(key: str) -> bool:
        """Write the section's heading; True if its content should follow.

        The blank separator is written *before* each section rather than
        after, so the document ends on real content the way it always has
        rather than gaining a trailing blank row.
        """
        spec = SECTION_BY_KEY[key]
        writer.writerow([])
        writer.writerow([spec.csv_heading])
        if key in included:
            return True
        writer.writerow([EXCLUDED_MARKER])
        return False

    if open_section("targets"):
        writer.writerow(["ID", "Name", "Repo URL", "Label", "Default Branch"])
        for t in data["targets"]:
            writer.writerow([t["id"], t["name"], t["repo_url"], t["label"], t["default_branch"]])

    if open_section("totals"):
        writer.writerow(["Severity", "State", "Count"])
        for r in data["totals_by_severity_state"]:
            writer.writerow([r["severity"], r["state"], r["count"]])

    if open_section("severity_state"):
        writer.writerow(["Target", "Severity", "State", "Count"])
        for r in data["severity_state_rows"]:
            writer.writerow([r["target"], r["severity"], r["state"], r["count"]])

    if open_section("open_age"):
        writer.writerow(
            [
                "Target",
                "Severity",
                "Open Count",
                "Avg Age (days)",
                "Oldest Age (days)",
                "0-7d",
                "8-30d",
                "31-90d",
                "90d+",
            ]
        )
        for r in data["open_age_rows"]:
            writer.writerow(
                [
                    r["target"],
                    r["severity"],
                    r["open_count"],
                    r["avg_age_days"],
                    r["oldest_age_days"],
                    r["bucket_0_7d"],
                    r["bucket_8_30d"],
                    r["bucket_31_90d"],
                    r["bucket_90d_plus"],
                ]
            )

    if open_section("scan_coverage"):
        writer.writerow(["Target", "Tool", "Branch", "Status", "Started At", "Completed At", "Findings Count"])
        for r in data["scan_rows"]:
            writer.writerow(
                [
                    r["target"],
                    r["tool"],
                    r["branch"],
                    r["status"],
                    r["started_at"],
                    r["completed_at"],
                    r["findings_count"],
                ]
            )

    if open_section("sbom"):
        writer.writerow(["Target", "Component Count", "Last Updated"])
        for r in data["sbom_rows"]:
            writer.writerow([r["target"], r["component_count"], r["last_updated"]])

    return buf.getvalue()


def render_pdf(data: dict) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, title="Toleman Compliance Posture Report")
    styles = getSampleStyleSheet()
    included = set(data["sections_included"])
    story = []

    story.append(Paragraph("Toleman Compliance Posture Report", styles["Title"]))
    story.append(Paragraph(f"Generated: {data['generated_at']}", styles["Normal"]))
    story.append(Paragraph(f"Figures as of: {data['as_of']}", styles["Normal"]))
    story.append(Paragraph(f"Scope: {data['scope']}", styles["Normal"]))
    story.append(Paragraph(f"Targets in scope: {data['target_count']}", styles["Normal"]))
    story.append(Paragraph(f"Filters applied: {data['filters_summary']}", styles["Normal"]))
    story.append(Paragraph(f"Sections included: {data['sections_summary']}", styles["Normal"]))
    if data["result_note"]:
        story.append(Paragraph(f"Result: {data['result_note']}", styles["Italic"]))
    story.append(Spacer(1, 0.25 * inch))

    def add_table(heading: str, header: list[str], rows: list[list]):
        story.append(Paragraph(heading, styles["Heading2"]))
        if not rows:
            story.append(Paragraph("No data.", styles["Normal"]))
            story.append(Spacer(1, 0.2 * inch))
            return
        table_data = [header] + rows
        table = Table(table_data, repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f4f6")]),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ]
            )
        )
        story.append(table)
        story.append(Spacer(1, 0.25 * inch))

    def add_section(key: str, header: list[str], rows: list[list]):
        """Render a selectable section, or an explicit excluded marker in its
        place. Never simply omitted: an absent heading and an empty one are
        indistinguishable to a reader, and only one of them is honest."""
        spec = SECTION_BY_KEY[key]
        if key in included:
            add_table(spec.pdf_heading, header, rows)
            return
        story.append(Paragraph(spec.pdf_heading, styles["Heading2"]))
        story.append(Paragraph(EXCLUDED_MARKER, styles["Italic"]))
        story.append(Spacer(1, 0.2 * inch))

    # Honesty block 1: the filters this document was generated under. Same
    # content as the CSV's, rendered as a table.
    add_table(
        APPLIED_FILTERS_HEADING,
        ["Filter", "Value"],
        [["Scope", data["scope"]]] + [[r["label"], r["value"]] for r in data["filters"]],
    )
    story.append(Paragraph(data["filter_scope_note"], styles["Italic"]))
    story.append(Paragraph(data["point_in_time_note"], styles["Italic"]))
    story.append(Spacer(1, 0.25 * inch))

    # Honesty block 2: which sections this document does and does not carry.
    add_table(
        SECTION_MANIFEST_HEADING,
        ["Section", "Status"],
        [[s["label"], "Included" if s["included"] else "Excluded"] for s in data["sections"]],
    )

    add_section(
        "targets",
        ["ID", "Name", "Repo URL", "Label", "Default Branch"],
        [[t["id"], t["name"], t["repo_url"], t["label"], t["default_branch"]] for t in data["targets"]],
    )

    add_section(
        "totals",
        ["Severity", "State", "Count"],
        [[r["severity"], r["state"], r["count"]] for r in data["totals_by_severity_state"]],
    )

    add_section(
        "severity_state",
        ["Target", "Severity", "State", "Count"],
        [[r["target"], r["severity"], r["state"], r["count"]] for r in data["severity_state_rows"]],
    )

    add_section(
        "open_age",
        ["Target", "Severity", "Open", "Avg Age (d)", "Oldest (d)", "0-7d", "8-30d", "31-90d", "90d+"],
        [
            [
                r["target"],
                r["severity"],
                r["open_count"],
                r["avg_age_days"],
                r["oldest_age_days"],
                r["bucket_0_7d"],
                r["bucket_8_30d"],
                r["bucket_31_90d"],
                r["bucket_90d_plus"],
            ]
            for r in data["open_age_rows"]
        ],
    )

    add_section(
        "scan_coverage",
        ["Target", "Tool", "Branch", "Status", "Started At", "Completed At", "Findings"],
        [
            [r["target"], r["tool"], r["branch"], r["status"], r["started_at"], r["completed_at"], r["findings_count"]]
            for r in data["scan_rows"]
        ],
    )

    add_section(
        "sbom",
        ["Target", "Component Count", "Last Updated"],
        [[r["target"], r["component_count"], r["last_updated"]] for r in data["sbom_rows"]],
    )

    doc.build(story)
    return buf.getvalue()


def _report_filename(data: dict, extension: str) -> str:
    """Informative filename: scope, whether it was filtered, how many
    sections it carries, and the date.

    The filtered/partial markers are part of the filename on purpose. These
    files get attached to tickets and mailed to auditors, where the filename
    is often all anyone reads before opening it -- a narrowed export that
    files itself under the same name as a full one is the same honesty
    problem as an unlabelled document, one directory level up.

    The scope segment goes in as the repository's real name, non-ASCII
    included; app.core.downloads.attachment_disposition is what makes it
    header-safe, and it sends an ASCII fallback alongside the true UTF-8
    name rather than flattening every non-Latin repo to one placeholder.
    Only whitespace is folded here, because a filename with spaces in it
    invites the exact quoting mistakes this is trying to avoid.
    """
    scope = re.sub(r"\s+", "-", data["scope_name"].strip()) or "report"
    parts = ["toleman-posture-report", scope]
    if data["filters_active_count"]:
        parts.append("filtered")
    included = len(data["sections_included"])
    if included != len(REPORT_SECTIONS):
        parts.append(f"{included}of{len(REPORT_SECTIONS)}-sections")
    parts.append(utcnow().strftime("%Y%m%d"))
    return f"{'-'.join(parts)}.{extension}"


def _reject_unknown(label: str, values: Optional[list[Optional[str]]], allowed) -> None:
    """400 on a filter value that matches nothing this caller could filter by.

    The alternative is a 200 carrying an empty report, which for a
    compliance artifact is the worst possible outcome: it looks like a clean
    result, and the Applied Filters block faithfully prints the typo as
    though it were meaningful. `allowed` is always derived from the caller's
    own visible data, so the error message cannot enumerate another
    tenant's values.
    """
    allowed_set = set(allowed)
    for value in values or []:
        if value is None:
            continue
        if value not in allowed_set:
            options = sorted(allowed_set)
            raise HTTPException(
                status_code=400,
                detail=(
                    f"unknown {label} '{value}'"
                    + (f"; expected one of {options}" if options else f"; no {label} values are recorded")
                ),
            )


@router.get("/sections")
def list_report_sections() -> list[dict]:
    """The selectable sections of the posture report (#302), so the report
    builder UI (and any API caller) can offer exactly the sections this
    backend actually knows how to render, rather than a hardcoded list that
    silently rots the next time one is added or renamed.

    No session dependency of its own: this router is registered with
    `login_required` in app/main.py, so a caller is already authenticated by
    the time it gets here. The catalog carries no workspace data, so there
    is nothing further to scope."""
    return [{"key": s.key, "label": s.label, "description": s.description} for s in REPORT_SECTIONS]


@router.get("/posture")
def posture_report(
    target_id: Optional[int] = Query(default=None),
    format: str = Query(default="csv", pattern="^(csv|pdf)$"),
    # --- #302 filters -------------------------------------------------
    # Multi-select params are repeated in the query string
    # (`?severity=Critical&severity=High`), the same convention
    # GET /api/findings uses, so the two pages' filter URLs read alike.
    group_id: Optional[int] = Query(default=None),
    severity: Optional[list[Severity]] = Query(default=None),
    state: Optional[list[FindingState]] = Query(default=None),
    tool: Optional[list[str]] = Query(default=None),
    category: Optional[str] = Query(default=None),
    environment: Optional[str] = Query(default=None),
    owner: Optional[str] = Query(default=None),
    date_from: Optional[date] = Query(default=None),
    date_to: Optional[date] = Query(default=None),
    # --- #302 section selection ---------------------------------------
    sections: Optional[list[str]] = Query(default=None),
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    """Real audit-evidence posture report (finding counts by
    severity/state, open-finding SLA/age, scan coverage, and SBOM summary)
    built from persisted Finding/Scan/SbomComponent rows. target_id omitted
    means org-wide (every target the caller can see), same "0/omitted = all"
    convention as TargetPicker's ALL_TARGETS sentinel on the frontend.

    Issue #86: the org-wide case is scoped to the caller's workspaces via
    accessible_workspace_ids(), the same helper #57 applied to
    dashboard/findings/targets but which reports.py was out of scope for at
    the time. A specific target_id outside the caller's workspaces 404s
    (see _resolve_targets), matching findings.py's get_finding.

    Issue #302: the report can additionally be filtered the way the Findings
    page can be (severity/state/tool/category/environment/owner/repo group,
    plus a date range over the finding window) and its sections selected via
    repeated `sections=` params. Both default to "everything", so a caller
    that predates #302 gets the same sections, in the same order, with the
    same rows it always did; the only addition to a default export is the
    applied-filters/sections header every report now carries, which on an
    unfiltered report positively states that nothing was left out.
    """
    if date_from and date_to and date_from > date_to:
        # Caught rather than quietly returning nothing: an empty compliance
        # report is the one failure mode nobody double-checks.
        raise HTTPException(status_code=400, detail="date_from must be on or before date_to")

    # Every free-text filter is validated against the values that actually
    # exist for this caller. A typo in any of them would otherwise narrow
    # the report to nothing and come back as a clean-looking empty document
    # -- exactly the failure the honesty header exists to prevent, arriving
    # through a different door. The candidate sets are the caller's own
    # facets, so a rejection message can never enumerate another tenant's
    # tools, environments or owners.
    _reject_unknown("category", [category], all_categories())
    _reject_unknown(
        "tool",
        tool,
        # Registry tools are accepted even with no findings yet: filtering
        # by a configured-but-not-yet-run scanner is a legitimate (empty)
        # question, unlike a misspelling of one.
        sorted(set(all_known_tools()) | set(list_tool_facets(session, user))),
    )
    _reject_unknown("environment", [environment], _target_facet(session, user, Target.environment))
    _reject_unknown("owner", [owner], _target_facet(session, user, Target.owner))

    if sections is not None:
        # `?sections=` with nothing after it parses as [""], not [], so the
        # blanks are stripped first -- otherwise an empty selection falls
        # through to the unknown-section branch and reports the wrong
        # problem, which is how this read as handled while never running.
        sections = [s for s in sections if s.strip()]
        if not sections:
            raise HTTPException(status_code=400, detail="at least one report section must be selected")
        unknown = [s for s in sections if s not in SECTION_BY_KEY]
        if unknown:
            raise HTTPException(
                status_code=400,
                detail=f"unknown report section(s) {unknown}; expected some of {list(SECTION_KEYS)}",
            )

    filters = ReportFilters(
        target_id=target_id,
        group_id=group_id,
        environment=environment,
        owner=owner,
        severity=list(severity or []),
        state=list(state or []),
        tool=list(tool or []),
        category=category,
        date_from=date_from,
        date_to=date_to,
    )
    data = build_posture_report(session, user, filters, sections)

    if format == "pdf":
        pdf_bytes = render_pdf(data)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": attachment_disposition(_report_filename(data, "pdf")),
                # The browser fetches this with XHR and reads the filename
                # back off the response (see api.exportPostureReport), which
                # cross-origin requires the header to be explicitly exposed.
                "Access-Control-Expose-Headers": "Content-Disposition",
            },
        )

    csv_text = render_csv(data)
    return StreamingResponse(
        iter([csv_text]),
        media_type="text/csv",
        headers={
            "Content-Disposition": attachment_disposition(_report_filename(data, "csv")),
            "Access-Control-Expose-Headers": "Content-Disposition",
        },
    )
