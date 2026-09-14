import json
import logging
from typing import Literal
from datetime import datetime, timedelta
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlmodel import Session, and_, func, or_, select

from app.api.auth import accessible_workspace_ids, current_user, enforce_workspace_role, require_workspace_role
from app.api.deps import get_session
from app.core.autofix import AutofixError, Patch, find_suppression_comment, open_fix_pr, suggest_fix
from app.core.cve_enrichment import get_cve_enrichment
from app.core.notifications import dispatch_notification
from app.core.sla import compute_sla_status
from app.core.remediation import group_remediations
from app.core.grouping import (
    DEFAULT_SORT,
    SORT_KEYS,
    UNGROUPED_CATEGORIES,
    group_aggregate_columns,
    representative_finding,
    severity_for_weight,
    severity_weight_case,
)
from app.core.time import utcnow
from app.core.tool_registry import UNKNOWN_TOOL_CATEGORY, all_categories, all_known_tools, tool_category, tools_in_category
from app.core.triage import apply_triage
from app.core.fixability import (
    UNKNOWN,
    VALID_FIXABILITY,
    fixability_for_enrichment,
    fixability_for_finding,
)
from app.models.models import (
    CveEnrichment,
    Finding,
    FindingState,
    FindingStateLog,
    NotificationEventType,
    OPEN_FINDING_STATES,
    RESOLVED_FINDING_STATES,
    SEVERITY_WEIGHT,
    Severity,
    Target,
    TargetGroup,
    User,
    WorkspaceRole,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/findings", tags=["findings"])

DEFAULT_PAGE_SIZE = 25


class FindingOut(Finding):
    """Finding plus resolved SLA fields (issue #70), computed on read via
    app.core.sla.compute_sla_status, not stored columns. sla_days is None
    when no SlaRule applies to this finding's (group, severity) or
    workspace default; sla_violated is always False in that case (never a
    fabricated countdown). Subclasses Finding (not a table) purely to reuse
    its field set without hand-duplicating every column, matching how this
    endpoint already returns Finding rows almost as-is elsewhere."""
    sla_days: int | None = None
    sla_violated: bool = False
    # (#246) "can I close this today?", derived from CveEnrichment, not a
    # stored column, so it cannot drift from the enrichment it summarises.
    # "unknown" means we have not established either way; it is NOT a softer
    # way of saying no_known_fix. See app.core.fixability.
    fixability: str = UNKNOWN
    # Vulnerability-type grouping/filter (Code/SAST, Secret, OSS/SCA,
    # License, IaC, AI/ML, ...), derived from `tool` via
    # app.core.tool_registry.tool_category, not a stored column, so it can
    # never drift from the registry Tool Marketplace itself reads.
    category: str = ""


def _to_finding_out(session: Session, finding: Finding, fixability: str | None = None) -> FindingOut:
    sla_days, sla_violated = compute_sla_status(session, finding)
    _maybe_notify_sla_breach(session, finding, sla_violated)
    if fixability is None:
        # Single-finding callers. List endpoints pass a pre-resolved value
        # from _fixability_map so a page of 50 findings is one query, not 50.
        fixability = fixability_for_finding(session, finding)
    return FindingOut(
        **finding.model_dump(),
        sla_days=sla_days,
        sla_violated=sla_violated,
        fixability=fixability,
        category=tool_category(finding.tool),
    )


def _fixability_map(session: Session, findings: list[Finding]) -> dict[int, str]:
    """Resolve fixability for a whole page in one query (#246)."""
    cve_ids = {f.cve_id for f in findings if f.cve_id}
    rows = (
        session.exec(select(CveEnrichment).where(CveEnrichment.cve_id.in_(cve_ids))).all()
        if cve_ids
        else []
    )
    by_cve = {r.cve_id: r for r in rows}
    return {f.id: fixability_for_enrichment(by_cve.get(f.cve_id)) if f.cve_id else UNKNOWN for f in findings}


def _maybe_notify_sla_breach(session: Session, finding: Finding, sla_violated: bool) -> None:
    """Issue #73 sla_breach trigger, fired at the same query-time point #70
    already computes sla_violated (see module docstring in app.core.sla,
    there's no background job for this). Dedup via
    Finding.sla_breach_notified_at: set the first time a finding is
    observed violating, never re-fired on subsequent reads while it stays
    violated. Reset to None once no longer violated (mitigated, or SLA rule
    changed) so a later re-violation (e.g. reopened past its SLA again)
    is treated as a fresh breach and notifies again, per the field's
    docstring in app.models.models.Finding."""
    if sla_violated and finding.sla_breach_notified_at is None:
        finding.sla_breach_notified_at = utcnow()
        session.add(finding)
        session.commit()
        # commit() expires every attribute on `finding` by default, without
        # this refresh, the caller's subsequent finding.model_dump() (in
        # _to_finding_out) triggers an implicit per-attribute reload that
        # SQLAlchemy/pydantic can mishandle mid-request (observed as a
        # "cannot pickle 'module' object" crash from deep inside pydantic's
        # default-value deepcopy machinery). Explicitly refreshing here keeps
        # the instance in a clean, fully-loaded state before it's read again.
        session.refresh(finding)
        workspace_id = _target_workspace_id(session, finding.target_id)
        if workspace_id is not None:
            try:
                dispatch_notification(
                    session,
                    workspace_id=workspace_id,
                    event_type=NotificationEventType.SLA_BREACH,
                    subject=f"SLA breach: {finding.title}",
                    detail=f"{finding.severity} finding open past its SLA window (file: {finding.file_path}).",
                )
            except Exception:
                logger.exception("sla_breach notification dispatch failed for finding %s", finding.id)
    elif not sla_violated and finding.sla_breach_notified_at is not None:
        finding.sla_breach_notified_at = None
        session.add(finding)
        session.commit()
        session.refresh(finding)


def _target_workspace_id(session: Session, target_id: int) -> int | None:
    target = session.get(Target, target_id)
    return target.workspace_id if target else None


class FindingListResponse(BaseModel):
    items: list[FindingOut]
    total: int


class BulkTriageRequest(BaseModel):
    finding_ids: list[int]
    to_state: FindingState
    reason: str = ""
    actor: str = "user"


class FindingEnrichmentResponse(BaseModel):
    """No-AI enrichment (issue #71): real CWE/CVSS/description from NVD and
    known fixed versions from OSV.dev, both keyed off Finding.cve_id.
    Fields are null when not applicable (e.g. a secrets-detection or SAST
    finding with no cve_id has no CVE/OSV data at all, that's correct, not
    a bug) or when the upstream source didn't have data for this CVE.
    Distinct from AI Analysis (app/api/ai.py); this always works with zero
    AI provider configured."""
    finding_id: int
    cve_id: str | None = None
    cve_description: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cwe_ids: list[str] | None = None
    references: list[str] | None = None
    fix_versions: list[dict] | None = None
    fetched_at: datetime | None = None


class FindingSuggestFixResponse(BaseModel):
    """Fix recommendation + (if one could be built) a patch to review --
    app.core.autofix.suggest_fix. Never opens a PR by itself; `recommendation`
    is always populated, the rest is None when no automated patch could be
    generated for this finding at all (still not a failure). `new_content`/
    `ref`/`strategy`/`explanation` must be sent back verbatim to
    POST /{finding_id}/raise-pr to actually open the PR for this exact
    patch -- nothing here is cached server-side, so what raise-pr commits
    is guaranteed to be exactly the diff shown here."""
    recommendation: str
    strategy: Literal["ai", "deterministic_sca"] | None = None
    diff: str | None = None
    file_path: str | None = None
    new_content: str | None = None
    ref: str | None = None
    explanation: str | None = None


class RaiseFixPrRequest(BaseModel):
    """Usually the exact patch fields FindingSuggestFixResponse returned --
    sent back verbatim so the PR committed is exactly the diff the caller
    reviewed, not a freshly (and possibly differently) regenerated one.
    strategy="mcp_client" is the exception: a caller that already read the
    flagged file itself (an MCP client, typically Claude Code, when
    suggest-fix returned no diff) and wrote its own fix, rather than
    replaying a patch suggest-fix produced."""
    file_path: str
    new_content: str
    ref: str
    strategy: Literal["ai", "deterministic_sca", "mcp_client"]
    explanation: str = ""


class RaiseFixPrResponse(BaseModel):
    pr_url: str
    pr_number: int
    branch: str


def _apply_finding_window(query, date_from: datetime | None, date_to: datetime | None):
    """(#302) Narrow to findings whose observed window overlaps
    [date_from, date_to].

    A Finding is not a point in time: it has a `first_seen` and a
    `last_seen`, and it is a live fact about the repository for the whole
    span between them. So "the report for Q3" has to mean "everything that
    was an open/triaged issue at some point during Q3", i.e. an interval
    overlap (`last_seen >= from AND first_seen <= to`), not
    `first_seen BETWEEN from AND to`. The latter would silently drop the
    worst rows in any compliance export -- a critical finding first seen in
    March and still open in September is precisely the one an auditor
    asking about Q3 wants to see, and it is the one a `first_seen`-only
    filter hides.

    Each bound is independent: passing only `date_from` means "still
    present on or after that date", passing only `date_to` means "already
    present on or before it".
    """
    if date_from is not None:
        query = query.where(Finding.last_seen >= date_from)
    if date_to is not None:
        query = query.where(Finding.first_seen <= date_to)
    return query


def _filtered_findings_query(
    session: Session,
    user: User,
    *,
    target_id: list[int] | None,
    group_id: int | None,
    branch: str | None,
    state: list[FindingState] | None,
    resolved: bool | None,
    severity: list[Severity] | None,
    tool: list[str] | None,
    fixability: list[Literal["fixable", "no_known_fix", "unknown"]] | None,
    environment: str | None,
    owner: str | None,
    search: str | None,
    rule_id: list[str] | None = None,
    new_since_days: int | None = None,
    # (#302) Finding-window date range, used by the compliance report export
    # (`app/api/reports.py`). Defaulted, like the two above, so the
    # Findings-page callers below stay exactly as they were: a report asking
    # for "Q3" must not change what the Findings page returns when it asks
    # for nothing. See _apply_finding_window for the overlap semantics.
    date_from: datetime | None = None,
    date_to: datetime | None = None,
):
    """Every list_findings filter except `category` (deliberately excluded:
    the category-counts facet below needs the SAME filters applied for its
    counts to mean anything -- "12 SCA findings" while severity=Critical is
    active must count only critical SCA findings -- but obviously can't
    itself filter by the one dimension it's counting across). Shared so the
    two endpoints can't drift on what a given filter param means.

    `target_id`/`state`/`severity`/`tool`/`fixability` are all multi-select
    (the Findings page's filter bar lets a caller pick more than one value
    per filter, e.g. Critical+High severity in one view) -- each is `None`
    for "no filter", or a non-empty list applied as `.in_(...)`, never a
    single bare value. An empty list is treated the same as `None` (a
    caller that deselects every checkbox means "no filter", not "match
    nothing") rather than a query that can never match any row.

    `resolved` (Open vs Resolved split on the Findings page) is `None` for
    every caller except that page itself: a target's own Vulnerabilities
    tab, the malicious-packages/AI-security inventories, and the public API
    (`app/api/public_api.py`, a wholly separate implementation) all still
    want every state by default, same as before this param existed --
    changing that default globally would have silently hidden already-
    triaged malicious-package/AI findings from pages whose whole point is
    being a complete inventory, not a triage queue. `state` wins when given
    (non-empty), same as it always has; `resolved` only ever narrows to the
    open (`OPEN_FINDING_STATES`) or resolved (`RESOLVED_FINDING_STATES`)
    group when `state` is absent.

    `date_from`/`date_to` (#302) bound the *finding window*, not a single
    timestamp -- see _apply_finding_window.

    Returns `(query, target_joined)`, or `(None, False)` when the caller's
    workspace membership resolves to zero workspaces (#57): a real query
    would come back empty anyway, and returning None here lets both callers
    short-circuit without a wasted round trip."""
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and not ws_ids:
        return None, False

    query = select(Finding)
    target_joined = ws_ids is not None
    if target_joined:
        query = query.join(Target, Target.id == Finding.target_id).where(Target.workspace_id.in_(ws_ids))
    if group_id is not None:
        # Issue #61: findings for targets tagged with this group. Joined on
        # Finding.target_id directly (not via the Target join above, which
        # only happens when ws_ids is not None) so this works regardless of
        # whether the caller is an admin.
        query = query.join(TargetGroup, TargetGroup.target_id == Finding.target_id).where(
            TargetGroup.group_id == group_id
        )
    if target_id:
        query = query.where(Finding.target_id.in_(target_id))
    if branch is not None:
        query = query.where(Finding.branch == branch)
    query = _apply_finding_window(query, date_from, date_to)
    if state:
        query = query.where(Finding.state.in_(state))
    elif resolved is not None:
        query = query.where(Finding.state.in_(RESOLVED_FINDING_STATES if resolved else OPEN_FINDING_STATES))
    if severity:
        query = query.where(Finding.severity.in_(severity))
    if tool:
        query = query.where(Finding.tool.in_(tool))
    if rule_id:
        # How a grouped row expands: the group key is (tool, rule_id), so
        # asking for its members is the same list endpoint with both pinned.
        # Deliberately not a new "members" endpoint -- every filter, sort and
        # permission check already applies here, and a parallel endpoint is a
        # second place for them to drift.
        query = query.where(Finding.rule_id.in_(rule_id))
    if new_since_days is not None:
        # "What landed since I last looked", the question first_seen was
        # always able to answer and nothing in the UI ever asked. Bounded
        # below at 1 so `?new_since_days=0` cannot mean "nothing ever".
        cutoff = utcnow() - timedelta(days=max(1, new_since_days))
        query = query.where(Finding.first_seen >= cutoff)
    if environment is not None or owner is not None:
        # (#251) Filter findings by the owning target's metadata. Needs the
        # Target join, which only happens above when ws_ids is not None (an
        # admin caller skips it), so join here if it hasn't happened yet;
        # joining twice raises rather than silently duplicating rows.
        if not target_joined:
            query = query.join(Target, Target.id == Finding.target_id)
            target_joined = True
        if environment is not None:
            query = query.where(Target.environment == environment)
        if owner is not None:
            query = query.where(Target.owner == owner)
    if fixability:
        # (#246) Expressed as a subquery over CveEnrichment rather than a
        # join, so it composes with the joins above without duplicating rows
        # when a finding's CVE has several enrichment matches.
        fixable_cves = select(CveEnrichment.cve_id).where(
            CveEnrichment.osv_found == True,  # noqa: E712
            CveEnrichment.fixed_versions.is_not(None),
            CveEnrichment.fixed_versions != "[]",
        )
        known_cves = select(CveEnrichment.cve_id).where(CveEnrichment.osv_found == True)  # noqa: E712
        # Multi-select: each requested value contributes its own condition,
        # OR'd together (e.g. "fixable" + "unknown" together means "either
        # a known fix exists, or fixability couldn't be established at
        # all" -- exactly what selecting both checkboxes should mean).
        conditions = []
        if "fixable" in fixability:
            conditions.append(Finding.cve_id.in_(fixable_cves))
        if "no_known_fix" in fixability:
            conditions.append(
                and_(Finding.cve_id.in_(known_cves), Finding.cve_id.not_in(fixable_cves))
            )
        if "unknown" in fixability:
            conditions.append(
                or_(Finding.cve_id.is_(None), Finding.cve_id.not_in(known_cves))
            )
        if conditions:
            query = query.where(or_(*conditions))
    if search:
        # Issue #122: AI Analysis' finding-search typeahead reuses this
        # query param rather than new backend search logic, and searches by
        # "title/CVE/target" per that issue; so cve_id and the target's
        # name need to be in scope here too, not just title/file_path/rule_id.
        if not target_joined:
            query = query.join(Target, Target.id == Finding.target_id)
            target_joined = True
        like = f"%{search}%"
        query = query.where(
            or_(
                Finding.title.ilike(like),
                Finding.file_path.ilike(like),
                Finding.rule_id.ilike(like),
                Finding.cve_id.ilike(like),
                Target.name.ilike(like),
            )
        )
    return query, target_joined



def _apply_category(query, category: str | None, exclude_category: list[str] | None = None):
    """Narrow a findings query to one derived category.

    `category` is not a stored column -- it is `tool_category(Finding.tool)`
    (see app.core.tool_registry), so filtering is the reverse lookup at SQL
    level. "Other" is every tool the registry does not recognise (notably a
    CI pipeline's free-form `tool` on POST /api/ingest/{target_id}), which is
    why it is a NOT IN rather than an IN.

    `exclude_category` is what the "Needs action" queue is built on: a
    copyleft licence on a transitive build binary is a quarterly policy call,
    not an incident, and letting 148 of them share a queue with one leaked
    credential is what buried the credential on page six. Expressed as its own
    parameter rather than "every category except X" so the caller states the
    exclusion it means and new categories land in the queue by default.

    Extracted so the flat list and the grouped list cannot disagree about
    what a category means. The compliance posture export (#302,
    app/api/reports.py) calls it for the same reason: a report that quietly
    disagreed with the Findings page about what "Other" covers would be an
    audit-evidence problem.
    """
    for excluded in exclude_category or []:
        if excluded == UNKNOWN_TOOL_CATEGORY:
            query = query.where(Finding.tool.in_(all_known_tools()))
        else:
            query = query.where(Finding.tool.not_in(tools_in_category(excluded)))
    if category is None:
        return query
    if category == UNKNOWN_TOOL_CATEGORY:
        return query.where(Finding.tool.not_in(all_known_tools()))
    return query.where(Finding.tool.in_(tools_in_category(category)))


def _sort_findings(query, sort: str):
    """Ordering for the flat list.

    `exploitability` is the default and is the ordering this endpoint has
    always used, so adding the parameter does not reorder anyone's existing
    view. Every branch ends in a deterministic tiebreak on id: without one,
    two findings with equal scores can swap places between page 1 and page 2
    and a row is silently skipped.
    """
    if sort == "severity":
        return query.order_by(severity_weight_case().desc(), Finding.priority_score.desc(), Finding.id.desc())
    if sort == "age":
        return query.order_by(Finding.first_seen.asc(), Finding.id.asc())
    if sort == "recent":
        return query.order_by(Finding.first_seen.desc(), Finding.id.desc())
    return query.order_by(Finding.priority_score.desc(), Finding.id.desc())


@router.get("")
def list_findings(
    # Multi-select filters (the Findings page's filter bar lets more than
    # one value be picked per filter): repeated query params, e.g.
    # `?severity=Critical&severity=High`. `Query(default=None)` accepts
    # zero, one, or many -- a single `?severity=Critical` still works
    # exactly as it always has.
    target_id: list[int] | None = Query(default=None),
    group_id: int | None = None,
    branch: str | None = None,
    state: list[FindingState] | None = Query(default=None),
    # Open vs Resolved split on the Findings page (None: every other
    # caller, unaffected -- see _filtered_findings_query's docstring).
    resolved: bool | None = None,
    severity: list[Severity] | None = Query(default=None),
    tool: list[str] | None = Query(default=None),
    category: str | None = None,
    exclude_category: list[str] | None = Query(default=None),
    fixability: list[Literal["fixable", "no_known_fix", "unknown"]] | None = Query(default=None),
    environment: str | None = None,
    owner: str | None = None,
    search: str | None = None,
    # Expanding a grouped row: same list, both halves of the group key pinned.
    rule_id: list[str] | None = Query(default=None),
    new_since_days: int | None = None,
    sort: Literal["exploitability", "severity", "age", "recent"] = DEFAULT_SORT,
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
) -> FindingListResponse:
    query, _ = _filtered_findings_query(
        session, user, target_id=target_id, group_id=group_id, branch=branch, state=state, resolved=resolved,
        severity=severity, tool=tool, fixability=fixability, environment=environment, owner=owner, search=search,
        rule_id=rule_id, new_since_days=new_since_days,
    )
    if query is None:
        # Issue #57: caller has zero workspace memberships -- an empty page,
        # not every workspace's data and not an error.
        return FindingListResponse(items=[], total=0)

    query = _apply_category(query, category, exclude_category)

    total = session.exec(select(func.count()).select_from(query.subquery())).one()

    page = max(page, 1)
    page_size = max(min(page_size, 500), 1)
    query = _sort_findings(query, sort).offset((page - 1) * page_size).limit(page_size)
    items = session.exec(query).all()
    fixmap = _fixability_map(session, items)
    return FindingListResponse(
        items=[_to_finding_out(session, f, fixability=fixmap.get(f.id)) for f in items],
        total=total,
    )



class FindingGroupOut(BaseModel):
    """One decision, standing for every finding that decision closes.

    The identity is `(tool, rule_id)` -- see app.core.grouping for why that
    key and not a package name parsed out of a title. `grouped` is False for
    a finding in an ungrouped category (Secrets, Malicious Package), where
    the row is a single finding rather than a collapsed set; the UI reads it
    to decide whether an expander belongs on the row at all.
    """
    tool: str
    rule_id: str
    category: str
    title: str
    severity: str
    grouped: bool
    finding_count: int
    target_count: int
    file_count: int
    max_priority_score: int
    oldest_first_seen: datetime
    newest_first_seen: datetime
    newest_last_seen: datetime
    max_epss: float | None = None
    kev_count: int = 0
    # Read off the single member most at risk (worst severity, then oldest),
    # never synthesised across members -- see grouping.representative_finding.
    representative_id: int
    representative_file_path: str
    representative_target_id: int
    sla_days: int | None = None
    sla_violated: bool = False
    fixability: str = UNKNOWN


class FindingGroupListResponse(BaseModel):
    items: list[FindingGroupOut]
    total: int
    # True when the group set hit MAX_GROUPS and the counts below are floors
    # rather than totals. Stated rather than silently absorbed: this module's
    # rule is never to round up, and a quietly capped total does exactly that.
    truncated: bool = False
    # Findings behind the groups on this page plus every other page, i.e. the
    # number the flat list would have shown. The UI states both ("14 groups /
    # 150 findings"); a grouped count alone reads as findings having vanished.
    total_findings: int


# A grouped page never loads more than this many group rows before sorting.
# Group cardinality is far below finding cardinality (150 findings collapsed
# to 14 groups on this repo's own scan), so this is a guard against a
# pathological result set, not an expected limit.
MAX_GROUPS = 2000


def _ungrouped_tools() -> set[str]:
    """Tools whose findings are never collapsed. See grouping.UNGROUPED_CATEGORIES."""
    tools: set[str] = set()
    for category in UNGROUPED_CATEGORIES:
        tools.update(tools_in_category(category))
    return tools


def _sort_groups(items: list[dict], sort: str) -> list[dict]:
    """Order group rows.

    Sorted in Python rather than SQL because the grouped and the deliberately
    ungrouped halves are two different queries (a Secrets finding must not be
    merged with its rule-mates), and ordering them separately would interleave
    them wrongly.

    Every key ends on `(tool, rule_id, representative_id)`, which is the real
    identity of a row. An earlier version tied on `rule_id` alone and called
    that total; it is not. `rule_id` is half the group key, and on the
    ungrouped half every finding under one rule emits its own row carrying the
    *same* tool and rule_id -- three gitleaks hits on one rule, all Critical,
    all the same score, produced three identical keys. `sorted` is stable, so
    the order fell through to whatever the database returned, which SQLite
    makes look deterministic and Postgres does not promise at all. With a page
    size of two, the same secret could appear on both pages and a third never
    appear -- exactly the outcome grouping is supposed to prevent.
    """
    identity = lambda g: (g["tool"], g["rule_id"], g["representative_id"])  # noqa: E731

    if sort == "severity":
        return sorted(
            items,
            key=lambda g: (SEVERITY_WEIGHT_BY_NAME.get(g["severity"], 0), g["max_priority_score"], identity(g)),
            reverse=True,
        )
    if sort == "blast_radius":
        return sorted(items, key=lambda g: (g["finding_count"], g["max_priority_score"], identity(g)), reverse=True)
    if sort == "age":
        return sorted(items, key=lambda g: (g["oldest_first_seen"], identity(g)))
    if sort == "recent":
        # first_seen, not last_seen: the flat list's `recent` is "newly found",
        # and a group re-detected by today's scan is not newly found. Ordering
        # on last_seen here made the same control mean two different things in
        # the two views.
        return sorted(items, key=lambda g: (g["newest_first_seen"], identity(g)), reverse=True)
    return sorted(items, key=lambda g: (g["max_priority_score"], g["finding_count"], identity(g)), reverse=True)


SEVERITY_WEIGHT_BY_NAME = {
    getattr(severity, "value", severity): weight for severity, weight in SEVERITY_WEIGHT.items()
}


@router.get("/groups")
def list_finding_groups(
    target_id: list[int] | None = Query(default=None),
    group_id: int | None = None,
    branch: str | None = None,
    state: list[FindingState] | None = Query(default=None),
    resolved: bool | None = None,
    severity: list[Severity] | None = Query(default=None),
    tool: list[str] | None = Query(default=None),
    category: str | None = None,
    exclude_category: list[str] | None = Query(default=None),
    fixability: list[Literal["fixable", "no_known_fix", "unknown"]] | None = Query(default=None),
    environment: str | None = None,
    owner: str | None = None,
    search: str | None = None,
    new_since_days: int | None = None,
    sort: Literal["exploitability", "severity", "blast_radius", "age", "recent"] = DEFAULT_SORT,
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
) -> FindingGroupListResponse:
    """The findings list with one row per decision instead of per detection.

    Takes exactly the filter set `GET /api/findings` takes, so a filter means
    the same thing in both views and switching between them cannot change
    which findings are in scope -- only how many rows they are drawn as.
    """
    query, _ = _filtered_findings_query(
        session, user, target_id=target_id, group_id=group_id, branch=branch, state=state, resolved=resolved,
        severity=severity, tool=tool, fixability=fixability, environment=environment, owner=owner, search=search,
        new_since_days=new_since_days,
    )
    if query is None:
        return FindingGroupListResponse(items=[], total=0, total_findings=0, truncated=False)
    query = _apply_category(query, category, exclude_category)

    ungrouped_tools = _ungrouped_tools()

    # Two passes, and the order matters for cost. The first builds a cheap stub
    # per group straight off the SQL aggregates, with no per-group queries at
    # all. Only after sorting and slicing does the second pass resolve the
    # representative, its SLA and its fixability -- and only for the rows on
    # the requested page. Doing that work up front meant a tenant with 400
    # distinct (tool, rule_id) pairs spent roughly 2,000 round trips to render
    # 25 rows.
    stubs: list[dict] = []

    # --- the collapsible majority ---------------------------------------
    grouped_query = query
    if ungrouped_tools:
        grouped_query = grouped_query.where(Finding.tool.not_in(ungrouped_tools))
    # `session.execute`, not SQLModel's `session.exec`: the filtered query
    # starts life as `select(Finding)`, so SQLModel still treats it as a
    # select-of-scalars and unwraps each result to its first column -- the
    # aggregate row arrives as a bare tool string rather than a Row, and every
    # attribute read off it raises. `execute` returns the labelled Row the
    # aggregates in group_aggregate_columns() are named for.
    #
    # Ordered before the limit: without an ORDER BY, *which* groups survive
    # MAX_GROUPS is whatever the plan happens to emit, so two identical
    # requests can truncate to different sets.
    rows = session.execute(
        grouped_query.with_only_columns(*group_aggregate_columns())
        .group_by(Finding.tool, Finding.rule_id)
        .order_by(func.max(Finding.priority_score).desc(), Finding.tool, Finding.rule_id)
        .limit(MAX_GROUPS)
    ).all()

    for row in rows:
        stubs.append(
            {
                "tool": row.tool,
                "rule_id": row.rule_id,
                "grouped": True,
                "finding": None,
                "severity": severity_for_weight(row.severity_weight or 0),
                "finding_count": row.finding_count,
                "target_count": row.target_count,
                "file_count": row.file_count,
                "max_priority_score": row.max_priority_score or 0,
                "oldest_first_seen": row.oldest_first_seen,
                "newest_first_seen": row.newest_first_seen,
                "newest_last_seen": row.newest_last_seen,
                # `is not None`, not `or None`: a measured EPSS of exactly 0.0
                # is a real answer ("no predicted exploitation"), and collapsing
                # it to null turns a measurement into "never assessed".
                "max_epss": row.max_epss if row.max_epss is not None else None,
                "kev_count": int(row.kev_count or 0),
                # Resolved in the second pass; the sort only needs an identity
                # that is stable, and (tool, rule_id) already is one here.
                "representative_id": 0,
            }
        )

    # --- the deliberately ungrouped ---------------------------------------
    # One leaked credential is one incident, not an instance of a gitleaks
    # rule; collapsing two of them would hide one behind the other's triage
    # decision. These are emitted as single-member groups so the page can
    # render one list, with `grouped=False` telling the row not to offer an
    # expander that would reveal only itself.
    if ungrouped_tools:
        singles = session.exec(
            query.where(Finding.tool.in_(ungrouped_tools))
            .order_by(Finding.priority_score.desc(), Finding.id)
            .limit(MAX_GROUPS)
        ).all()
        for finding in singles:
            stubs.append(
                {
                    "tool": finding.tool,
                    "rule_id": finding.rule_id,
                    "grouped": False,
                    "finding": finding,
                    "severity": getattr(finding.severity, "value", finding.severity),
                    "finding_count": 1,
                    "target_count": 1,
                    "file_count": 1,
                    "max_priority_score": finding.priority_score,
                    "oldest_first_seen": finding.first_seen,
                    "newest_first_seen": finding.first_seen,
                    "newest_last_seen": finding.last_seen,
                    "max_epss": finding.epss_score,
                    "kev_count": 1 if finding.kev_listed else 0,
                    "representative_id": finding.id,
                }
            )

    total_findings = sum(g["finding_count"] for g in stubs)
    truncated = len(rows) >= MAX_GROUPS or (ungrouped_tools and len(singles) >= MAX_GROUPS)

    stubs = _sort_groups(stubs, sort)
    page = max(page, 1)
    page_size = max(min(page_size, 500), 1)
    start = (page - 1) * page_size
    page_stubs = stubs[start : start + page_size]

    # --- second pass: enrich only what this page renders -------------------
    items: list[FindingGroupOut] = []
    page_singles = [g["finding"] for g in page_stubs if g["finding"] is not None]
    fixmap = _fixability_map(session, page_singles) if page_singles else {}

    for stub in page_stubs:
        rep = stub["finding"]
        if rep is None:
            # Scoped to `grouped_query`, never a bare select over the table:
            # that query already carries the caller's workspace restriction and
            # every active filter. A representative picked outside it could be
            # a finding the caller is not entitled to see, and its title, file
            # path and SLA are all rendered on the row.
            rep = representative_finding(
                session, grouped_query.where(Finding.tool == stub["tool"], Finding.rule_id == stub["rule_id"])
            )
            if rep is None:
                continue
            fixability_value = fixability_for_finding(session, rep)
        else:
            fixability_value = fixmap.get(rep.id, UNKNOWN)

        sla_days, sla_violated = compute_sla_status(session, rep)
        items.append(
            FindingGroupOut(
                tool=stub["tool"],
                rule_id=stub["rule_id"],
                category=tool_category(stub["tool"]),
                title=rep.title,
                severity=stub["severity"],
                grouped=stub["grouped"],
                finding_count=stub["finding_count"],
                target_count=stub["target_count"],
                file_count=stub["file_count"],
                max_priority_score=stub["max_priority_score"],
                oldest_first_seen=stub["oldest_first_seen"],
                newest_first_seen=stub["newest_first_seen"],
                newest_last_seen=stub["newest_last_seen"],
                max_epss=stub["max_epss"],
                kev_count=stub["kev_count"],
                representative_id=rep.id,
                representative_file_path=rep.file_path,
                representative_target_id=rep.target_id,
                sla_days=sla_days,
                sla_violated=sla_violated,
                fixability=fixability_value,
            )
        )

    return FindingGroupListResponse(
        items=items,
        total=len(stubs),
        truncated=bool(truncated),
        total_findings=total_findings,
    )


def distinct_finding_tools(session: Session, user: User) -> list[str]:
    """Distinct tool names across findings visible to the caller (issue #57).

    The plain function behind GET /facets/tools, so other modules
    (app/api/reports.py validates its `tool` filter against this) can reuse
    it without calling a route handler as if it were one -- that works, but
    only by accident of its `Depends(...)` defaults, and it breaks silently
    the moment the endpoint grows a parameter.
    """
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and not ws_ids:
        return []
    query = select(Finding.tool).distinct()
    if ws_ids is not None:
        query = query.join(Target, Target.id == Finding.target_id).where(Target.workspace_id.in_(ws_ids))
    rows = session.exec(query).all()
    return sorted(rows)


def distinct_target_environments(session: Session, user: User) -> list[str]:
    """(#251) Distinct environments among targets the caller can see.

    Reads Target rows, not findings, so a target nobody has scanned yet is
    still a valid thing to filter by.
    """
    return _target_facet(session, user, Target.environment)


def distinct_target_owners(session: Session, user: User) -> list[str]:
    """(#251) Distinct owners among targets the caller can see."""
    return _target_facet(session, user, Target.owner)


@router.get("/facets/tools")
def list_tool_facets(session: Session = Depends(get_session), user: User = Depends(current_user)) -> list[str]:
    """Distinct tool names across findings visible to the caller (issue #57),
    for populating the tool filter."""
    return distinct_finding_tools(session, user)


class CategoryFacet(BaseModel):
    category: str
    count: int


@router.get("/facets/categories")
def list_category_facets(
    target_id: list[int] | None = Query(default=None),
    group_id: int | None = None,
    branch: str | None = None,
    state: list[FindingState] | None = Query(default=None),
    resolved: bool | None = None,
    severity: list[Severity] | None = Query(default=None),
    tool: list[str] | None = Query(default=None),
    fixability: list[Literal["fixable", "no_known_fix", "unknown"]] | None = Query(default=None),
    environment: str | None = None,
    owner: str | None = None,
    search: str | None = None,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
) -> list[CategoryFacet]:
    """Per-category finding counts for the Findings page's category tabs
    ("SCA (12)", "Secrets (3)", ...) -- tabs, not a filter dropdown, replace
    an active category *view*, so each tab's count must reflect every OTHER
    filter currently applied (severity/tool/state/resolved/search/...) the
    same way list_findings itself would, via the same
    `_filtered_findings_query` both endpoints share. `category` itself is
    deliberately not one of the accepted filters here: it's the one
    dimension being counted across, not filtered by.

    Every registered category is returned, including ones with count 0 --
    a tab that's currently empty under the active filters is still a real,
    clickable destination, not the same as a category that doesn't exist
    (app.core.tool_registry.all_categories)."""
    query, _ = _filtered_findings_query(
        session, user, target_id=target_id, group_id=group_id, branch=branch, state=state, resolved=resolved,
        severity=severity, tool=tool, fixability=fixability, environment=environment, owner=owner, search=search,
    )
    counts = {c: 0 for c in all_categories()}
    if query is not None:
        subq = query.subquery()
        rows = session.exec(select(subq.c.tool, func.count()).group_by(subq.c.tool)).all()
        for tool_name, count in rows:
            counts[tool_category(tool_name)] += count
    return [CategoryFacet(category=c, count=counts[c]) for c in all_categories()]


@router.get("/remediations")
def list_remediations(
    target_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
) -> list[dict]:
    """(#247) Open findings for a target, grouped into the upgrades that
    would close them: "upgrade starlette to 0.40.0, fixes 3 issues".

    Workspace-scoped like every other read here (#57), a target id from
    another tenant returns 404, not that tenant's remediation plan.
    """
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="target not found")
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and target.workspace_id not in ws_ids:
        # 404 rather than 403: the existence of another tenant's target is
        # itself information.
        raise HTTPException(status_code=404, detail="target not found")
    return group_remediations(session, target_id)


@router.get("/facets/environments")
def list_environment_facets(
    session: Session = Depends(get_session), user: User = Depends(current_user)
) -> list[str]:
    """(#251) Distinct environments among targets the caller can see.

    Nulls are dropped rather than surfaced as an "unrecorded" option: the
    facet exists to narrow a list, and offering a bucket for every target
    nobody has labelled yet would be the largest and least useful entry in
    it on day one.
    """
    return distinct_target_environments(session, user)


@router.get("/facets/owners")
def list_owner_facets(
    session: Session = Depends(get_session), user: User = Depends(current_user)
) -> list[str]:
    """(#251) Distinct owners among targets the caller can see."""
    return distinct_target_owners(session, user)


def _target_facet(session: Session, user: User, column) -> list[str]:
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and not ws_ids:
        return []
    query = select(column).distinct().where(column.is_not(None), column != "")
    if ws_ids is not None:
        query = query.where(Target.workspace_id.in_(ws_ids))
    return sorted(r for r in session.exec(query).all() if r)


@router.get("/{finding_id}")
def get_finding(finding_id: int, session: Session = Depends(get_session), user: User = Depends(current_user)) -> FindingOut:
    finding = session.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="finding not found")
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None:
        # 404 rather than 403 to avoid confirming the finding exists in a
        # workspace the caller can't see (matches the "not found" wording
        # already used across this codebase for missing resources).
        target = session.get(Target, finding.target_id)
        if not target or target.workspace_id not in ws_ids:
            raise HTTPException(status_code=404, detail="finding not found")
    return _to_finding_out(session, finding)


@router.get("/{finding_id}/enrichment")
def get_finding_enrichment(
    finding_id: int, session: Session = Depends(get_session), user: User = Depends(current_user)
) -> FindingEnrichmentResponse:
    finding = session.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="finding not found")
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None:
        target = session.get(Target, finding.target_id)
        if not target or target.workspace_id not in ws_ids:
            raise HTTPException(status_code=404, detail="finding not found")

    if not finding.cve_id:
        # No CVE on this finding (SAST/secrets finding); nothing to
        # enrich from NVD/OSV. Correct, not a bug: return an all-null body
        # rather than a 404, so the frontend can render "no enrichment
        # available" instead of treating it as an error.
        return FindingEnrichmentResponse(finding_id=finding_id)

    row = get_cve_enrichment(session, finding.cve_id)

    references: list[str] = []
    if row.nvd_references:
        references.extend(json.loads(row.nvd_references))
    if row.osv_references:
        references.extend(json.loads(row.osv_references))
    deduped_references = list(dict.fromkeys(references))  # de-dup, preserve order

    return FindingEnrichmentResponse(
        finding_id=finding_id,
        cve_id=finding.cve_id,
        cve_description=row.nvd_description,
        cvss_score=row.cvss_score,
        cvss_vector=row.cvss_vector,
        cwe_ids=json.loads(row.cwe_ids) if row.cwe_ids else None,
        references=deduped_references or None,
        fix_versions=json.loads(row.fixed_versions) if row.fixed_versions else None,
        fetched_at=row.fetched_at,
    )


@router.post("/bulk-triage")
def bulk_triage_findings(
    payload: BulkTriageRequest,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    # Issue #123: a single bulk-triage call over N findings previously wrote
    # N indistinguishable FindingStateLog rows, which flooded the Audit Log
    # (a real 30-finding bulk action produced 30 near-identical cards). Tag
    # every row this call writes with one shared batch_id so /api/audit/log
    # can group them back into a single feed item. Only stamped when there's
    # actually more than one finding; a "batch" of one is just a normal
    # single triage and shouldn't render as a collapsible group.
    batch_id = uuid4().hex if len(payload.finding_ids) > 1 else None
    updated = []
    for finding_id in payload.finding_ids:
        finding = session.get(Finding, finding_id)
        if not finding:
            continue
        # finding_id is inside the request body's finding_ids list, and each
        # one can belong to a different target/workspace; check per finding
        # rather than once, the same reason create_target checks explicitly
        # instead of using require_workspace_role (see its comment).
        enforce_workspace_role(session, user, WorkspaceRole.DEVELOPER, finding_id=finding_id)
        updated.append(apply_triage(finding, payload.to_state, payload.reason, payload.actor, session, batch_id=batch_id))
    session.commit()
    for finding in updated:
        session.refresh(finding)
    return {"updated": len(updated), "items": updated}


@router.post("/{finding_id}/triage")
def triage_finding(
    finding_id: int,
    to_state: FindingState,
    reason: str = "",
    actor: str = "user",
    session: Session = Depends(get_session),
    user: User = Depends(require_workspace_role(WorkspaceRole.DEVELOPER)),
):
    finding = session.get(Finding, finding_id)
    if not finding:
        return {"error": "not found"}
    apply_triage(finding, to_state, reason, actor, session)
    session.commit()
    session.refresh(finding)
    return finding


@router.post("/{finding_id}/suggest-fix")
def suggest_fix_endpoint(
    finding_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
) -> FindingSuggestFixResponse:
    """Fix recommendation + (if possible) a patch to review
    (app.core.autofix.suggest_fix). Read-only/generative, same permission
    level as POST /api/ai/analyze/{finding_id} -- this never writes to the
    target's repo, so no elevated role is required; only actually raising
    the PR (POST /{finding_id}/raise-pr) does."""
    finding = session.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="finding not found")
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None:
        target = session.get(Target, finding.target_id)
        if not target or target.workspace_id not in ws_ids:
            raise HTTPException(status_code=404, detail="finding not found")
    return FindingSuggestFixResponse(**suggest_fix(session, finding))


@router.post("/{finding_id}/raise-pr")
def raise_fix_pr_endpoint(
    finding_id: int,
    payload: RaiseFixPrRequest,
    session: Session = Depends(get_session),
    user: User = Depends(require_workspace_role(WorkspaceRole.DEVELOPER)),
) -> RaiseFixPrResponse:
    """Opens the fix PR for the exact patch a prior POST /{finding_id}/suggest-fix
    returned (see RaiseFixPrRequest). DEVELOPER role required, same gate as
    /triage, since this writes a branch/PR to the target's real GitHub repo.
    `file_path` must match the finding's own file -- this can only commit a
    fix to the file the finding actually points at, not an arbitrary path."""
    finding = session.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="finding not found")
    target = session.get(Target, finding.target_id)
    if not target:
        raise HTTPException(status_code=404, detail="finding not found")
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and target.workspace_id not in ws_ids:
        raise HTTPException(status_code=404, detail="finding not found")
    if payload.file_path != finding.file_path:
        raise HTTPException(status_code=400, detail="file_path does not match this finding")
    suppression = find_suppression_comment(payload.new_content, finding)
    if suppression:
        raise HTTPException(
            status_code=400,
            detail=(
                f"This patch adds a suppression comment ('{suppression}') on the flagged line instead of "
                "fixing the underlying issue -- Toleman doesn't accept that as a fix. If this is a false "
                "positive or an accepted risk, triage it directly in Toleman instead of editing the code."
            ),
        )

    patch = Patch(
        file_path=payload.file_path,
        old_content="",  # unused by open_fix_pr; only unified_diff() (suggest-fix) needs it
        new_content=payload.new_content,
        ref=payload.ref,
        strategy=payload.strategy,
        explanation=payload.explanation,
    )
    try:
        pr = open_fix_pr(session, target, finding, patch)
    except AutofixError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return RaiseFixPrResponse(**pr)


@router.get("/{finding_id}/history")
def finding_history(finding_id: int, session: Session = Depends(get_session), user: User = Depends(current_user)):
    finding = session.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="finding not found")
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None:
        target = session.get(Target, finding.target_id)
        if not target or target.workspace_id not in ws_ids:
            raise HTTPException(status_code=404, detail="finding not found")
    return session.exec(select(FindingStateLog).where(FindingStateLog.finding_id == finding_id).order_by(FindingStateLog.created_at)).all()
