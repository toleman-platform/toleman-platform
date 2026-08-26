import json
import logging
from typing import Literal
from datetime import datetime
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, func, or_, select

from app.api.auth import accessible_workspace_ids, current_user, enforce_workspace_role, require_workspace_role
from app.api.deps import get_session
from app.core.cve_enrichment import get_cve_enrichment
from app.core.fp_learning import learn_suppression_rule
from app.core.notifications import dispatch_notification
from app.core.sla import compute_sla_status
from app.core.remediation import group_remediations
from app.core.time import utcnow
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


def _apply_triage(
    finding: Finding,
    to_state: FindingState,
    reason: str,
    actor: str,
    session: Session,
    batch_id: str | None = None,
) -> Finding:
    """Shared single-finding state-transition + audit-log logic, used by
    both the single triage endpoint and the bulk triage endpoint.

    batch_id (issue #123) tags every FindingStateLog row written by the same
    bulk-triage call so the Audit Log can collapse them into one grouped feed
    item at read time instead of flooding the feed with N near-identical
    rows. None for single-finding triage."""
    log = FindingStateLog(
        finding_id=finding.id, from_state=finding.state, to_state=to_state, reason=reason, actor=actor, batch_id=batch_id
    )
    finding.state = to_state
    session.add(finding)
    session.add(log)
    if to_state == FindingState.FALSE_POSITIVE:
        # Issue #76: teach the false-positive learning engine right at the
        # moment a human marks this as noise, so the same shape of finding
        # (same rule_id+tool+file basename) is auto-suppressed on future
        # ingestion; including in a different repo within this workspace.
        # Best-effort: a learning failure must never block the triage action
        # itself, same "never break the primary action" philosophy as the
        # Jira/notification hooks in app.core.ingestion.
        try:
            learn_suppression_rule(session, finding, actor=actor)
        except Exception:
            logger.exception("learn_suppression_rule failed for finding %s", finding.id)
    return finding


@router.get("")
def list_findings(
    target_id: int | None = None,
    group_id: int | None = None,
    branch: str | None = None,
    state: FindingState | None = None,
    severity: Severity | None = None,
    tool: str | None = None,
    fixability: Literal["fixable", "no_known_fix", "unknown"] | None = None,
    environment: str | None = None,
    owner: str | None = None,
    search: str | None = None,
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
) -> FindingListResponse:
    # Issue #57: scope to workspaces the caller is a member of (None = admin,
    # no filter). A caller with no memberships gets ws_ids == [] below, which
    # short-circuits to an empty page rather than every workspace's findings.
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and not ws_ids:
        return FindingListResponse(items=[], total=0)

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
    if target_id is not None:
        query = query.where(Finding.target_id == target_id)
    if branch is not None:
        query = query.where(Finding.branch == branch)
    if state is not None:
        query = query.where(Finding.state == state)
    if severity is not None:
        query = query.where(Finding.severity == severity)
    if tool is not None:
        query = query.where(Finding.tool == tool)
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
    if fixability is not None:
        # (#246) Expressed as a subquery over CveEnrichment rather than a
        # join, so it composes with the joins above without duplicating rows
        # when a finding's CVE has several enrichment matches.
        fixable_cves = select(CveEnrichment.cve_id).where(
            CveEnrichment.osv_found == True,  # noqa: E712
            CveEnrichment.fixed_versions.is_not(None),
            CveEnrichment.fixed_versions != "[]",
        )
        known_cves = select(CveEnrichment.cve_id).where(CveEnrichment.osv_found == True)  # noqa: E712
        if fixability == "fixable":
            query = query.where(Finding.cve_id.in_(fixable_cves))
        elif fixability == "no_known_fix":
            query = query.where(
                Finding.cve_id.in_(known_cves), Finding.cve_id.not_in(fixable_cves)
            )
        else:  # unknown, no CVE at all, or no resolved advisory
            query = query.where(
                or_(Finding.cve_id.is_(None), Finding.cve_id.not_in(known_cves))
            )
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

    total = session.exec(select(func.count()).select_from(query.subquery())).one()

    page = max(page, 1)
    page_size = max(min(page_size, 500), 1)
    query = query.order_by(Finding.priority_score.desc()).offset((page - 1) * page_size).limit(page_size)
    items = session.exec(query).all()
    fixmap = _fixability_map(session, items)
    return FindingListResponse(
        items=[_to_finding_out(session, f, fixability=fixmap.get(f.id)) for f in items],
        total=total,
    )


@router.get("/facets/tools")
def list_tool_facets(session: Session = Depends(get_session), user: User = Depends(current_user)) -> list[str]:
    """Distinct tool names across findings visible to the caller (issue #57),
    for populating the tool filter."""
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and not ws_ids:
        return []
    query = select(Finding.tool).distinct()
    if ws_ids is not None:
        query = query.join(Target, Target.id == Finding.target_id).where(Target.workspace_id.in_(ws_ids))
    rows = session.exec(query).all()
    return sorted(rows)


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
    return _target_facet(session, user, Target.environment)


@router.get("/facets/owners")
def list_owner_facets(
    session: Session = Depends(get_session), user: User = Depends(current_user)
) -> list[str]:
    """(#251) Distinct owners among targets the caller can see."""
    return _target_facet(session, user, Target.owner)


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
        updated.append(_apply_triage(finding, payload.to_state, payload.reason, payload.actor, session, batch_id=batch_id))
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
    _apply_triage(finding, to_state, reason, actor, session)
    session.commit()
    session.refresh(finding)
    return finding


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
