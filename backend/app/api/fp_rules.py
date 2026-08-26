"""False-positive learning engine management API (issue #76).

Read is workspace-scoped the same way GET /api/sla-rules is (issue #57's
accessible_workspace_ids); write actions (expire/reactivate/delete) require
at least SECURITY_ENGINEER on that rule's workspace via enforce_workspace_role,
same trust tier as SlaRule, since a FalsePositiveRule can suppress a real
finding across every repo in the workspace, same blast radius as an SLA
override. Rules are created automatically by app.core.fp_learning (triggered
from app.api.findings' triage endpoints), not via a POST here; there's
deliberately no manual "create a suppression rule from scratch" endpoint in
this first version, mirroring the issue's "on FP marking, extract a
suppression signature" framing (learned, not hand-authored). A security
engineer's controls are PATCH (expire/reactivate, or widen/narrow the
file_path_pattern) and DELETE (permanent removal) over what was learned.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select

from app.api.auth import accessible_workspace_ids, current_user, enforce_workspace_role
from app.api.deps import get_session
from app.models.models import FalsePositiveRule, User, WorkspaceRole

router = APIRouter(prefix="/api/fp-rules", tags=["fp-rules"])


class UpdateFpRuleRequest(BaseModel):
    active: bool | None = None
    # Nullable-and-present-vs-absent matters here: omitting the field leaves
    # file_path_pattern untouched, while explicitly passing null widens the
    # rule to "any file" for this rule_id/tool. Modeled as a plain optional
    # str with a separate "was it provided" flag since pydantic can't
    # otherwise distinguish "field omitted" from "field explicitly null".
    file_path_pattern: str | None = None
    clear_file_path_pattern: bool = False


@router.get("")
def list_fp_rules(
    workspace_id: int | None = None,
    active_only: bool = False,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and not ws_ids:
        return []
    query = select(FalsePositiveRule)
    if workspace_id is not None:
        if ws_ids is not None and workspace_id not in ws_ids:
            return []
        query = query.where(FalsePositiveRule.workspace_id == workspace_id)
    elif ws_ids is not None:
        query = query.where(FalsePositiveRule.workspace_id.in_(ws_ids))
    if active_only:
        query = query.where(FalsePositiveRule.active == True)  # noqa: E712
    return session.exec(query.order_by(FalsePositiveRule.created_at.desc())).all()


@router.get("/stats")
def fp_rule_stats(
    workspace_id: int | None = None,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    """Aggregate counts for the "X findings auto-suppressed" dashboard
    surface: total active rules in scope + total lifetime matches. The
    dashboard widget itself (app.core.widgets.resolve_fp_auto_suppressions)
    computes the calendar-month figure straight from Finding rows; this
    endpoint is for the management page's summary header."""
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and not ws_ids:
        return {"active_rules": 0, "total_matches": 0}
    query = select(FalsePositiveRule)
    if workspace_id is not None:
        if ws_ids is not None and workspace_id not in ws_ids:
            return {"active_rules": 0, "total_matches": 0}
        query = query.where(FalsePositiveRule.workspace_id == workspace_id)
    elif ws_ids is not None:
        query = query.where(FalsePositiveRule.workspace_id.in_(ws_ids))
    rules = session.exec(query).all()
    return {
        "active_rules": sum(1 for r in rules if r.active),
        "total_matches": sum(r.match_count for r in rules),
    }


@router.patch("/{rule_id}")
def update_fp_rule(
    rule_id: int,
    payload: UpdateFpRuleRequest,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    rule = session.get(FalsePositiveRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="false-positive rule not found")
    enforce_workspace_role(session, user, WorkspaceRole.SECURITY_ENGINEER, workspace_id=rule.workspace_id)

    if payload.active is not None:
        rule.active = payload.active
    if payload.clear_file_path_pattern:
        rule.file_path_pattern = None
    elif payload.file_path_pattern is not None:
        rule.file_path_pattern = payload.file_path_pattern.strip() or None

    session.add(rule)
    session.commit()
    session.refresh(rule)
    return rule


@router.delete("/{rule_id}")
def delete_fp_rule(
    rule_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    rule = session.get(FalsePositiveRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="false-positive rule not found")
    enforce_workspace_role(session, user, WorkspaceRole.SECURITY_ENGINEER, workspace_id=rule.workspace_id)
    session.delete(rule)
    session.commit()
    return {"ok": True}
