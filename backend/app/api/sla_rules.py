"""SlaRule CRUD (issue #70): workspace-scoped days-to-fix rules keyed by
severity and optionally a repo Group (#61) -- see app/core/sla.py for the
group -> workspace-default -> "no SLA" resolution these rules feed.

Gated at SECURITY_ENGINEER (or global admin) rather than DEVELOPER like
groups.py's CRUD -- an SLA rule is a compliance/security-policy decision
(same trust level as PolicyRule and ignore-request approval,
require_security_reviewer), not general repo organization.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select

from app.api.auth import accessible_workspace_ids, current_user, enforce_workspace_role
from app.api.deps import get_session
from app.models.models import Severity, SlaRule, User, WorkspaceRole

router = APIRouter(prefix="/api/sla-rules", tags=["sla-rules"])


class CreateSlaRuleRequest(BaseModel):
    workspace_id: int
    group_id: int | None = None
    severity: Severity
    days_to_fix: int

    def validate_days(self):
        if self.days_to_fix < 0:
            raise HTTPException(status_code=422, detail="days_to_fix must be >= 0")


class UpdateSlaRuleRequest(BaseModel):
    days_to_fix: int


def _existing_rule(session: Session, workspace_id: int, group_id: int | None, severity: Severity) -> SlaRule | None:
    return session.exec(
        select(SlaRule).where(
            SlaRule.workspace_id == workspace_id,
            SlaRule.group_id == group_id if group_id is not None else SlaRule.group_id.is_(None),
            SlaRule.severity == severity,
        )
    ).first()


@router.get("")
def list_sla_rules(
    workspace_id: int | None = None,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    # Same workspace-scoping shape as GET /api/groups (issue #57).
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and not ws_ids:
        return []
    query = select(SlaRule)
    if workspace_id is not None:
        if ws_ids is not None and workspace_id not in ws_ids:
            return []
        query = query.where(SlaRule.workspace_id == workspace_id)
    elif ws_ids is not None:
        query = query.where(SlaRule.workspace_id.in_(ws_ids))
    return session.exec(query.order_by(SlaRule.workspace_id, SlaRule.severity)).all()


@router.post("")
def create_sla_rule(
    payload: CreateSlaRuleRequest,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    payload.validate_days()
    # workspace_id lives inside the JSON body -- same reason POST
    # /api/groups checks explicitly instead of using a Depends-based
    # require_workspace_role (see groups.py's create_group).
    enforce_workspace_role(session, user, WorkspaceRole.SECURITY_ENGINEER, workspace_id=payload.workspace_id)

    if payload.group_id is not None:
        from app.models.models import Group

        group = session.get(Group, payload.group_id)
        if not group or group.workspace_id != payload.workspace_id:
            raise HTTPException(status_code=404, detail="group not found in this workspace")

    if _existing_rule(session, payload.workspace_id, payload.group_id, payload.severity):
        # DB-level UniqueConstraint doesn't reliably catch the NULL-group_id
        # "workspace default" case (Postgres treats NULL as distinct for
        # uniqueness) -- see SlaRule's docstring. Check explicitly so callers
        # get a clean 409 instead of silently stacking duplicate defaults.
        raise HTTPException(status_code=409, detail="an SLA rule for this workspace/group/severity already exists")

    rule = SlaRule(
        workspace_id=payload.workspace_id,
        group_id=payload.group_id,
        severity=payload.severity,
        days_to_fix=payload.days_to_fix,
    )
    session.add(rule)
    session.commit()
    session.refresh(rule)
    return rule


@router.patch("/{rule_id}")
def update_sla_rule(
    rule_id: int,
    payload: UpdateSlaRuleRequest,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    if payload.days_to_fix < 0:
        raise HTTPException(status_code=422, detail="days_to_fix must be >= 0")
    rule = session.get(SlaRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="sla rule not found")
    enforce_workspace_role(session, user, WorkspaceRole.SECURITY_ENGINEER, workspace_id=rule.workspace_id)
    rule.days_to_fix = payload.days_to_fix
    session.add(rule)
    session.commit()
    session.refresh(rule)
    return rule


@router.delete("/{rule_id}")
def delete_sla_rule(
    rule_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    rule = session.get(SlaRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="sla rule not found")
    enforce_workspace_role(session, user, WorkspaceRole.SECURITY_ENGINEER, workspace_id=rule.workspace_id)
    session.delete(rule)
    session.commit()
    return {"ok": True}
