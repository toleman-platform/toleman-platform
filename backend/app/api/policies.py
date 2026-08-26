"""Policy-as-code API (ROADMAP Sprint 4): workspace-scoped severity/license
threshold and org-level suppression rules that adjust PR Guardrail's default
blocking decision (see app.core.policy.apply_policies and
app.core.pr_guardrail_executor.execute_pr_guardrail_scan).
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select

from app.api.auth import current_user
from app.api.deps import get_session
from app.models.models import PolicyRule, PolicyRuleType, User, Workspace

router = APIRouter(prefix="/api/policies", tags=["policies"])


def _get_workspace_or_404(workspace_id: int, session: Session) -> Workspace:
    workspace = session.get(Workspace, workspace_id)
    if not workspace:
        raise HTTPException(status_code=404, detail="workspace not found")
    return workspace


@router.get("")
def list_policies(workspace_id: int, session: Session = Depends(get_session)):
    """List active policy rules for a workspace."""
    _get_workspace_or_404(workspace_id, session)
    return session.exec(
        select(PolicyRule).where(
            PolicyRule.workspace_id == workspace_id,
            PolicyRule.active == True,  # noqa: E712
        ).order_by(PolicyRule.created_at.desc())
    ).all()


@router.post("")
def create_policy(
    body: dict,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    workspace_id = body.get("workspace_id")
    rule_type = body.get("rule_type")
    value = body.get("value")
    if not workspace_id or not rule_type or not value:
        raise HTTPException(status_code=400, detail="workspace_id, rule_type, and value are required")
    _get_workspace_or_404(workspace_id, session)
    try:
        rule_type = PolicyRuleType(rule_type)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"invalid rule_type: {rule_type}")

    rule = PolicyRule(
        workspace_id=workspace_id,
        rule_type=rule_type,
        value=value,
        reason=body.get("reason", ""),
        # Taken from the authenticated session, never the request body; a
        # client-supplied created_by would let anyone forge the audit trail
        # for who suppressed a finding.
        created_by=user.email,
    )
    session.add(rule)
    session.commit()
    session.refresh(rule)
    return rule


@router.delete("/{policy_id}")
def delete_policy(policy_id: int, session: Session = Depends(get_session)):
    """Soft-delete: this is an audit-relevant record, so we deactivate rather
    than hard-delete."""
    rule = session.get(PolicyRule, policy_id)
    if not rule:
        raise HTTPException(status_code=404, detail="policy rule not found")
    rule.active = False
    session.add(rule)
    session.commit()
    session.refresh(rule)
    return rule
