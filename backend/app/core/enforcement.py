"""PR Guardrail enforcement-mode resolution (issue #62).

Whether PR Guardrail actually fails the build ("block"), just posts a PR
comment without failing the commit status ("alert"), or doesn't run at all
("disabled") is configurable at three levels -- Target, Group (#61), and
Workspace -- with most-specific-wins inheritance:

    target.enforcement_mode
        -> (if unset) the target's group(s)' enforcement_mode
        -> (if unset) workspace.enforcement_mode
        -> (if unset) the hardcoded default, "block"

This is a distinct concept from app.core.policy: policy decides WHICH
net-new findings are severe enough to count as blocking (severity threshold,
suppression rules); enforcement_mode decides whether a PR carrying
blocking findings actually fails the build or just warns.

A target can carry multiple groups (see TargetGroup, #61). If those groups
disagree, we resolve to the MOST RESTRICTIVE setting rather than e.g. "first
group wins" or "last group wins" -- a security gate should fail closed, not
have its strictest group's intent silently overridden by a laxer one purely
because of join-row ordering. Restrictiveness order: block > alert >
disabled.
"""
from typing import Literal

from sqlmodel import Session, select

from app.models.models import Group, Target, TargetGroup, Workspace

EnforcementMode = Literal["block", "alert", "disabled"]

DEFAULT_ENFORCEMENT_MODE: EnforcementMode = "block"

# Higher number = more restrictive. Used both to validate incoming values
# and to pick a winner when a target's groups disagree (see module docstring).
_RESTRICTIVENESS: dict[str, int] = {"block": 3, "alert": 2, "disabled": 1}

VALID_ENFORCEMENT_MODES = frozenset(_RESTRICTIVENESS)


def _most_restrictive(modes: list[str]) -> EnforcementMode:
    return max(modes, key=lambda m: _RESTRICTIVENESS[m])  # type: ignore[return-value]


def resolve_enforcement_mode(session: Session, target: Target) -> EnforcementMode:
    """Resolve the effective enforcement mode for one target: target ->
    group(s) (most-restrictive-wins on conflict) -> workspace -> "block"."""
    if target.enforcement_mode:
        return target.enforcement_mode  # type: ignore[return-value]

    group_modes = [
        g.enforcement_mode
        for g in session.exec(
            select(Group)
            .join(TargetGroup, TargetGroup.group_id == Group.id)
            .where(TargetGroup.target_id == target.id)
        ).all()
        if g.enforcement_mode
    ]
    if group_modes:
        return _most_restrictive(group_modes)

    workspace = session.get(Workspace, target.workspace_id)
    if workspace and workspace.enforcement_mode:
        return workspace.enforcement_mode  # type: ignore[return-value]

    return DEFAULT_ENFORCEMENT_MODE


def resolve_enforcement_mode_with_source(session: Session, target: Target) -> tuple[EnforcementMode, str]:
    """Same resolution as resolve_enforcement_mode, plus a human-readable
    label of where the effective mode came from -- for the "Enforcement:
    Block (inherited from workspace)" style legibility the frontend target
    detail page shows (issue #62)."""
    if target.enforcement_mode:
        return target.enforcement_mode, "target"  # type: ignore[return-value]

    group_rows = session.exec(
        select(Group)
        .join(TargetGroup, TargetGroup.group_id == Group.id)
        .where(TargetGroup.target_id == target.id)
    ).all()
    group_modes = [g.enforcement_mode for g in group_rows if g.enforcement_mode]
    if group_modes:
        mode = _most_restrictive(group_modes)
        return mode, "group"

    workspace = session.get(Workspace, target.workspace_id)
    if workspace and workspace.enforcement_mode:
        return workspace.enforcement_mode, "workspace"  # type: ignore[return-value]

    return DEFAULT_ENFORCEMENT_MODE, "default"
