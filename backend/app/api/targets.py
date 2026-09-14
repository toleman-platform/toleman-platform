import re
import secrets
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator
from sqlmodel import Session, func, select

from app.api.auth import accessible_workspace_ids, current_user, enforce_workspace_role, require_workspace_role
from app.api.deps import get_session
from app.core.auth_audit import log_auth_event
from app.core.config import settings
from app.core.crypto import encrypt_secret
from app.core.enforcement import VALID_ENFORCEMENT_MODES, resolve_enforcement_mode_with_source
from app.core import target_lifecycle
from app.core.pipeline_pr import PipelinePrError, open_pipeline_pr
from app.core.pipeline_workflow import generate_workflow_yaml
from app.core.ai_repo_status import effective_is_ai_repo
from app.api.github_app import BACKEND_URL
from app.core.github_app import target_has_pr_guardrail_coverage
from app.core.security_score import OPEN_STATES
from app.core.staleness import mark_stale_if_needed
from app.core.tool_registry import vulnerability_tools
from app.models.models import (
    WORKSPACE_ROLE_RANK,
    AuthEventType,
    Finding,
    Group,
    PipelineIntegrationBatch,
    PipelineIntegrationBatchItem,
    PipelineWorkflowTemplate,
    Severity,
    Target,
    TargetGroup,
    User,
    Workspace,
    WorkspaceMembership,
    WorkspaceRole,
)
from app.tasks.pipeline_tasks import run_pipeline_integration_batch
from app.tasks.sbom_tasks import queue_dependency_graph_sync

router = APIRouter(prefix="/api/targets", tags=["targets"])

# Scan execution clones this URL and runs local tools against the checkout, so
# an unrestricted repo_url is an SSRF / local-file-read primitive (file://,
# internal hosts, cloud metadata IPs). Only allow real GitHub HTTPS clone URLs.
_ALLOWED_REPO_URL = re.compile(r"^https://(?P<host>[\w.\-]+)/[\w.\-]+/[\w.\-]+(\.git)?/?$")


def _validate_repo_url(url: str) -> str:
    # (#298) github.com is always allowed; EXTRA_CLONE_HOSTS (operator-set
    # env var, see its docstring in app/core/config.py) extends this the
    # same way for a VPN-gated/client-cert-protected internal host. This
    # must stay in lockstep with app/scanners/runner.py's own
    # ALLOWED_CLONE_HOSTS | extra_clone_hosts_set check - that's the SSRF
    # defense that actually matters at clone time, this is just the
    # earliest point to reject a bad host with a clear 400 instead of a
    # scan failing later.
    match = _ALLOWED_REPO_URL.match(url)
    allowed_hosts = {"github.com"} | settings.extra_clone_hosts_set
    if not match or match.group("host") not in allowed_hosts:
        raise HTTPException(
            status_code=400,
            detail=f"repo_url must be an https://<host>/<org>/<repo> URL where <host> is one of {sorted(allowed_hosts)}",
        )
    return url


class CreateTargetRequest(BaseModel):
    workspace_id: int
    name: str
    repo_url: str
    default_branch: str = "main"
    label: str = "Dev"
    criticality_weight: int = 1

    @field_validator("repo_url")
    @classmethod
    def _check_repo_url(cls, v: str) -> str:
        return _validate_repo_url(v)


class UpdateTargetRequest(BaseModel):
    name: str | None = None
    default_branch: str | None = None
    label: str | None = None
    criticality_weight: int | None = None
    # PR Guardrail enforcement mode override (issue #62). Explicit null
    # clears the override (falls back to inheriting from the target's
    # group(s)/workspace); exclude_unset in update_target below means
    # simply omitting the field leaves the existing value untouched.
    enforcement_mode: str | None = None

    # Issue #72: the live base URL active API scanning combines with
    # already-discovered routes; see Target.api_base_url's docstring in
    # app/models/models.py for why this is the only allowed source of a
    # scan target host. Explicit null clears it (same exclude_unset
    # semantics as enforcement_mode above).
    api_base_url: str | None = None

    # Issue #185: human override of AI-repo detection. Explicit null clears
    # it (back to following detection), same exclude_unset semantics as
    # enforcement_mode above, so omitting the field leaves it untouched.
    is_ai_repo_override: bool | None = None

    # (#251) Ownership metadata. Free text: every org names its environments
    # differently, and an enum here would force a vocabulary on people. Null
    # clears the field, which is meaningful; "not recorded" is a real state,
    # distinct from any value someone might set.
    owner: str | None = None
    environment: str | None = None
    lifecycle: str | None = None

    # Issue #243: scan only the PR's changed files rather than the whole
    # checkout. Not nullable-to-inherit like enforcement_mode; this is a
    # plain per-target on/off, because it trades coverage for speed and an
    # inherited default would make it easy to narrow many targets' PR gate
    # without anyone deciding to.
    diff_scoped_pr_scans: bool | None = None

    # (#298) HTTP(S) proxy (e.g. a VPN gateway) git's clone should tunnel
    # through for this target. Not a secret (no encrypt_secret here, unlike
    # client_cert/key below), just a URL; explicit null clears it, same
    # exclude_unset semantics as enforcement_mode above.
    clone_proxy_url: str | None = None

    @field_validator("diff_scoped_pr_scans")
    @classmethod
    def _check_diff_scoped(cls, v: bool | None) -> bool | None:
        # Unlike enforcement_mode, null has no "inherit" meaning here and the
        # column is NOT NULL; an explicit null would be a 500 rather than a
        # 422. Omit the field to leave it alone.
        if v is None:
            raise ValueError("diff_scoped_pr_scans must be true or false; omit the field to leave it unchanged")
        return v

    @field_validator("enforcement_mode")
    @classmethod
    def _check_enforcement_mode(cls, v: str | None) -> str | None:
        if v is not None and v not in VALID_ENFORCEMENT_MODES:
            raise ValueError(f"enforcement_mode must be one of {sorted(VALID_ENFORCEMENT_MODES)} or null")
        return v

    @field_validator("api_base_url")
    @classmethod
    def _check_api_base_url(cls, v: str | None) -> str | None:
        if v is None:
            return v
        parsed = urlparse(v)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError("api_base_url must be a real http(s):// URL with a host")
        return v


def _groups_by_target(session: Session, target_ids: list[int]) -> dict[int, list[dict]]:
    """Batch-load {target_id: [{id, name, color}, ...]} for embedding group
    badges in target list/detail responses (issue #61), one query instead of
    N+1 per target."""
    if not target_ids:
        return {}
    rows = session.exec(
        select(TargetGroup.target_id, Group)
        .join(Group, Group.id == TargetGroup.group_id)
        .where(TargetGroup.target_id.in_(target_ids))
    ).all()
    out: dict[int, list[dict]] = {tid: [] for tid in target_ids}
    for target_id, group in rows:
        out.setdefault(target_id, []).append({"id": group.id, "name": group.name, "color": group.color})
    return out


def _with_groups(target: Target, groups_by_target: dict[int, list[dict]]) -> dict:
    # `is_ai_repo_effective` (issue #185) is what callers should gate on;
    # it folds the human override over detection, so a client never has to
    # reimplement that precedence and get it subtly wrong. The raw
    # is_ai_repo / is_ai_repo_override fields ride along via model_dump()
    # so the UI can still distinguish "auto-detected" from "forced".
    out = target.model_dump()
    # (#298) Never echo the encrypted client cert/key back to the client,
    # same "token_set, not the token" pattern as GitHubToken/app.api.github_token.
    # client_cert_ciphertext/client_key_ciphertext are internal storage
    # details a caller never needs and must never receive.
    client_cert_set = bool(out.pop("client_cert_ciphertext", ""))
    client_key_set = bool(out.pop("client_key_ciphertext", ""))
    return {
        **out,
        "groups": groups_by_target.get(target.id, []),
        "is_ai_repo_effective": effective_is_ai_repo(target),
        "client_cert_set": client_cert_set,
        "client_key_set": client_key_set,
        # (#273) Derived from deactivated_at rather than stored beside it, so
        # the two can never disagree; `deactivated_at` rides along via
        # model_dump() above for "deactivated 3 days ago" display. Same
        # reasoning as is_ai_repo_effective: the server owns the precedence
        # so no client re-derives it and gets it subtly wrong.
        "is_active": target_lifecycle.is_active(target),
    }


def _live_target(session: Session, target_id: int) -> Target | None:
    """`session.get(Target, id)` plus #273's soft-delete predicate; None for
    both "no such row" and "soft-deleted", which every route in this file
    then turns into the same 404.

    Collapsing the two cases is the point: a soft-deleted target has to be
    indistinguishable from a never-existed one at every product surface, or
    the 404-vs-410 difference becomes a side channel that says "this used to
    exist here" to anyone probing ids. The audit log is where deletion is
    answerable, and that is admin-gated.

    Deliberately not pushed down into a session-level hook: the audit feed
    (app/api/audit.py) and scan history still resolve deleted targets on
    purpose, so that a historical row keeps rendering a repo name instead of
    a bare id.
    """
    target = session.get(Target, target_id)
    if target is None or target_lifecycle.is_deleted(target):
        return None
    return target


@router.get("")
def list_targets(
    group_id: int | None = None,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    # Issue #57: scope to workspaces the caller is a member of (None = admin,
    # no filter; [] = no memberships yet -> empty list, not everything).
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and not ws_ids:
        return []
    # (#273) Soft-deleted targets are gone as far as the product is
    # concerned; they stay in the table only so their findings/scans keep
    # an owner the audit trail can name. Deactivated ones are NOT filtered
    # here on purpose -- "still visible and filterable" is the whole
    # difference between deactivate and delete, and the row renders with a
    # Deactivated badge (see targets-list.tsx) rather than vanishing.
    query = target_lifecycle.live_targets(select(Target))
    if ws_ids is not None:
        query = query.where(Target.workspace_id.in_(ws_ids))
    if group_id is not None:
        # Issue #61: filter to targets carrying this group, storage with no
        # way to actually query by it would be a foundation nobody can use.
        query = query.join(TargetGroup, TargetGroup.target_id == Target.id).where(TargetGroup.group_id == group_id)
    targets = session.exec(query).all()
    groups_by_target = _groups_by_target(session, [t.id for t in targets])
    return [_with_groups(t, groups_by_target) for t in targets]


@router.get("/summary")
def targets_summary(
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    """Per-target open-finding counts for the Repo Sync inventory (#174),
    keyed by target_id (string, matching /api/scans/summary's convention so
    both summaries index the same way on the client).

    Repo Sync previously showed only a name, a clone URL and a bare
    `weight N`, so the page couldn't answer the one question it exists to
    answer; which of these repos actually needs attention. This is the
    same default-branch + open-state scoping the Posture dashboard and the
    security score already use (app.core.security_score.OPEN_STATES), so the
    number here can't disagree with those surfaces. License findings are
    excluded for the same reason the security score zeroes them out
    (app.core.security_score.CATEGORY_RISK_WEIGHT): a legal/compliance
    signal, not something that makes a repo "need attention" the way an
    open vulnerability does.

    Declared before /{target_id} so "summary" isn't captured as a target id.
    One query for findings plus one for targets, not N+1.
    """
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and not ws_ids:
        return {}

    target_query = target_lifecycle.live_targets(select(Target))
    if ws_ids is not None:
        target_query = target_query.where(Target.workspace_id.in_(ws_ids))
    targets = session.exec(target_query).all()
    if not targets:
        return {}

    default_branch_by_target = {t.id: t.default_branch for t in targets}
    finding_rows = session.exec(
        select(Finding.target_id, Finding.severity, Finding.branch).where(
            Finding.target_id.in_(list(default_branch_by_target.keys())),
            Finding.state.in_(OPEN_STATES),
            Finding.tool.in_(vulnerability_tools()),
        )
    ).all()

    # Full severity breakdown, not just critical/high: the target Overview
    # (#197) renders open-findings-by-severity and must count the whole
    # target rather than whichever page of findings the UI happens to have
    # fetched. Deriving it from a paged list silently reports "3 Medium" for
    # a target with 1137 findings.
    def _blank() -> dict:
        return {"open": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}

    summary: dict[int, dict] = {t.id: _blank() for t in targets}
    severity_key = {
        Severity.CRITICAL: "critical",
        Severity.HIGH: "high",
        Severity.MEDIUM: "medium",
        Severity.LOW: "low",
        Severity.INFO: "informational",
    }
    for target_id, severity, branch in finding_rows:
        if branch != default_branch_by_target.get(target_id):
            continue
        entry = summary[target_id]
        entry["open"] += 1
        key = severity_key.get(severity)
        if key:
            entry[key] += 1

    return {str(target_id): counts for target_id, counts in summary.items()}


@router.post("")
def create_target(
    payload: CreateTargetRequest,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    # workspace_id lives inside the JSON body here, not a path/query param,
    # so require_workspace_role's name-binding trick can't see it; check
    # explicitly instead (see enforce_workspace_role's docstring).
    enforce_workspace_role(session, user, WorkspaceRole.DEVELOPER, workspace_id=payload.workspace_id)
    # (#356) Target.workspace_id is a real FK, and nothing above proves the
    # row exists: enforce_workspace_role returns immediately for a global
    # admin, and for everyone else it only asks whether a WorkspaceMembership
    # exists (which, for a nonexistent workspace, simply doesn't, so that
    # path 403s before ever reaching here). An admin POSTing a workspace_id
    # with no matching row therefore fell straight through to commit(), where
    # Postgres raised ForeignKeyViolation -> an unhandled IntegrityError.
    # That escapes past CORSMiddleware before it has built a response, so
    # Starlette's outer ServerErrorMiddleware emits the bare 500 itself and
    # the CORS headers are never attached; the browser then reports a
    # "No 'Access-Control-Allow-Origin' header" failure and the frontend's
    # error banner points the operator at CORS config, which is not the
    # problem. On a fresh deployment with zero workspaces this was the
    # *default* outcome of the add-a-repo form, which used to default
    # workspace_id to a hardcoded 1. Check first and 404 cleanly.
    #
    # Deliberately after the role check, not before: for a non-member the
    # role check already 403s regardless of whether the id exists, so
    # ordering it first keeps this route from becoming a way to probe which
    # workspace ids are real from outside the workspace.
    if not session.get(Workspace, payload.workspace_id):
        raise HTTPException(status_code=404, detail="workspace not found")
    target = Target(**payload.model_dump())
    session.add(target)
    session.commit()
    session.refresh(target)
    # (#330) Fetch the GitHub Dependency Graph in the background so the
    # target does not sit with an empty inventory until somebody clicks
    # "Import from GitHub". No-op for a non-github.com repo_url.
    queue_dependency_graph_sync(session, target)
    session.refresh(target)
    return target


@router.get("/{target_id}")
def get_target(target_id: int, session: Session = Depends(get_session), user: User = Depends(current_user)):
    target = _live_target(session, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="target not found")
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and target.workspace_id not in ws_ids:
        # 404 rather than 403 to avoid confirming the target exists in a
        # workspace the caller can't see (matches the "not found" wording
        # already used across this codebase for missing resources).
        raise HTTPException(status_code=404, detail="target not found")
    groups_by_target = _groups_by_target(session, [target.id])
    out = _with_groups(target, groups_by_target)
    # Issue #62: surface the *effective* resolved enforcement mode (and
    # where it came from) alongside the target's own raw override, so the
    # frontend can show "Enforcement: Block (inherited from workspace)"
    # without re-implementing the resolution logic client-side.
    effective_mode, source = resolve_enforcement_mode_with_source(session, target)
    out["effective_enforcement_mode"] = effective_mode
    out["enforcement_mode_source"] = source
    return out


@router.patch("/{target_id}")
def update_target(
    target_id: int,
    payload: UpdateTargetRequest,
    session: Session = Depends(get_session),
    user: User = Depends(require_workspace_role(WorkspaceRole.DEVELOPER)),
):
    target = _live_target(session, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="target not found")
    for field, value in payload.model_dump(exclude_unset=True).items():
        if field == "clone_proxy_url" and value is None:
            # Not Optional on the model (default ""); null in the request
            # means "clear it", same as every other nullable field here.
            value = ""
        setattr(target, field, value)
    session.add(target)
    session.commit()
    session.refresh(target)
    return _with_groups(target, {})


# ---------------------------------------------------------------------------
# Lifecycle (#273): deactivate / reactivate / delete.
#
# Before this, a registered target was permanent. There was no DELETE for a
# target at all -- only DELETE /{target_id}/groups/{group_id}, which un-tags
# one -- and no flag to stop scanning short of removing it, which wasn't
# possible either. A decommissioned repo, a typo'd registration and a test
# target created while exploring the product all accumulated forever.
#
# The two verbs are deliberately different products, not one with a
# parameter:
#
#   Deactivate  stop starting work against this repo. Findings, scans and
#               PR history are retained and keep counting toward dashboards
#               and scores; the target stays visible and filterable, badged
#               as deactivated. Reversible, gated at DEVELOPER (the same bar
#               as PATCH, which can already set enforcement_mode="disabled"
#               and switch off the PR gate).
#
#   Delete      the target is gone from every list, aggregate and dispatch
#               path. Implemented as a soft delete: not one row is
#               destroyed. See app/core/target_lifecycle's module docstring
#               for the cascade reasoning. Gated at SECURITY_ENGINEER, the
#               bar this codebase already uses for writes that change what
#               the platform records or enforces (sla_rules, fp_rules, tool
#               assignments) rather than DEVELOPER's day-to-day config bar.
#
# Both write an AuthAuditLog row via log_auth_event, the same path every
# other destructive platform action here uses (admin user delete, role
# change, workspace-role removal). "Who switched scanning off for this repo,
# and when" has to be answerable for the same reason the scan results do.
# ---------------------------------------------------------------------------


def _audit_target_event(
    session: Session,
    request: Request,
    user: User,
    event_type: AuthEventType,
    target: Target,
) -> None:
    """One writer for all three lifecycle events so they can't drift on
    detail formatting -- AuthAuditLog has no target_id column (it was built
    for account events), so the target's identity lives in `detail` and has
    to be written identically every time for the admin security log to be
    greppable. repo_url is included, not just the display name: a name can
    be edited before the delete, the clone URL is what actually identifies
    the repository afterwards.

    `target_email` is passed explicitly even though log_auth_event would
    default it to `actor` anyway. The default exists for the self-service
    events (login/logout/password), where "the user the event is about" and
    "the user who did it" are genuinely the same person; that reasoning does
    not transfer here, since these events are about a *repository* and
    AuthAuditLog has no column for one. Setting it deliberately keeps every
    row findable under the security log's email filter (which matches actor
    OR target_email) and means this behaviour is a decision recorded here
    rather than an accident of another function's default.
    """
    log_auth_event(
        session,
        event_type,
        actor=user.email,
        target_email=user.email,
        detail=f"target #{target.id} {target.name} ({target.repo_url})",
        ip_address=request.client.host if request.client else "unknown",
    )


@router.post("/{target_id}/deactivate")
def deactivate_target(
    target_id: int,
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(require_workspace_role(WorkspaceRole.DEVELOPER)),
):
    """Stop scanning this target without losing anything.

    Enforcement does not live here. Every dispatch path checks the flag
    itself (POST /api/scans/run, the public API's trigger_scan, POST
    /api/api-scan/{id}, POST /api/ingest/{id}, the PR Guardrail webhook and
    on-demand route, the beat-scheduled full scan, the baseline catch-up,
    and the pipeline rollout paths below) rather than trusting the UI to
    hide a button -- a target-level "off" that only the frontend honours is
    not off.
    """
    target = _get_target_scoped(target_id, session, user)
    changed = target_lifecycle.deactivate(target)
    if changed:
        session.add(target)
        session.commit()
        session.refresh(target)
        # Only on a real transition, same guard as admin.update_role's
        # `if old_role != user.role`: a no-op re-POST must not manufacture a
        # second audit row saying it happened twice.
        _audit_target_event(session, request, user, AuthEventType.TARGET_DEACTIVATED, target)
    return _with_groups(target, _groups_by_target(session, [target.id]))


@router.post("/{target_id}/reactivate")
def reactivate_target(
    target_id: int,
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(require_workspace_role(WorkspaceRole.DEVELOPER)),
):
    """Resume scanning. Nothing is replayed: the next scheduled full scan,
    push, or PR picks the target up normally. Scans that would have run
    while it was deactivated are gone, which is the point of deactivating
    -- silently backfilling them would make "off" mean "deferred"."""
    target = _get_target_scoped(target_id, session, user)
    changed = target_lifecycle.reactivate(target)
    if changed:
        session.add(target)
        session.commit()
        session.refresh(target)
        _audit_target_event(session, request, user, AuthEventType.TARGET_REACTIVATED, target)
    return _with_groups(target, _groups_by_target(session, [target.id]))


@router.delete("/{target_id}")
def delete_target(
    target_id: int,
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(require_workspace_role(WorkspaceRole.SECURITY_ENGINEER)),
):
    """Remove a target. Soft delete: every Finding, Scan and PRGuardrailScan
    row survives, and so does the Target row itself -- it simply stops
    existing everywhere the product looks (see target_lifecycle.live_targets
    for the query-side half, and _live_target above for the read-side one).

    The response says what was retained rather than reporting a bare
    `{"ok": true}`. Someone clicking Delete on a repo with 1137 findings
    should be told those findings still exist and where the record of them
    lives; a delete that silently keeps data is worse than one that keeps it
    and says so.
    """
    target = _get_target_scoped(target_id, session, user)
    # Same count-over-subquery shape as scans.scan_history's `total`, so a
    # target with 1137 findings doesn't ship 1137 rows to produce one number.
    retained = select(Finding).where(Finding.target_id == target.id)
    retained_findings = session.exec(select(func.count()).select_from(retained.subquery())).one()
    changed = target_lifecycle.soft_delete(target)
    if changed:
        session.add(target)
        session.commit()
        session.refresh(target)
        _audit_target_event(session, request, user, AuthEventType.TARGET_DELETED, target)
    return {
        "id": target.id,
        "deleted_at": target.deleted_at,
        # Stated explicitly so the UI can say it out loud (see the delete
        # ConfirmDialog in targets/[id]/target-lifecycle.tsx) instead of the
        # operator having to infer it from a docs page.
        "retained_findings": retained_findings,
        "retention": (
            "Findings, scan history and PR Guardrail records for this target are retained "
            "and remain visible in the audit log."
        ),
    }


@router.get("/{target_id}/workspace-key")
def get_workspace_key(target_id: int, session: Session = Depends(get_session), user: User = Depends(current_user)):
    target = _live_target(session, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="target not found")
    # Issue #57: this returns the workspace's api_key, so an unscoped check
    # here is worse than the plain read IDOR on the other routes; it leaks
    # another workspace's secret, not just its data.
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and target.workspace_id not in ws_ids:
        raise HTTPException(status_code=404, detail="target not found")
    workspace = session.get(Workspace, target.workspace_id)
    return {"workspace_id": workspace.id, "workspace_name": workspace.name, "api_key": workspace.api_key}


@router.post("/{target_id}/workspace-key/regenerate")
def regenerate_workspace_key(
    target_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(require_workspace_role(WorkspaceRole.DEVELOPER)),
):
    """Issue #129: the workspace API key (X-API-Key, used for CI push
    ingestion via /api/ingest/{target_id}; see app.api.deps.require_workspace)
    had no rotation path at all. Rotating a CI-push-capable credential is at
    least as sensitive as the other workspace-settings writes gated at
    DEVELOPER (PATCH /api/targets/{id}, PATCH /api/workspaces/{id}) via
    require_workspace_role, so this matches that bar rather than inventing a
    new one; require_workspace_role's dependency already resolves the
    workspace from this route's target_id path param.

    The old key is overwritten in place (not soft-revoked/kept around), so
    it stops authenticating against require_workspace (app/api/deps.py)
    immediately on commit, no grace period, since none of the existing
    secret-rotation patterns in this codebase (e.g. session token_version
    bump on password change) leave a stale credential valid.
    """
    target = _live_target(session, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="target not found")
    workspace = session.get(Workspace, target.workspace_id)
    if not workspace:
        raise HTTPException(status_code=404, detail="workspace not found")
    workspace.api_key = secrets.token_urlsafe(24)
    session.add(workspace)
    session.commit()
    session.refresh(workspace)
    return {"workspace_id": workspace.id, "workspace_name": workspace.name, "api_key": workspace.api_key}


def _get_target_scoped(target_id: int, session: Session, user: User) -> Target:
    """404-not-403 workspace scoping, same pattern used throughout this
    file and app/api/pr_guardrail.py."""
    target = _live_target(session, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="target not found")
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and target.workspace_id not in ws_ids:
        raise HTTPException(status_code=404, detail="target not found")
    return target


class SaveCloneCredentialsRequest(BaseModel):
    # PEM text for the mTLS client cert/key git presents when cloning this
    # target's repo_url. Omit a field (exclude_unset) to leave it
    # unchanged; pass "" explicitly to clear it. Mirrors
    # SaveGithubTokenRequest's plaintext-in/never-echoed-back shape.
    client_cert_pem: str | None = None
    client_key_pem: str | None = None


@router.put("/{target_id}/clone-credentials")
def save_clone_credentials(
    target_id: int,
    payload: SaveCloneCredentialsRequest,
    session: Session = Depends(get_session),
    user: User = Depends(require_workspace_role(WorkspaceRole.DEVELOPER)),
):
    """(#298) Set/clear the mTLS client cert/key used to clone this target's
    repo_url, for a host behind a VPN or requiring client-cert auth (see
    EXTRA_CLONE_HOSTS in app/core/config.py). Encrypted at rest the same way
    as GitHubToken (app.core.crypto); never echoed back - the response only
    reports whether each is set, same as GET/PUT /api/github-token."""
    target = _live_target(session, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="target not found")
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and target.workspace_id not in ws_ids:
        raise HTTPException(status_code=404, detail="target not found")

    updates = payload.model_dump(exclude_unset=True)
    if "client_cert_pem" in updates:
        target.client_cert_ciphertext = encrypt_secret(updates["client_cert_pem"])
    if "client_key_pem" in updates:
        target.client_key_ciphertext = encrypt_secret(updates["client_key_pem"])
    session.add(target)
    session.commit()
    session.refresh(target)
    return {
        "client_cert_set": bool(target.client_cert_ciphertext),
        "client_key_set": bool(target.client_key_ciphertext),
    }


@router.get("/{target_id}/pipeline-workflow")
def get_pipeline_workflow(target_id: int, session: Session = Depends(get_session), user: User = Depends(current_user)):
    """Issue #66: real, target-specific GitHub Actions workflow YAML that
    runs Semgrep/Gitleaks/Trivy (+ gosec for Go repos, detected from this
    target's own scan history or, failing that, GitHub's languages API)
    natively in the runner and pushes results back to Toleman via
    POST /api/ingest. Generation only; doesn't write anything to GitHub;
    see POST .../pipeline-integrate for that."""
    target = _get_target_scoped(target_id, session, user)
    return generate_workflow_yaml(session, target)


@router.post("/{target_id}/pipeline-integrate")
def integrate_pipeline(
    target_id: int,
    force: bool = False,
    session: Session = Depends(get_session),
    user: User = Depends(require_workspace_role(WorkspaceRole.DEVELOPER)),
):
    """Issue #66: opens a real PR on the target's GitHub repo (via the
    GitHub App's installation token) adding the generated
    .github/workflows/toleman-scan.yml, and records the outcome on the Target
    row so the frontend can show integration status without re-hitting
    GitHub every page load.

    (#245's double-scan gap) Server-side PR Guardrail (the webhook path)
    already scans every PR for free once GitHub can reach this backend AND
    a working, enabled installation actually covers this target's repo
    (app.core.github_app.target_has_pr_guardrail_coverage -- webhook
    reachability alone isn't proof of that: this target's repo might have
    no installation, that installation's webhook_secret might not be set,
    or PR Guardrail might be explicitly disabled for this target). Pipeline
    Integration adds a second, Actions-based scan of the same PRs on top of
    it, and ARCHITECTURE.md's own framing is that the Actions path exists
    for the case where the webhook path *can't* work, not as a second
    implementation to run alongside it. So on a first-time integration (not
    a re-run -- see the pipeline_integrated check below) where real
    coverage already exists, this 409s instead of silently doubling every
    PR's scan count; `force=true` proceeds anyway for an operator who wants
    the redundancy on purpose (e.g. as a fallback in case the webhook path
    breaks later)."""
    target = _get_target_scoped(target_id, session, user)
    # (#273) Pipeline integration opens a PR that wires this repo up to scan
    # itself on every push. Doing that for a target whose scanning has been
    # switched off would re-enable it through the back door, in a place
    # nobody would think to look for it -- a workflow file committed to the
    # repo, outliving any flag in this database.
    refusal = target_lifecycle.scan_refusal_reason(target)
    if refusal:
        raise HTTPException(status_code=409, detail=refusal)
    if not target.pipeline_integrated and target_has_pr_guardrail_coverage(session, target, BACKEND_URL) and not force:
        raise HTTPException(
            status_code=409,
            detail=(
                "Server-side PR Guardrail already scans every PR for this deployment "
                "(GitHub can reach this backend's webhook). Adding Pipeline Integration "
                "too will scan every PR twice, once server-side and once in GitHub "
                "Actions. Pass force=true to integrate anyway."
            ),
        )
    try:
        result = open_pipeline_pr(session, target)
    except PipelinePrError as exc:
        raise HTTPException(status_code=502, detail=str(exc))

    target.pipeline_integrated = True
    target.pipeline_pr_url = result["pr_url"]
    session.add(target)
    session.commit()
    session.refresh(target)
    return {
        "pipeline_integrated": target.pipeline_integrated,
        "pipeline_pr_url": target.pipeline_pr_url,
        "pr_number": result["pr_number"],
        "branch": result["branch"],
    }


class BulkPipelineIntegrateRequest(BaseModel):
    target_ids: list[int]
    # (#245's double-scan gap) Same escape hatch as the single-target
    # POST .../pipeline-integrate's force=true; batch-level rather than
    # per-target since a rollout either accepts the redundancy across the
    # whole selection or it doesn't -- see run_pipeline_integration_batch's
    # docstring for the per-item skip this defaults to.
    force: bool = False
    # Custom Workflow Builder (#35), same field as MassPipelineRolloutRequest's
    # below. Lets the frontend's "Integrate skipped anyway" retry (targets-list.tsx,
    # re-POSTing the original mass rollout's skipped items through this
    # manual-selection endpoint with force=true) carry the original rollout's
    # template through instead of silently falling back to #66's fixed
    # default scanner set.
    workflow_template_id: int | None = None


def _caller_can_integrate(session: Session, user: User, target: Target) -> bool:
    """Same bar as the single-target POST .../pipeline-integrate
    (require_workspace_role(DEVELOPER)), applied per-target here since a
    bulk selection can span multiple workspaces at once."""
    if user.role == "admin":
        return True
    membership = session.exec(
        select(WorkspaceMembership).where(
            WorkspaceMembership.user_id == user.id,
            WorkspaceMembership.workspace_id == target.workspace_id,
        )
    ).first()
    return bool(membership) and WORKSPACE_ROLE_RANK[membership.role] >= WORKSPACE_ROLE_RANK[WorkspaceRole.DEVELOPER]


@router.post("/bulk-pipeline-integrate")
def bulk_pipeline_integrate(
    payload: BulkPipelineIntegrateRequest,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    """Issue #68: multi-select wrapper around #66's per-target pipeline
    integration. Accepts a list of target_ids, silently drops any the
    caller can't see or doesn't hold at least DEVELOPER on (same
    404-shaped hiding this file uses everywhere else; see
    _get_target_scoped), and dispatches the rest as one Celery batch
    instead of blocking the request thread on N sequential real GitHub API
    calls (branch create + contents write + PR open per target, same
    "don't block the request thread" reasoning as #59's scan/discovery/sbom
    offload). Returns 202 with a batch_id to poll via
    GET /bulk-pipeline-integrate/{batch_id}.
    """
    if not payload.target_ids:
        raise HTTPException(status_code=400, detail="target_ids must not be empty")

    ws_ids = accessible_workspace_ids(session, user)
    unique_ids = list(dict.fromkeys(payload.target_ids))
    # (#273) Deleted and deactivated targets drop out of the selection here
    # rather than failing the whole batch: the caller sent a list of ids,
    # possibly from a stale page, and one switched-off repo in it shouldn't
    # cancel the rollout for the other forty. Same silent-drop shape this
    # endpoint already uses for ids the caller can't see (see the loop
    # below), and the 403 at the end still fires if nothing is left.
    targets = session.exec(
        target_lifecycle.scannable_targets(select(Target)).where(Target.id.in_(unique_ids))
    ).all()
    targets_by_id = {t.id: t for t in targets}

    eligible_ids: list[int] = []
    for tid in unique_ids:
        target = targets_by_id.get(tid)
        if not target:
            continue
        if ws_ids is not None and target.workspace_id not in ws_ids:
            continue
        if not _caller_can_integrate(session, user, target):
            continue
        eligible_ids.append(tid)

    if not eligible_ids:
        raise HTTPException(status_code=403, detail="no accessible targets with sufficient role in the selection")

    template = None
    if payload.workflow_template_id is not None:
        template = session.get(PipelineWorkflowTemplate, payload.workflow_template_id)
        if not template:
            raise HTTPException(status_code=404, detail="pipeline workflow template not found")
        if ws_ids is not None and template.workspace_id not in ws_ids:
            raise HTTPException(status_code=404, detail="pipeline workflow template not found")

    batch = PipelineIntegrationBatch(
        created_by_user_id=user.id,
        total=len(eligible_ids),
        status="running",
        force=payload.force,
        workflow_template_id=template.id if template else None,
    )
    session.add(batch)
    session.commit()
    session.refresh(batch)

    for tid in eligible_ids:
        session.add(PipelineIntegrationBatchItem(batch_id=batch.id, target_id=tid, status="pending"))
    session.commit()

    run_pipeline_integration_batch.delay(batch_id=batch.id)

    return JSONResponse(
        status_code=202,
        content={"batch_id": batch.id, "total": batch.total, "status": batch.status},
    )


@router.get("/bulk-pipeline-integrate/{batch_id}")
def get_bulk_pipeline_integrate_batch(
    batch_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    """Poll target for the async batch dispatched by POST above. Item
    detail is workspace-scoped the same way as everything else in this
    file, items for targets outside the caller's accessible workspaces
    (relevant if role/membership changed after the batch was created) are
    left out of the returned items list."""
    batch = session.get(PipelineIntegrationBatch, batch_id)
    if not batch:
        raise HTTPException(status_code=404, detail="batch not found")
    mark_stale_if_needed(session, batch)

    ws_ids = accessible_workspace_ids(session, user)
    items = session.exec(
        select(PipelineIntegrationBatchItem).where(PipelineIntegrationBatchItem.batch_id == batch_id)
    ).all()
    target_ids = [i.target_id for i in items]
    targets_by_id = {t.id: t for t in session.exec(select(Target).where(Target.id.in_(target_ids))).all()}

    item_payload = []
    for item in items:
        target = targets_by_id.get(item.target_id)
        if target and ws_ids is not None and target.workspace_id not in ws_ids:
            continue
        item_payload.append(
            {
                "target_id": item.target_id,
                "target_name": target.name if target else None,
                "repo_url": target.repo_url if target else None,
                "status": item.status,
                "error": item.error,
                "pr_url": item.pr_url,
                "pr_number": item.pr_number,
                "completed_at": item.completed_at,
            }
        )

    return {
        "batch_id": batch.id,
        "status": batch.status,
        "total": batch.total,
        "succeeded": batch.succeeded,
        "failed": batch.failed,
        "already_integrated": batch.already_integrated,
        # #245's double-scan gap: how many items run_pipeline_integration_batch
        # skipped because server-side PR Guardrail already covers this
        # deployment's PRs, and whether this batch opted into the
        # redundancy anyway (force=true on the request that created it).
        "skipped_webhook_reachable": batch.skipped_webhook_reachable,
        "force": batch.force,
        "started_at": batch.started_at,
        "completed_at": batch.completed_at,
        "items": item_payload,
        # "" for #68's original manual-selection batches; set for #35's
        # scope-based mass rollout (see mass_pipeline_rollout below).
        "scope_label": batch.scope_label,
        "workflow_template_id": batch.workflow_template_id,
    }


class MassPipelineRolloutRequest(BaseModel):
    """Issue #35 (Mass CI/CD Rollout Engine): resolve an entire *scope*
    (a workspace, a repo Group, or every repo the caller can see) into a
    target set instead of requiring an explicit checkbox selection like
    #68's bulk_pipeline_integrate above, the "fleet-wide" part of the
    issue. `workflow_template_id` is the Custom Workflow Builder half:
    optionally use a saved PipelineWorkflowTemplate's step list instead of
    #66's fixed default scanner set for every item in this rollout."""

    scope: str
    workspace_id: int | None = None
    group_id: int | None = None
    workflow_template_id: int | None = None
    # (#245's double-scan gap) Same escape hatch as bulk_pipeline_integrate's;
    # see BulkPipelineIntegrateRequest.force.
    force: bool = False

    @field_validator("scope")
    @classmethod
    def _check_scope(cls, v: str) -> str:
        if v not in ("workspace", "group", "all"):
            raise ValueError("scope must be one of 'workspace', 'group', 'all'")
        return v


@router.post("/mass-pipeline-rollout")
def mass_pipeline_rollout(
    payload: MassPipelineRolloutRequest,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    """Issue #35: scope-based sibling to #68's bulk_pipeline_integrate.
    Resolves `payload.scope` into a target_id set fleet-wide (instead of an
    explicit target_ids list), applies the exact same per-target
    eligibility bar as the manual bulk flow (_caller_can_integrate:
    DEVELOPER+ on the target's workspace), then reuses #68's
    PipelineIntegrationBatch/BatchItem tracking rows and
    run_pipeline_integration_batch Celery task verbatim; the only new
    pieces are scope resolution and an optional workflow_template_id
    (Custom Workflow Builder) recorded on the batch so the task generates
    each item's YAML from that template's step list (see
    app.tasks.pipeline_tasks) instead of #66's fixed default set.
    """
    ws_ids = accessible_workspace_ids(session, user)

    # (#273) Every scope below resolves through scannable_targets: this is
    # the fleet-wide path, so it is the one place where a single missed
    # predicate silently pipelines *every* deactivated repo in an org at
    # once. Applied at the query rather than filtered out of `candidates`
    # afterwards so a future fourth scope can't forget it.
    scannable = target_lifecycle.scannable_targets(select(Target))

    if payload.scope == "workspace":
        if payload.workspace_id is None:
            raise HTTPException(status_code=400, detail="workspace_id is required for scope='workspace'")
        if ws_ids is not None and payload.workspace_id not in ws_ids:
            raise HTTPException(status_code=404, detail="workspace not found")
        workspace = session.get(Workspace, payload.workspace_id)
        if not workspace:
            raise HTTPException(status_code=404, detail="workspace not found")
        candidates = session.exec(scannable.where(Target.workspace_id == payload.workspace_id)).all()
        scope_label = f"Workspace: {workspace.name}"
    elif payload.scope == "group":
        if payload.group_id is None:
            raise HTTPException(status_code=400, detail="group_id is required for scope='group'")
        group = session.get(Group, payload.group_id)
        if not group:
            raise HTTPException(status_code=404, detail="group not found")
        if ws_ids is not None and group.workspace_id not in ws_ids:
            raise HTTPException(status_code=404, detail="group not found")
        member_ids = session.exec(
            select(TargetGroup.target_id).where(TargetGroup.group_id == payload.group_id)
        ).all()
        candidates = (
            session.exec(scannable.where(Target.id.in_(member_ids))).all() if member_ids else []
        )
        scope_label = f"Group: {group.name}"
    else:  # "all", every target across every accessible workspace (or literally all, for an admin)
        query = scannable
        if ws_ids is not None:
            candidates = session.exec(query.where(Target.workspace_id.in_(ws_ids))).all() if ws_ids else []
        else:
            candidates = session.exec(query).all()
        scope_label = "All accessible repositories"

    template = None
    if payload.workflow_template_id is not None:
        template = session.get(PipelineWorkflowTemplate, payload.workflow_template_id)
        if not template:
            raise HTTPException(status_code=404, detail="pipeline workflow template not found")
        if ws_ids is not None and template.workspace_id not in ws_ids:
            raise HTTPException(status_code=404, detail="pipeline workflow template not found")

    eligible_ids = [t.id for t in candidates if _caller_can_integrate(session, user, t)]
    if not eligible_ids:
        raise HTTPException(status_code=404, detail="no accessible, eligible targets found for this scope")

    batch = PipelineIntegrationBatch(
        created_by_user_id=user.id,
        total=len(eligible_ids),
        status="running",
        scope_label=scope_label,
        workflow_template_id=template.id if template else None,
        force=payload.force,
    )
    session.add(batch)
    session.commit()
    session.refresh(batch)

    for tid in eligible_ids:
        session.add(PipelineIntegrationBatchItem(batch_id=batch.id, target_id=tid, status="pending"))
    session.commit()

    run_pipeline_integration_batch.delay(batch_id=batch.id)

    return JSONResponse(
        status_code=202,
        content={
            "batch_id": batch.id,
            "total": batch.total,
            "status": batch.status,
            "scope_label": batch.scope_label,
        },
    )


@router.get("/{target_id}/groups")
def list_target_groups(target_id: int, session: Session = Depends(get_session), user: User = Depends(current_user)):
    target = _live_target(session, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="target not found")
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and target.workspace_id not in ws_ids:
        raise HTTPException(status_code=404, detail="target not found")
    return _groups_by_target(session, [target_id]).get(target_id, [])


@router.post("/{target_id}/groups/{group_id}")
def assign_target_group(
    target_id: int,
    group_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(require_workspace_role(WorkspaceRole.DEVELOPER)),
):
    target = _live_target(session, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="target not found")
    group = session.get(Group, group_id)
    if not group:
        raise HTTPException(status_code=404, detail="group not found")
    if group.workspace_id != target.workspace_id:
        # A group only makes sense scoped to the same workspace its targets
        # live in, otherwise a caller with developer access to workspace A
        # could tag a workspace-B target with a workspace-A group, leaking
        # naming/existence across the workspace boundary #57 exists to draw.
        raise HTTPException(status_code=400, detail="group and target must belong to the same workspace")
    existing = session.exec(
        select(TargetGroup).where(TargetGroup.target_id == target_id, TargetGroup.group_id == group_id)
    ).first()
    if not existing:
        session.add(TargetGroup(target_id=target_id, group_id=group_id))
        session.commit()
    return _groups_by_target(session, [target_id]).get(target_id, [])


@router.delete("/{target_id}/groups/{group_id}")
def remove_target_group(
    target_id: int,
    group_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(require_workspace_role(WorkspaceRole.DEVELOPER)),
):
    target = _live_target(session, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="target not found")
    link = session.exec(
        select(TargetGroup).where(TargetGroup.target_id == target_id, TargetGroup.group_id == group_id)
    ).first()
    if link:
        session.delete(link)
        session.commit()
    return _groups_by_target(session, [target_id]).get(target_id, [])
