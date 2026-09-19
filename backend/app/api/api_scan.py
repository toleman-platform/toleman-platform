import re
import httpx
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator
from sqlmodel import Session, select

from app.api.auth import accessible_workspace_ids, current_user, require_workspace_role
from app.api.deps import get_session
from app.core.api_scan_targets import ApiScanConfigError, build_scan_headers, build_scan_urls
from app.core.crypto import encrypt_secret
from app.core.tool_usage import is_nuclei_enabled_for_api_scan
from app.core.async_jobs import create_running_row
from app.core.staleness import mark_stale_if_needed
from app.core import target_lifecycle
from app.models.models import Scan, Target, User, WorkspaceRole
from app.tasks.api_scan_tasks import run_api_scan

router = APIRouter(prefix="/api/api-scan", tags=["api-scan"])


def _get_target(target_id: int, session: Session) -> Target:
    target = session.get(Target, target_id)
    # (#273) Soft-deleted targets 404 everywhere in the product. Deactivation
    # is not checked here: this helper also backs the read-only
    # GET /{target_id}/latest, and a deactivated target's last scan result
    # stays readable -- that is the difference between deactivate and delete.
    if not target or target_lifecycle.is_deleted(target):
        raise HTTPException(status_code=404, detail="target not found")
    return target


class RunApiScanRequest(BaseModel):
    # None = scan every endpoint discovered for this target's default
    # branch; a list narrows to a specific selection (e.g. checkboxes in
    # the UI). Ids that don't belong to this target+branch are silently
    # dropped by app.core.api_scan_targets.build_scan_urls, never used to
    # reach into another target's endpoints.
    endpoint_ids: list[int] | None = None


@router.post("/{target_id}")
def trigger_api_scan(
    target_id: int,
    payload: RunApiScanRequest = RunApiScanRequest(),
    session: Session = Depends(get_session),
    user: User = Depends(require_workspace_role(WorkspaceRole.DEVELOPER)),
):
    """Issue #72: dispatch an active API scan (nuclei) against endpoints
    already discovered for this target (Sprint 1's API Discovery). Async,
    same POST-creates-tracking-row-and-.delay()s pattern as
    POST /api/scans/run, creates a Scan row (tool="api-scan",
    status="running") and returns its id immediately; poll
    GET /api/scans/{scan_id} until status leaves "running".

    Refuses outright (400, before any Scan row or Celery task exists) if
    the target has no api_base_url configured or has zero scannable
    endpoints for its current selection; this is active scanning against
    a real network endpoint, so it must fail loud and immediately on
    obviously-unscannable input rather than silently creating a scan that
    can only ever fail once a worker picks it up.
    """
    target = _get_target(target_id, session)
    # (#273) Checked first, before every other refusal in this handler:
    # active API scanning sends real traffic at a real deployed host, so
    # "this target is switched off" has to win over any question about
    # whether the scan would otherwise be well-formed.
    refusal = target_lifecycle.scan_refusal_reason(target)
    if refusal:
        raise HTTPException(status_code=409, detail=refusal)
    # (#232) The one and only surface check for Active API Scanning; see
    # is_nuclei_enabled_for_api_scan's docstring for why this can't go
    # through tools_for_surface like the other three surfaces do. Checked
    # before build_scan_urls below (which can be a slower DB-and-validation
    # path) so a workspace that has explicitly turned this off gets an
    # immediate, specific answer rather than the generic "no scannable
    # endpoints"; a different failure mode that would otherwise look
    # identical to a target with no discovered endpoints yet.
    if not is_nuclei_enabled_for_api_scan(session, target.workspace_id):
        raise HTTPException(
            status_code=400,
            detail="Active API scanning (nuclei) is disabled for this workspace; enable it in Tool Marketplace",
        )
    try:
        scope = build_scan_urls(session, target, payload.endpoint_ids)
        urls, endpoints = scope.urls, scope.endpoints
    except ApiScanConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not urls:
        # Distinguish "nothing discovered" from "everything discovered is
        # out of scope". They look identical from a zero-URL list and lead
        # an operator to completely different next actions: run discovery,
        # versus review the exclusions they themselves set.
        if scope.skipped:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"no scannable endpoints: all {len(scope.skipped)} discovered "
                    "endpoint(s) are out of scope for this scan"
                ),
            )
        raise HTTPException(
            status_code=400,
            detail="no scannable endpoints; run API Discovery first, or check the endpoint selection",
        )

    scan = create_running_row(
        session, Scan(target_id=target_id, tool="api-scan", branch=target.default_branch, status="running")
    )

    run_api_scan.delay(target_id=target_id, scan_id=scan.id, endpoint_ids=payload.endpoint_ids)

    return JSONResponse(
        status_code=202,
        content={
            "scan_id": scan.id,
            "target_id": target_id,
            "status": scan.status,
            "endpoint_count": len(endpoints),
            # Surfaced so the UI can say what was left alone and why,
            # rather than showing a smaller number with no explanation.
            "skipped": [
                {"endpoint_id": s.endpoint.id, "method": s.endpoint.method, "route": s.endpoint.route, "reason": s.reason}
                for s in scope.skipped
            ],
        },
    )


@router.get("/{target_id}/latest")
def get_latest_api_scan(target_id: int, session: Session = Depends(get_session), user: User = Depends(current_user)):
    """Most recent tool="api-scan" Scan row for this target, so the frontend
    can show 'last scanned' state on page load without holding a scan_id in
    client state across a reload; same rationale as discovery/sbom's
    persisted-GET pattern, just backed by the shared Scan table instead of a
    dedicated *Run model, since active-scan results reuse the normal Finding
    table (tool="api-scan") rather than a bespoke schema."""
    target = _get_target(target_id, session)
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and target.workspace_id not in ws_ids:
        raise HTTPException(status_code=404, detail="target not found")

    scan = session.exec(
        select(Scan)
        .where(Scan.target_id == target_id, Scan.tool == "api-scan")
        .order_by(Scan.started_at.desc())
    ).first()
    if not scan:
        return {"target_id": target_id, "scan": None}
    mark_stale_if_needed(session, scan)
    return {
        "target_id": target_id,
        "scan": {
            "scan_id": scan.id,
            "target_id": scan.target_id,
            "tool": scan.tool,
            "branch": scan.branch,
            "status": scan.status,
            "findings_count": scan.findings_count,
            "started_at": scan.started_at,
            "completed_at": scan.completed_at,
            "error_message": scan.error,
        },
    }


# Header names are a restricted token grammar (RFC 9110 field-name), and a
# name carrying CR/LF or a colon would let a caller inject a second header
# into the config file this ends up in. Kept narrow deliberately: every
# real auth header name is letters, digits and hyphens.
_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")


class SetApiScanCredentialRequest(BaseModel):
    header_name: str
    header_value: str

    @field_validator("header_name")
    @classmethod
    def _check_name(cls, v: str) -> str:
        v = v.strip()
        if not _HEADER_NAME_RE.match(v):
            raise ValueError("header_name must be 1-64 characters of letters, digits or hyphens")
        return v

    @field_validator("header_value")
    @classmethod
    def _check_value(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("header_value must not be blank")
        if "\n" in v or "\r" in v:
            raise ValueError("header_value must not contain newlines")
        return v.strip()


@router.get("/{target_id}/credential")
def get_api_scan_credential(
    target_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(current_user),
):
    """Whether a credential is configured, and under which header name.

    Never returns the value, not even to the person who set it, and not
    masked: a mask still confirms length. The only operations on a stored
    credential are replace and clear.
    """
    target = _get_target(target_id, session)
    # Unlike the sibling PUT/DELETE/test endpoints below (all gated on
    # require_workspace_role) and get_latest_api_scan above (which checks
    # accessible_workspace_ids), this GET had no workspace check at all --
    # any authenticated user could learn whether another tenant's target has
    # an API-scan credential configured and its header name.
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and target.workspace_id not in ws_ids:
        raise HTTPException(status_code=404, detail="target not found")
    return {
        "target_id": target.id,
        "configured": bool(target.api_auth_header_name and target.api_auth_header_value_ciphertext),
        "header_name": target.api_auth_header_name,
    }


@router.put("/{target_id}/credential")
def set_api_scan_credential(
    target_id: int,
    payload: SetApiScanCredentialRequest,
    session: Session = Depends(get_session),
    user: User = Depends(require_workspace_role(WorkspaceRole.DEVELOPER)),
):
    """Store the credential the active scanner presents for this target.

    DEVELOPER, the same bar as triggering a scan: this decides what
    authority the scanner's traffic carries.
    """
    target = _get_target(target_id, session)
    target.api_auth_header_name = payload.header_name
    target.api_auth_header_value_ciphertext = encrypt_secret(payload.header_value)
    session.add(target)
    session.commit()
    return {"target_id": target.id, "configured": True, "header_name": target.api_auth_header_name}


@router.delete("/{target_id}/credential")
def clear_api_scan_credential(
    target_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(require_workspace_role(WorkspaceRole.DEVELOPER)),
):
    """Remove the credential. Scans go back to anonymous, which is a
    supported mode, not an error -- so this does not disable scanning."""
    target = _get_target(target_id, session)
    target.api_auth_header_name = None
    target.api_auth_header_value_ciphertext = None
    session.add(target)
    session.commit()
    return {"target_id": target.id, "configured": False, "header_name": None}


@router.post("/{target_id}/credential/test")
def test_api_scan_credential(
    target_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(require_workspace_role(WorkspaceRole.DEVELOPER)),
):
    """Make one request with the stored credential and report whether it
    was accepted.

    This exists because the failure it catches is silent. A wrong or
    expired token makes every authenticated route answer 401, and the scan
    still completes and still reports zero findings -- which reads as a
    clean API rather than as a scan that never got in. An operator needs to
    find that out here, deliberately, rather than from a green result.

    Sends exactly one GET at the target's own configured api_base_url, the
    same host boundary every other part of active scanning uses; never a
    caller-supplied URL, and never one of the discovered routes, which
    could be destructive.
    """
    target = _get_target(target_id, session)
    if not target.api_base_url:
        raise HTTPException(status_code=400, detail="target has no api_base_url configured")
    try:
        headers = build_scan_headers(target)
    except ApiScanConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not headers:
        raise HTTPException(status_code=400, detail="no credential is configured for this target")

    try:
        response = httpx.get(target.api_base_url, headers=headers, timeout=10, follow_redirects=False)
    except httpx.HTTPError as exc:
        # str(exc) is httpx's own message about the connection, never the
        # request headers, so this cannot echo the credential back.
        raise HTTPException(status_code=502, detail=f"could not reach {target.api_base_url}: {exc}")

    rejected = response.status_code in (401, 403)
    return {
        "target_id": target.id,
        "status_code": response.status_code,
        "accepted": not rejected,
        "detail": (
            "the API rejected this credential; scans would test the login wall, not the API"
            if rejected
            else "the API did not reject this credential"
        ),
    }
