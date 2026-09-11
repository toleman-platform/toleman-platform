"""Issue #109: the public API, versioned, token-authenticated
(`Authorization: Bearer <token>`, see app.api.auth.current_api_token_user),
for third-party/scripted integrations. Distinct from the internal `/api/*`
routers the frontend calls (session-cookie authenticated).

v1 is deliberately a curated read-mostly surface (targets/findings/scans)
plus one write endpoint (trigger a scan, gated by a read_write-scoped
token) rather than exposing every internal endpoint; narrower surface to
secure and keep stable across internal refactors. `/api/public/v1` so a
breaking v2 can exist alongside v1 rather than forcing every integration
to update in lockstep.
"""
import json
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlmodel import Session, select

from app.api.auth import accessible_workspace_ids, current_api_token_user, require_api_token_write_scope
from app.api.deps import get_session
from app.core.async_jobs import create_running_row
from app.core.autofix import AutofixError, Patch, open_fix_pr, suggest_fix
from app.core.mcp_audit import log_mcp_action
from app.core.rate_limit import enforce_rate_limit
from app.models.models import Finding, Scan, SnippetScanRun, Target, User
from app.scanners import parsers
from app.core.tool_usage import tools_for_surface
from app.tasks.scan_tasks import run_scan
from app.tasks.snippet_scan_tasks import run_snippet_scan

router = APIRouter(prefix="/api/public/v1", tags=["public-api"])

PARSER_MAP = parsers.PARSER_MAP


def mcp_agent(request: Request) -> str:
    """Best-effort caller-*software* identity (not a person -- `user` above
    already identifies who). Forwarded by mcp-server as the X-MCP-Agent
    header (see server.py's _resolve_agent for why it can't be read off
    the MCP session itself in streamable-http mode); "unknown" for a bare
    API-token script that isn't the MCP server at all."""
    return request.headers.get("x-mcp-agent", "unknown")


def _get_target_scoped(target_id: int, session: Session, user: User) -> Target:
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="target not found")
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and target.workspace_id not in ws_ids:
        raise HTTPException(status_code=404, detail="target not found")
    return target


@router.get("/targets")
def list_targets(
    session: Session = Depends(get_session),
    user: User = Depends(current_api_token_user),
    agent: str = Depends(mcp_agent),
):
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and not ws_ids:
        targets = []
    else:
        query = select(Target)
        if ws_ids is not None:
            query = query.where(Target.workspace_id.in_(ws_ids))
        targets = session.exec(query).all()
    log_mcp_action(session, user, agent=agent, tool="list_targets", summary=f"listed {len(targets)} target(s)")
    return targets


@router.get("/targets/{target_id}")
def get_target(
    target_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(current_api_token_user),
    agent: str = Depends(mcp_agent),
):
    target = _get_target_scoped(target_id, session, user)
    log_mcp_action(
        session, user, agent=agent, tool="get_target", summary=f"viewed target: {target.name}", target_id=target.id
    )
    return target


@router.get("/findings")
def list_findings(
    target_id: int | None = None,
    severity: str | None = None,
    state: str | None = None,
    page: int = 1,
    page_size: int = 25,
    session: Session = Depends(get_session),
    user: User = Depends(current_api_token_user),
    agent: str = Depends(mcp_agent),
):
    ws_ids = accessible_workspace_ids(session, user)
    if ws_ids is not None and not ws_ids:
        result = {"items": [], "total": 0}
    else:
        query = select(Finding)
        if ws_ids is not None:
            query = query.join(Target, Target.id == Finding.target_id).where(Target.workspace_id.in_(ws_ids))
        if target_id is not None:
            query = query.where(Finding.target_id == target_id)
        if severity is not None:
            query = query.where(Finding.severity == severity)
        if state is not None:
            query = query.where(Finding.state == state)

        total = len(session.exec(query).all())
        page_size = max(1, min(page_size, 100))
        items = session.exec(query.offset((max(page, 1) - 1) * page_size).limit(page_size)).all()
        result = {"items": items, "total": total}
    filters = ", ".join(
        f"{k}={v}" for k, v in [("target_id", target_id), ("severity", severity), ("state", state)] if v is not None
    )
    log_mcp_action(
        session, user, agent=agent, tool="list_findings",
        summary=f"listed findings ({filters or 'no filters'}) -> {result['total']} total",
        target_id=target_id,
    )
    return result


@router.get("/findings/{finding_id}")
def get_finding(
    finding_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(current_api_token_user),
    agent: str = Depends(mcp_agent),
):
    finding = session.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="finding not found")
    # A finding has no workspace_id of its own, scope via its target,
    # same 404-shaped hiding as every other workspace-owned resource.
    _get_target_scoped(finding.target_id, session, user)
    log_mcp_action(
        session, user, agent=agent, tool="get_finding", summary=f"viewed finding #{finding.id}: {finding.title}",
        target_id=finding.target_id, finding_id=finding.id,
    )
    return finding


@router.get("/scans/{scan_id}")
def get_scan(
    scan_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(current_api_token_user),
    agent: str = Depends(mcp_agent),
):
    scan = session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")
    _get_target_scoped(scan.target_id, session, user)
    log_mcp_action(
        session, user, agent=agent, tool="get_scan_status",
        summary=f"checked scan #{scan.id} status: {scan.status}", target_id=scan.target_id,
    )
    return scan


# Same limit as the internal POST /api/scans/run, a public-API token
# dispatching scans still clones+shells a scanner subprocess per call, the
# rate concern this limit exists for doesn't change based on caller type.
SCAN_RUN_RATE_LIMIT = 10
SCAN_RUN_RATE_WINDOW_SECONDS = 60


@router.post("/scans")
def trigger_scan(
    target_id: int,
    tool: str,
    session: Session = Depends(get_session),
    user: User = Depends(current_api_token_user),
    _write_scope: None = Depends(require_api_token_write_scope),
    agent: str = Depends(mcp_agent),
):
    """Requires a read_write-scoped token (see require_api_token_write_scope);
    the default token scope is read-only, so a caller must have
    deliberately requested write access at token-creation time."""
    enforce_rate_limit(
        key=f"public_api_scan_run:user:{user.id}",
        limit=SCAN_RUN_RATE_LIMIT,
        window_seconds=SCAN_RUN_RATE_WINDOW_SECONDS,
    )

    target = _get_target_scoped(target_id, session, user)
    if tool not in PARSER_MAP:
        raise HTTPException(status_code=400, detail=f"unsupported tool: {tool}")
    # (#232) Same gate as the internal POST /api/scans/run; an assignment
    # disabling a tool for on_demand_scan must hold regardless of which
    # authenticated caller is asking, or a public API token becomes a way to
    # route around a workspace's own configuration.
    if tool not in tools_for_surface(session, target.workspace_id, "on_demand_scan"):
        raise HTTPException(
            status_code=400, detail=f"{tool} is disabled for on-demand scanning in this workspace"
        )

    scan = Scan(target_id=target.id, tool=tool, branch=target.default_branch, status="running")
    session.add(scan)
    session.commit()
    session.refresh(scan)

    run_scan.delay(target_id=target.id, tool=tool, scan_id=scan.id)

    log_mcp_action(
        session, user, agent=agent, tool="trigger_scan",
        summary=f"triggered {tool} scan on target {target.name} (scan #{scan.id})", target_id=target.id,
    )
    return {"scan_id": scan.id, "status": scan.status}


# ---------------------------------------------------------------------------
# Autofix (issue #108 follow-up): the same suggest-fix/raise-pr split
# GET/POST /api/findings/{id}/suggest-fix and /raise-pr already expose to
# the frontend (see FindingSuggestFixResponse's docstring in
# app/api/findings.py for why this is two calls, not one) -- mirrored here
# so a public-API/MCP caller gets the identical capability: read a
# recommendation + diff first, only commit a PR on an explicit second call
# for the *exact* patch just shown, never a freshly-regenerated one.
# ---------------------------------------------------------------------------


class SuggestFixResponse(BaseModel):
    recommendation: str
    strategy: Literal["ai", "deterministic_sca"] | None = None
    diff: str | None = None
    file_path: str | None = None
    new_content: str | None = None
    ref: str | None = None
    explanation: str | None = None


class RaiseFixPrRequest(BaseModel):
    """strategy="mcp_client" covers a caller (typically Claude Code via the
    MCP server) that read the flagged file itself and wrote its own fix --
    see app.core.autofix's module docstring -- rather than replaying a
    patch a prior suggest-fix call returned."""
    file_path: str
    new_content: str
    ref: str
    strategy: Literal["ai", "deterministic_sca", "mcp_client"]
    explanation: str = ""


@router.post("/findings/{finding_id}/suggest-fix")
def suggest_fix_endpoint(
    finding_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(current_api_token_user),
    agent: str = Depends(mcp_agent),
) -> SuggestFixResponse:
    """Read-scoped: never writes anywhere, same permission level as every
    other GET-shaped endpoint on this router."""
    finding = session.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="finding not found")
    _get_target_scoped(finding.target_id, session, user)
    response = SuggestFixResponse(**suggest_fix(session, finding))
    log_mcp_action(
        session, user, agent=agent, tool="suggest_fix",
        summary=f"requested fix suggestion for finding #{finding.id}"
                + (f" (strategy={response.strategy})" if response.strategy else " (no patch built)"),
        target_id=finding.target_id, finding_id=finding.id,
    )
    return response


@router.post("/findings/{finding_id}/raise-pr")
def raise_fix_pr_endpoint(
    finding_id: int,
    payload: RaiseFixPrRequest,
    session: Session = Depends(get_session),
    user: User = Depends(current_api_token_user),
    _write_scope: None = Depends(require_api_token_write_scope),
    agent: str = Depends(mcp_agent),
) -> dict:
    """Requires a read_write-scoped token (writes a branch/PR to the
    target's real GitHub repo). `file_path` must match the finding's own
    file, same guard the internal endpoint applies, so this can only ever
    commit a fix to the file the finding actually points at."""
    finding = session.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="finding not found")
    target = _get_target_scoped(finding.target_id, session, user)
    if payload.file_path != finding.file_path:
        raise HTTPException(status_code=400, detail="file_path does not match this finding")

    patch = Patch(
        file_path=payload.file_path,
        old_content="",  # unused by open_fix_pr; only unified_diff() (suggest-fix) needs it
        new_content=payload.new_content,
        ref=payload.ref,
        strategy=payload.strategy,
        explanation=payload.explanation,
    )
    try:
        result = open_fix_pr(session, target, finding, patch)
    except AutofixError as exc:
        log_mcp_action(
            session, user, agent=agent, tool="raise_fix_pr",
            summary=f"failed to open PR for finding #{finding.id} (strategy={payload.strategy})",
            target_id=finding.target_id, finding_id=finding.id, success=False, error=str(exc),
        )
        raise HTTPException(status_code=502, detail=str(exc))

    log_mcp_action(
        session, user, agent=agent, tool="raise_fix_pr",
        summary=f"opened PR {result['pr_url']} for finding #{finding.id} (strategy={payload.strategy})",
        target_id=finding.target_id, finding_id=finding.id,
    )
    return result


# ---------------------------------------------------------------------------
# Snippet scan (issue #108 follow-up): "find vulns when it's getting
# written", not just after it's already committed -- scans a code snippet
# an MCP client hands over directly (e.g. Claude Code, mid-edit), no Target
# required. See app.tasks.snippet_scan_tasks and SnippetScanRun's own
# docstring for why this is async (create-row-then-.delay(), same as
# POST /scans above) and why nothing here is persisted as a real Finding.
# ---------------------------------------------------------------------------

# semgrep/semgrep-llm (SAST) and gitleaks (secrets) cover the common "did I
# just write something dangerous" case fast; trivy/noseyparker/modelscan are
# deliberately excluded (they want a real manifest/lockfile, a full git
# history, or a model file respectively -- meaningless against one arbitrary
# snippet, at best a guaranteed ToolNotApplicable). checkov/tfsec/trivy-
# license/gosec are still allowed on request (e.g. an agent writing a single
# Terraform/Go file), just not run by default.
DEFAULT_SNIPPET_TOOLS = ["semgrep", "gitleaks"]
ALLOWED_SNIPPET_TOOLS = {"semgrep", "semgrep-llm", "gitleaks", "checkov", "tfsec", "trivy-license", "gosec"}

# A real subprocess (semgrep/gitleaks) invocation per call, same rate-limit
# rationale as SCAN_RUN_RATE_LIMIT above; snippet scans are expected to be
# called far more often though (an agent checking as it writes), hence the
# higher ceiling.
SNIPPET_SCAN_RATE_LIMIT = 30
SNIPPET_SCAN_RATE_WINDOW_SECONDS = 60

# Keeps a runaway/malicious payload from tying up a worker slot or ballooning
# the Celery broker's message size; large enough for any single real source
# file.
MAX_SNIPPET_CONTENT_BYTES = 200_000


class ScanSnippetRequest(BaseModel):
    filename: str
    content: str
    tools: list[str] | None = None


class ScanSnippetFinding(BaseModel):
    tool: str
    rule_id: str
    title: str
    description: str
    file_path: str
    line_start: int | None = None
    line_end: int | None = None
    severity: str
    snippet: str


class ScanSnippetRunOut(BaseModel):
    id: int
    status: str
    filename: str
    findings: list[ScanSnippetFinding] | None = None
    error: str = ""


@router.post("/scan-snippet")
def create_snippet_scan(
    payload: ScanSnippetRequest,
    session: Session = Depends(get_session),
    user: User = Depends(current_api_token_user),
    agent: str = Depends(mcp_agent),
) -> dict:
    """Read-scoped: this never touches a real target/repo, so no elevated
    token scope is required, same reasoning as suggest-fix above."""
    enforce_rate_limit(
        key=f"public_api_scan_snippet:user:{user.id}",
        limit=SNIPPET_SCAN_RATE_LIMIT,
        window_seconds=SNIPPET_SCAN_RATE_WINDOW_SECONDS,
    )

    relative = payload.filename.lstrip("/")
    if not relative or ".." in Path(relative).parts:
        raise HTTPException(status_code=400, detail="invalid filename")
    if len(payload.content.encode("utf-8")) > MAX_SNIPPET_CONTENT_BYTES:
        raise HTTPException(
            status_code=400, detail=f"content too large (max {MAX_SNIPPET_CONTENT_BYTES} bytes)"
        )
    tools = payload.tools or DEFAULT_SNIPPET_TOOLS
    unknown = sorted(set(tools) - ALLOWED_SNIPPET_TOOLS)
    if unknown:
        raise HTTPException(status_code=400, detail=f"unsupported tool(s) for snippet scanning: {unknown}")

    run = create_running_row(
        session, SnippetScanRun(user_id=user.id, filename=payload.filename, status="running")
    )
    run_snippet_scan.delay(run_id=run.id, filename=payload.filename, content=payload.content, tools=tools)
    # Logged once here, not on GET /scan-snippet/{run_id} below -- the MCP
    # tool polls that endpoint in a loop until the run completes (see
    # mcp-server/server.py's check_code_for_vulnerabilities), and logging
    # every poll iteration would flood the audit trail with near-duplicate
    # rows for what is, from the caller's side, one action.
    log_mcp_action(
        session, user, agent=agent, tool="check_code_for_vulnerabilities",
        summary=f"submitted snippet scan for {payload.filename} (tools={', '.join(tools)})",
    )
    return {"run_id": run.id, "status": run.status}


@router.get("/scan-snippet/{run_id}")
def get_snippet_scan(
    run_id: int, session: Session = Depends(get_session), user: User = Depends(current_api_token_user)
) -> ScanSnippetRunOut:
    run = session.get(SnippetScanRun, run_id)
    # Owner-scoped, not workspace-scoped: this content was never associated
    # with any target/workspace at all, so the only real ownership boundary
    # is "the same user who submitted it" -- same as ApiToken itself.
    if not run or run.user_id != user.id:
        raise HTTPException(status_code=404, detail="snippet scan run not found")
    return ScanSnippetRunOut(
        id=run.id,
        status=run.status,
        filename=run.filename,
        findings=json.loads(run.findings_json) if run.status == "completed" else None,
        error=run.error,
    )
