"""`POST /api/tools/{tool}/install` + `GET /api/tools/installs/{id}` --
admin-only one-click install (issue #216).

The endpoint takes a **registry key**, never a package name, so a caller
can only choose from app.core.tool_registry -- see that module's docstring
and app.core.tool_install for the full argument about why this is not the
"shell out to a package manager from a web request" surface #75 declined to
build.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select

from app.api.auth import require_admin
from app.api.deps import get_session
from app.core import tool_install
from app.core.async_jobs import create_running_row
from app.core.rate_limit import enforce_rate_limit
from app.core.staleness import mark_stale_if_needed
from app.models.models import ToolInstallRun, User
from app.tasks.tool_install_tasks import run_tool_install

router = APIRouter()

# Each request runs pip against a real package index and can pull a large
# dependency tree, so this is tighter than plain API reads -- enough for an
# admin kitting out a fresh deployment, not enough to hammer the worker pool.
TOOL_INSTALL_RATE_LIMIT = 6
TOOL_INSTALL_RATE_WINDOW_SECONDS = 300


def _install_run_out(run: ToolInstallRun) -> dict:
    return {
        "run_id": run.id,
        "tool": run.tool,
        "package": run.package,
        "status": run.status,
        "started_at": run.started_at.isoformat() + "Z",
        "completed_at": run.completed_at.isoformat() + "Z" if run.completed_at else None,
        "installed_version": run.installed_version,
        "error": run.error,
        "output_tail": run.output_tail,
    }


@router.get("/installs/active")
def active_installs(
    session: Session = Depends(get_session),
    user: User = Depends(require_admin),
):
    """Every tool install currently running, keyed by registry key.

    Finding CTX-03's second half: useToolInstall held the spinner in local
    React state, so navigating away during an install and coming back offered
    a fresh "Install" button while the job was still running on the worker.
    Same class of bug as CTX-02 on PR History, and the same fix -- the server
    knows what is in flight, so the card can render it without having been
    the thing that started it.

    Declared before /installs/{run_id} because FastAPI matches routes in
    declaration order, and "active" would otherwise be captured as a run_id
    and 422 on int coercion.
    """
    running = session.exec(
        select(ToolInstallRun).where(ToolInstallRun.status == "running")
    ).all()

    out = {}
    for run in running:
        # A worker that died mid-install leaves this "running" forever, which
        # renders as a permanently spinning card -- indistinguishable from a
        # very slow install of a big dependency tree.
        if mark_stale_if_needed(session, run):
            continue
        out[run.tool] = _install_run_out(run)
    return out


@router.post("/{tool}/install", status_code=202)
def install_tool(
    tool: str,
    session: Session = Depends(get_session),
    user: User = Depends(require_admin),
):
    """Install a registry tool into the running environment (#216).

    Admin-only, and the allowlist is the real control: `tool` is a registry
    key, and `resolve_package` returns None for anything not in
    TOOL_REGISTRY or not pip-installable. There is no path from this request
    to a package name of the caller's choosing.

    Returns 202 with a run id; poll GET /api/tools/installs/{id}, same
    dispatch-then-poll shape as scans (#59).
    """
    package = tool_install.resolve_package(tool)
    if package is None:
        # One message for both "unknown tool" and "needs brew/go/docker": an
        # admin gets the useful detail from the registry entry in the UI, and
        # the endpoint does not enumerate what does or does not exist.
        raise HTTPException(
            status_code=400,
            detail=f"{tool!r} cannot be installed from here -- see its install command in the marketplace",
        )

    enforce_rate_limit(
        key=f"tool_install:user:{user.id}",
        limit=TOOL_INSTALL_RATE_LIMIT,
        window_seconds=TOOL_INSTALL_RATE_WINDOW_SECONDS,
    )

    run = create_running_row(
        session,
        ToolInstallRun(
            tool=tool,
            package=package,
            status="running",
            # This row is the audit record for an action that mutates the
            # running environment, so the actor is recorded, not inferred
            # later.
            requested_by_user_id=user.id,
        ),
    )

    run_tool_install.delay(run_id=run.id)
    return _install_run_out(run)


@router.get("/installs/{run_id}")
def get_install_run(
    run_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(require_admin),
):
    """Poll target for POST /{tool}/install."""
    run = session.get(ToolInstallRun, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="install run not found")
    # A worker that died mid-install would otherwise leave this "running"
    # forever, which is indistinguishable from a slow install (#153, #212).
    mark_stale_if_needed(session, run, message="Install timed out: no update received from the worker")
    return _install_run_out(run)
