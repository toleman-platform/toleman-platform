"""`GET /api/tools/health`: the original Sprint 1 health check.

Kept for backwards compatibility with the original Sprint 1 shape (the
frontend's existing ToolsHealth component, and any external caller relying
on it); registry.py's `/registry` supersedes it for the marketplace page,
but there is no reason to break this one.

`_check_one` is the shared subprocess `--version` check reused by
registry.py; the two endpoints check the same thing (is this binary
present and does it answer), just over different tool sets.

VERSION_COMMANDS used to be its own hand-maintained 4-entry dict (semgrep,
gitleaks, trivy, gosec: the original Sprint 1 set), independent of
app.core.tool_registry.TOOL_REGISTRY. Installing checkov, tfsec, modelscan
or noseyparker from the marketplace made them run real scans and produce
real findings, but there was no code path that could ever show them here:
this endpoint's tool set was fixed at Sprint 1 and the registry's was not,
so the two silently diverged the moment #75 added a fifth tool. Deriving
this dict from the registry's own `version_cmd` (already carried by every
entry, for exactly this probe) makes that drift structurally impossible:
whatever /registry can install or list, /health can check.
"""
import shutil
import subprocess
import time

from fastapi import APIRouter

from app.core.tool_registry import TOOL_REGISTRY

router = APIRouter()

# `.get(...)`, not `entry["version_cmd"]`: every entry today carries one,
# but this endpoint would rather silently skip a future registry addition
# that ships without one than 500 the whole page over it. A tool missing
# here for that reason still renders honestly on the frontend (ToolsHealth
# unions its known-tools list against whatever this actually returns, and
# treats an absent tool as "not checked", never as a confident failure).
VERSION_COMMANDS = {entry["tool"]: entry["version_cmd"] for entry in TOOL_REGISTRY if entry.get("version_cmd")}


def _check_one(tool: str, cmd: list[str], checked_in: str = "api") -> dict:
    """`checked_in` records which process ran the probe, "api" (this web
    process) or "worker" (the Celery worker).

    This is not bookkeeping. Finding CTX-03: one-click install runs on the
    Celery worker, the health probe ran `shutil.which()` inside the *backend*
    process, and those are separate containers in the default Compose
    topology. A successful Checkov install (version 3.3.13, `which checkov`
    resolving fine in the worker) showed permanently as "not installed" on
    the marketplace card, even after "Recheck all". The card was answering a
    question nobody asked ("is it installed next to the web server")
    while every scan runs on the worker.
    """
    binary_path = shutil.which(cmd[0])
    if not binary_path:
        return {"tool": tool, "installed": False, "version": None, "response_ms": None, "checked_in": checked_in}

    start = time.monotonic()
    try:
        # cmd is one of the fixed VERSION_COMMANDS argv lists above, no shell,
        # no interpolated input.
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit
        elapsed_ms = round((time.monotonic() - start) * 1000)
        output = (proc.stdout or proc.stderr).strip().splitlines()
        version = output[0] if output else "unknown"
        return {
            "tool": tool,
            "installed": True,
            "version": version,
            "response_ms": elapsed_ms,
            "checked_in": checked_in,
        }
    except (subprocess.TimeoutExpired, OSError):
        return {"tool": tool, "installed": True, "version": None, "response_ms": None, "checked_in": checked_in}


@router.get("/health")
def tools_health():
    """Real version + reachability check for every tool in the registry, no
    simulated status. Every registry tool, not just the original Sprint 1
    four, because VERSION_COMMANDS above is now derived from the registry
    itself. See /registry for the full tool marketplace (issue #75), which
    runs this identical probe plus a cache and the CTX-03 worker-visibility
    merge; this endpoint stays deliberately uncached and api-only, since its
    job is a plain answer for the process actually serving the request, not
    the marketplace's fuller picture."""
    return [_check_one(tool, cmd) for tool, cmd in VERSION_COMMANDS.items()]
