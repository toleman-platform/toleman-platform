"""`GET /api/tools/health`: the original Sprint 1 health check.

Kept for backwards compatibility with the original Sprint 1 shape (the
frontend's existing ToolsHealth component, and any external caller relying
on it); registry.py's `/registry` supersedes it for the marketplace page,
but there is no reason to break this one.

`_check_one` is the shared subprocess `--version` check reused by
registry.py; the two endpoints check the same thing (is this binary
present and does it answer), just over different tool sets.
"""
import shutil
import subprocess
import time

from fastapi import APIRouter

router = APIRouter()

VERSION_COMMANDS = {
    "semgrep": ["semgrep", "--version"],
    "gitleaks": ["gitleaks", "version"],
    "trivy": ["trivy", "--version"],
    "gosec": ["gosec", "--version"],
}


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
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
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
    """Real version + reachability check for each of the 4 originally
    integrated scanners, no simulated status. See /registry for the full
    tool marketplace (issue #75), which includes this same live check for
    every registered tool, not just these four."""
    return [_check_one(tool, cmd) for tool, cmd in VERSION_COMMANDS.items()]
