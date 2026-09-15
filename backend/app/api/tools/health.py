"""`GET /api/tools/health`: the original Sprint 1 health check.

Kept for backwards compatibility with the original Sprint 1 shape (the
frontend's existing ToolsHealth component, and any external caller relying
on it); registry.py's `/registry` supersedes it for the marketplace page,
but there is no reason to break this one.

`_check_one` is the shared subprocess `--version` check reused by
registry.py, and `_merge_worker_health` the shared CTX-03 fold-in of what
the Celery worker reported; the two endpoints check the same thing (is this
binary present and does it answer), just over different tool sets.

Both helpers live here rather than in registry.py because registry.py
already imports from this module: keeping the dependency pointing one way
(registry -> health) is what makes sharing them acyclic.

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

from app.core import tool_health_cache
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


def _merge_worker_health(tool: str, local: dict) -> dict:
    """Fold in what the Celery worker reported, when this process can't see
    the tool itself (CTX-03).

    The probe above runs `shutil.which()` in *this* process. One-click
    installs run on the worker, which in the default Compose topology is a
    separate container; so a successful install was invisible here and the
    card read "not installed" forever, even after "Recheck all". Scans run on
    the worker, so the worker's answer is the operationally correct one.

    Only ever upgrades absent -> present, never the reverse. If this process
    can see the binary, its own live probe is fresher and wins; a worker
    record is a memory of an install, not a live check, and must not override
    direct evidence.

    Shared by both endpoints in this package: /registry merges it into each
    catalog entry, /health into each probe (via `_health_for`).
    """
    if local.get("installed"):
        return local

    worker = tool_health_cache.get_worker_health(tool)
    if not worker or not worker.get("installed"):
        return local

    return {**local, **worker, "checked_in": "worker"}


def _health_for(tool: str, cmd: list[str]) -> dict:
    """One tool's status as the platform sees it, rather than as this
    container sees it.

    `_check_one` answers a narrower question than the page asks: "can the
    process serving this request see the binary". For anything installed from
    the marketplace that is the wrong question, because the install ran on the
    Celery worker, a separate container in the default Compose topology
    (CTX-03), and the api process was never going to see it. Three outcomes,
    in decreasing order of evidence:

    * this process ran the binary -> `installed` True, `checked_in` "api";
    * it could not, but the worker reported an install -> `installed` True,
      `checked_in` "worker". Scans run on the worker, so its answer is the
      operationally meaningful one;
    * neither -> `installed` None and `checked_in` None. Nothing that would
      actually run this tool has reported on it, and a miss inside the api
      container is an absence of evidence, not evidence of absence.

    That third case is the defect this function exists for. Reporting it as
    `installed: False` let a page titled "tool health" present an
    api-container implementation detail as the platform's tool status: a tool
    installed from the marketplace, running scans on the worker, read as
    missing here. `installed` is therefore tri-state; callers that treat None
    as falsy degrade to exactly the old reading, and the frontend renders it
    as unknown rather than as a red negative.
    """
    merged = _merge_worker_health(tool, _check_one(tool, cmd))
    if merged.get("installed"):
        return merged

    # A worker record that says "not installed" is still a real answer from
    # the environment that runs scans, so it stays a confident negative; only
    # the no-record-at-all case is genuinely unknown.
    if tool_health_cache.get_worker_health(tool) is not None:
        return merged

    return {**merged, "installed": None, "checked_in": None}


@router.get("/health")
def tools_health():
    """Real version + reachability check for every tool in the registry, no
    simulated status. Every registry tool, not just the original Sprint 1
    four, because VERSION_COMMANDS above is now derived from the registry
    itself.

    The api-side probe is uncached, unlike /registry (see issue #221): this
    endpoint's job is a fresh answer on demand, and "Recheck" has to mean
    recheck. The worker's view is necessarily the cached one -- the api
    process cannot run a subprocess in another container -- so a tool present
    only on the worker is as fresh as that record. It is not, however,
    api-only any more. Probing only the process that serves the
    request made every marketplace-installed tool read as missing here, which
    is a true statement about this container and a false one about the
    platform; `_health_for` merges in the worker's view for exactly the
    reason /registry does.
    """
    return [_health_for(tool, cmd) for tool, cmd in VERSION_COMMANDS.items()]
