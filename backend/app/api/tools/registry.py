"""`GET /api/tools/registry` -- the full tool marketplace listing (issue #75).

Every supported OSS security tool across SAST/SCA/Secrets/Container/IaC/
License/AI-ML, each merged with a real live health check (reusing health.py's
`_check_one`, same subprocess `--version` probe /health always ran) and an
`integrated`/`installable` flag pair.
"""
from concurrent.futures import ThreadPoolExecutor

from fastapi import APIRouter

from app.api.tools.health import _check_one
from app.core import tool_health_cache
from app.core.tool_registry import registry_with_integration_status

router = APIRouter()


@router.get("/registry")
def tools_registry():
    """Full tool marketplace registry (issue #75): every supported OSS
    security tool across SAST/SCA/Secrets/Container/IaC/License/AI-ML, each
    merged with a real live health check (subprocess `--version`, exactly
    like /health) and an `integrated` flag (whether Toleman can actually
    dispatch a scan for it today via app.scanners.runner.TOOL_COMMANDS)."""
    entries = registry_with_integration_status()

    # Issue #187: the checks run concurrently rather than in sequence. They
    # are independent blocking `--version` subprocesses, so serial cost was
    # their sum rather than their max.
    #
    # Measured on a dev box, serial: semgrep 2061ms, trivy 111ms,
    # trivy-license 107ms, gosec 71ms, gitleaks 21ms = 2371ms total.
    # `semgrep --version` dominates because it pays full Python interpreter
    # startup, and that is the real cost of this endpoint -- parallelising
    # takes it to roughly max() instead of sum(), about 2.37s -> 2.06s.
    #
    # Issue #221 (senior-review pass): that 2.06s is still paid on *every*
    # request, for information -- is this tool installed, at what version --
    # that only changes when an admin installs/removes a tool. Cached
    # per-tool for tool_health_cache.TTL_SECONDS (app.core.tool_health_cache)
    # and invalidated explicitly the moment an install through this UI
    # settles (app.core.tool_install), so the one thing that actually just
    # changed is never the one left stale. Everything else can be up to
    # tool_health_cache.TTL_SECONDS old, which is an acceptable trade for
    # turning "2s on every marketplace page view" into "2s once every 30s,
    # shared across every admin viewing it".
    #
    # Note the five AI/ML entries added in #187 cost essentially nothing even
    # uncached: _check_one short-circuits on shutil.which() before spawning
    # anything, so an uninstalled tool is a path lookup, not a process.
    cached = {}
    to_check = []
    for entry in entries:
        hit = tool_health_cache.get(entry["tool"])
        if hit is not None:
            cached[entry["tool"]] = hit
        else:
            to_check.append(entry)

    if to_check:
        # Thread pool rather than async because subprocess.run blocks.
        with ThreadPoolExecutor(max_workers=min(16, len(to_check))) as pool:
            healths = list(pool.map(lambda e: _check_one(e["tool"], e["version_cmd"]), to_check))
        for entry, health in zip(to_check, healths):
            tool_health_cache.set(entry["tool"], health)
            cached[entry["tool"]] = health

    return [{**entry, **_merge_worker_health(entry["tool"], cached[entry["tool"]])} for entry in entries]


def _merge_worker_health(tool: str, local: dict) -> dict:
    """Fold in what the Celery worker reported, when this process can't see
    the tool itself (CTX-03).

    The probe above runs `shutil.which()` in *this* process. One-click
    installs run on the worker, which in the default Compose topology is a
    separate container -- so a successful install was invisible here and the
    card read "not installed" forever, even after "Recheck all". Scans run on
    the worker, so the worker's answer is the operationally correct one.

    Only ever upgrades absent -> present, never the reverse. If this process
    can see the binary, its own live probe is fresher and wins; a worker
    record is a memory of an install, not a live check, and must not override
    direct evidence.
    """
    if local.get("installed"):
        return local

    worker = tool_health_cache.get_worker_health(tool)
    if not worker or not worker.get("installed"):
        return local

    return {**local, **worker, "checked_in": "worker"}
