"""`GET /api/tools/registry`: the full tool marketplace listing (issue #75).

Every supported OSS security tool across SAST/SCA/Secrets/Container/IaC/
License/AI-ML, each merged with a real live health check (reusing health.py's
`_check_one`, same subprocess `--version` probe /health always ran) and an
`integrated`/`installable` flag pair.

`_merge_worker_health` (the CTX-03 fold-in of what the Celery worker
reported) used to live here and is now imported from health.py alongside
`_check_one`, because /health needs the same merge for the same reason and
health.py is the end of the dependency chain: registry -> health, never
back. There is one implementation of that merge, not one per endpoint.
"""
from concurrent.futures import ThreadPoolExecutor

from fastapi import APIRouter

from app.api.tools.health import _check_one, _merge_worker_health
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

    # Probe independent --version commands concurrently and cache per tool for
    # TTL_SECONDS. UI installs invalidate that tool immediately. Missing binaries
    # short-circuit through shutil.which without spawning a process.
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
