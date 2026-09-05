"""One-click scanner installation, allowlist-only (#216).

The security shape of this module matters more than its size, so it is worth
stating plainly.

Installing software in response to an HTTP request is an obvious remote-code-
execution surface, and #75 originally declined to build it for exactly that
reason. What made it declinable then, and buildable now, is *where the
command comes from*:

  * The caller supplies a **registry key**, not a package. `resolve_package`
    looks the key up in TOOL_REGISTRY and returns None for anything absent.
    There is no code path from a request body to a package name; the set
    of installable packages is fixed at deploy time, in source.
  * The command is an argv list built from a module constant with the
    package appended as one element. No shell, no `shell=True`, no string
    formatting into a command. Even if a registry entry somehow contained
    `; rm -rf /`, it would be passed to pip as a single (invalid) package
    name and rejected, not executed.
  * pip runs with `--no-input` so it can never block on a prompt, and under
    a timeout so a hung resolve cannot pin a worker forever.

Two honest limitations, both surfaced in the UI rather than hidden:

  1. **Installs are ephemeral.** This installs into the running container's
     site-packages. A redeploy, or `docker compose up --build`, starts from
     the image again and the tool is gone. Presenting a one-click install as
     permanent would be a lie, and an operator who believes a scanner is
     installed when it is not gets silent zero-finding scans; the same
     failure this codebase keeps guarding against. The durable fix is adding
     the tool to the image; the UI says so.
  2. **Only pip-installable tools qualify.** gitleaks, trivy, gosec, tfsec
     and kics need brew/go/docker, which the backend image does not carry.
     They have no `pip_package` and get no button, rather than a button that
     fails.
"""
from __future__ import annotations

import subprocess
import sys
from typing import Optional

from sqlmodel import Session

from app.core import tool_health_cache
from app.core.tool_registry import TOOL_REGISTRY
from app.core.time import utcnow

# A big dependency tree (modelscan pulls tensorflow) is genuinely slow, but
# an unbounded install would hold a Celery worker indefinitely.
INSTALL_TIMEOUT_SECONDS = 900

# pip is chatty. This is a display aid for an operator, not a build log, and
# an unbounded write would put megabytes in a row that gets rendered in a UI.
OUTPUT_TAIL_CHARS = 4000

VERSION_CHECK_TIMEOUT_SECONDS = 60

_BY_TOOL = {entry["tool"]: entry for entry in TOOL_REGISTRY}


def resolve_package(tool: str) -> Optional[str]:
    """The pip package for a registry key, or None if it is not installable.

    None covers both "no such tool" and "this tool needs brew/go/docker".
    Callers must treat None as a refusal; it is the allowlist check.
    """
    entry = _BY_TOOL.get(tool)
    if entry is None:
        return None
    return entry.get("pip_package")


def installable_tools() -> set[str]:
    return {t for t in _BY_TOOL if _BY_TOOL[t].get("pip_package")}


def _tail(text: str) -> str:
    text = text.strip()
    if len(text) <= OUTPUT_TAIL_CHARS:
        return text
    return "...\n" + text[-OUTPUT_TAIL_CHARS:]


def _installed_version(tool: str) -> str:
    """Run the tool's own version_cmd after installing.

    pip exiting zero is not proof the tool runs; the setuptools/pkg_resources
    break that prompted scripts/verify_tools.py was exactly a clean install
    whose binary then failed on invocation. So an install is only reported as
    successful once the thing actually answers.
    """
    entry = _BY_TOOL.get(tool)
    if not entry:
        return ""
    try:
        # entry["version_cmd"] is a fixed argv list from the tool registry,
        # no shell, no interpolated input.
        proc = subprocess.run(  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit
            entry["version_cmd"],
            capture_output=True,
            text=True,
            timeout=VERSION_CHECK_TIMEOUT_SECONDS,
        )
    except (subprocess.TimeoutExpired, OSError):
        return ""
    if proc.returncode != 0:
        return ""
    output = (proc.stdout or "") + (proc.stderr or "")
    return next((line.strip() for line in output.splitlines() if line.strip()), "")[:200]


def perform_install(session: Session, run) -> None:
    """Execute the install for an already-created ToolInstallRun row.

    Never raises: any failure is recorded on the row, because a Celery task
    that dies leaves the row "running" forever and the UI spinning.
    """
    package = resolve_package(run.tool)
    if not package:
        # Belt and braces. The API refuses this first, but this module must
        # not be trustable only because its callers are careful.
        _finish(session, run, status="failed", error=f"{run.tool!r} is not installable from here")
        return

    # Built from a constant. The package is one argv element, never
    # interpolated into a string and never seen by a shell.
    cmd = [sys.executable, "-m", "pip", "install", "--no-input", "--disable-pip-version-check", package]

    try:
        # cmd is built from sys.executable and a package name resolved via
        # resolve_package(), a registry-key lookup, not a package string
        # supplied by the caller. No shell, one argv element per part.
        proc = subprocess.run(  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit
            cmd, capture_output=True, text=True, timeout=INSTALL_TIMEOUT_SECONDS
        )
    except subprocess.TimeoutExpired:
        _finish(
            session,
            run,
            status="failed",
            error=f"install timed out after {INSTALL_TIMEOUT_SECONDS // 60} minutes",
        )
        return
    except OSError as exc:
        _finish(session, run, status="failed", error=f"could not start pip: {exc}")
        return

    output = _tail((proc.stdout or "") + (proc.stderr or ""))

    if proc.returncode != 0:
        _finish(session, run, status="failed", error=f"pip exited {proc.returncode}", output=output)
        return

    version = _installed_version(run.tool)
    if not version:
        # Installed, but does not run. Reporting this as success is precisely
        # the "clean install, broken binary" case that produces silent
        # zero-finding scans later.
        _finish(
            session,
            run,
            status="failed",
            error="pip succeeded but the tool did not report a version when run",
            output=output,
        )
        return

    _finish(session, run, status="completed", version=version, output=output)


def _finish(session: Session, run, *, status: str, error: str = "", version: str = "", output: str = "") -> None:
    run.status = status
    run.completed_at = utcnow()
    run.error = error
    run.installed_version = version
    run.output_tail = output
    session.add(run)
    session.commit()
    session.refresh(run)

    # (#221) Whatever GET /api/tools/registry cached for this tool is now
    # stale by definition, an install just settled, successfully or not.
    # Invalidating here rather than waiting out the cache's own TTL means
    # the tool an admin just watched install shows correctly on the very
    # next registry fetch (the frontend's useToolInstall calls that fetch
    # itself once this row settles), instead of on whichever refresh happens
    # to land after the TTL expires.
    tool_health_cache.invalidate(run.tool)

    # (CTX-03) ...but invalidating alone was actively wrong here, and it is
    # worth being precise about why.
    #
    # This code runs on the Celery worker. The registry endpoint runs in the
    # backend web process. In the default Compose topology those are separate
    # containers from the same image, so a pip install into the worker's
    # site-packages is invisible to the backend's `shutil.which()`. Dropping
    # the cache just made the backend re-probe *itself*, find nothing, and
    # publish "not installed"; for a tool that had installed successfully
    # and whose version we had just read, one line above. An external
    # evaluation hit exactly this: Checkov installed (3.3.13), card said "not
    # installed", still said it after "Recheck all".
    #
    # The version this worker read is the operationally meaningful one (
    # every scan runs on a worker, not in the web process) so publish it
    # rather than throwing it away. `checked_in` keeps the answer honest
    # about which environment it describes.
    if status == "completed" and version:
        tool_health_cache.set_worker_health(
            run.tool,
            {
                "tool": run.tool,
                "installed": True,
                "version": version,
                "response_ms": None,
                "checked_in": "worker",
            },
        )
