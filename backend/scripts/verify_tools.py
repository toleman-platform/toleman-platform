#!/usr/bin/env python3
"""Prove every bundled scanner actually runs inside the built image.

Run this *in the image*, not on a developer's machine:

    docker run --rm <image> python scripts/verify_tools.py

Why it exists: `docker build` succeeding only proves the install commands
exited zero at build time. It does not prove the binaries still run. The
break that prompted this (setuptools 82 dropping `pkg_resources` out from
under semgrep's pinned opentelemetry) happened to fail loudly because the
Dockerfile ran `semgrep --version` inline, but nothing covered the other
scanners, and nothing at all covered the case where a tool installs fine and
then fails on first invocation.

That failure mode matters more here than in most projects. A scanner that is
missing or broken does not announce itself: `run_scan` catches the error, the
scan completes, and the repo shows zero findings. Zero findings from a broken
scanner is indistinguishable from zero findings from clean code, which is the
same "absence of evidence is not evidence of absence" problem this codebase
keeps running into (#174 never-scanned repos, #190 ungenerated AIBOM).

Exits non-zero listing every tool that is missing, unrunnable, or silent.
"""
from __future__ import annotations

import shutil
import subprocess
import sys

sys.path.insert(0, "/app")

from app.core.tool_registry import BUNDLED_TOOLS, TOOL_REGISTRY  # noqa: E402

# Generous: some of these pay full interpreter startup, and a slow CI runner
# should not be reported as a broken tool.
VERSION_TIMEOUT_SECONDS = 60


def check(tool: str, cmd: list[str]) -> tuple[bool, str]:
    binary = cmd[0]
    if shutil.which(binary) is None:
        return False, f"{binary!r} not on PATH"

    try:
        # cmd comes from TOOL_REGISTRY's fixed version_cmd entries, no shell,
        # no interpolated input.
        proc = subprocess.run(  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit
            cmd, capture_output=True, text=True, timeout=VERSION_TIMEOUT_SECONDS
        )
    except subprocess.TimeoutExpired:
        return False, f"timed out after {VERSION_TIMEOUT_SECONDS}s"
    except OSError as exc:
        return False, f"could not execute: {exc}"

    # Some tools print their version to stderr, so both streams count.
    output = (proc.stdout or "") + (proc.stderr or "")

    if proc.returncode != 0:
        first_error = next(
            (line for line in output.splitlines() if line.strip()), "no output"
        )
        return False, f"exited {proc.returncode}: {first_error.strip()[:200]}"

    version = next((line for line in output.splitlines() if line.strip()), "")
    if not version:
        # A zero exit with nothing on either stream means the tool did not
        # really answer, which is not the same as being healthy.
        return False, "exited 0 but printed no version"

    return True, version.strip()[:120]


def main() -> int:
    by_tool = {entry["tool"]: entry for entry in TOOL_REGISTRY}

    missing_from_registry = sorted(BUNDLED_TOOLS - by_tool.keys())
    if missing_from_registry:
        print(f"BUNDLED_TOOLS names entries not in TOOL_REGISTRY: {missing_from_registry}")
        return 1

    failures: list[str] = []
    for tool in sorted(BUNDLED_TOOLS):
        ok, detail = check(tool, by_tool[tool]["version_cmd"])
        print(f"{'ok  ' if ok else 'FAIL'} {tool:<16} {detail}")
        if not ok:
            failures.append(f"{tool}: {detail}")

    print()
    if failures:
        print(f"{len(failures)} bundled tool(s) not usable in this image:")
        for line in failures:
            print(f"  - {line}")
        return 1

    print(f"All {len(BUNDLED_TOOLS)} bundled tools run in this image.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
