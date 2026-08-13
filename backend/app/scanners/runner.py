"""Native execution: clone target repo, run CLI security tools, return raw output.

MVP note: runs directly via subprocess (no container isolation yet). Architecture
review flagged this as a blocker before mass-scale/multi-tenant rollout — fine for
single-user local/dev use, must move to ephemeral containers (K8s Job) before
that feature ships.
"""
import json
import os
import shutil
import subprocess
import uuid
from pathlib import Path

from app.core.config import settings

TOOL_COMMANDS = {
    "semgrep": lambda path: ["semgrep", "scan", "--config=auto", "--json", "--quiet", path],
    "gitleaks": lambda path: ["gitleaks", "detect", "--source", path, "--report-format", "json", "--report-path", "/dev/stdout", "--no-git", "--exit-code", "0"],
    "trivy": lambda path: ["trivy", "fs", "--format", "json", "--quiet", path],
    "trivy-license": lambda path: ["trivy", "fs", "--scanners", "license", "--format", "json", "--quiet", path],
    "gosec": lambda path: ["gosec", "-fmt=json", "-quiet", "./..."],
}


def clone_repo(repo_url: str, branch: str, github_token: str = "", scan_id: int | str | None = None) -> Path:
    """Clone repo_url@branch into a scan-scoped workdir.

    The destination is keyed by repo name AND a unique suffix (the caller's
    scan_id when available, otherwise a fresh UUID) so that two concurrent
    scans of the same target -- or of different targets that happen to
    share a repo name -- never resolve to the same directory. Previously
    the dir was keyed by repo name alone and unconditionally rmtree'd +
    recloned on every call, which let one scan's rmtree delete files while
    another scan's clone/tool run was still reading them (a race that could
    corrupt or blow up a concurrent scan). Cleaning up old scan workdirs is
    a separate ops concern, intentionally out of scope here.
    """
    workdir = Path(settings.scan_workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
    unique = str(scan_id) if scan_id is not None else uuid.uuid4().hex
    dest = workdir / f"{repo_name}-{unique}"
    if dest.exists():
        shutil.rmtree(dest)

    clone_url = repo_url
    if github_token and repo_url.startswith("https://github.com/"):
        clone_url = repo_url.replace("https://github.com/", f"https://x-access-token:{github_token}@github.com/")

    subprocess.run(
        ["git", "clone", "--depth", "1", "--branch", branch, clone_url, str(dest)],
        check=True, capture_output=True, text=True,
    )
    return dest


def normalize_file_path(file_path: str, repo_path: Path) -> str:
    """Strip the scan-scoped clone directory prefix so file_path is relative
    to the repo root, e.g. "vulnerability/idor/idor.go" not
    "/tmp/osp-scans/govwa-<scan-id>/vulnerability/idor/idor.go".

    This matters beyond cosmetics: compute_dedup_hash includes file_path, and
    since clone_repo (above) gives every scan its own unique directory name
    for isolation, an un-normalized absolute path made the dedup hash change
    on every single scan -- silently defeating dedup entirely (every rescan
    created a new Finding instead of updating last_seen on the existing one).
    Call this on every parsed finding's file_path before hashing/persisting.
    """
    if not file_path:
        return file_path
    try:
        return str(Path(file_path).relative_to(repo_path))
    except ValueError:
        # Already relative (some tools report paths relative to the scan
        # root they were invoked against) -- nothing to strip.
        return file_path


def run_tool(tool: str, repo_path: Path) -> dict | list:
    if tool not in TOOL_COMMANDS:
        raise ValueError(f"unsupported tool: {tool}")

    cmd = TOOL_COMMANDS[tool](str(repo_path))
    cwd = str(repo_path) if tool == "gosec" else None
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)

    stdout = proc.stdout.strip()
    if not stdout:
        return {} if tool in ("semgrep", "trivy", "trivy-license", "gosec") else []
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        return {} if tool in ("semgrep", "trivy", "trivy-license", "gosec") else []
