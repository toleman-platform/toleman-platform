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
from pathlib import Path

from app.core.config import settings

TOOL_COMMANDS = {
    "semgrep": lambda path: ["semgrep", "scan", "--config=auto", "--json", "--quiet", path],
    "gitleaks": lambda path: ["gitleaks", "detect", "--source", path, "--report-format", "json", "--report-path", "/dev/stdout", "--no-git", "--exit-code", "0"],
    "trivy": lambda path: ["trivy", "fs", "--format", "json", "--quiet", path],
    "gosec": lambda path: ["gosec", "-fmt=json", "-quiet", "./..."],
}


def clone_repo(repo_url: str, branch: str, github_token: str = "") -> Path:
    workdir = Path(settings.scan_workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
    dest = workdir / repo_name
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


def run_tool(tool: str, repo_path: Path) -> dict | list:
    if tool not in TOOL_COMMANDS:
        raise ValueError(f"unsupported tool: {tool}")

    cmd = TOOL_COMMANDS[tool](str(repo_path))
    cwd = str(repo_path) if tool == "gosec" else None
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)

    stdout = proc.stdout.strip()
    if not stdout:
        return {} if tool in ("semgrep", "trivy", "gosec") else []
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        return {} if tool in ("semgrep", "trivy", "gosec") else []
