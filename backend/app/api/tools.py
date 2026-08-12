import shutil
import subprocess
import time

from fastapi import APIRouter

router = APIRouter(prefix="/api/tools", tags=["tools"])

VERSION_COMMANDS = {
    "semgrep": ["semgrep", "--version"],
    "gitleaks": ["gitleaks", "version"],
    "trivy": ["trivy", "--version"],
    "gosec": ["gosec", "--version"],
}


@router.get("/health")
def tools_health():
    """Real version + reachability check for each scanner — no simulated status."""
    results = []
    for tool, cmd in VERSION_COMMANDS.items():
        binary_path = shutil.which(cmd[0])
        if not binary_path:
            results.append({"tool": tool, "installed": False, "version": None, "response_ms": None})
            continue

        start = time.monotonic()
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            elapsed_ms = round((time.monotonic() - start) * 1000)
            output = (proc.stdout or proc.stderr).strip().splitlines()
            version = output[0] if output else "unknown"
            results.append({"tool": tool, "installed": True, "version": version, "response_ms": elapsed_ms})
        except (subprocess.TimeoutExpired, OSError):
            results.append({"tool": tool, "installed": True, "version": None, "response_ms": None})
    return results
