import subprocess
from functools import lru_cache
from urllib.parse import urlparse

import httpx

from app.core.config import settings


@lru_cache(maxsize=1)
def get_github_token() -> str:
    """Resolve a GitHub token for REST API calls.

    Prefers GITHUB_TOKEN from settings; falls back to the `gh` CLI's stored
    credential (same one git already uses transparently for cloning) so the
    platform works without asking the user to paste a token into .env.
    """
    if settings.github_token:
        return settings.github_token
    try:
        result = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, timeout=10)
        return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""


def repo_slug_from_url(repo_url: str) -> str:
    """https://github.com/org/repo.git -> org/repo"""
    path = urlparse(repo_url).path.strip("/")
    return path[:-4] if path.endswith(".git") else path


def github_get(path: str, params: dict | None = None) -> httpx.Response:
    token = get_github_token()
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return httpx.get(f"https://api.github.com{path}", headers=headers, params=params, timeout=15)
