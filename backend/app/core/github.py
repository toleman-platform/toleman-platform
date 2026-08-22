from urllib.parse import urlparse

import httpx


def repo_slug_from_url(repo_url: str) -> str:
    """https://github.com/org/repo.git -> org/repo"""
    path = urlparse(repo_url).path.strip("/")
    return path[:-4] if path.endswith(".git") else path


def github_get(path: str, params: dict | None = None, token: str = "") -> httpx.Response:
    """Authenticated read-only GET against api.github.com.

    ``token`` is an already-resolved credential (see
    app.core.github_token.resolve_github_token) supplied by the caller; when
    empty the request is made unauthenticated (public-repo only). The token is
    only ever placed in the Authorization header, never in the URL/query, and
    is never logged.
    """
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return httpx.get(f"https://api.github.com{path}", headers=headers, params=params, timeout=15)
