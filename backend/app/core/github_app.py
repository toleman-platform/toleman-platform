import time

import httpx
import jwt

from app.core.crypto import decrypt_secret
from app.models.models import GitHubAppConfig


def build_manifest(app_url: str, backend_url: str, name_suffix: str) -> dict:
    """GitHub App Manifest — https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-from-a-manifest

    Permissions mirror the architecture doc's Integration & Permissions Matrix:
    contents (clone + commit fixes), pull_requests + statuses (PR Guardrail),
    metadata read-only (mandatory baseline).
    """
    return {
        "name": f"OSP DevSecOps {name_suffix}",
        "url": app_url,
        "redirect_url": f"{backend_url}/api/github-app/callback",
        "setup_url": f"{backend_url}/api/github-app/setup-callback",
        "setup_on_update": True,
        "public": False,
        "default_permissions": {
            "contents": "write",
            "pull_requests": "write",
            "statuses": "write",
            "metadata": "read",
        },
        "default_events": [],
    }


def generate_app_jwt(config: GitHubAppConfig) -> str:
    now = int(time.time())
    payload = {"iat": now - 60, "exp": now + 9 * 60, "iss": config.app_id}
    private_key_pem = decrypt_secret(config.private_key_pem)
    return jwt.encode(payload, private_key_pem, algorithm="RS256")


def get_installation_token(config: GitHubAppConfig, installation_id: int) -> str:
    app_jwt = generate_app_jwt(config)
    res = httpx.post(
        f"https://api.github.com/app/installations/{installation_id}/access_tokens",
        headers={"Authorization": f"Bearer {app_jwt}", "Accept": "application/vnd.github+json"},
        timeout=15,
    )
    res.raise_for_status()
    return res.json()["token"]


def list_installation_repos(installation_token: str) -> list[dict]:
    repos = []
    page = 1
    while True:
        res = httpx.get(
            "https://api.github.com/installation/repositories",
            headers={"Authorization": f"Bearer {installation_token}", "Accept": "application/vnd.github+json"},
            params={"per_page": 100, "page": page},
            timeout=15,
        )
        res.raise_for_status()
        data = res.json()
        repos.extend(data.get("repositories", []))
        if len(data.get("repositories", [])) < 100:
            break
        page += 1
    return repos


def get_installation_account(config: GitHubAppConfig, installation_id: int) -> dict:
    app_jwt = generate_app_jwt(config)
    res = httpx.get(
        f"https://api.github.com/app/installations/{installation_id}",
        headers={"Authorization": f"Bearer {app_jwt}", "Accept": "application/vnd.github+json"},
        timeout=15,
    )
    res.raise_for_status()
    return res.json()
