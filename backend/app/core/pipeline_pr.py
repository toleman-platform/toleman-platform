"""Pipeline integration (issue #66): open a real PR against a target's
GitHub repo adding the generated `.github/workflows/rikugan-scan.yml` (see
`app.core.pipeline_workflow`). Uses the GitHub App's installation token via
the same resolution helpers PR Guardrail's comment/commit-status posting
already relies on (`app.core.github_app`), rather than the plain
`GITHUB_TOKEN`/`gh` CLI fallback `app.core.github.github_get` uses for
read-only calls -- opening a branch + PR needs `contents: write` /
`pull_requests: write`, which only the App's installation token carries.
"""
import base64
import logging
import time

import httpx
from sqlmodel import Session

from app.core.github import repo_slug_from_url
from app.core.github_app import get_installation_token, resolve_config_for_installation, resolve_installation_for_repo
from app.core.pipeline_workflow import WORKFLOW_PATH, generate_workflow_yaml
from app.models.models import Target

logger = logging.getLogger(__name__)


class PipelinePrError(Exception):
    """Raised for any failure opening the pipeline-integration PR -- callers
    turn this into an HTTP 4xx/502 with the message as detail."""


def _get_installation_token(session: Session, target: Target) -> str:
    slug = repo_slug_from_url(target.repo_url)
    installation = resolve_installation_for_repo(session, target.workspace_id, slug)
    if not installation:
        raise PipelinePrError(
            "No GitHub App installation found for this target's workspace. "
            "Connect the GitHub App to this repo first."
        )
    config = resolve_config_for_installation(session, installation)
    if not config:
        raise PipelinePrError("Could not resolve the GitHub App config for this target's installation.")
    return get_installation_token(config, installation.installation_id)


def open_pipeline_pr(session: Session, target: Target, steps: list[str] | None = None) -> dict:
    """Opens a real PR on the target's GitHub repo adding
    .github/workflows/rikugan-scan.yml on a new branch off the default branch.
    Returns {"pr_url": str, "pr_number": int, "branch": str}. Raises
    PipelinePrError (never a bare httpx exception) on any failure so the API
    layer can return a clean error message instead of a stack trace.

    `steps` (issue #35, Custom Workflow Builder / Mass CI/CD Rollout Engine)
    is passed straight through to generate_workflow_yaml -- an ordered list
    of tool names from a PipelineWorkflowTemplate, or None to keep #66's
    original fixed default scanner set."""
    slug = repo_slug_from_url(target.repo_url)
    token = _get_installation_token(session, target)
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}

    # 1. Latest commit sha on the default branch -- the new branch and PR
    # base both need this.
    ref_res = httpx.get(
        f"https://api.github.com/repos/{slug}/git/ref/heads/{target.default_branch}", headers=headers, timeout=15
    )
    if ref_res.status_code != 200:
        raise PipelinePrError(
            f"failed to read default branch '{target.default_branch}' from GitHub: "
            f"{ref_res.status_code} {ref_res.text[:200]}"
        )
    base_sha = ref_res.json()["object"]["sha"]

    # 2. Create a new branch off that sha. Suffix with a timestamp so a
    # repeat "Integrate Pipeline" click after an earlier PR was merged/closed
    # doesn't collide with a stale branch of the same name.
    branch_name = f"rikugan/add-pipeline-scan-{int(time.time())}"
    create_ref_res = httpx.post(
        f"https://api.github.com/repos/{slug}/git/refs",
        headers=headers,
        json={"ref": f"refs/heads/{branch_name}", "sha": base_sha},
        timeout=15,
    )
    if create_ref_res.status_code not in (200, 201):
        raise PipelinePrError(
            f"failed to create branch '{branch_name}' on GitHub: "
            f"{create_ref_res.status_code} {create_ref_res.text[:200]}"
        )

    # 3. Generate the workflow content for this target (real target-specific
    # tool set), then check whether the file already exists on the default
    # branch (repeat integration) so the contents-write API gets the sha it
    # requires to update rather than create.
    generated = generate_workflow_yaml(session, target, steps=steps)
    existing_res = httpx.get(
        f"https://api.github.com/repos/{slug}/contents/{WORKFLOW_PATH}",
        headers=headers,
        params={"ref": target.default_branch},
        timeout=15,
    )
    existing_sha = existing_res.json().get("sha") if existing_res.status_code == 200 else None

    content_b64 = base64.b64encode(generated["yaml"].encode("utf-8")).decode("ascii")
    put_body = {
        "message": "Add Rikugan DevSecOps pipeline scan workflow",
        "content": content_b64,
        "branch": branch_name,
    }
    if existing_sha:
        put_body["sha"] = existing_sha
    put_res = httpx.put(
        f"https://api.github.com/repos/{slug}/contents/{WORKFLOW_PATH}", headers=headers, json=put_body, timeout=15
    )
    if put_res.status_code not in (200, 201):
        raise PipelinePrError(
            f"failed to write {WORKFLOW_PATH} on GitHub: {put_res.status_code} {put_res.text[:200]}"
        )

    # 4. Open the PR.
    pr_body = (
        "Adds a Rikugan DevSecOps Platform CI/CD scan workflow "
        f"(`{WORKFLOW_PATH}`), opened automatically via **Integrate Pipeline** "
        "in Rikugan.\n\n"
        "Runs Semgrep, Gitleaks, and Trivy (plus gosec for Go repos) natively "
        "in the GitHub Actions runner and, when the `RIKUGAN_API_URL`/`RIKUGAN_API_KEY` "
        "repo secrets are configured, pushes results back into Rikugan via "
        "`POST /api/ingest`.\n\n"
        "**Note:** `RIKUGAN_API_URL` must point to a publicly reachable Rikugan "
        "deployment -- GitHub's cloud runners cannot reach `localhost`. See "
        "the comments at the top of the workflow file for setup details."
    )
    pr_res = httpx.post(
        f"https://api.github.com/repos/{slug}/pulls",
        headers=headers,
        json={
            "title": "Add Rikugan DevSecOps pipeline scan workflow",
            "head": branch_name,
            "base": target.default_branch,
            "body": pr_body,
        },
        timeout=15,
    )
    if pr_res.status_code not in (200, 201):
        raise PipelinePrError(f"failed to open PR on GitHub: {pr_res.status_code} {pr_res.text[:300]}")

    pr = pr_res.json()
    return {"pr_url": pr["html_url"], "pr_number": pr["number"], "branch": branch_name}
