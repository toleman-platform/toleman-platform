"""Pipeline integration (issue #66): open a real PR against a target's
GitHub repo adding the generated `.github/workflows/toleman-scan.yml` (see
`app.core.pipeline_workflow`). Uses the GitHub App's installation token via
the same resolution helpers PR Guardrail's comment/commit-status posting
already relies on (`app.core.github_app`), rather than the plain
`GITHUB_TOKEN`/`gh` CLI fallback `app.core.github.github_get` uses for
read-only calls; opening a branch + PR needs `contents: write` /
`pull_requests: write`, which only the App's installation token carries.
"""
import base64
import logging
import time

import httpx
from sqlmodel import Session

from app.core.github import repo_slug_from_url
from app.core.github_app import get_installation_token, resolve_config_for_installation, resolve_installation_for_repo
from app.core.pipeline_workflow import LEGACY_WORKFLOW_PATH, WORKFLOW_PATH, generate_workflow_yaml
from app.models.models import Target

logger = logging.getLogger(__name__)


class PipelinePrError(Exception):
    """Raised for any failure opening the pipeline-integration PR; callers
    turn this into an HTTP 4xx/502 with the message as detail."""


def _delete_legacy_workflow(slug: str, headers: dict, branch_name: str, default_branch: str) -> bool:
    """Remove the pre-rename `rikugan-scan.yml` on the PR branch, if the repo
    still has one. Returns True if it was deleted.

    Best-effort by design: this runs *after* the new workflow file has already
    been written to the branch, so raising here would throw away a PR that is
    otherwise complete. A repo that was never integrated before the rename (
    every new integration) simply 404s on the lookup and returns False.
    """
    try:
        res = httpx.get(
            f"https://api.github.com/repos/{slug}/contents/{LEGACY_WORKFLOW_PATH}",
            headers=headers,
            params={"ref": default_branch},
            timeout=15,
        )
        if res.status_code != 200:
            return False
        legacy_sha = res.json().get("sha")
        if not legacy_sha:
            return False
        del_res = httpx.delete(
            f"https://api.github.com/repos/{slug}/contents/{LEGACY_WORKFLOW_PATH}",
            headers=headers,
            json={
                "message": "Remove pre-rename Rikugan scan workflow (replaced by toleman-scan.yml)",
                "sha": legacy_sha,
                "branch": branch_name,
            },
            timeout=15,
        )
        if del_res.status_code not in (200, 201):
            logger.warning(
                "pipeline PR: failed to delete %s on %s: %s %s",
                LEGACY_WORKFLOW_PATH, slug, del_res.status_code, del_res.text[:200],
            )
            return False
        return True
    except httpx.HTTPError:
        logger.warning("pipeline PR: error deleting %s on %s", LEGACY_WORKFLOW_PATH, slug, exc_info=True)
        return False


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
    .github/workflows/toleman-scan.yml on a new branch off the default branch.
    Returns {"pr_url": str, "pr_number": int, "branch": str}. Raises
    PipelinePrError (never a bare httpx exception) on any failure so the API
    layer can return a clean error message instead of a stack trace.

    `steps` (issue #35, Custom Workflow Builder / Mass CI/CD Rollout Engine)
    is passed straight through to generate_workflow_yaml; an ordered list
    of tool names from a PipelineWorkflowTemplate, or None to keep #66's
    original fixed default scanner set."""
    slug = repo_slug_from_url(target.repo_url)
    token = _get_installation_token(session, target)
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}

    # 1. Latest commit sha on the default branch; the new branch and PR
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
    branch_name = f"toleman/add-pipeline-scan-{int(time.time())}"
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
        "message": "Add Toleman DevSecOps pipeline scan workflow",
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

    # 3b. Rename, don't duplicate: a repo integrated before the Rikugan ->
    # Toleman rename already has the workflow under LEGACY_WORKFLOW_PATH.
    # Leaving it would run two near-identical scan workflows on every PR
    # forever. Best-effort; a repo that never had the old file (the common
    # case) 404s here, and failing to remove it is not worth losing the PR
    # that just wrote the new one over.
    legacy_removed = _delete_legacy_workflow(slug, headers, branch_name, target.default_branch)

    # 4. Open the PR.
    pr_body = (
        "Adds a Toleman DevSecOps Platform CI/CD scan workflow "
        f"(`{WORKFLOW_PATH}`), opened automatically via **Integrate Pipeline** "
        "in Toleman.\n\n"
        "Runs Semgrep, Gitleaks, and Trivy (plus gosec for Go repos) natively "
        "in the GitHub Actions runner and, when the `TOLEMAN_API_URL`/`TOLEMAN_API_KEY` "
        "repo secrets are configured, pushes results back into Toleman via "
        "`POST /api/ingest`.\n\n"
        "**Note:** `TOLEMAN_API_URL` must point to a publicly reachable Toleman "
        "deployment, GitHub's cloud runners cannot reach `localhost`. See "
        "the comments at the top of the workflow file for setup details."
    )
    if legacy_removed:
        pr_body += (
            f"\n\n**Also removes** the previous `{LEGACY_WORKFLOW_PATH}`; this product was "
            "renamed from Rikugan to Toleman, so this PR is a rename of the existing scan "
            "workflow, not a second one. Update the repo secrets to `TOLEMAN_API_URL`/"
            "`TOLEMAN_API_KEY` (the old `RIKUGAN_*` names are no longer read) before merging."
        )
    pr_res = httpx.post(
        f"https://api.github.com/repos/{slug}/pulls",
        headers=headers,
        json={
            "title": "Add Toleman DevSecOps pipeline scan workflow",
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
